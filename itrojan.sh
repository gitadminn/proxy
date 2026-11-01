#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 077
export PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

readonly DEFAULT_SING_BOX_VERSION="1.13.15"
readonly DEFAULT_SING_BOX_SHA256="52104a3acd39be021fd00de5c0f5a4a134ca748378ebaa99cc7397969996f34b"
readonly ACME_COMMIT="3661fd86b6304115e42f43910e6dd452ab9866d6"
readonly ACME_SHA256="fcabf274d4f96966ec933879ae0257266e8ef2f7d16161f14b84dd896c0cac32"

readonly SERVICE_NAME="trojan-sing-box.service"
readonly SERVICE_USER="trojan-sing-box"
readonly SERVICE_GROUP="trojan-sing-box"
readonly INSTALL_DIR="/usr/local/lib/trojan-sing-box"
readonly SING_BOX_BIN="${INSTALL_DIR}/sing-box"
readonly CONFIG_DIR="/etc/trojan-sing-box"
readonly CONFIG_FILE="${CONFIG_DIR}/config.json"
readonly CERT_DIR="${CONFIG_DIR}/certs"
readonly CERT_FILE="${CERT_DIR}/fullchain.pem"
readonly KEY_FILE="${CERT_DIR}/private.key"
readonly STATE_DIR="/var/lib/trojan-sing-box"
readonly ACME_HOME="${STATE_DIR}/acme"
readonly ACME_INSTALL_DIR="/opt/trojan-sing-box-acme"
readonly ACME_BIN="${ACME_INSTALL_DIR}/acme.sh"
readonly SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}"
readonly RENEW_SERVICE_FILE="/etc/systemd/system/trojan-sing-box-cert-renew.service"
readonly RENEW_TIMER_FILE="/etc/systemd/system/trojan-sing-box-cert-renew.timer"
readonly CERT_RELOAD_HOOK="/usr/local/sbin/trojan-sing-box-cert-reload"
readonly CLIENT_FILE="/root/trojan-sing-box-clients.txt"
readonly LOCK_FILE="/var/lock/trojan-sing-box-installer.lock"

DOMAIN=""
ACCOUNT_EMAIL=""
PASSWORD_FILE=""
SING_BOX_VERSION="$DEFAULT_SING_BOX_VERSION"
SING_BOX_SHA256="$DEFAULT_SING_BOX_SHA256"
CUSTOM_SING_BOX_VERSION=0
SKIP_DNS_CHECK=0
ACCEPT_EOL_RISK=0
FORCE_INSTALL=0
NON_INTERACTIVE=0
TMP_DIR=""
BACKUP_DIR=""
COMMIT_STARTED=0
COMMIT_SUCCEEDED=0
FIREWALL_ADDED_80=0
FIREWALL_ADDED_443=0
SERVICE_WAS_ACTIVE=0
SERVICE_WAS_ENABLED=0
TIMER_WAS_ACTIVE=0
TIMER_WAS_ENABLED=0
PASSWORDS=()
BACKUP_PATHS=()
BACKUP_FILES=()

log() {
    printf '[INFO] %s\n' "$*"
}

warn() {
    printf '[WARN] %s\n' "$*" >&2
}

die() {
    printf '[ERROR] %s\n' "$*" >&2
    if ((COMMIT_STARTED == 1 && COMMIT_SUCCEEDED == 0)); then
        restore_backups
        rollback_firewall
    fi
    exit 1
}

usage() {
    cat <<'EOF'
CentOS 7 Trojan + TLS installer (sing-box)

Usage:
  sudo bash install_trojan.sh [options]

Options:
  --domain DOMAIN          Certificate and Trojan domain name.
  --email EMAIL            ACME account email.
  --password PASSWORD      Trojan password; repeat for multiple users.
                           Interactive input or --password-file is safer.
  --password-file FILE     Read one Trojan password per non-empty line.
  --sing-box-version VER   sing-box stable version. A custom version also
                           requires --sing-box-sha256.
  --sing-box-sha256 SHA256 Expected SHA-256 of the Linux amd64 musl archive.
  --skip-dns-check         Skip the domain A-record/public-IP comparison.
  --accept-eol-risk        Confirm awareness that CentOS 7 is end-of-life.
  --force                  Replace an existing installation managed here;
                           current managed files are backed up first.
  --non-interactive        Do not prompt. Domain, email and EOL acceptance
                           must be supplied; a password is generated if absent.
  -h, --help               Show this help.

Example:
  sudo bash install_trojan.sh \
    --domain vpn.example.com \
    --email admin@example.com \
    --accept-eol-risk
EOF
}

is_valid_domain() {
    local domain="$1"
    local label=""
    local last_label=""
    local old_ifs="$IFS"

    [[ ${#domain} -le 253 ]] || return 1
    [[ "$domain" != *..* && "$domain" == *.* ]] || return 1
    [[ "$domain" =~ ^[a-z0-9.-]+$ ]] || return 1

    IFS='.'
    for label in $domain; do
        [[ -n "$label" && ${#label} -le 63 ]] || {
            IFS="$old_ifs"
            return 1
        }
        [[ "$label" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || {
            IFS="$old_ifs"
            return 1
        }
        last_label="$label"
    done
    IFS="$old_ifs"

    [[ "$last_label" =~ [a-z] ]]
}

is_valid_email() {
    local email="$1"
    [[ ${#email} -le 254 && "$email" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]
}

is_valid_sha256() {
    [[ "$1" =~ ^[a-fA-F0-9]{64}$ ]]
}

validate_password() {
    local password="$1"
    [[ ${#password} -ge 8 && ${#password} -le 128 ]] || return 1
    if LC_ALL=C grep -q '[[:cntrl:]]' <<< "$password"; then
        return 1
    fi
    return 0
}

json_escape() {
    local value="$1"
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//$'\b'/\\b}
    value=${value//$'\f'/\\f}
    value=${value//$'\n'/\\n}
    value=${value//$'\r'/\\r}
    value=${value//$'\t'/\\t}
    printf '%s' "$value"
}

url_encode() {
    local LC_ALL=C
    local value="$1"
    local output=""
    local char=""
    local hex=""
    local index=0

    for ((index = 0; index < ${#value}; index++)); do
        char=${value:index:1}
        case "$char" in
            [a-zA-Z0-9.~_-]) output+="$char" ;;
            *)
                printf -v hex '%02X' "'$char"
                output+="%${hex}"
                ;;
        esac
    done
    printf '%s' "$output"
}

resolve_sing_box_asset_arch() {
    case "$1" in
        x86_64 | amd64) printf 'amd64' ;;
        *) return 1 ;;
    esac
}

require_option_value() {
    local option="$1"
    local remaining="$2"
    ((remaining >= 2)) || die "${option} 缺少参数"
}

parse_args() {
    while (($# > 0)); do
        case "$1" in
            --domain)
                require_option_value "$1" "$#"
                DOMAIN="$2"
                shift 2
                ;;
            --email)
                require_option_value "$1" "$#"
                ACCOUNT_EMAIL="$2"
                shift 2
                ;;
            --password)
                require_option_value "$1" "$#"
                PASSWORDS+=("$2")
                shift 2
                ;;
            --password-file)
                require_option_value "$1" "$#"
                PASSWORD_FILE="$2"
                shift 2
                ;;
            --sing-box-version)
                require_option_value "$1" "$#"
                SING_BOX_VERSION="$2"
                CUSTOM_SING_BOX_VERSION=1
                shift 2
                ;;
            --sing-box-sha256)
                require_option_value "$1" "$#"
                SING_BOX_SHA256="$2"
                shift 2
                ;;
            --skip-dns-check)
                SKIP_DNS_CHECK=1
                shift
                ;;
            --accept-eol-risk)
                ACCEPT_EOL_RISK=1
                shift
                ;;
            --force)
                FORCE_INSTALL=1
                shift
                ;;
            --non-interactive)
                NON_INTERACTIVE=1
                shift
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            *) die "未知参数：$1" ;;
        esac
    done
}

prompt_text() {
    local prompt="$1"
    local value=""
    read -r -p "$prompt" value
    printf '%s' "$value"
}

confirm_eol_risk() {
    local answer=""
    if ((ACCEPT_EOL_RISK == 1)); then
        return
    fi
    ((NON_INTERACTIVE == 0)) || die "CentOS 7 已停止维护；非交互运行必须传入 --accept-eol-risk"

    warn "CentOS 7 已停止安全维护，建议迁移到 AlmaLinux/Rocky Linux 9。"
    read -r -p "确认仍要在 CentOS 7 安装？请输入 YES：" answer
    [[ "$answer" == "YES" ]] || die "用户取消安装"
    ACCEPT_EOL_RISK=1
}

read_password_file() {
    local password=""
    local permissions=""
    local permission_bits=0
    local owner_uid=""
    [[ -r "$PASSWORD_FILE" ]] || die "密码文件不可读：${PASSWORD_FILE}"
    [[ -f "$PASSWORD_FILE" && ! -L "$PASSWORD_FILE" ]] || die "密码文件必须是普通文件且不能是符号链接"
    permissions=$(stat -c '%a' "$PASSWORD_FILE")
    permission_bits=$((8#$permissions))
    owner_uid=$(stat -c '%u' "$PASSWORD_FILE")
    [[ "$owner_uid" == "0" ]] || die "密码文件必须由 root 所有"
    (((permission_bits & 077) == 0)) || die "密码文件不能授予 group/other 权限，请设置 chmod 600"
    while IFS= read -r password || [[ -n "$password" ]]; do
        [[ -z "$password" ]] && continue
        PASSWORDS+=("$password")
    done < "$PASSWORD_FILE"
}

generate_password() {
    openssl rand -base64 32 | tr -d '\n'
}

collect_passwords_interactively() {
    local count=""
    local index=0
    local first=""
    local second=""

    read -r -p "Trojan 用户数量 [1-20，默认 1]：" count
    count=${count:-1}
    [[ "$count" =~ ^[0-9]+$ ]] && ((count >= 1 && count <= 20)) || die "用户数量必须是 1 到 20"

    for ((index = 1; index <= count; index++)); do
        while true; do
            read -r -s -p "用户 ${index} 密码（至少 8 位，留空自动生成）：" first
            printf '\n'
            if [[ -z "$first" ]]; then
                first=$(generate_password)
                log "已为用户 ${index} 生成随机密码"
                PASSWORDS+=("$first")
                break
            fi
            validate_password "$first" || {
                warn "密码必须为 8-128 个字符，且不能含制表符或换行"
                continue
            }
            read -r -s -p "再次输入用户 ${index} 密码：" second
            printf '\n'
            [[ "$first" == "$second" ]] || {
                warn "两次密码不一致，请重试"
                continue
            }
            PASSWORDS+=("$first")
            break
        done
    done
}

deduplicate_and_validate_passwords() {
    local index=0
    local previous=0

    ((${#PASSWORDS[@]} >= 1 && ${#PASSWORDS[@]} <= 20)) || die "Trojan 用户数量必须是 1 到 20"
    for ((index = 0; index < ${#PASSWORDS[@]}; index++)); do
        validate_password "${PASSWORDS[index]}" || die "第 $((index + 1)) 个密码不符合 8-128 位要求或含控制字符"
        for ((previous = 0; previous < index; previous++)); do
            [[ "${PASSWORDS[index]}" != "${PASSWORDS[previous]}" ]] || die "第 $((index + 1)) 个密码与前面的密码重复"
        done
    done
}

collect_inputs() {
    DOMAIN=$(printf '%s' "${DOMAIN%.}" | tr '[:upper:]' '[:lower:]')
    if [[ -z "$DOMAIN" ]]; then
        ((NON_INTERACTIVE == 0)) || die "非交互运行必须提供 --domain"
        DOMAIN=$(prompt_text "请输入已解析到本机公网 IPv4 的域名：")
        DOMAIN=$(printf '%s' "${DOMAIN%.}" | tr '[:upper:]' '[:lower:]')
    fi
    is_valid_domain "$DOMAIN" || die "域名格式无效：${DOMAIN}"

    if [[ -z "$ACCOUNT_EMAIL" ]]; then
        ((NON_INTERACTIVE == 0)) || die "非交互运行必须提供 --email"
        ACCOUNT_EMAIL=$(prompt_text "请输入 ACME 账户邮箱：")
    fi
    is_valid_email "$ACCOUNT_EMAIL" || die "邮箱格式无效：${ACCOUNT_EMAIL}"

    [[ -z "$PASSWORD_FILE" ]] || read_password_file
    if ((${#PASSWORDS[@]} == 0)); then
        if ((NON_INTERACTIVE == 1)); then
            PASSWORDS+=("$(generate_password)")
            log "未提供密码，已生成一个随机密码"
        else
            collect_passwords_interactively
        fi
    fi
    deduplicate_and_validate_passwords

    [[ "$SING_BOX_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([._-][0-9A-Za-z]+)*$ ]] || die "sing-box 版本格式无效：${SING_BOX_VERSION}"
    if ((CUSTOM_SING_BOX_VERSION == 1)) && [[ "$SING_BOX_VERSION" != "$DEFAULT_SING_BOX_VERSION" && "$SING_BOX_SHA256" == "$DEFAULT_SING_BOX_SHA256" ]]; then
        die "自定义 sing-box 版本必须同时提供该发布包的 --sing-box-sha256"
    fi
    SING_BOX_SHA256=$(printf '%s' "$SING_BOX_SHA256" | tr '[:upper:]' '[:lower:]')
    is_valid_sha256 "$SING_BOX_SHA256" || die "sing-box SHA-256 格式无效"
}

check_root_and_os() {
    local os_id=""
    local version_id=""

    [[ $(id -u) -eq 0 ]] || die "必须以 root 身份运行"
    [[ -r /etc/os-release ]] || die "无法读取 /etc/os-release"

    # shellcheck disable=SC1091
    source /etc/os-release
    os_id=${ID:-}
    version_id=${VERSION_ID:-}
    [[ "$os_id" == "centos" && "$version_id" == 7* ]] || die "仅支持 CentOS 7；当前系统为 ${os_id:-unknown} ${version_id:-unknown}"
    [[ -d /run/systemd/system ]] || die "必须在使用 systemd 的真实服务器环境运行"
    resolve_sing_box_asset_arch "$(uname -m)" >/dev/null || die "仅支持 CentOS 7 x86_64"
}

acquire_lock() {
    exec 9>"$LOCK_FILE"
    flock -n 9 || die "另一个安装进程正在运行"
}

check_existing_install() {
    systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null && SERVICE_WAS_ACTIVE=1 || true
    systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null && SERVICE_WAS_ENABLED=1 || true
    systemctl is-active --quiet trojan-sing-box-cert-renew.timer 2>/dev/null && TIMER_WAS_ACTIVE=1 || true
    systemctl is-enabled --quiet trojan-sing-box-cert-renew.timer 2>/dev/null && TIMER_WAS_ENABLED=1 || true
    if [[ -e "$CONFIG_FILE" || -e "$SING_BOX_BIN" || -e "$SERVICE_FILE" ]]; then
        ((FORCE_INSTALL == 1)) || die "检测到已有受管安装；如需更新，请检查备份策略后使用 --force"
    fi
}

install_dependencies() {
    log "安装必要系统组件"
    yum install -y ca-certificates curl tar gzip openssl socat libcap iproute >/dev/null || {
        die "依赖安装失败。CentOS 7 仓库已归档，请先修复可用的软件源；本脚本不会自动替换系统仓库。"
    }
    update-ca-trust >/dev/null 2>&1 || true

    local command_name=""
    for command_name in curl tar gzip openssl socat sha256sum setcap getcap ss getent systemctl install flock; do
        command -v "$command_name" >/dev/null 2>&1 || die "缺少命令：${command_name}"
    done
}

port_is_listening() {
    local port="$1"
    ss -ltn | awk '{print $4}' | grep -Eq "(^|:)${port}$"
}

managed_service_owns_port() {
    local port="$1"
    local main_pid=""
    main_pid=$(systemctl show "$SERVICE_NAME" --property MainPID 2>/dev/null | awk -F= '$1 == "MainPID" {print $2}') || return 1
    [[ "$main_pid" =~ ^[1-9][0-9]*$ ]] || return 1
    ss -ltnp | grep -E "(^|:)${port}([[:space:]]|$)" | grep -Fq "pid=${main_pid},"
}

preflight_ports() {
    port_is_listening 80 && die "TCP 80 已被占用；HTTP-01 申请和续期证书需要独占 80 端口"

    if port_is_listening 443; then
        managed_service_owns_port 443 || die "TCP 443 已被其他服务占用"
    fi
}

check_dns() {
    local public_ip=""
    local dns_ips=""

    ((SKIP_DNS_CHECK == 0)) || {
        warn "已跳过 DNS/IP 检查；请确保 HTTP 80 可从公网访问"
        return
    }

    public_ip=$(curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
        --connect-timeout 10 --max-time 20 https://api.ipify.org) || die "无法获取本机公网 IPv4；可确认无误后使用 --skip-dns-check"
    [[ "$public_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "公网 IPv4 响应格式异常"

    dns_ips=$(getent ahostsv4 "$DOMAIN" | awk '{print $1}' | sort -u) || true
    [[ -n "$dns_ips" ]] || die "域名没有可用的 A 记录：${DOMAIN}"
    grep -Fqx "$public_ip" <<< "$dns_ips" || {
        printf '[ERROR] 域名 %s 的 A 记录未包含本机公网 IPv4 %s\n' "$DOMAIN" "$public_ip" >&2
        printf '[ERROR] 当前解析结果：\n%s\n' "$dns_ips" >&2
        die "请修正 DNS，或在 CDN/代理场景确认回源配置后使用 --skip-dns-check"
    }
    log "DNS 检查通过：${DOMAIN} -> ${public_ip}"
}

download_file() {
    local url="$1"
    local destination="$2"
    curl --proto '=https' --tlsv1.2 --fail --show-error --location \
        --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 300 \
        --output "$destination" "$url"
}

file_sha256() {
    sha256sum "$1" | awk '{print $1}'
}

verify_sha256() {
    local file="$1"
    local expected="$2"
    local actual=""
    actual=$(file_sha256 "$file")
    [[ "$actual" == "$expected" ]] || die "SHA-256 校验失败：$(basename "$file")"
}

download_and_verify_artifacts() {
    local asset_arch=""
    local archive_url=""
    local extracted_dir=""

    asset_arch=$(resolve_sing_box_asset_arch "$(uname -m)")
    archive_url="https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-${asset_arch}-musl.tar.gz"

    log "下载并验证 sing-box ${SING_BOX_VERSION} musl 构建"
    download_file "$archive_url" "${TMP_DIR}/sing-box.tar.gz"
    verify_sha256 "${TMP_DIR}/sing-box.tar.gz" "$SING_BOX_SHA256"

    mkdir -p "${TMP_DIR}/sing-box"
    tar -xzf "${TMP_DIR}/sing-box.tar.gz" -C "${TMP_DIR}/sing-box"
    extracted_dir="${TMP_DIR}/sing-box/sing-box-${SING_BOX_VERSION}-linux-${asset_arch}-musl"
    [[ -x "${extracted_dir}/sing-box" ]] || die "sing-box 发布包缺少可执行文件"
    install -m 0755 "${extracted_dir}/sing-box" "${TMP_DIR}/sing-box-bin"

    log "下载并验证固定版本 acme.sh"
    download_file "https://raw.githubusercontent.com/acmesh-official/acme.sh/${ACME_COMMIT}/acme.sh" "${TMP_DIR}/acme.sh"
    verify_sha256 "${TMP_DIR}/acme.sh" "$ACME_SHA256"
}

ensure_service_user_and_directories() {
    if ! getent group "$SERVICE_GROUP" >/dev/null; then
        groupadd --system "$SERVICE_GROUP"
    fi
    if ! id "$SERVICE_USER" >/dev/null 2>&1; then
        useradd --system --gid "$SERVICE_GROUP" --home-dir "$STATE_DIR" --shell /sbin/nologin "$SERVICE_USER"
    elif [[ $(id -gn "$SERVICE_USER") != "$SERVICE_GROUP" ]]; then
        die "已有用户 ${SERVICE_USER} 的主组不是 ${SERVICE_GROUP}，拒绝复用"
    fi

    install -d -m 0755 -o root -g root "$INSTALL_DIR" "$CONFIG_DIR" "$ACME_INSTALL_DIR"
    install -d -m 0750 -o root -g "$SERVICE_GROUP" "$CERT_DIR"
    install -d -m 0700 -o root -g root "$STATE_DIR" "$ACME_HOME"
}

backup_path() {
    local path="$1"
    local index=${#BACKUP_PATHS[@]}
    BACKUP_PATHS+=("$path")
    if [[ -e "$path" || -L "$path" ]]; then
        cp -a -- "$path" "${BACKUP_DIR}/item-${index}"
        BACKUP_FILES+=("${BACKUP_DIR}/item-${index}")
    else
        BACKUP_FILES+=("")
    fi
}

prepare_backup() {
    local timestamp=""
    local path=""

    timestamp=$(date -u +%Y%m%dT%H%M%SZ)
    install -d -m 0700 -o root -g root /var/backups/trojan-sing-box
    BACKUP_DIR=$(mktemp -d "/var/backups/trojan-sing-box/${timestamp}.XXXXXX")
    chmod 0700 "$BACKUP_DIR"

    for path in "$SING_BOX_BIN" "$CONFIG_FILE" "$CERT_FILE" "$KEY_FILE" "$SERVICE_FILE" \
        "$RENEW_SERVICE_FILE" "$RENEW_TIMER_FILE" "$CERT_RELOAD_HOOK" "$CLIENT_FILE" "$ACME_BIN"; do
        backup_path "$path"
    done
    COMMIT_STARTED=1
}

restore_backups() {
    local index=0
    local path=""
    local backup=""

    ((COMMIT_STARTED == 1 && COMMIT_SUCCEEDED == 0)) || return
    warn "安装失败，正在恢复脚本管理的文件"
    systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
    systemctl stop trojan-sing-box-cert-renew.timer >/dev/null 2>&1 || true

    for ((index = 0; index < ${#BACKUP_PATHS[@]}; index++)); do
        path=${BACKUP_PATHS[index]}
        backup=${BACKUP_FILES[index]}
        if [[ -n "$backup" ]]; then
            cp -a -- "$backup" "$path"
        else
            rm -f -- "$path"
        fi
    done

    systemctl daemon-reload >/dev/null 2>&1 || true
    if ((SERVICE_WAS_ENABLED == 1)); then
        systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
    else
        systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
    fi
    if ((TIMER_WAS_ENABLED == 1)); then
        systemctl enable trojan-sing-box-cert-renew.timer >/dev/null 2>&1 || true
    else
        systemctl disable trojan-sing-box-cert-renew.timer >/dev/null 2>&1 || true
    fi
    if ((SERVICE_WAS_ACTIVE == 1)); then
        systemctl start "$SERVICE_NAME" >/dev/null 2>&1 || warn "旧服务未能自动恢复，请检查 ${BACKUP_DIR}"
    fi
    if ((TIMER_WAS_ACTIVE == 1)); then
        systemctl start trojan-sing-box-cert-renew.timer >/dev/null 2>&1 || warn "旧续期定时器未能自动恢复"
    fi
}

rollback_firewall() {
    systemctl is-active --quiet firewalld || return
    if ((FIREWALL_ADDED_80 == 1)); then
        firewall-cmd --quiet --permanent --remove-port=80/tcp >/dev/null 2>&1 || true
    fi
    if ((FIREWALL_ADDED_443 == 1)); then
        firewall-cmd --quiet --permanent --remove-port=443/tcp >/dev/null 2>&1 || true
    fi
    if ((FIREWALL_ADDED_80 == 1 || FIREWALL_ADDED_443 == 1)); then
        firewall-cmd --quiet --reload >/dev/null 2>&1 || true
    fi
}

cleanup() {
    if [[ -n "$TMP_DIR" && "$TMP_DIR" == /tmp/trojan-sing-box.* && -d "$TMP_DIR" ]]; then
        rm -r -- "$TMP_DIR"
    fi
}

on_error() {
    local exit_code=$?
    local line="$1"
    trap - ERR
    printf '[ERROR] 安装在第 %s 行失败，退出码 %s\n' "$line" "$exit_code" >&2
    restore_backups
    rollback_firewall
    exit "$exit_code"
}

configure_firewall() {
    command -v firewall-cmd >/dev/null 2>&1 || return
    systemctl is-active --quiet firewalld || return

    if ! firewall-cmd --quiet --permanent --query-port=80/tcp; then
        firewall-cmd --quiet --permanent --add-port=80/tcp
        FIREWALL_ADDED_80=1
    fi
    if ! firewall-cmd --quiet --permanent --query-port=443/tcp; then
        firewall-cmd --quiet --permanent --add-port=443/tcp
        FIREWALL_ADDED_443=1
    fi
    firewall-cmd --quiet --reload
    log "firewalld 已放行 TCP 80/443"
}

install_acme_client() {
    install -m 0755 -o root -g root "${TMP_DIR}/acme.sh" "$ACME_BIN"
}

run_acme() {
    "$ACME_BIN" --home "$ACME_INSTALL_DIR" --config-home "$ACME_HOME" "$@"
}

issue_certificate() {
    local issue_code=0

    log "注册 ACME 账户并申请 ${DOMAIN} 的 ECDSA 证书"
    run_acme --set-default-ca --server letsencrypt
    run_acme --register-account --server letsencrypt --accountemail "$ACCOUNT_EMAIL"

    if run_acme --issue --server letsencrypt --standalone --keylength ec-256 -d "$DOMAIN"; then
        issue_code=0
    else
        issue_code=$?
        [[ $issue_code -eq 2 ]] || return "$issue_code"
        log "现有证书仍在有效期内，无需立即续期"
    fi

    run_acme --install-cert --ecc -d "$DOMAIN" \
        --key-file "${TMP_DIR}/private.key" \
        --fullchain-file "${TMP_DIR}/fullchain.pem" \
        --reloadcmd /bin/true
    [[ -s "${TMP_DIR}/private.key" && -s "${TMP_DIR}/fullchain.pem" ]] || die "证书文件生成失败"
    openssl x509 -in "${TMP_DIR}/fullchain.pem" -noout -checkend 86400 >/dev/null || die "证书有效期不足 24 小时"
}

render_config() {
    local destination="$1"
    local cert_path="$2"
    local key_path="$3"
    local index=0
    local comma=""

    {
        printf '{\n'
        printf '  "log": {"level": "warn", "timestamp": true},\n'
        printf '  "inbounds": [\n'
        printf '    {\n'
        printf '      "type": "trojan",\n'
        printf '      "tag": "trojan-in",\n'
        printf '      "listen": "0.0.0.0",\n'
        printf '      "listen_port": 443,\n'
        printf '      "users": [\n'
        for ((index = 0; index < ${#PASSWORDS[@]}; index++)); do
            ((index > 0)) && comma=',' || comma=''
            printf '        %s{"name": "user-%d", "password": "%s"}\n' \
                "$comma" "$((index + 1))" "$(json_escape "${PASSWORDS[index]}")"
        done
        printf '      ],\n'
        printf '      "tls": {\n'
        printf '        "enabled": true,\n'
        printf '        "server_name": "%s",\n' "$(json_escape "$DOMAIN")"
        printf '        "min_version": "1.2",\n'
        printf '        "alpn": ["h2", "http/1.1"],\n'
        printf '        "certificate_path": "%s",\n' "$(json_escape "$cert_path")"
        printf '        "key_path": "%s"\n' "$(json_escape "$key_path")"
        printf '      }\n'
        printf '    }\n'
        printf '  ],\n'
        printf '  "outbounds": [\n'
        printf '    {"type": "direct", "tag": "direct"}\n'
        printf '  ]\n'
        printf '}\n'
    } > "$destination"
}

test_sing_box_config() {
    local binary="$1"
    local config="$2"
    "$binary" check -c "$config" >/dev/null
}

install_cert_reload_hook() {
    cat > "${TMP_DIR}/cert-reload-hook" <<EOF
#!/usr/bin/env bash
set -euo pipefail
/bin/chown root:${SERVICE_GROUP} '${CERT_FILE}' '${KEY_FILE}'
/bin/chmod 0640 '${CERT_FILE}' '${KEY_FILE}'
if /bin/systemctl is-active --quiet '${SERVICE_NAME}'; then
    /bin/systemctl restart '${SERVICE_NAME}'
fi
EOF
    install -m 0755 -o root -g root "${TMP_DIR}/cert-reload-hook" "$CERT_RELOAD_HOOK"
}

install_final_certificate() {
    install_cert_reload_hook
    run_acme --install-cert --ecc -d "$DOMAIN" \
        --key-file "$KEY_FILE" \
        --fullchain-file "$CERT_FILE" \
        --reloadcmd "$CERT_RELOAD_HOOK"
    "$CERT_RELOAD_HOOK"
}

install_sing_box_and_config() {
    local final_config="${TMP_DIR}/config.final.json"

    systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
    install -m 0755 -o root -g root "${TMP_DIR}/sing-box-bin" "$SING_BOX_BIN"
    setcap cap_net_bind_service=+ep "$SING_BOX_BIN"
    getcap "$SING_BOX_BIN" | grep -Fq 'cap_net_bind_service' || die "未能为 sing-box 设置低端口绑定能力"

    install_final_certificate
    render_config "$final_config" "$CERT_FILE" "$KEY_FILE"
    test_sing_box_config "$SING_BOX_BIN" "$final_config"
    install -m 0640 -o root -g "$SERVICE_GROUP" "$final_config" "$CONFIG_FILE"
}

render_client_file() {
    local destination="$1"
    local index=0
    local encoded_password=""

    {
        printf 'Domain: %s\n' "$DOMAIN"
        printf 'Port: 443\n'
        printf 'Protocol: trojan\n'
        printf 'TLS/SNI: %s\n\n' "$DOMAIN"
        for ((index = 0; index < ${#PASSWORDS[@]}; index++)); do
            encoded_password=$(url_encode "${PASSWORDS[index]}")
            printf 'User %d password: %s\n' "$((index + 1))" "${PASSWORDS[index]}"
            printf 'User %d URI: trojan://%s@%s:443?security=tls&sni=%s&type=tcp#%s-user-%d\n\n' \
                "$((index + 1))" "$encoded_password" "$DOMAIN" "$DOMAIN" "$DOMAIN" "$((index + 1))"
        done
    } > "$destination"
}

install_systemd_units() {
    cat > "${TMP_DIR}/trojan-sing-box.service" <<EOF
[Unit]
Description=Trojan TLS service powered by sing-box
Documentation=https://sing-box.sagernet.org/configuration/inbound/trojan/
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
UMask=0077
ExecStart=${SING_BOX_BIN} run -c ${CONFIG_FILE}
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
PrivateTmp=true
PrivateDevices=true
ProtectSystem=full
ProtectHome=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

    cat > "${TMP_DIR}/trojan-sing-box-cert-renew.service" <<EOF
[Unit]
Description=Renew Trojan TLS certificate with acme.sh
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
UMask=0077
ExecStart=${ACME_BIN} --cron --home ${ACME_INSTALL_DIR} --config-home ${ACME_HOME}
PrivateTmp=true
ProtectHome=true
EOF

    cat > "${TMP_DIR}/trojan-sing-box-cert-renew.timer" <<'EOF'
[Unit]
Description=Check Trojan TLS certificate renewal every six hours

[Timer]
OnCalendar=*-*-* 00:17:00
OnCalendar=*-*-* 06:17:00
OnCalendar=*-*-* 12:17:00
OnCalendar=*-*-* 18:17:00
Persistent=true
AccuracySec=5m

[Install]
WantedBy=timers.target
EOF

    install -m 0644 -o root -g root "${TMP_DIR}/trojan-sing-box.service" "$SERVICE_FILE"
    install -m 0644 -o root -g root "${TMP_DIR}/trojan-sing-box-cert-renew.service" "$RENEW_SERVICE_FILE"
    install -m 0644 -o root -g root "${TMP_DIR}/trojan-sing-box-cert-renew.timer" "$RENEW_TIMER_FILE"

    render_client_file "${TMP_DIR}/clients.txt"
    install -m 0600 -o root -g root "${TMP_DIR}/clients.txt" "$CLIENT_FILE"
}

start_and_verify_services() {
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" trojan-sing-box-cert-renew.timer >/dev/null
    systemctl restart "$SERVICE_NAME"
    systemctl start trojan-sing-box-cert-renew.timer

    systemctl is-active --quiet "$SERVICE_NAME" || die "Trojan 服务启动失败"
    systemctl is-active --quiet trojan-sing-box-cert-renew.timer || die "证书续期定时器启动失败"
    managed_service_owns_port 443 || die "服务已启动但未确认由 sing-box 监听 TCP 443"
}

print_result() {
    local cert_end=""
    cert_end=$(openssl x509 -in "$CERT_FILE" -noout -enddate | cut -d= -f2-)
    printf '\n安装完成。\n'
    printf '  服务：%s\n' "$SERVICE_NAME"
    printf '  域名：%s\n' "$DOMAIN"
    printf '  证书到期时间：%s\n' "$cert_end"
    printf '  客户端配置：%s（权限 600）\n' "$CLIENT_FILE"
    printf '  配置文件：%s\n' "$CONFIG_FILE"
    printf '  备份目录：%s\n' "$BACKUP_DIR"
    printf '\n客户端链接：\n'
    sed -n '/ URI: /p' "$CLIENT_FILE"
    printf '\n检查状态：systemctl status %s\n' "$SERVICE_NAME"
}

main() {
    parse_args "$@"
    check_root_and_os
    acquire_lock
    check_existing_install
    confirm_eol_risk
    install_dependencies
    collect_inputs
    preflight_ports
    check_dns

    TMP_DIR=$(mktemp -d /tmp/trojan-sing-box.XXXXXX)
    trap cleanup EXIT
    trap 'on_error $LINENO' ERR

    download_and_verify_artifacts
    prepare_backup
    ensure_service_user_and_directories
    install_acme_client
    configure_firewall
    issue_certificate

    render_config "${TMP_DIR}/config.staged.json" "${TMP_DIR}/fullchain.pem" "${TMP_DIR}/private.key"
    test_sing_box_config "${TMP_DIR}/sing-box-bin" "${TMP_DIR}/config.staged.json"

    install_sing_box_and_config
    install_systemd_units
    start_and_verify_services

    COMMIT_SUCCEEDED=1
    log "安装文件已通过校验，服务运行正常"
    print_result
}

if [[ "${TROJAN_INSTALLER_LIB_ONLY:-0}" != "1" ]]; then
    main "$@"
fi
