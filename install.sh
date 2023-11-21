#!/bin/bash

die() {
    echo "Error: $1"
    exit 1
}

separator() {
    echo "=============================================="
}

if [ "$EUID" -ne 0 ]; then
    echo "请使用root权限运行此脚本"
    exit 1
fi

separator
if command -v nginx &>/dev/null; then
    echo "Nginx已安装，跳过安装步骤"
else
    echo "正在安装Nginx..."
    yum install -y epel-release
    yum install -y nginx
    systemctl start nginx
    systemctl enable nginx
fi

separator
if command -v wget &>/dev/null; then
    echo "wget已安装，跳过安装步骤"
else
    echo "正在安装wget..."
    yum install -y wget
fi

separator
if command -v snapd &>/dev/null; then
    echo "snapd已安装，跳过安装步骤"
else
    echo "正在安装snapd..."
    yum install -y snapd
    systemctl enable --now snapd.socket
    ln -s /var/lib/snapd/snap /snap
fi

separator
if command -v certbot &>/dev/null; then
    echo "Certbot已安装，跳过安装步骤"
else
    echo "正在安装Certbot..."
    snap install --classic certbot
    ln -s /snap/bin/certbot /usr/bin/certbot
    certbot --version
fi

separator
if command -v certbot-nginx &>/dev/null; then
    echo "Certbot的Nginx插件已安装，跳过安装步骤"
else
    echo "正在安装Certbot的Nginx插件..."
    yum install -y certbot-nginx
fi

trojan_version="1.16.0"
trojan_url="https://github.com/trojan-gfw/trojan/releases/download/v${trojan_version}/trojan-${trojan_version}-linux-amd64.tar.xz"
trojan_dir="/usr/local/bin/trojan"

separator
if command -v trojan &>/dev/null; then
    echo "Trojan已安装，跳过安装步骤"
else
    echo "正在安装Trojan..."

    echo "下载并解压 Trojan..."
    mkdir -p ${trojan_dir}
    wget ${trojan_url} -O /tmp/trojan.tar.xz
    tar -xf /tmp/trojan.tar.xz -C ${trojan_dir}
    rm /tmp/trojan.tar.xz
fi

separator
read -p "域名: " domain

separator
config_file="/etc/nginx/conf.d/${domain}.conf"
echo "生成nginx临时配置文件: ${config_file}"
cat >${config_file} <<EOF
server {
    listen 80;
    #listen 443 ssl;
    server_name ${domain};
    root /usr/share/nginx/html/${domain};
    index index.html;

    #ssl_certificate /home/n/ssl/${domain}.crt;
    #ssl_certificate_key /home/n/ssl/${domain}.key;

    #ssl_protocols TLSv1.2 TLSv1.3;
    #ssl_ciphers 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384';

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

mkdir -p /usr/share/nginx/html/${domain}

separator
echo "重新加载Nginx配置..."
systemctl reload nginx

separator
echo "获取或续期Let's Encrypt证书..."
certbot --nginx -d ${domain} --register-unsafely-without-email --non-interactive --agree-tos

separator
echo "设置自动续期的crontab任务..."
(
    if ! crontab -l | grep -q "/usr/bin/certbot renew --quiet"; then
        # 如果不存在，则添加到crontab
        echo "0 0 * * * /usr/bin/certbot renew --quiet" | crontab -
        echo "已成功添加到crontab。"
    else
        echo "已经存在相同的条目，未进行更改。"
    fi
) | crontab -l

separator
echo "生成trojan配置文件..."
trojan_password=$(cat /dev/urandom | head -1 | md5sum | head -c 8)

cat >${trojan_dir}/trojan/config.json <<EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": ["${trojan_password}"],
    "log_level": 1,
    "ssl": {
        "cert": "/etc/letsencrypt/live/${domain}/fullchain.pem",
        "key": "/etc/letsencrypt/live/${domain}/privkey.pem",
        "key_password": "",
        "cipher_tls13":"TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
	    "prefer_server_cipher": true,
        "alpn": [
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "session_timeout": 600,
        "plain_http_response": "",
        "curves": "",
        "dhparam": ""
    },
    "tcp": {
        "no_delay": true,
        "keep_alive": true,
        "fast_open": false,
        "fast_open_qlen": 20
    },
    "mysql": {
        "enabled": false,
        "server_addr": "127.0.0.1",
        "server_port": 3306,
        "database": "trojan",
        "username": "trojan",
        "password": ""
    }
}
EOF

separator
echo "启动Trojan..."
cat >/etc/systemd/system/trojan.service <<EOF
[Unit]
Description=Trojan
After=network.target

[Service]
ExecStart=/usr/local/bin/trojan/trojan/trojan -c /usr/local/bin/trojan/trojan/config.json
Restart=always
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=yes
ProtectKernelModules=yes
ProtectKernelModules=yes
ProtectKernelModules=yes
ProtectKernelModules=yes

[Install]
WantedBy=multi-user.target
EOF

separator
echo "临时关闭nginx服务..."
sed -i 's/listen 443/#listen 443/g' /etc/nginx/conf.d/${domain}.conf
sed -i 's/listen 80/#listen 80/g' /etc/nginx/conf.d/${domain}.conf

separator
echo "启动trojan..."
systemctl daemon-reload
systemctl restart trojan
systemctl enable trojan

separator
echo "安装和配置完成！"

separator
echo "trojan密码：${trojan_password} trojan配置文件路径：/usr/local/bin/trojan/trojan/config.json"

