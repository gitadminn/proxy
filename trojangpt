#!/bin/bash

# 提示输入域名和密码
read -p "请输入您的域名: " your_domain
read -p "请输入您的Trojan密码: " trojan_passwd

# 安装 EPEL 仓库和必要软件
sudo yum install -y epel-release
sudo yum update -y
sudo yum install -y nginx

# 安装并启动 Nginx
sudo systemctl start nginx
sudo systemctl enable nginx

# 安装 ACME
curl https://get.acme.sh | sh

# 生成 SSL 证书
~/.acme.sh/acme.sh --issue -d "$your_domain" --nginx
~/.acme.sh/acme.sh --installcert -d "$your_domain" \
    --key-file /etc/nginx/ssl/"$your_domain".key \
    --fullchain-file /etc/nginx/ssl/"$your_domain".cer \
    --reloadcmd "sudo systemctl reload nginx"

# 安装 Trojan
wget https://github.com/trojan-gfw/trojan/releases/latest/download/trojan-1.x.x-linux-amd64.tar.xz
tar xf trojan-*.tar.xz
sudo cp trojan/trojan /usr/local/bin
sudo mkdir -p /usr/local/etc/trojan

# 配置 Trojan
cat <<EOF | sudo tee /usr/local/etc/trojan/config.json
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        "$trojan_passwd"
    ],
    "log_level": 1,
    "ssl": {
        "cert": "/etc/nginx/ssl/$your_domain.cer",
        "key": "/etc/nginx/ssl/$your_domain.key",
        "fallback_port": 80
    }
}
EOF

# 启动 Trojan
sudo nohup trojan -c /usr/local/etc/trojan/config.json &

# 设置证书自动更新
(crontab -l 2>/dev/null; echo "0 0 1 */2 * ~/.acme.sh/acme.sh --renew -d $your_domain --force") | crontab -
