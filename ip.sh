#!/bin/bash
set -e

# ===================================================================
# ‼️ 请在这里修改为您的真实网卡名称 ‼️
INTERFACE="eth0"
# ===================================================================

# --- 定义文件路径 ---
IP_SCRIPT_PATH="/usr/local/sbin/manage-ip-aliases.sh"
SYSTEMD_SERVICE_PATH="/etc/systemd/system/ip-aliases.service"


echo "--- 步骤 1: 正在创建从 /root/ip.txt 读取IP的管理脚本 ---"
# 使用 sudo 和 tee 命令来创建需要root权限的文件
# 脚本内容已被修改为从文件读取IP
sudo tee "$IP_SCRIPT_PATH" > /dev/null <<'EOF'
#!/bin/bash
INTERFACE="eth0" # 此处的网卡名会被下面的sed命令替换
IP_FILE="/root/ip.txt"

# 添加IP的函数
add_ips() {
    if [ ! -r "$IP_FILE" ]; then
        echo "[警告] IP列表文件 '$IP_FILE' 不存在或不可读。"
        exit 0
    fi
    
    echo "正在从 $IP_FILE 为网卡 $INTERFACE 添加IP..."
    while IFS= read -r ip || [[ -n "$ip" ]]; do
        # 移除前后空格并忽略空行和注释行
        ip=$(echo "$ip" | xargs)
        if [[ -z "$ip" || "$ip" =~ ^# ]]; then
            continue
        fi
        
        # 添加IP，使用/32前缀以确保稳定
        /sbin/ip addr add "$ip/32" dev "$INTERFACE"
        echo "  + Added $ip"
    done < "$IP_FILE"
    echo "IP添加完成。"
}

# 删除IP的函数
del_ips() {
    if [ ! -r "$IP_FILE" ]; then
        return # 文件不存在，无需删除
    fi

    echo "正在从 $IP_FILE 为网卡 $INTERFACE 删除IP..."
    while IFS= read -r ip || [[ -n "$ip" ]]; do
        # 移除前后空格并忽略空行和注释行
        ip=$(echo "$ip" | xargs)
        if [[ -z "$ip" || "$ip" =~ ^# ]]; then
            continue
        fi

        # 删除IP，忽略可能出现的错误（例如IP不存在）
        /sbin/ip addr del "$ip/32" dev "$INTERFACE" 2>/dev/null || true
    done < "$IP_FILE"
    echo "IP删除完成。"
}

# 根据参数执行操作
case "$1" in
    start) 
        add_ips 
        ;;
    stop) 
        del_ips 
        ;;
    restart) 
        del_ips
        add_ips 
        ;;
    *) 
        echo "用法: $0 {start|stop|restart}"
        exit 1 
        ;;
esac
exit 0
EOF

# 动态替换脚本中的网卡名
sudo sed -i "s/INTERFACE=\"eth0\"/INTERFACE=\"$INTERFACE\"/" "$IP_SCRIPT_PATH"
# 添加执行权限
sudo chmod +x "$IP_SCRIPT_PATH"
echo "✅ IP管理脚本已创建在 $IP_SCRIPT_PATH"

echo "--- 步骤 2: 正在创建 systemd 服务文件 ---"
sudo tee "$SYSTEMD_SERVICE_PATH" > /dev/null <<'EOF'
[Unit]
Description=Manage Additional IP Aliases from /root/ip.txt
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/manage-ip-aliases.sh start
ExecStop=/usr/local/sbin/manage-ip-aliases.sh stop
Restart=no

[Install]
WantedBy=multi-user.target
EOF
echo "✅ systemd 服务文件已创建在 $SYSTEMD_SERVICE_PATH"

echo "--- 步骤 3: 正在重载配置并启动服务 ---"
sudo systemctl daemon-reload
sudo systemctl enable ip-aliases.service
sudo systemctl restart ip-aliases.service
echo ""
echo "🎉 --- 安装成功 --- 🎉"
echo ""
echo "服务已设置为开机自启，它会自动从 '/root/ip.txt' 读取IP列表并附加到网卡 '$INTERFACE'。"
echo "您可以通过运行以下命令来验证:"
echo "ip addr show dev $INTERFACE"
echo ""
echo "管理服务:"
echo "  重启服务 (重新加载ip.txt): sudo systemctl restart ip-aliases.service"
echo "  查看状态: systemctl status ip-aliases.service"
