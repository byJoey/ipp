#!/bin/bash

VERSION="0.9.4"
CONFIG_FILE="/etc/3proxy.cfg"
INSTALL_PATH="/usr/local/bin/3proxy"
SERVICE_FILE="/etc/systemd/system/3proxy.service"
LOG_FILE="/var/log/3proxy.log"
# --- 新增全局变量 ---
GOOGLE_DOMAINS_FILE="/etc/3proxy/google-domains.txt"


# --- 功能函数定义 ---

show_menu() {
    clear
    # --- 新增: 在显示菜单前检查分流状态 ---
    local SPLIT_STATUS="关闭" # 默认状态为关闭
    if [ -f "${CONFIG_FILE}" ] && grep -q "# --- Google Splitter Start ---" "${CONFIG_FILE}"; then
        SPLIT_STATUS="开启"
    fi
    # --- 状态检查结束 ---

    echo "=========================================="
    echo "   多IP代理服务 - acck擦屁股本 "
    echo "=========================================="
    echo " 配置文件位于: ${CONFIG_FILE}"
    echo " Google分流状态: ${SPLIT_STATUS}" # <-- 新增的状态显示行
    echo "------------------------------------------"
    echo "1. 首次安装 / 重新编译安装"
    echo "2. 修改配置 (端口或认证)"
    echo "3. 查看当前代理信息"
    echo "4. 测试代理可用性"
    echo "5. 重启代理服务"
    echo "6. 查看服务状态"
    echo "7. 卸载代理服务"
    echo "8. [高级] 配置Google分流 (修改现有文件)"
    echo "9. 退出脚本"
    echo "------------------------------------------"
}

press_any_key_to_continue() {
    echo ""
    read -p "按 [Enter] 键返回主菜单..."
}

get_port_from_config() { grep -m 1 'socks' "${CONFIG_FILE}" 2>/dev/null | sed -E -n 's/.*-p *([0-9]+).*/\1/p'; }
get_ips_from_config() { grep 'socks' "${CONFIG_FILE}" 2>/dev/null | sed -E -n 's/.*-e *([^ ]+).*/\1/p' | grep -v '127.0.0.1'; }

show_proxy_info() {
    clear
    echo "--- 当前代理配置信息 ---"
    if [ ! -f "${CONFIG_FILE}" ]; then echo "错误: 未找到配置文件，请先执行安装。" && return; fi
    
    local PORT=$(get_port_from_config)
    local IP_LIST_FROM_FILE=($(get_ips_from_config))
    local USER_LINE=$(grep '^users ' "${CONFIG_FILE}" || echo "")
    local AUTH_METHOD="无认证"
    local USER=""
    local PASS=""
    local SPLIT_MODE=$(grep -q "# --- Google Splitter Start ---" "${CONFIG_FILE}" && echo "开启" || echo "关闭")

    if [ -n "$USER_LINE" ]; then
        AUTH_METHOD="用户名/密码"
        USER=$(echo "$USER_LINE" | cut -d' ' -f2 | cut -d':' -f1)
        PASS=$(echo "$USER_LINE" | cut -d' ' -f2 | cut -d':' -f3)
    fi

    echo "配置文件: ${CONFIG_FILE}"
    echo "代理端口: ${PORT}"
    echo "认证方式: ${AUTH_METHOD}"
    if [ -n "$USER" ]; then echo "用户名:   ${USER}"; echo "密码:     ${PASS}"; fi
    echo "Google分流: ${SPLIT_MODE}"
    if [ "$SPLIT_MODE" == "开启" ]; then
        local GOOGLE_IP=$(grep '# Google-dedicated exit IP' "${CONFIG_FILE}" | sed -E -n 's/.*-e *([^ ]+).*/\1/p')
        echo "Google专用出口IP: ${GOOGLE_IP}"
    fi
    
    echo ""
    echo "--- 可用代理IP列表 (共 ${#IP_LIST_FROM_FILE[@]} 个) ---"
    for IP in "${IP_LIST_FROM_FILE[@]}"; do echo "${IP}:${PORT}"; done
    echo "---------------------------------"
}

get_server_ips() { ip -4 addr show | grep -oP 'inet \K[\d.]+' | grep -vE '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)'; }

get_user_config() {
    read -p "请输入代理端口 (留空则默认为 8888): " PORT
    PORT=${PORT:-8888}
    read -p "请输入用户名 (重要: 留空则为无认证模式): " USER
    if [[ -n "$USER" ]]; then
        read -s -p "请输入密码 (输入时不可见): " PASS
        echo
        if [[ -z "$PASS" ]]; then echo "错误：密码不能为空。" && sleep 2 && return 1; fi
        AUTH_TYPE="strong"
    else
        AUTH_TYPE="none"
    fi
    return 0
}

generate_config_file() {
    echo "--> 正在生成配置文件..."
    IP_LIST=($(get_server_ips))
    if [ ${#IP_LIST[@]} -eq 0 ]; then echo "错误: 未能找到任何公网IPv4地址。" && return 1; fi
    echo "--> 检测到 ${#IP_LIST[@]} 个公网IPv4地址将用于配置。"
    (
    cat <<EOC
daemon
nserver 8.8.8.8
nserver 1.1.1.1
log ${LOG_FILE} D
EOC
    if [ "$AUTH_TYPE" == "strong" ]; then
        echo "auth strong"; echo "users ${USER}:CL:${PASS}"
    fi
    for IP in "${IP_LIST[@]}"; do
        if [ "$AUTH_TYPE" == "strong" ]; then echo "socks -p${PORT} -i${IP} -e${IP}"; else echo "socks -a -p${PORT} -i${IP} -e${IP}"; fi
    done
    ) | sudo tee "${CONFIG_FILE}" > /dev/null
    echo "--> 配置文件已写入 ${CONFIG_FILE}"
}

do_install() {
    clear; echo "--- 启动 3proxy 完整安装/编译流程 ---"
    if ! get_user_config; then return; fi
    echo "------------------------------------------"
    echo "[步骤 1/4] 安装编译依赖..."; sudo apt-get update -y > /dev/null; sudo apt-get install -y build-essential wget curl > /dev/null
    echo "[步骤 2/4] 下载并编译 3proxy..."; cd /tmp; rm -rf 3proxy-${VERSION}* 3proxy.tar.gz; wget -q --show-progress "https://github.com/3proxy/3proxy/archive/refs/tags/${VERSION}.tar.gz" -O 3proxy.tar.gz; tar -xvzf 3proxy.tar.gz; cd 3proxy-${VERSION}/; make -f Makefile.Linux > /dev/null 2>&1
    echo "[步骤 3/4] 安装程序和创建服务文件..."; sudo cp ./bin/3proxy "${INSTALL_PATH}"; sudo chmod +x "${INSTALL_PATH}"; sudo tee "${SERVICE_FILE}" > /dev/null <<'EOSS'
[Unit]
Description=3proxy Proxy Server
After=network.target
[Service]
Type=forking
ExecStart=/usr/local/bin/3proxy /etc/3proxy.cfg
Restart=always
[Install]
WantedBy=multi-user.target
EOSS
    if ! generate_config_file; then return 1; fi
    echo "[步骤 4/4] 启动服务..."; sudo systemctl daemon-reload; sudo systemctl enable --now 3proxy.service > /dev/null
    echo "------------------------------------------"; echo "安装成功！服务已启动并设为开机自启。"; show_proxy_info; echo ""
    read -p "是否立即运行可用性测试? (y/n): " run_test
    if [[ "$run_test" == "y" ]]; then do_test_proxies; fi
}

do_modify_config() {
    clear; echo "--- 修改现有配置 (无需重新编译) ---"
    if [ ! -f "${INSTALL_PATH}" ]; then echo "错误: 未找到3proxy程序。请先执行 '1' 完成首次安装。" && sleep 3 && return; fi
    if ! get_user_config; then return; fi
    if ! generate_config_file; then return 1; fi
    echo "--> 正在重启服务以应用新配置..."; sudo systemctl restart 3proxy.service
    echo "------------------------------------------"; echo "配置修改成功！"; show_proxy_info; echo ""
    read -p "是否立即运行可用性测试? (y/n): " run_test
    if [[ "$run_test" == "y" ]]; then do_test_proxies; fi
}

do_test_proxies() {
    clear; echo "--- 启动代理可用性测试 ---"
    if ! command -v curl &> /dev/null; then echo "错误: 'curl' 命令未找到。" && sleep 2 && return; fi
    if [ ! -f "${CONFIG_FILE}" ]; then echo "错误: 未找到配置文件。" && sleep 2 && return; fi
    
    local PORT=$(get_port_from_config)
    local IP_LIST_FROM_FILE=($(get_ips_from_config))
    local USER_LINE=$(grep '^users ' "${CONFIG_FILE}" || echo "")
    local CURL_AUTH_FLAG=""

    if [ -n "$USER_LINE" ]; then
        local USER=$(echo "$USER_LINE" | cut -d' ' -f2 | cut -d':' -f1)
        local PASS=$(echo "$USER_LINE" | cut -d' ' -f2 | cut -d':' -f3)
        CURL_AUTH_FLAG="--proxy-user ${USER}:${PASS}"
        echo "检测到认证配置，将使用用户 '${USER}' 进行测试。"
    else
        echo "无认证模式，将进行匿名测试。"
    fi

    if [ ${#IP_LIST_FROM_FILE[@]} -eq 0 ]; then echo "配置文件中未找到可测试的代理。" && sleep 2 && return; fi
    
    echo "将逐一测试 ${#IP_LIST_FROM_FILE[@]} 个代理..."
    echo "---------------------------------"
    local SUCCESS_COUNT=0
    local FAIL_COUNT=0
    for PROXY_IP in "${IP_LIST_FROM_FILE[@]}"; do
        echo -n "正在测试: ${PROXY_IP}:${PORT}... "
        local ACTUAL_EXIT_IP=$(curl ${CURL_AUTH_FLAG} --socks5 "${PROXY_IP}:${PORT}" --connect-timeout 5 -sS "http://ifconfig.me")
        local CURL_EXIT_CODE=$?
        if [ $CURL_EXIT_CODE -eq 0 ] && [[ "$ACTUAL_EXIT_IP" =~ ^[0-9]{1,3}\. ]]; then
            if [ "$PROXY_IP" == "$ACTUAL_EXIT_IP" ]; then
                echo -e "\e[32m成功 (出口IP一致)\e[0m"
                SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
            else
                echo -e "\e[31m失败 (出口IP不匹配: ${ACTUAL_EXIT_IP})\e[0m"
                FAIL_COUNT=$((FAIL_COUNT + 1))
            fi
        else
            echo -e "\e[31m失败 (连接超时或错误, curl退出码: ${CURL_EXIT_CODE})\e[0m"
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
    done
    echo "---------------------------------"
    echo "测试完成: ${SUCCESS_COUNT} 个成功, ${FAIL_COUNT} 个失败。"
}

do_uninstall(){ clear; read -p "确定要完全卸载3proxy吗? (y/n): " c; if [[ "$c" != "y" ]]; then echo "已取消"; sleep 2; return; fi; echo "正在卸载..."; sudo systemctl stop 3proxy.service || true; sudo systemctl disable 3proxy.service || true; sudo rm -f "${SERVICE_FILE}" "${CONFIG_FILE}" "${INSTALL_PATH}" "${LOG_FILE}"; sudo systemctl daemon-reload; echo "卸载完成。"; }
do_restart(){ clear; echo "正在重启服务..."; sudo systemctl restart 3proxy.service; sleep 1; do_status; }
do_status(){ clear; echo "查询当前状态..."; sudo systemctl status 3proxy.service; }

# ==========================================================
# --- 新增独立功能区 ---
# ==========================================================

create_google_domains_file() {
    sudo mkdir -p /etc/3proxy
    sudo tee "${GOOGLE_DOMAINS_FILE}" > /dev/null <<'EOF'
.google.com
.googleapis.com
.gstatic.com
.ggpht.com
.googlevideo.com
.googleusercontent.com
.youtube.com
.ytimg.com
.g.co
.goo.gl
.google.cn
.gcr.io
EOF
}

disable_split_mode() {
    echo "--> 正在关闭Google分流模式..."
    if grep -q "# --- Google Splitter Start ---" "${CONFIG_FILE}"; then
        sudo sed -i '/# --- Google Splitter Start ---/,/# --- Google Splitter End ---/d' "${CONFIG_FILE}"
        echo "--> 分流规则已从配置文件中移除。"
    else
        echo "--> 未找到分流规则，无需操作。"
    fi
}

enable_split_mode() {
    local GOOGLE_IP="$1"
    local INTERNAL_PORT="10800"

    disable_split_mode
    echo "--> 正在启用Google分流模式..."
    echo "--> Google专用出口IP将被设置为: ${GOOGLE_IP}"

    local USER=$(grep '^users ' "${CONFIG_FILE}" | cut -d' ' -f2 | cut -d':' -f1)
    if [ -z "$USER" ]; then USER="*"; fi

    local SPLIT_CONFIG_BLOCK
    read -r -d '' SPLIT_CONFIG_BLOCK << EOM

# --- Google Splitter Start ---
# 1. 定义上游的Google专用代理 (运行在本地)
parent 1000 socks5 127.0.0.1 ${INTERNAL_PORT}

# 2. 定义分流规则 (用户: ${USER})
allow ${USER} * @${GOOGLE_DOMAINS_FILE} * parent 1000
allow ${USER}

# 3. 供内部使用的Google专用代理服务
# Google-dedicated exit IP
socks -a -p${INTERNAL_PORT} -i127.0.0.1 -e${GOOGLE_IP}
# --- Google Splitter End ---

EOM
    sudo awk -v block="${SPLIT_CONFIG_BLOCK}" '
        !p && /^[ \t]*socks[ \t]*/ {
            print block;
            p=1
        }
        {
            print
        }
    ' "${CONFIG_FILE}" > "${CONFIG_FILE}.tmp" && sudo mv "${CONFIG_FILE}.tmp" "${CONFIG_FILE}"
    echo "--> 分流规则已成功注入配置文件。"
}

do_advanced_split_config() {
    clear
    echo "--- [高级] Google分流配置 (直接修改文件) ---"
    echo "此功能会读取并直接修改您现有的 ${CONFIG_FILE} 文件。"
    if [ ! -f "${CONFIG_FILE}" ]; then echo "错误: 未找到配置文件 ${CONFIG_FILE}。" && sleep 3 && return; fi
    echo "------------------------------------------"
    echo "请选择要执行的操作:"
    echo " 1) 启用或修改 Google分流"
    echo " 2) 关闭 Google分流"
    echo " 3) 返回主菜单"
    read -p "请输入选择 [1-3]: " choice

    case $choice in
        1)
            local IP_LIST=($(get_ips_from_config))
            if [ ${#IP_LIST[@]} -eq 0 ]; then echo "错误: 未能在配置文件中找到任何可用的出口IP。" && sleep 3 && return; fi
            echo ""
            echo "请从您现有配置中选择一个IP用于解锁Google:"
            local i=1
            for IP in "${IP_LIST[@]}"; do echo "  $i) $IP"; i=$((i+1)); done
            echo ""
            read -p "请输入IP编号: " ip_choice
            
            if [[ ! "$ip_choice" =~ ^[0-9]+$ ]] || [ "$ip_choice" -lt 1 ] || [ "$ip_choice" -gt ${#IP_LIST[@]} ]; then
                echo "无效选择。" && sleep 2 && return
            fi
            
            local GOOGLE_IP=${IP_LIST[$((ip_choice-1))]}
            create_google_domains_file
            enable_split_mode "$GOOGLE_IP"
            ;;
        2)
            disable_split_mode
            ;;
        3) return ;;
        *) echo "无效输入。" && sleep 2 && return ;;
    esac

    echo "--> 正在重启服务以应用新配置..."; sudo systemctl restart 3proxy.service
    echo "------------------------------------------"
    echo "操作完成！";
}

# --- 主循环 ---
while true; do
    show_menu
    read -p "请输入您的选择 [1-9]: " choice
    case $choice in
        1) do_install; press_any_key_to_continue ;;
        2) do_modify_config; press_any_key_to_continue ;;
        3) show_proxy_info; press_any_key_to_continue ;;
        4) do_test_proxies; press_any_key_to_continue ;;
        5) do_restart; press_any_key_to_continue ;;
        6) do_status; press_any_key_to_continue ;;
        7) do_uninstall; press_any_key_to_continue ;;
        8) do_advanced_split_config; press_any_key_to_continue ;;
        9) 
            echo "正在退出..."
            exit 0
            ;;
        *) 
            echo "无效输入，请重新选择。" && sleep 2 
            ;;
    esac
done
