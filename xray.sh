#!/bin/bash

#================================================
# Xray代理管理脚本 v6.2 (整理版)
# 功能：管理Xray代理服务器配置
# 支持：Shadowsocks和SOCKS5协议
#================================================

set -e

#================================================
# 全局配置和变量定义
#================================================

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# 配置文件路径
readonly XRAY_CONFIG="/usr/local/etc/xray/config.json"
readonly PROXY_CONFIG="/etc/3proxy.cfg"
readonly BACKUP_DIR="/root/xray_backups"
readonly EXCLUSIVE_IP_LIST_FILE="/usr/local/etc/xray/exclusive_ips.list"

# 创建必要目录
mkdir -p "$BACKUP_DIR"

#================================================
# 日志和工具函数
#================================================

# 日志函数
log_info() {
    echo -e "${GREEN}[信息]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[警告]${NC} $1"
}

log_error() {
    echo -e "${RED}[错误]${NC} $1"
}

# 生成随机值
generate_port() {
    while true; do
        local port=$((RANDOM % 55535 + 10000))
        if ! netstat -tuln 2>/dev/null | grep -q ":$port "; then
            echo "$port"
            return
        fi
    done
}

generate_password() {
    openssl rand -base64 16 | tr -d '+/=' | cut -c1-16
}

generate_user_id() {
    echo "user_$(openssl rand -hex 4)"
}

#================================================
# 服务管理函数
#================================================

# 重启Xray服务
restart_xray() {
    log_info "正在重启Xray服务..."
    if systemctl is-active --quiet xray; then
        systemctl restart xray
        log_info "Xray服务已成功重启。"
    else
        log_warn "Xray服务未在运行。请手动启动它。"
    fi
}

# 安装Xray
install_xray() {
    log_info "未找到Xray，开始安装..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)"
    log_info "Xray安装完成。"
}

# 检查依赖
check_dependencies() {
    local missing=()
    for cmd in jq openssl; do
        if ! command -v "$cmd" > /dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "缺少依赖项: ${missing[*]}"
        log_info "请使用以下命令安装: apt update && apt install -y ${missing[*]}"
        exit 1
    fi

    if ! command -v xray > /dev/null 2>&1; then
        install_xray
    fi
}

#================================================
# 配置文件管理函数
#================================================

# 备份配置文件
backup_config() {
    local config_file="$1"
    if [ -f "$config_file" ]; then
        local backup_name="$(basename "$config_file")_$(date +%Y%m%d_%H%M%S).bak"
        cp "$config_file" "$BACKUP_DIR/$backup_name"
        log_info "配置文件已备份: $backup_name"
    fi
}

# 创建基础Xray配置
create_base_xray_config() {
    if [ ! -f "$XRAY_CONFIG" ]; then
        log_info "正在创建基础Xray配置文件..."
        mkdir -p "$(dirname "$XRAY_CONFIG")"
        cat > "$XRAY_CONFIG" << 'EOF'
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [],
    "outbounds": [
        {
            "tag": "direct",
            "protocol": "freedom",
            "settings": {}
        },
        {
            "tag": "blocked",
            "protocol": "blackhole",
            "settings": {}
        }
    ],
    "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "ip": [
                    "geoip:private"
                ],
                "outboundTag": "blocked"
            }
        ]
    }
}
EOF
        log_info "基础配置文件已创建。"
    fi
}

#================================================
# 3proxy配置解析函数
#================================================

# 解析3proxy配置
parse_3proxy_config() {
    local config_file="$1"
    local -n proxy_ips_ref=$2
    local -n proxy_ports_ref=$3
    local -n user_ref=$4
    local -n pass_ref=$5

    if [ ! -f "$config_file" ]; then
        log_error "3proxy配置文件不存在: $config_file"
        return 1
    fi

    proxy_ips_ref=()
    proxy_ports_ref=()
    user_ref=""
    pass_ref=""
    local auth_found=false

    while IFS= read -r line; do
        # 跳过注释和空行
        case "$line" in
            \#*|"") continue ;;
        esac

        # 解析SOCKS代理配置
        if echo "$line" | grep -q "^socks"; then
            local ip=$(echo "$line" | grep -o '\-i[0-9.]*' | sed 's/-i//')
            local port=$(echo "$line" | grep -o '\-p[0-9]*' | sed 's/-p//')
            if [ -n "$ip" ] && [ -n "$port" ]; then
                proxy_ips_ref+=("$ip")
                proxy_ports_ref+=("$port")
            fi
        # 解析用户认证信息
        elif [[ "$line" == "users "* ]] && [ -z "$user_ref" ]; then
            local user_line_creds=$(echo "$line" | awk '{print $2}')
            user_ref=$(echo "$user_line_creds" | cut -d: -f1)
            pass_ref=$(echo "$user_line_creds" | cut -d: -f3)
            auth_found=true
        fi
    done < "$config_file"

    if $auth_found; then
        log_info "发现3proxy认证用户: $user_ref"
    fi
    log_info "从3proxy配置中解析到 ${#proxy_ips_ref[@]} 个SOCKS代理。"
    return 0
}

#================================================
# IP管理函数
#================================================

# 获取服务器本地IP列表
get_server_local_ips() {
    ip addr show | grep -oE 'inet ([0-9]+\.){3}[0-9]+' | awk '{print $2}' | grep -v '127.0.0.1' | sort -u
}

# 获取可用的（非独享）代理列表
get_available_proxies() {
    local -n all_ips_ref=$1
    local -n all_ports_ref=$2
    local -n available_ips_ref=$3
    local -n available_ports_ref=$4

    available_ips_ref=()
    available_ports_ref=()
    local exclusive_ips=()
    
    if [ -f "$EXCLUSIVE_IP_LIST_FILE" ]; then
        mapfile -t exclusive_ips < "$EXCLUSIVE_IP_LIST_FILE"
    fi

    for i in "${!all_ips_ref[@]}"; do
        local current_ip="${all_ips_ref[$i]}"
        local is_exclusive=false
        
        for ex_ip in "${exclusive_ips[@]}"; do
            if [[ "$current_ip" == "$ex_ip" ]]; then
                is_exclusive=true
                break
            fi
        done
        
        if ! $is_exclusive; then
            available_ips_ref+=("$current_ip")
            available_ports_ref+=("${all_ports_ref[$i]}")
        fi
    done
}

# 释放独享IP
release_exclusive_ip() {
    local ip="$1"
    if [ -z "$ip" ]; then 
        return
    fi

    if grep -q "^${ip}$" "$EXCLUSIVE_IP_LIST_FILE"; then
        log_info "正在释放独享IP: ${ip}"
        grep -v "^${ip}$" "$EXCLUSIVE_IP_LIST_FILE" > "${EXCLUSIVE_IP_LIST_FILE}.tmp"
        mv "${EXCLUSIVE_IP_LIST_FILE}.tmp" "$EXCLUSIVE_IP_LIST_FILE"
    fi
}

# 根据入站标签查找并释放IP
find_and_release_ip_for_inbound_tag() {
    local inbound_tag="$1"
    local outbound_tag
    
    outbound_tag=$(jq -r --arg t "$inbound_tag" '.routing.rules[] | select(.inboundTag[0] == $t) | .outboundTag' "$XRAY_CONFIG")
    
    if [ -n "$outbound_tag" ]; then
        local outbound_ip
        outbound_ip=$(echo "$outbound_tag" | sed -n 's/^3proxy-\([0-9.]*\)-[0-9]*$/\1/p')
        release_exclusive_ip "$outbound_ip"
    fi
}

#================================================
# 用户界面函数
#================================================

# 显示本地IP选择菜单
show_local_ip_menu() {
    local local_ips=($(get_server_local_ips))
    if [ ${#local_ips[@]} -eq 0 ]; then
        log_error "未找到可用的本地IP地址。"
        return 1
    fi

    echo -e "${BLUE}=== 可用的本地监听IP ===${NC}"
    for i in "${!local_ips[@]}"; do
        echo "[$((i + 1))] ${local_ips[$i]}"
    done
    echo "[0] 使用 0.0.0.0 (监听所有网络接口)"
    echo

    read -p "请选择一个监听IP: " choice
    if [ "$choice" = "0" ]; then
        selected_listen_ip="0.0.0.0"
        return 0
    elif [ "$choice" -ge 1 ] && [ "$choice" -le ${#local_ips[@]} ] 2>/dev/null; then
        selected_listen_ip="${local_ips[$((choice - 1))]}"
        return 0
    else
        log_error "无效的选择。"
        return 1
    fi
}

# 显示3proxy IP选择菜单
show_proxy_ip_menu() {
    local -n proxy_ips_ref=$1
    local -n proxy_ports_ref=$2
    
    if [ ${#proxy_ips_ref[@]} -eq 0 ]; then
        log_warn "当前没有可用的（非独享）出站IP。"
        return 1
    fi

    echo -e "${BLUE}=== 可用的 (非独享) 3proxy出站代理 ===${NC}"
    for i in "${!proxy_ips_ref[@]}"; do
        echo "[$((i + 1))] ${proxy_ips_ref[$i]}:${proxy_ports_ref[$i]}"
    done
    echo "[0] 返回主菜单"
    echo

    read -p "请选择一个出站代理: " choice
    if [ "$choice" = "0" ]; then
        return 1
    elif [ "$choice" -ge 1 ] && [ "$choice" -le ${#proxy_ips_ref[@]} ] 2>/dev/null; then
        selected_proxy_ip="${proxy_ips_ref[$((choice - 1))]}"
        selected_proxy_port="${proxy_ports_ref[$((choice - 1))]}"
        return 0
    else
        log_error "无效的选择。"
        return 1
    fi
}

#================================================
# 代理配置管理函数
#================================================

# 获取下一个可用端口
get_next_port() {
    local used_ports=()
    if [ -f "$XRAY_CONFIG" ]; then
        used_ports=($(jq -r '.inbounds[].port' "$XRAY_CONFIG" 2>/dev/null))
    fi
    
    while true; do
        local new_port=$(generate_port)
        local found=0
        for port in "${used_ports[@]}"; do
            if [ "$port" = "$new_port" ]; then
                found=1
                break
            fi
        done
        if [ $found -eq 0 ]; then
            echo "$new_port"
            return
        fi
    done
}

# 添加Shadowsocks入站
add_shadowsocks() {
    local listen_ip="$1"
    local port="$2"
    local password="$3"
    local method="$4"
    local outbound_tag="$5"
    local inbound_tag="ss-$listen_ip-$port"
    
    local inbound
    inbound=$(jq -n \
        --argjson port "$port" \
        --arg listen "$listen_ip" \
        --arg method "$method" \
        --arg password "$password" \
        --arg tag "$inbound_tag" \
        '{
            port: $port,
            listen: $listen,
            protocol: "shadowsocks",
            settings: {
                method: $method,
                password: $password,
                network: "tcp,udp"
            },
            tag: $tag
        }')
    
    jq ".inbounds += [$inbound]" "$XRAY_CONFIG" > "${XRAY_CONFIG}.tmp" && mv "${XRAY_CONFIG}.tmp" "$XRAY_CONFIG"
    add_routing "$inbound_tag" "$outbound_tag"
    log_info "Shadowsocks已添加: $listen_ip:$port"
}

# 添加SOCKS5入站
add_socks5() {
    local listen_ip="$1"
    local port="$2"
    local username="$3"
    local password="$4"
    local outbound_tag="$5"
    local inbound_tag="socks-$listen_ip-$port"
    
    local account
    account=$(jq -n --arg user "$username" --arg pass "$password" '{user: $user, pass: $pass}')
    
    local inbound
    inbound=$(jq -n \
        --argjson port "$port" \
        --arg listen "$listen_ip" \
        --argjson acct "$account" \
        --arg tag "$inbound_tag" \
        '{
            port: $port,
            listen: $listen,
            protocol: "socks",
            settings: {
                auth: "password",
                accounts: [$acct],
                udp: true
            },
            tag: $tag
        }')

    jq ".inbounds += [$inbound]" "$XRAY_CONFIG" > "${XRAY_CONFIG}.tmp" && mv "${XRAY_CONFIG}.tmp" "$XRAY_CONFIG"
    add_routing "$inbound_tag" "$outbound_tag"
    log_info "SOCKS5已添加: $listen_ip:$port"
}

# 添加出站配置
add_outbound_and_routing() {
    local outbound_tag="$1"
    local proxy_ip="$2"
    local proxy_port="$3"
    local username="$4"
    local password="$5"
    
    if ! jq -e ".outbounds[] | select(.tag == \"$outbound_tag\")" "$XRAY_CONFIG" >/dev/null 2>&1; then
        local server_obj
        server_obj=$(jq -n --arg a "$proxy_ip" --argjson p "$proxy_port" '{address: $a, port: $p}')
        
        if [ -n "$username" ] && [ -n "$password" ]; then
            local user_auth_obj
            user_auth_obj=$(jq -n --arg u "$username" --arg p "$password" '{user: $u, pass: $p}')
            server_obj=$(echo "$server_obj" | jq ".users = [$user_auth_obj]")
        fi
        
        local outbound_obj
        outbound_obj=$(jq -n --arg t "$outbound_tag" --argjson s "$server_obj" \
            '{tag: $t, protocol: "socks", settings: {servers: [$s]}}')
        
        jq ".outbounds += [$outbound_obj]" "$XRAY_CONFIG" > "${XRAY_CONFIG}.tmp" && mv "${XRAY_CONFIG}.tmp" "$XRAY_CONFIG"
        
        if [ -n "$username" ]; then
            log_info "已添加带认证的出站: $outbound_tag -> $proxy_ip:$proxy_port (用户: $username)"
        else
            log_info "已添加出站: $outbound_tag -> $proxy_ip:$proxy_port"
        fi
    fi
}

# 添加路由规则
add_routing() {
    local inbound_tag="$1"
    local outbound_tag="$2"
    
    local rule
    rule=$(jq -n --arg it "$inbound_tag" --arg ot "$outbound_tag" \
        '{type: "field", inboundTag: [$it], outboundTag: $ot}')
    
    jq ".routing.rules += [$rule]" "$XRAY_CONFIG" > "${XRAY_CONFIG}.tmp" && mv "${XRAY_CONFIG}.tmp" "$XRAY_CONFIG"
    log_info "已添加路由规则: $inbound_tag -> $outbound_tag"
}

#================================================
# 代理管理操作函数
#================================================

# 添加单个代理
add_single_proxy() {
    echo -e "${BLUE}=== 添加单个代理 (支持设置IP独享) ===${NC}"
    
    local all_ips=() all_ports=() available_ips=() available_ports=()
    local proxy_user="" proxy_pass=""
    
    if ! parse_3proxy_config "$PROXY_CONFIG" all_ips all_ports proxy_user proxy_pass; then 
        return
    fi
    
    get_available_proxies all_ips all_ports available_ips available_ports
    
    if ! show_proxy_ip_menu available_ips available_ports; then 
        return
    fi
    
    if ! show_local_ip_menu; then 
        return
    fi

    local outbound_tag="3proxy-$selected_proxy_ip-$selected_proxy_port"
    add_outbound_and_routing "$outbound_tag" "$selected_proxy_ip" "$selected_proxy_port" "$proxy_user" "$proxy_pass"

    backup_config "$XRAY_CONFIG"

    echo -e "${BLUE}选择代理类型:${NC}"
    echo "[1] Shadowsocks"
    echo "[2] SOCKS5"
    echo "[0] 返回"
    read -p "请输入选项: " proxy_type

    case "$proxy_type" in
        1) add_shadowsocks "$selected_listen_ip" "$(get_next_port)" "$(generate_password)" "aes-256-gcm" "$outbound_tag" ;;
        2) add_socks5 "$selected_listen_ip" "$(get_next_port)" "$(generate_user_id)" "$(generate_password)" "$outbound_tag" ;;
        0) return ;;
        *) log_error "无效的选择"; return ;;
    esac

    read -p "是否将此出站IP ${selected_proxy_ip} 设为独享? (y/n): " make_exclusive
    if [[ "$make_exclusive" == "y" ]]; then
        echo "$selected_proxy_ip" >> "$EXCLUSIVE_IP_LIST_FILE"
        log_info "IP ${selected_proxy_ip} 已被标记为独享。"
    fi

    restart_xray
}

# 批量添加共享代理
batch_add_shared_proxies() {
    echo -e "${BLUE}=== 批量添加共享代理 (轮询出口) ===${NC}"
    log_info "此模式通过轮询可用出口IP，创建您指定数量的代理。"
    
    read -p "代理类型 (1-SS, 2-SOCKS5): " proxy_type
    if [ "$proxy_type" != "1" ] && [ "$proxy_type" != "2" ]; then
        log_error "无效的代理类型。"
        return
    fi

    read -p "请输入统一监听端口 (留空则随机): " unified_port
    local unified_user=""
    local unified_pass=""
    
    if [ "$proxy_type" = "2" ]; then
        read -p "请输入统一用户名 (留空则随机): " unified_user
    fi
    read -p "请输入统一密码 (留空则随机): " unified_pass

    local all_ips=() all_ports=() available_ips=() available_ports=()
    local proxy_user="" proxy_pass=""
    
    if ! parse_3proxy_config "$PROXY_CONFIG" all_ips all_ports proxy_user proxy_pass; then
        return
    fi
    
    get_available_proxies all_ips all_ports available_ips available_ports

    local num_available_ips=${#available_ips[@]}
    if [ "$num_available_ips" -eq 0 ]; then
        log_error "未找到任何可用的（非独享）3proxy代理。"
        return
    fi

    local count
    local listen_method
    
    if [ -n "$unified_port" ]; then
        log_warn "检测到统一端口设置，监听模式将固定为[每个代理监听其对应的出站IP]。"
        listen_method="1"
        read -p "您最多可创建 ${num_available_ips} 个代理, 请输入生成数量: " count
        if ! [[ "$count" =~ ^[0-9]+$ ]] || [ "$count" -lt 1 ] || [ "$count" -gt "$num_available_ips" ]; then
            log_error "无效数量。数量必须是 1 到 ${num_available_ips} 之间的数字。"
            return
        fi
    else
        read -p "请输入生成数量: " count
        if ! echo "$count" | grep -q '^[0-9]\+$' || [ "$count" -lt 1 ]; then
            log_error "无效的数量。"
            return
        fi

        echo -e "${BLUE}监听IP配置:${NC}"
        echo "[1] 每个代理监听其对应的出站IP"
        echo "[2] 所有代理都监听 0.0.0.0"
        echo "[3] 选择一个固定的IP"
        read -p "请输入选项: " listen_method
    fi

    local fixed_ip=""
    if [ "$listen_method" = "3" ]; then
        if ! show_local_ip_menu; then 
            return
        fi
        fixed_ip="$selected_listen_ip"
    elif [ "$listen_method" = "2" ]; then
        fixed_ip="0.0.0.0"
    fi

    log_info "开始批量生成 $count 个代理..."
    backup_config "$XRAY_CONFIG"

    for i in $(seq 1 $count); do
        local idx=$(((i - 1) % num_available_ips))
        local proxy_ip="${available_ips[$idx]}"
        local proxy_port="${available_ports[$idx]}"
        local outbound_tag="3proxy-$proxy_ip-$proxy_port"

        local listen_ip
        case "$listen_method" in
            1) listen_ip="$proxy_ip" ;;
            2|3) listen_ip="$fixed_ip" ;;
            *) listen_ip="0.0.0.0" ;;
        esac

        add_outbound_and_routing "$outbound_tag" "$proxy_ip" "$proxy_port" "$proxy_user" "$proxy_pass"

        local port
        if [ -n "$unified_port" ]; then
            port="$unified_port"
        else
            port=$(get_next_port)
        fi

        if [ "$proxy_type" = "1" ]; then
            local password
            if [ -n "$unified_pass" ]; then 
                password="$unified_pass"
            else 
                password=$(generate_password)
            fi
            add_shadowsocks "$listen_ip" "$port" "$password" "aes-256-gcm" "$outbound_tag"
        elif [ "$proxy_type" = "2" ]; then
            local username password
            if [ -n "$unified_user" ]; then 
                username="$unified_user"
            else 
                username="user_$i"
            fi
            if [ -n "$unified_pass" ]; then 
                password="$unified_pass"
            else 
                password=$(generate_password)
            fi
            add_socks5 "$listen_ip" "$port" "$username" "$password" "$outbound_tag"
        fi

        sleep 0.1
    done

    log_info "批量生成完成！"
    restart_xray
}

# 批量添加独享代理
batch_add_exclusive_proxies() {
    echo -e "${BLUE}=== 批量添加独享代理 (一对一出口/强制创建) ===${NC}"
    
    local all_ips=() all_ports=() available_ips=() available_ports=()
    local proxy_user="" proxy_pass=""
    
    if ! parse_3proxy_config "$PROXY_CONFIG" all_ips all_ports proxy_user proxy_pass; then 
        return
    fi
    
    get_available_proxies all_ips all_ports available_ips available_ports

    local num_all_ips=${#all_ips[@]}
    local num_available_ips=${#available_ips[@]}
    local ips_to_process=() ports_to_process=()

    log_info "总共发现 ${num_all_ips} 个IP, 其中 ${num_available_ips} 个为全新可用IP。"
    echo

    echo "[1] 为所有 ${num_available_ips} 个全新可用IP创建代理 (推荐)"
    echo "[2] 从 ${num_available_ips} 个全新可用IP中按序号选择一部分创建"
    echo "[3] 从 ${num_all_ips} 个总IP列表中强行指定范围创建 (覆盖独享状态)"
    echo "[0] 返回"
    read -p "请选择操作模式: " mode_choice

    case "$mode_choice" in
        1)
            if [ "$num_available_ips" -eq 0 ]; then 
                log_warn "没有可用的全新IP。"
                return
            fi
            ips_to_process=("${available_ips[@]}")
            ports_to_process=("${available_ports[@]}")
            ;;
        2)
            if [ "$num_available_ips" -eq 0 ]; then 
                log_warn "没有可用的全新IP。"
                return
            fi
            echo "--- 全新可用IP列表 ---"
            for i in "${!available_ips[@]}"; do 
                echo "$((i+1))) ${available_ips[i]}"
            done
            read -p "请输入要创建的IP序号范围 (例如: 1-5): " range_input
            if [[ ! "$range_input" =~ ^[0-9]+-[0-9]+$ ]]; then 
                log_error "范围格式错误。"
                return
            fi
            local start=$(echo "$range_input" | cut -d- -f1)
            local end=$(echo "$range_input" | cut -d- -f2)
            if [ "$start" -gt "$end" ] || [ "$start" -lt 1 ] || [ "$end" -gt "$num_available_ips" ]; then 
                log_error "范围无效。请输入 1 到 ${num_available_ips} 之间的有效范围。"
                return
            fi
            for (( i=start-1; i<end; i++ )); do
                ips_to_process+=("${available_ips[i]}")
                ports_to_process+=("${available_ports[i]}")
            done
            ;;
        3)
            log_warn "强制创建模式将忽略IP当前的独享状态。"
            read -p "请输入要从总列表中选择的IP序号范围 (1-${num_all_ips}, 例如: 1-10): " range_input
            if [[ ! "$range_input" =~ ^[0-9]+-[0-9]+$ ]]; then 
                log_error "范围格式错误。"
                return
            fi
            local start=$(echo "$range_input" | cut -d- -f1)
            local end=$(echo "$range_input" | cut -d- -f2)
            if [ "$start" -gt "$end" ] || [ "$start" -lt 1 ] || [ "$end" -gt "$num_all_ips" ]; then 
                log_error "范围无效。请输入 1 到 ${num_all_ips} 之间的有效范围。"
                return
            fi
            for (( i=start-1; i<end; i++ )); do
                ips_to_process+=("${all_ips[i]}")
                ports_to_process+=("${all_ports[i]}")
            done
            ;;
        0) return ;;
        *) log_error "无效选择"; return ;;
    esac

    local num_to_process=${#ips_to_process[@]}
    if [ "$num_to_process" -eq 0 ]; then 
        log_warn "没有选中任何IP用于创建代理。"
        return
    fi
    
    log_info "此模式将为选中的 ${num_to_process} 个IP创建一对一的独享代理。"
    log_info "入口的监听IP将与出口IP保持一致，创建后IP将被自动标记为独享。"

    read -p "代理类型 (1-SS, 2-SOCKS5): " proxy_type
    if [ "$proxy_type" != "1" ] && [ "$proxy_type" != "2" ]; then 
        log_error "无效的代理类型。"
        return
    fi
    
    read -p "请输入所有代理统一使用的监听端口: " unified_port
    if ! [[ "$unified_port" =~ ^[0-9]+$ ]]; then 
        log_error "无效的端口号，请输入数字。"
        return
    fi
    
    local unified_user="" unified_pass=""
    if [ "$proxy_type" = "2" ]; then 
        read -p "请输入统一用户名 (留空则随机): " unified_user
    fi
    read -p "请输入统一密码 (留空则随机): " unified_pass

    echo -e "${YELLOW}即将为以下 ${num_to_process} 个IP地址创建独享代理:${NC}"
    printf " %s\n" "${ips_to_process[@]}"
    echo "所有代理将监听在端口: ${unified_port}"
    read -p "您确定要继续吗? (y/n): " confirm
    if [ "$confirm" != "y" ]; then 
        log_info "操作已取消。"
        return
    fi
    
    log_info "开始为 ${num_to_process} 个IP创建独享代理..."
    backup_config "$XRAY_CONFIG"
    
    for i in "${!ips_to_process[@]}"; do
        local proxy_ip="${ips_to_process[i]}"
        local proxy_port="${ports_to_process[i]}"
        local listen_ip="$proxy_ip"
        local port="$unified_port"
        local outbound_tag="3proxy-$proxy_ip-$proxy_port"

        add_outbound_and_routing "$outbound_tag" "$proxy_ip" "$proxy_port" "$proxy_user" "$proxy_pass"

        if [ "$proxy_type" = "1" ]; then
            local password
            if [ -n "$unified_pass" ]; then 
                password="$unified_pass"
            else 
                password=$(generate_password)
            fi
            add_shadowsocks "$listen_ip" "$port" "$password" "aes-256-gcm" "$outbound_tag"
        elif [ "$proxy_type" = "2" ]; then
            local username password
            if [ -n "$unified_user" ]; then 
                username="$unified_user"
            else 
                username="user_d_$((i+1))"
            fi
            if [ -n "$unified_pass" ]; then 
                password="$unified_pass"
            else 
                password=$(generate_password)
            fi
            add_socks5 "$listen_ip" "$port" "$username" "$password" "$outbound_tag"
        fi

        # 标记为独享IP
        grep -qxF "$proxy_ip" "$EXCLUSIVE_IP_LIST_FILE" || echo "$proxy_ip" >> "$EXCLUSIVE_IP_LIST_FILE"
        log_info "IP ${proxy_ip} 已创建代理并标记为独享。"
        sleep 0.1
    done

    log_info "批量独享代理创建完成！"
    restart_xray
}

#================================================
# 代理删除操作函数
#================================================

# 删除单个代理
delete_single_proxy() {
    echo -e "${BLUE}=== 删除单个代理 ===${NC}"
    
    if [ ! -f "$XRAY_CONFIG" ]; then 
        log_error "Xray配置文件不存在。"
        return
    fi

    log_info "正在加载入站代理列表..."
    local tags
    tags=($(jq -r '.inbounds[].tag' "$XRAY_CONFIG"))
    local details=()
    
    if [ ${#tags[@]} -eq 0 ]; then 
        log_warn "没有找到任何可以删除的入站代理。"
        return
    fi

    for tag in "${tags[@]}"; do
        details+=("$(jq -r --arg t "$tag" '.inbounds[] | select(.tag == $t) | "\(.protocol) | \(.listen):\(.port) | 标签: \(.tag)"' "$XRAY_CONFIG")")
    done

    echo -e "${YELLOW}请选择要删除的代理:${NC}"
    for i in "${!details[@]}"; do 
        echo "[$((i + 1))] ${details[$i]}"
    done
    echo "[0] 返回主菜单"

    read -p "请输入选项: " choice
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 0 ] || [ "$choice" -gt ${#details[@]} ]; then 
        log_error "无效的选择。"
        return
    fi

    if [ "$choice" -eq 0 ]; then 
        log_info "操作取消。"
        return
    fi

    local tag_to_delete="${tags[$((choice - 1))]}"
    read -p "您确定要删除代理 '${details[$((choice - 1))]}' 吗? (y/n): " confirm
    if [ "$confirm" != "y" ]; then 
        log_info "操作已取消。"
        return
    fi

    backup_config "$XRAY_CONFIG"
    find_and_release_ip_for_inbound_tag "$tag_to_delete"

    log_info "正在删除入站: ${tag_to_delete} ..."
    local new_config
    new_config=$(jq --arg t "$tag_to_delete" 'del(.inbounds[] | select(.tag == $t)) | del(.routing.rules[] | select(.inboundTag[0] == $t))' "$XRAY_CONFIG")
    echo "$new_config" > "$XRAY_CONFIG"

    log_info "代理 '${tag_to_delete}' 及其关联路由规则已删除。"
    restart_xray
}

# 按用户名批量删除代理
batch_delete_proxies_by_user() {
    echo -e "${BLUE}=== 按用户名批量删除代理 ===${NC}"
    log_warn "此功能仅适用于SOCKS5代理。"
    
    if [ ! -f "$XRAY_CONFIG" ]; then 
        log_error "Xray配置文件不存在。"
        return
    fi

    read -p "请输入要匹配的用户名: " pattern
    if [ -z "$pattern" ]; then 
        log_error "用户名模式不能为空。"
        return
    fi

    local tags_json
    tags_json=$(jq -c --arg p "$pattern" '[.inbounds[] | select(.protocol == "socks" and (.settings.accounts[].user | contains($p))) | .tag]' "$XRAY_CONFIG")

    local num
    num=$(echo "$tags_json" | jq 'length')
    if [ "$num" -eq 0 ]; then 
        log_warn "没有找到用户匹配 '${pattern}' 的SOCKS5代理。"
        return
    fi

    echo -e "${YELLOW}以下 ${num} 个代理将被删除:${NC}"
    echo "$tags_json" | jq -r '.[]'
    echo

    read -p "您确定要全部删除吗? (y/n): " confirm
    if [ "$confirm" != "y" ]; then 
        log_info "操作已取消。"
        return
    fi

    backup_config "$XRAY_CONFIG"

    # 释放独享IP
    for tag in $(echo "$tags_json" | jq -r '.[]'); do
        find_and_release_ip_for_inbound_tag "$tag"
    done

    log_info "正在批量删除 ${num} 个代理..."
    local new_config
    new_config=$(jq --argjson tags "$tags_json" 'del(.inbounds[] | select(.tag as $t | $tags | index($t))) | del(.routing.rules[] | select(.inboundTag[0] as $it | $tags | index($it)))' "$XRAY_CONFIG")
    echo "$new_config" > "$XRAY_CONFIG"

    log_info "批量删除完成。"
    restart_xray
}

# 按端口批量删除代理
batch_delete_proxies_by_port() {
    echo -e "${BLUE}=== 按端口批量删除代理 ===${NC}"
    
    if [ ! -f "$XRAY_CONFIG" ]; then 
        log_error "Xray配置文件不存在。"
        return
    fi

    read -p "请输入要删除的代理所使用的端口号: " port
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then 
        log_error "无效的端口号。"
        return
    fi

    local tags_json
    tags_json=$(jq -c --argjson p "$port" '[.inbounds[] | select(.port == $p) | .tag]' "$XRAY_CONFIG")

    local num
    num=$(echo "$tags_json" | jq 'length')
    if [ "$num" -eq 0 ]; then 
        log_warn "没有找到在端口 ${port} 上运行的代理。"
        return
    fi

    echo -e "${YELLOW}以下 ${num} 个在端口 ${port} 上的代理将被删除:${NC}"
    jq -r --argjson p "$port" '.inbounds[] | select(.port == $p) | " - 协议: \(.protocol), 监听IP: \(.listen), 标签: \(.tag)"' "$XRAY_CONFIG"
    echo

    read -p "您确定要全部删除吗? (y/n): " confirm
    if [ "$confirm" != "y" ]; then 
        log_info "操作已取消。"
        return
    fi

    backup_config "$XRAY_CONFIG"

    # 释放独享IP
    for tag in $(echo "$tags_json" | jq -r '.[]'); do
        find_and_release_ip_for_inbound_tag "$tag"
    done

    log_info "正在批量删除 ${num} 个代理..."
    local new_config
    new_config=$(jq --argjson tags "$tags_json" 'del(.inbounds[] | select(.tag as $t | $tags | index($t))) | del(.routing.rules[] | select(.inboundTag[0] as $it | $tags | index($it)))' "$XRAY_CONFIG")
    echo "$new_config" > "$XRAY_CONFIG"

    log_info "批量删除完成。"
    restart_xray
}

#================================================
# 信息查看和导出函数
#================================================

# 列出现有代理
list_proxies() {
    echo -e "${BLUE}=== 现有代理列表 ===${NC}"
    
    if [ ! -f "$XRAY_CONFIG" ]; then
        log_error "Xray配置文件不存在。"
        return
    fi

    echo -e "${YELLOW}Shadowsocks代理:${NC}"
    jq -r '.inbounds[] | select(.protocol == "shadowsocks") | "监听: \(.listen):\(.port) | 方法: \(.settings.method) | 标签: \(.tag)"' "$XRAY_CONFIG" 2>/dev/null
    echo

    echo -e "${YELLOW}SOCKS5代理:${NC}"
    jq -r '.inbounds[] | select(.protocol == "socks") | "监听: \(.listen):\(.port) | 用户: \(.settings.accounts[0].user) | 标签: \(.tag)"' "$XRAY_CONFIG" 2>/dev/null
    echo

    echo -e "${YELLOW}出站配置:${NC}"
    jq -r '.outbounds[] | select(.protocol == "socks") | "标签: \(.tag) | 目标: \(.settings.servers[0].address):\(.settings.servers[0].port) | 认证用户: \(.settings.servers[0].users[0].user // "无")"' "$XRAY_CONFIG" 2>/dev/null
}

# 导出所有代理链接
export_all_links() {
    echo -e "${BLUE}=== 导出所有代理链接 ===${NC}"
    
    if [ ! -f "$XRAY_CONFIG" ]; then 
        log_error "Xray配置文件不存在。"
        return
    fi

    local output_file="/tmp/all_proxy_links_$(date +%Y%m%d_%H%M%S).txt"
    
    echo "# 全部代理链接导出 - $(date)" > "$output_file"
    echo "" >> "$output_file"

    echo -e "${YELLOW}Shadowsocks链接:${NC}"
    echo "# Shadowsocks链接" >> "$output_file"
    
    jq -c '.inbounds[] | select(.protocol == "shadowsocks")' "$XRAY_CONFIG" 2>/dev/null | while read -r line; do
        if [ -n "$line" ]; then
            local listen_ip port method password
            listen_ip=$(echo "$line" | jq -r .listen)
            port=$(echo "$line" | jq -r .port)
            method=$(echo "$line" | jq -r .settings.method)
            password=$(echo "$line" | jq -r .settings.password)
            
            local ss_link="ss://$(echo -n "$method:$password" | base64)@$listen_ip:$port"
            echo "$ss_link"
            echo "$ss_link" >> "$output_file"
        fi
    done

    echo
    echo -e "${YELLOW}SOCKS5链接:${NC}"
    echo "" >> "$output_file"
    echo "# SOCKS5链接" >> "$output_file"
    
    jq -c '.inbounds[] | select(.protocol == "socks")' "$XRAY_CONFIG" 2>/dev/null | while read -r line; do
        if [ -n "$line" ]; then
            local listen_ip port username password
            listen_ip=$(echo "$line" | jq -r .listen)
            port=$(echo "$line" | jq -r .port)
            username=$(echo "$line" | jq -r .settings.accounts[0].user)
            password=$(echo "$line" | jq -r .settings.accounts[0].pass)
            
            local socks_link="socks5://$username:$password@$listen_ip:$port"
            echo "$socks_link"
            echo "$socks_link" >> "$output_file"
        fi
    done

    echo
    log_info "所有链接已导出到: $output_file"
}

# 显示3proxy配置
show_3proxy_config() {
    echo -e "${BLUE}=== 3proxy配置内容 ===${NC}"
    
    if [ -f "$PROXY_CONFIG" ]; then
        cat "$PROXY_CONFIG"
    else
        log_error "3proxy配置文件不存在。"
    fi
}

#================================================
# 主菜单和程序入口
#================================================

# 主菜单
main_menu() {
    while true; do
        echo
        echo -e "${BLUE}=== Xray代理管理脚本 v6.2 (整理版) ===${NC}"
        echo "[1] 添加单个代理 (支持设置IP独享)"
        echo "[2] 批量添加共享代理 (轮询出口)"
        echo "[3] 批量添加独享代理 (一对一出口/强制创建)"
        echo "[4] 列出现有代理和出站"
        echo "[5] 导出所有代理链接"
        echo -e "${RED}--- 删除操作 (自动释放独享IP) ---${NC}"
        echo -e "${RED}[6] 删除单个代理${NC}"
        echo -e "${RED}[7] 按用户名批量删除SOCKS5代理${NC}"
        echo -e "${RED}[8] 按端口批量删除代理${NC}"
        echo "-------------------------------------"
        echo "[9] 查看3proxy配置"
        echo "[10] 查看备份"
        echo "[0] 退出"
        echo

        read -p "请输入选项: " choice

        case "$choice" in
            1) add_single_proxy ;;
            2) batch_add_shared_proxies ;;
            3) batch_add_exclusive_proxies ;;
            4) list_proxies ;;
            5) export_all_links ;;
            6) delete_single_proxy ;;
            7) batch_delete_proxies_by_user ;;
            8) batch_delete_proxies_by_port ;;
            9) show_3proxy_config ;;
            10) ls -la "$BACKUP_DIR" ;;
            0) log_info "正在退出"; exit 0 ;;
            *) log_error "无效的选择" ;;
        esac

        echo
        read -p "按回车键继续..."
    done
}

# 程序入口点
main() {
    # 检查root权限
    if [ $EUID -ne 0 ]; then
        log_error "请使用root权限运行此脚本。"
        exit 1
    fi

    # 检查依赖
    check_dependencies

    # 初始化配置
    create_base_xray_config
    touch "$EXCLUSIVE_IP_LIST_FILE"

    # 检查3proxy配置文件
    if [ ! -f "$PROXY_CONFIG" ]; then
        log_error "3proxy配置文件不存在: $PROXY_CONFIG"
        exit 1
    fi

    # 启动主菜单
    main_menu
}

# 脚本执行入口
main "$@"
