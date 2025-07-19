#!/bin/bash

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 配置文件路径
XRAY_CONFIG="/usr/local/etc/xray/config.json"
PROXY_CONFIG="/etc/3proxy.cfg"
BACKUP_DIR="/root/xray_backups"
EXCLUSIVE_IP_LIST_FILE="/usr/local/etc/xray/exclusive_ips.list"

# 创建备份目录
mkdir -p "$BACKUP_DIR"

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

# 重启Xray服务
restart_xray() {
    log_info "正在重启Xray服务..."
    if systemctl is-active --quiet xray; then
        systemctl restart xray
        sleep 2
        if systemctl is-active --quiet xray; then
            log_info "Xray服务已成功重启。"
        else
            log_error "Xray服务重启失败！"
            echo "查看错误详情: sudo journalctl -u xray -e --no-pager"
            return 1
        fi
    else
        systemctl start xray
        sleep 2
        if systemctl is-active --quiet xray; then
            log_info "Xray服务已成功启动。"
        else
            log_error "Xray服务启动失败！"
            echo "查看错误详情: sudo journalctl -u xray -e --no-pager"
            return 1
        fi
    fi
}

# 解析3proxy.cfg配置
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
        case "$line" in
            \#*|"") continue ;;
        esac

        if echo "$line" | grep -q "^socks"; then
            local ip=$(echo "$line" | grep -o '\-i[0-9.]*' | sed 's/-i//')
            local port=$(echo "$line" | grep -o '\-p[0-9]*' | sed 's/-p//')
            if [ -n "$ip" ] && [ -n "$port" ]; then
                proxy_ips_ref+=("$ip")
                proxy_ports_ref+=("$port")
            fi
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

# 获取本地IP列表
get_server_local_ips() {
    ip addr show | grep -oE 'inet ([0-9]+\.){3}[0-9]+' | awk '{print $2}' | grep -v '127.0.0.1' | sort -u
}

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

# 生成随机端口/密码/用户ID
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

# 生成唯一标签（修复标签冲突问题）
generate_unique_tag() {
    local base_tag="$1"
    local counter=1
    local unique_tag="$base_tag"
    
    # 检查标签是否已存在
    while jq -e ".inbounds[] | select(.tag == \"$unique_tag\")" "$XRAY_CONFIG" >/dev/null 2>&1; do
        unique_tag="${base_tag}-${counter}"
        counter=$((counter + 1))
    done
    
    echo "$unique_tag"
}

# 备份和创建配置
backup_config() {
    if [ -f "$1" ]; then
        local bn="$(basename "$1")_$(date +%Y%m%d_%H%M%S).bak"
        cp "$1" "$BACKUP_DIR/$bn"
        log_info "配置文件已备份: $bn"
    fi
}

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

# 检测并修复现有配置中的重复标签
fix_duplicate_tags() {
    echo -e "${BLUE}=== 检查并修复重复标签 ===${NC}"
    
    if [ ! -f "$XRAY_CONFIG" ]; then
        log_warn "Xray配置文件不存在，跳过标签检查。"
        return 0
    fi
    
    # 检查JSON格式是否有效
    if ! jq empty "$XRAY_CONFIG" 2>/dev/null; then
        log_error "配置文件JSON格式无效！"
        return 1
    fi
    
    # 获取所有入站标签并检测重复
    local all_tags=($(jq -r '.inbounds[].tag' "$XRAY_CONFIG" 2>/dev/null | sort))
    local duplicate_tags=()
    local prev_tag=""
    
    for tag in "${all_tags[@]}"; do
        if [ "$tag" = "$prev_tag" ] && [ -n "$tag" ]; then
            if [[ ! " ${duplicate_tags[@]} " =~ " ${tag} " ]]; then
                duplicate_tags+=("$tag")
            fi
        fi
        prev_tag="$tag"
    done
    
    # 检查空标签
    local empty_tags=$(jq '[.inbounds[] | select(.tag == "" or .tag == null)] | length' "$XRAY_CONFIG" 2>/dev/null)
    empty_tags=${empty_tags:-0}  # 确保不为空
    
    if [ ${#duplicate_tags[@]} -eq 0 ] && [ "$empty_tags" -eq 0 ]; then
        log_info "未发现重复标签或空标签。"
        return 0
    fi
    
    log_warn "发现问题标签，开始修复..."
    if [ ${#duplicate_tags[@]} -gt 0 ]; then
        log_warn "重复标签: ${duplicate_tags[*]}"
    fi
    if [ "$empty_tags" -gt 0 ]; then
        log_warn "空标签数量: $empty_tags"
    fi
    
    # 备份配置
    backup_config "$XRAY_CONFIG"
    
    # 修复重复标签
    for dup_tag in "${duplicate_tags[@]}"; do
        log_info "修复重复标签: $dup_tag"
        fix_single_duplicate_tag "$dup_tag"
    done
    
    # 修复空标签
    if [ "$empty_tags" -gt 0 ]; then
        fix_empty_tags
    fi
    
    log_info "标签修复完成！"
    return 0
}

# 修复单个重复标签
fix_single_duplicate_tag() {
    local dup_tag="$1"
    local temp_file=$(mktemp)
    local counter=2
    local first_found=false
    
    cp "$XRAY_CONFIG" "$temp_file"
    
    # 获取所有使用此标签的入站配置索引
    local inbound_indices=($(jq -r --arg tag "$dup_tag" '.inbounds | to_entries[] | select(.value.tag == $tag) | .key' "$XRAY_CONFIG"))
    
    log_info "找到 ${#inbound_indices[@]} 个使用标签 '$dup_tag' 的入站配置"
    
    # 从后往前处理，避免索引变化问题
    for ((i=${#inbound_indices[@]}-1; i>=0; i--)); do
        local idx="${inbound_indices[i]}"
        
        if [ "$first_found" = false ]; then
            # 保留第一个，不修改
            first_found=true
            log_info "保留第一个入站配置 (索引: $idx)"
        else
            # 修改后续的重复标签
            local new_tag="${dup_tag}-${counter}"
            
            # 确保新标签唯一
            while jq -e --arg tag "$new_tag" '.inbounds[] | select(.tag == $tag)' "$temp_file" >/dev/null 2>&1; do
                counter=$((counter + 1))
                new_tag="${dup_tag}-${counter}"
            done
            
            log_info "将入站配置 (索引: $idx) 的标签改为: $new_tag"
            
            # 更新入站标签
            jq --argjson idx "$idx" --arg new_tag "$new_tag" '.inbounds[$idx].tag = $new_tag' "$temp_file" > "${temp_file}.tmp" && mv "${temp_file}.tmp" "$temp_file"
            
            # 更新对应的路由规则
            jq --arg old_tag "$dup_tag" --arg new_tag "$new_tag" '
                .routing.rules = [
                    .routing.rules[] | 
                    if .inboundTag and (.inboundTag | type == "array") and (.inboundTag | length == 1) and .inboundTag[0] == $old_tag then
                        .inboundTag = [$new_tag]
                    else
                        .
                    end
                ]' "$temp_file" > "${temp_file}.tmp" && mv "${temp_file}.tmp" "$temp_file"
            
            counter=$((counter + 1))
        fi
    done
    
    # 应用修改
    mv "$temp_file" "$XRAY_CONFIG"
}

# 修复空标签
fix_empty_tags() {
    local temp_file=$(mktemp)
    local counter=1
    
    cp "$XRAY_CONFIG" "$temp_file"
    
    # 为每个空标签生成唯一标签
    local empty_indices=($(jq -r '.inbounds | to_entries[] | select(.value.tag == "" or .value.tag == null) | .key' "$XRAY_CONFIG"))
    
    for idx in "${empty_indices[@]}"; do
        local protocol=$(jq -r --argjson idx "$idx" '.inbounds[$idx].protocol' "$temp_file")
        local port=$(jq -r --argjson idx "$idx" '.inbounds[$idx].port' "$temp_file")
        local listen=$(jq -r --argjson idx "$idx" '.inbounds[$idx].listen' "$temp_file")
        local new_tag="${protocol}-${listen}-${port}-auto${counter}"
        
        # 确保标签唯一
        while jq -e --arg tag "$new_tag" '.inbounds[] | select(.tag == $tag)' "$temp_file" >/dev/null 2>&1; do
            counter=$((counter + 1))
            new_tag="${protocol}-${listen}-${port}-auto${counter}"
        done
        
        log_info "为空标签生成新标签: $new_tag (索引: $idx)"
        jq --argjson idx "$idx" --arg new_tag "$new_tag" '.inbounds[$idx].tag = $new_tag' "$temp_file" > "${temp_file}.tmp" && mv "${temp_file}.tmp" "$temp_file"
        
        counter=$((counter + 1))
    done
    
    mv "$temp_file" "$XRAY_CONFIG"
    log_info "空标签修复完成。"
}

# 验证配置文件
validate_config() {
    log_info "验证配置文件..."
    
    if [ ! -f "$XRAY_CONFIG" ]; then
        log_error "配置文件不存在！"
        return 1
    fi
    
    # 检查JSON格式
    if ! jq empty "$XRAY_CONFIG" 2>/dev/null; then
        log_error "配置文件JSON格式无效！"
        return 1
    fi
    
    # 检查是否还有重复标签
    local all_tags=($(jq -r '.inbounds[].tag' "$XRAY_CONFIG" 2>/dev/null | sort))
    local has_duplicates=false
    local prev_tag=""
    
    for tag in "${all_tags[@]}"; do
        if [ "$tag" = "$prev_tag" ] && [ -n "$tag" ]; then
            log_error "仍然存在重复标签: $tag"
            has_duplicates=true
        fi
        prev_tag="$tag"
    done
    
    if [ "$has_duplicates" = true ]; then
        log_error "配置文件仍有重复标签！"
        return 1
    fi
    
    # 检查空标签
    local empty_count=$(jq '[.inbounds[] | select(.tag == "" or .tag == null)] | length' "$XRAY_CONFIG" 2>/dev/null)
    empty_count=${empty_count:-0}  # 确保不为空
    
    if [ "$empty_count" -gt 0 ]; then
        log_warn "仍然存在 $empty_count 个空标签，但这不会阻止Xray运行。"
    fi
    
    log_info "配置文件验证通过！"
    return 0
}

# 测试配置
test_config() {
    log_info "测试Xray配置..."
    
    if command -v xray >/dev/null 2>&1; then
        # 使用正确的xray命令语法
        if xray run -test -config "$XRAY_CONFIG" 2>/dev/null; then
            log_info "Xray配置测试通过！"
            return 0
        else
            log_error "Xray配置测试失败！"
            echo "详细错误信息："
            xray run -test -config "$XRAY_CONFIG" 2>&1 || true
            return 1
        fi
    else
        log_warn "Xray命令未找到，跳过配置测试。"
        return 0
    fi
}

# 添加Shadowsocks/SOCKS5入站（修复标签冲突）
add_shadowsocks() {
    local listen_ip="$1"
    local port="$2"
    local password="$3"
    local method="$4"
    local outbound_tag="$5"
    
    # 生成基础标签并确保唯一性
    local unique_outbound_suffix=$(echo "$outbound_tag" | sed 's/3proxy-//')
    local base_tag="ss-$listen_ip-$port-via-$unique_outbound_suffix"
    local inbound_tag=$(generate_unique_tag "$base_tag")
    
    local inbound
    inbound=$(jq -n \
        --argjson port "$port" \
        --arg listen "$listen_ip" \
        --arg method "$method" \
        --arg password "$password" \
        --arg tag "$inbound_tag" \
        '{port: $port, listen: $listen, protocol: "shadowsocks", settings: {method: $method, password: $password, network: "tcp,udp"}, tag: $tag}')
    
    jq ".inbounds += [$inbound]" "$XRAY_CONFIG" > "${XRAY_CONFIG}.tmp" && mv "${XRAY_CONFIG}.tmp" "$XRAY_CONFIG"
    add_routing "$inbound_tag" "$outbound_tag"
    log_info "Shadowsocks已添加: $listen_ip:$port (标签: $inbound_tag)"
}

add_socks5() {
    local listen_ip="$1"
    local port="$2"
    local username="$3"
    local password="$4"
    local outbound_tag="$5"
    
    # 生成基础标签并确保唯一性
    local unique_outbound_suffix=$(echo "$outbound_tag" | sed 's/3proxy-//')
    local base_tag="socks-$listen_ip-$port-via-$unique_outbound_suffix"
    local inbound_tag=$(generate_unique_tag "$base_tag")
    
    local account
    account=$(jq -n --arg user "$username" --arg pass "$password" '{user: $user, pass: $pass}')
    local inbound
    inbound=$(jq -n \
        --argjson port "$port" \
        --arg listen "$listen_ip" \
        --argjson acct "$account" \
        --arg tag "$inbound_tag" \
        '{port: $port, listen: $listen, protocol: "socks", settings: {auth: "password", accounts: [$acct], udp: true}, tag: $tag}')

    jq ".inbounds += [$inbound]" "$XRAY_CONFIG" > "${XRAY_CONFIG}.tmp" && mv "${XRAY_CONFIG}.tmp" "$XRAY_CONFIG"
    add_routing "$inbound_tag" "$outbound_tag"
    log_info "SOCKS5已添加: $listen_ip:$port (标签: $inbound_tag)"
}

# 添加出站和路由规则
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
        outbound_obj=$(jq -n --arg t "$outbound_tag" --argjson s "$server_obj" '{tag: $t, protocol: "socks", settings: {servers: [$s]}}')
        jq ".outbounds += [$outbound_obj]" "$XRAY_CONFIG" > "${XRAY_CONFIG}.tmp" && mv "${XRAY_CONFIG}.tmp" "$XRAY_CONFIG"
        if [ -n "$username" ]; then
            log_info "已添加带认证的出站: $outbound_tag -> $proxy_ip:$proxy_port (用户: $username)"
        else
            log_info "已添加出站: $outbound_tag -> $proxy_ip:$proxy_port"
        fi
    fi
}

add_routing() {
    local inbound_tag="$1"
    local outbound_tag="$2"
    local rule
    rule=$(jq -n --arg it "$inbound_tag" --arg ot "$outbound_tag" '{type: "field", inboundTag: [$it], outboundTag: $ot}')
    jq ".routing.rules += [$rule]" "$XRAY_CONFIG" > "${XRAY_CONFIG}.tmp" && mv "${XRAY_CONFIG}.tmp" "$XRAY_CONFIG"
    log_info "已添加路由规则: $inbound_tag -> $outbound_tag"
}

# 添加单个代理
add_single_proxy() {
    echo -e "${BLUE}=== 添加单个代理 (支持设置IP独享) ===${NC}"
    local all_ips=() all_ports=() available_ips=() available_ports=()
    local proxy_user="" proxy_pass=""
    if ! parse_3proxy_config "$PROXY_CONFIG" all_ips all_ports proxy_user proxy_pass; then return; fi
    get_available_proxies all_ips all_ports available_ips available_ports
    if ! show_proxy_ip_menu available_ips available_ports; then return; fi
    if ! show_local_ip_menu; then return; fi
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
    local proxy_user=""
    local proxy_pass=""
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
        if ! show_local_ip_menu; then return; fi
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
            if [ -n "$unified_pass" ]; then password="$unified_pass"; else password=$(generate_password); fi
            add_shadowsocks "$listen_ip" "$port" "$password" "aes-256-gcm" "$outbound_tag"
        elif [ "$proxy_type" = "2" ]; then
            local username
            local password
            if [ -n "$unified_user" ]; then username="$unified_user"; else username="user_$i"; fi
            if [ -n "$unified_pass" ]; then password="$unified_pass"; else password=$(generate_password); fi
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
    if ! parse_3proxy_config "$PROXY_CONFIG" all_ips all_ports proxy_user proxy_pass; then return; fi
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
            if [ "$num_available_ips" -eq 0 ]; then log_warn "没有可用的全新IP。"; return; fi
            ips_to_process=("${available_ips[@]}")
            ports_to_process=("${available_ports[@]}")
            ;;
        2)
            if [ "$num_available_ips" -eq 0 ]; then log_warn "没有可用的全新IP。"; return; fi
            echo "--- 全新可用IP列表 ---"
            for i in "${!available_ips[@]}"; do echo "$((i+1))) ${available_ips[i]}"; done
            read -p "请输入要创建的IP序号范围 (例如: 1-5): " range_input
            if [[ ! "$range_input" =~ ^[0-9]+-[0-9]+$ ]]; then log_error "范围格式错误。"; return; fi
            local start=$(echo "$range_input" | cut -d- -f1)
            local end=$(echo "$range_input" | cut -d- -f2)
            if [ "$start" -gt "$end" ] || [ "$start" -lt 1 ] || [ "$end" -gt "$num_available_ips" ]; then log_error "范围无效。请输入 1 到 ${num_available_ips} 之间的有效范围。"; return; fi
            for (( i=start-1; i<end; i++ )); do
                ips_to_process+=("${available_ips[i]}")
                ports_to_process+=("${available_ports[i]}")
            done
            ;;
        3)
            log_warn "强制创建模式将忽略IP当前的独享状态。"
            read -p "请输入要从总列表中选择的IP序号范围 (1-${num_all_ips}, 例如: 1-10): " range_input
            if [[ ! "$range_input" =~ ^[0-9]+-[0-9]+$ ]]; then log_error "范围格式错误。"; return; fi
            local start=$(echo "$range_input" | cut -d- -f1)
            local end=$(echo "$range_input" | cut -d- -f2)
            if [ "$start" -gt "$end" ] || [ "$start" -lt 1 ] || [ "$end" -gt "$num_all_ips" ]; then log_error "范围无效。请输入 1 到 ${num_all_ips} 之间的有效范围。"; return; fi
            for (( i=start-1; i<end; i++ )); do
                ips_to_process+=("${all_ips[i]}")
                ports_to_process+=("${all_ports[i]}")
            done
            ;;
        0) return ;;
        *) log_error "无效选择"; return ;;
    esac

    local num_to_process=${#ips_to_process[@]}
    if [ "$num_to_process" -eq 0 ]; then log_warn "没有选中任何IP用于创建代理。"; return; fi
    
    log_info "此模式将为选中的 ${num_to_process} 个IP创建一对一的独享代理。"
    log_info "入口的监听IP将与出口IP保持一致，创建后IP将被自动标记为独享。"

    read -p "代理类型 (1-SS, 2-SOCKS5): " proxy_type
    if [ "$proxy_type" != "1" ] && [ "$proxy_type" != "2" ]; then log_error "无效的代理类型。"; return; fi
    read -p "请输入所有代理统一使用的监听端口: " unified_port
    if ! [[ "$unified_port" =~ ^[0-9]+$ ]]; then log_error "无效的端口号，请输入数字。"; return; fi
    local unified_user="" unified_pass=""
    if [ "$proxy_type" = "2" ]; then read -p "请输入统一用户名 (留空则随机): " unified_user; fi
    read -p "请输入统一密码 (留空则随机): " unified_pass
    echo -e "${YELLOW}即将为以下 ${num_to_process} 个IP地址创建独享代理:${NC}"; printf " %s\n" "${ips_to_process[@]}"; echo "所有代理将监听在端口: ${unified_port}"
    read -p "您确定要继续吗? (y/n): " confirm
    if [ "$confirm" != "y" ]; then log_info "操作已取消。"; return; fi
    
    log_info "开始为 ${num_to_process} 个IP创建独享代理..."
    backup_config "$XRAY_CONFIG"
    for i in "${!ips_to_process[@]}"; do
        local proxy_ip="${ips_to_process[i]}"; local proxy_port="${ports_to_process[i]}"; local listen_ip="$proxy_ip"; local port="$unified_port"
        local outbound_tag="3proxy-$proxy_ip-$proxy_port"
        add_outbound_and_routing "$outbound_tag" "$proxy_ip" "$proxy_port" "$proxy_user" "$proxy_pass"
        if [ "$proxy_type" = "1" ]; then
            local password;
            if [ -n "$unified_pass" ]; then password="$unified_pass"; else password=$(generate_password); fi
            add_shadowsocks "$listen_ip" "$port" "$password" "aes-256-gcm" "$outbound_tag"
        elif [ "$proxy_type" = "2" ]; then
            local username password
            if [ -n "$unified_user" ]; then username="$unified_user"; else username="user_d_$((i+1))"; fi
            if [ -n "$unified_pass" ]; then password="$unified_pass"; else password=$(generate_password); fi
            add_socks5 "$listen_ip" "$port" "$username" "$password" "$outbound_tag"
        fi
        grep -qxF "$proxy_ip" "$EXCLUSIVE_IP_LIST_FILE" || echo "$proxy_ip" >> "$EXCLUSIVE_IP_LIST_FILE"
        log_info "IP ${proxy_ip} 已创建代理并标记为独享。"
        sleep 0.1
    done
    log_info "批量独享代理创建完成！"; restart_xray
}

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

# 释放独享IP
release_exclusive_ip() {
    local ip=$1
    if [ -z "$ip" ]; then return; fi
    if [ -f "$EXCLUSIVE_IP_LIST_FILE" ] && grep -q "^${ip}$" "$EXCLUSIVE_IP_LIST_FILE"; then
        log_info "正在释放独享IP: ${ip}"
        grep -v "^${ip}$" "$EXCLUSIVE_IP_LIST_FILE" > "${EXCLUSIVE_IP_LIST_FILE}.tmp"
        mv "${EXCLUSIVE_IP_LIST_FILE}.tmp" "$EXCLUSIVE_IP_LIST_FILE"
    fi
}

find_and_release_ip_for_inbound_tag() {
    local inbound_tag=$1
    local outbound_tag
    outbound_tag=$(jq -r --arg t "$inbound_tag" '.routing.rules[] | select(.inboundTag[0] == $t) | .outboundTag' "$XRAY_CONFIG")
    if [ -n "$outbound_tag" ]; then
        local outbound_ip
        outbound_ip=$(echo "$outbound_tag" | sed -n 's/^3proxy-\([0-9.]*\)-[0-9]*$/\1/p')
        release_exclusive_ip "$outbound_ip"
    fi
}

# 删除代理
delete_single_proxy() {
    echo -e "${BLUE}=== 删除单个代理 ===${NC}"
    if [ ! -f "$XRAY_CONFIG" ]; then log_error "Xray配置文件不存在。"; return; fi
    log_info "正在加载入站代理列表..."
    local tags
    tags=($(jq -r '.inbounds[].tag' "$XRAY_CONFIG"))
    local details=()
    if [ ${#tags[@]} -eq 0 ]; then log_warn "没有找到任何可以删除的入站代理。"; return; fi
    for tag in "${tags[@]}"; do
        details+=("$(jq -r --arg t "$tag" '.inbounds[] | select(.tag == $t) | "\(.protocol) | \(.listen):\(.port) | 标签(tag): \(.tag)"' "$XRAY_CONFIG")")
    done
    echo -e "${YELLOW}请选择要删除的代理:${NC}"
    for i in "${!details[@]}"; do echo "[$((i + 1))] ${details[$i]}"; done
    echo "[0] 返回主菜单"
    read -p "请输入选项: " choice
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 0 ] || [ "$choice" -gt ${#details[@]} ]; then log_error "无效的选择。"; return; fi
    if [ "$choice" -eq 0 ]; then log_info "操作取消。"; return; fi
    local tag_to_delete="${tags[$((choice - 1))]}"
    read -p "您确定要删除代理 '${details[$((choice - 1))]}' 吗? (y/n): " confirm
    if [ "$confirm" != "y" ]; then log_info "操作已取消。"; return; fi
    backup_config "$XRAY_CONFIG"
    find_and_release_ip_for_inbound_tag "$tag_to_delete"
    log_info "正在删除入站: ${tag_to_delete} ..."
    local new_config
    new_config=$(jq --arg t "$tag_to_delete" 'del(.inbounds[] | select(.tag == $t)) | del(.routing.rules[] | select(.inboundTag[0] == $t))' "$XRAY_CONFIG")
    echo "$new_config" > "$XRAY_CONFIG"
    log_info "代理 '${tag_to_delete}' 及其关联路由规则已删除。"
    restart_xray
}

batch_delete_proxies_by_user() {
    echo -e "${BLUE}=== 按用户名批量删除代理 ===${NC}"
    log_warn "此功能仅适用于SOCKS5代理。"
    if [ ! -f "$XRAY_CONFIG" ]; then log_error "Xray配置文件不存在。"; return; fi
    read -p "请输入要匹配的用户名: " pattern
    if [ -z "$pattern" ]; then log_error "用户名模式不能为空。"; return; fi
    local tags_json
    tags_json=$(jq -c --arg p "$pattern" '[.inbounds[] | select(.protocol == "socks" and (.settings.accounts[].user | contains($p))) | .tag]' "$XRAY_CONFIG")
    local num
    num=$(echo "$tags_json" | jq 'length')
    if [ "$num" -eq 0 ]; then log_warn "没有找到用户匹配 '${pattern}' 的SOCKS5代理。"; return; fi
    echo -e "${YELLOW}以下 ${num} 个代理将被删除 (基于标签):${NC}"; echo "$tags_json" | jq -r '.[]'; echo
    read -p "您确定要全部删除吗? (y/n): " confirm
    if [ "$confirm" != "y" ]; then log_info "操作已取消。"; return; fi
    backup_config "$XRAY_CONFIG"
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

batch_delete_proxies_by_port() {
    echo -e "${BLUE}=== 按端口批量删除代理 ===${NC}"
    if [ ! -f "$XRAY_CONFIG" ]; then log_error "Xray配置文件不存在。"; return; fi
    read -p "请输入要删除的代理所使用的端口号: " port
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then log_error "无效的端口号。"; return; fi
    local tags_json
    tags_json=$(jq -c --argjson p "$port" '[.inbounds[] | select(.port == $p) | .tag]' "$XRAY_CONFIG")
    local num
    num=$(echo "$tags_json" | jq 'length')
    if [ "$num" -eq 0 ]; then log_warn "没有找到在端口 ${port} 上运行的代理。"; return; fi
    echo -e "${YELLOW}以下 ${num} 个在端口 ${port} 上的代理将被删除:${NC}"
    jq -r --argjson p "$port" '.inbounds[] | select(.port == $p) | " - 协议: \(.protocol), 监听IP: \(.listen), 标签: \(.tag)"' "$XRAY_CONFIG"
    echo
    read -p "您确定要全部删除吗? (y/n): " confirm
    if [ "$confirm" != "y" ]; then log_info "操作已取消。"; return; fi
    backup_config "$XRAY_CONFIG"
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

# 清除所有代理（删除全部IP的功能）
delete_all_proxies() {
    echo -e "${RED}=== 删除全部代理 (危险操作) ===${NC}"
    log_warn "此操作将删除所有代理配置，包括入站、出站和路由规则！"
    
    if [ ! -f "$XRAY_CONFIG" ]; then
        log_error "Xray配置文件不存在。"
        return
    fi
    
    # 显示当前代理数量
    local inbound_count=$(jq '.inbounds | length' "$XRAY_CONFIG" 2>/dev/null)
    local outbound_count=$(jq '.outbounds | length' "$XRAY_CONFIG" 2>/dev/null)
    local custom_outbound_count=$(jq '[.outbounds[] | select(.protocol == "socks")] | length' "$XRAY_CONFIG" 2>/dev/null)
    
    # 确保变量不为空
    inbound_count=${inbound_count:-0}
    outbound_count=${outbound_count:-0}
    custom_outbound_count=${custom_outbound_count:-0}
    
    echo -e "${YELLOW}当前配置统计:${NC}"
    echo "  - 入站代理: $inbound_count 个"
    echo "  - 自定义出站: $custom_outbound_count 个"
    echo "  - 总出站: $outbound_count 个"
    echo
    
    if [ "$inbound_count" -eq 0 ] && [ "$custom_outbound_count" -eq 0 ]; then
        log_warn "当前没有任何代理配置需要删除。"
        return
    fi
    
    echo -e "${RED}警告: 此操作不可恢复！${NC}"
    echo "以下操作将被执行："
    echo "1. 删除所有入站代理配置"
    echo "2. 删除所有自定义出站配置（保留 direct 和 blocked）"
    echo "3. 清除所有相关路由规则"
    echo "4. 清空独享IP列表"
    echo "5. 自动备份当前配置"
    echo
    
    read -p "请输入 'DELETE ALL' 确认删除所有代理: " confirm
    if [ "$confirm" != "DELETE ALL" ]; then
        log_info "操作已取消。"
        return
    fi
    
    # 二次确认
    read -p "您真的确定要删除所有代理吗？这个操作无法撤销！(y/N): " final_confirm
    if [ "$final_confirm" != "y" ] && [ "$final_confirm" != "Y" ]; then
        log_info "操作已取消。"
        return
    fi
    
    log_info "开始执行删除操作..."
    
    # 备份当前配置
    backup_config "$XRAY_CONFIG"
    
    # 清空独享IP列表
    if [ -f "$EXCLUSIVE_IP_LIST_FILE" ]; then
        > "$EXCLUSIVE_IP_LIST_FILE"
        log_info "已清空独享IP列表。"
    fi
    
    # 重置配置为基础状态
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
    
    log_info "所有代理配置已删除！"
    log_info "配置已重置为基础状态。"
    
    # 重启服务
    restart_xray
    
    echo -e "${GREEN}删除操作完成！${NC}"
    echo "如需恢复，请使用备份文件: $BACKUP_DIR"
}

# 导出和显示配置
export_all_links() {
    echo -e "${BLUE}=== 导出所有代理链接 ===${NC}"
    if [ ! -f "$XRAY_CONFIG" ]; then log_error "Xray配置文件不存在。"; return; fi
    local out="/tmp/all_proxy_links_$(date +%Y%m%d_%H%M%S).txt"
    echo "# 全部代理链接导出 - $(date)" > "$out"
    echo "" >> "$out"
    echo -e "${YELLOW}Shadowsocks链接:${NC}"
    echo "# Shadowsocks链接" >> "$out"
    jq -c '.inbounds[] | select(.protocol == "shadowsocks")' "$XRAY_CONFIG" 2>/dev/null | while read -r l; do
        if [ -n "$l" ]; then
            local li p m pw
            li=$(echo "$l" | jq -r .listen); p=$(echo "$l" | jq -r .port); m=$(echo "$l" | jq -r .settings.method); pw=$(echo "$l" | jq -r .settings.password)
            local sl="ss://$(echo -n "$m:$pw" | base64)@$li:$p"
            echo "$sl"; echo "$sl" >> "$out"
        fi
    done
    echo
    echo -e "${YELLOW}SOCKS5链接:${NC}"
    echo "" >> "$out"; echo "# SOCKS5链接" >> "$out"
    jq -c '.inbounds[] | select(.protocol == "socks")' "$XRAY_CONFIG" 2>/dev/null | while read -r l; do
        if [ -n "$l" ]; then
            local li p u pw
            li=$(echo "$l" | jq -r .listen); p=$(echo "$l" | jq -r .port); u=$(echo "$l" | jq -r .settings.accounts[0].user); pw=$(echo "$l" | jq -r .settings.accounts[0].pass)
            local sl="socks5://$u:$pw@$li:$p"
            echo "$sl"; echo "$sl" >> "$out"
        fi
    done
    echo
    log_info "所有链接已导出到: $out"
}

show_3proxy_config() {
    echo -e "${BLUE}=== 3proxy配置内容 ===${NC}"
    if [ -f "$PROXY_CONFIG" ]; then
        cat "$PROXY_CONFIG"
    else
        log_error "3proxy配置文件不存在。"
    fi
}

# 显示统计信息
show_stats() {
    if [ ! -f "$XRAY_CONFIG" ]; then
        echo -e "${BLUE}=== 配置统计 ===${NC}"
        echo "配置文件不存在"
        return
    fi
    
    # 安全地获取统计信息，处理空值
    local inbound_count=$(jq '.inbounds | length' "$XRAY_CONFIG" 2>/dev/null)
    local ss_count=$(jq '[.inbounds[] | select(.protocol == "shadowsocks")] | length' "$XRAY_CONFIG" 2>/dev/null)
    local socks_count=$(jq '[.inbounds[] | select(.protocol == "socks")] | length' "$XRAY_CONFIG" 2>/dev/null)
    local outbound_count=$(jq '[.outbounds[] | select(.protocol == "socks")] | length' "$XRAY_CONFIG" 2>/dev/null)
    
    # 确保变量不为空
    inbound_count=${inbound_count:-0}
    ss_count=${ss_count:-0}
    socks_count=${socks_count:-0}
    outbound_count=${outbound_count:-0}
    
    echo -e "${BLUE}=== 配置统计 ===${NC}"
    echo "入站代理总数: $inbound_count"
    echo "  - Shadowsocks: $ss_count"
    echo "  - SOCKS5: $socks_count"
    echo "自定义出站: $outbound_count"
    
    # 显示独享IP数量
    local exclusive_count=0
    if [ -f "$EXCLUSIVE_IP_LIST_FILE" ]; then
        exclusive_count=$(wc -l < "$EXCLUSIVE_IP_LIST_FILE" 2>/dev/null || echo "0")
        exclusive_count=${exclusive_count:-0}
    fi
    echo "独享IP数量: $exclusive_count"
}

# 自动修复和诊断
auto_fix_and_diagnose() {
    echo -e "${BLUE}=== 自动修复和诊断 ===${NC}"
    
    log_info "开始自动修复和诊断..."
    
    # 检查配置文件是否存在
    if [ ! -f "$XRAY_CONFIG" ]; then
        log_warn "配置文件不存在，创建基础配置..."
        create_base_xray_config
    fi
    
    # 修复重复标签
    if ! fix_duplicate_tags; then
        log_error "修复重复标签失败"
        return 1
    fi
    
    # 验证配置
    if ! validate_config; then
        log_error "配置验证失败"
        return 1
    fi
    
    # 测试配置
    if ! test_config; then
        log_error "配置测试失败"
        return 1
    fi
    
    # 检查服务状态
    if systemctl is-active --quiet xray; then
        log_info "Xray服务正在运行"
    else
        log_warn "Xray服务未运行，尝试启动..."
        if ! restart_xray; then
            log_error "Xray服务启动失败"
            echo "请检查日志: sudo journalctl -u xray -e --no-pager"
            return 1
        fi
    fi
    
    log_info "自动修复和诊断完成！"
    echo
    show_stats
    return 0
}

# 安装和检查依赖
install_xray() {
    log_info "未找到Xray，开始安装..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)"
    log_info "Xray安装完成。"
}

check_deps() {
    local m=()
    for c in jq openssl; do
        if ! command -v "$c" > /dev/null 2>&1; then
            m+=("$c")
        fi
    done
    if [ ${#m[@]} -gt 0 ]; then
        log_error "缺少依赖项: ${m[*]}"
        log_info "请尝试使用以下命令安装: apt update && apt install -y ${m[*]}"
        exit 1
    fi
    if ! command -v xray > /dev/null 2>&1; then
        install_xray
    fi
}

# 主菜单
main_menu() {
    while true; do
        echo
        echo -e "${BLUE}=== Xray代理管理脚本 v6.5 (完整修复版) ===${NC}"
        echo "[1] 添加单个代理 (支持设置IP独享)"
        echo "[2] 批量添加共享代理 (轮询出口)"
        echo "[3] 批量添加独享代理 (一对一出口/强制创建)"
        echo "[4] 列出现有代理和出站"
        echo "[5] 导出所有代理链接"
        echo "[6] 自动修复和诊断 (修复标签冲突、验证配置)"
        echo "[7] 手动修复重复标签"
        echo -e "${RED}--- 删除操作 (自动释放独享IP) ---${NC}"
        echo -e "${RED}[8] 删除单个代理${NC}"
        echo -e "${RED}[9] 按用户名批量删除SOCKS5代理${NC}"
        echo -e "${RED}[10] 按端口批量删除代理${NC}"
        echo -e "${RED}[11] 删除全部代理 (危险操作)${NC}"
        echo "-------------------------------------"
        echo "[12] 查看3proxy配置"
        echo "[13] 查看备份"
        echo "[14] 查看配置统计"
        echo "[15] 查看Xray服务状态和日志"
        echo "[0] 退出"
        echo

        read -p "请输入选项: " choice

        case "$choice" in
            1) add_single_proxy ;;
            2) batch_add_shared_proxies ;;
            3) batch_add_exclusive_proxies ;;
            4) list_proxies ;;
            5) export_all_links ;;
            6) auto_fix_and_diagnose ;;
            7) fix_duplicate_tags ;;
            8) delete_single_proxy ;;
            9) batch_delete_proxies_by_user ;;
            10) batch_delete_proxies_by_port ;;
            11) delete_all_proxies ;;
            12) show_3proxy_config ;;
            13) ls -la "$BACKUP_DIR" ;;
            14) show_stats ;;
            15) 
                echo -e "${BLUE}=== Xray服务状态 ===${NC}"
                systemctl status xray --no-pager || true
                echo
                echo -e "${BLUE}=== 最新日志 ===${NC}"
                journalctl -u xray -e --no-pager -n 20 || true
                ;;
            0) log_info "正在退出"; exit 0 ;;
            *) log_error "无效的选择" ;;
        esac
        echo
        read -p "按回车键继续..."
    done
}

# 主程序
main() {
    if [ $EUID -ne 0 ]; then
        log_error "请使用root权限运行此脚本。"
        exit 1
    fi
    
    echo -e "${GREEN}正在检查依赖和环境...${NC}"
    check_deps
    create_base_xray_config
    touch "$EXCLUSIVE_IP_LIST_FILE"
    
    if [ ! -f "$PROXY_CONFIG" ]; then
        log_error "3proxy配置文件不存在: $PROXY_CONFIG"
        log_info "请确保3proxy已正确配置，或者修改脚本中的PROXY_CONFIG路径"
        exit 1
    fi
    
    echo -e "${GREEN}环境检查完成！${NC}"
    echo
    show_stats
    
    # 自动检查并修复配置问题
    if [ -f "$XRAY_CONFIG" ]; then
        log_info "自动检查配置文件..."
        
        # 检查JSON格式
        if ! jq empty "$XRAY_CONFIG" 2>/dev/null; then
            log_error "配置文件JSON格式错误！将尝试自动修复..."
            if ! auto_fix_and_diagnose; then
                log_error "自动修复失败，请手动检查配置文件。"
                echo "配置文件位置: $XRAY_CONFIG"
                echo "备份目录: $BACKUP_DIR"
                exit 1
            fi
        else
            # 检查重复标签
            local all_tags=($(jq -r '.inbounds[].tag' "$XRAY_CONFIG" 2>/dev/null))
            local duplicate_count=0
            if [ ${#all_tags[@]} -gt 0 ]; then
                duplicate_count=$(printf '%s\n' "${all_tags[@]}" | sort | uniq -d | wc -l)
                duplicate_count=${duplicate_count:-0}
            fi
            
            if [ "$duplicate_count" -gt 0 ]; then
                log_warn "检测到重复标签，建议运行自动修复功能。"
                echo "您可以选择菜单项 [6] 进行自动修复。"
            fi
            
            # 检查服务状态
            if ! systemctl is-active --quiet xray; then
                log_warn "Xray服务未运行，建议检查配置。"
                echo "您可以选择菜单项 [6] 进行自动修复和启动。"
            fi
        fi
    fi
    
    main_menu
}

main "$@"
