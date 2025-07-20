#!/bin/bash

#================================================
# 3x-ui代理管理脚本 v6.2 (基于3x-ui数据库)
# 功能：管理3x-ui代理服务器配置
# 支持：Shadowsocks和SOCKS5协议
# 基于3x-ui数据库操作，完全兼容3x-ui格式
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

# 3x-ui相关路径
readonly X3UI_DB="/etc/x-ui/x-ui.db"
readonly X3UI_SERVICE="x-ui"
readonly BACKUP_DIR="/root/x3ui_backups"

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
        if ! netstat -tuln 2>/dev/null | grep -q ":$port " && ! check_port_in_db "$port"; then
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

# 重启3x-ui和xray服务
restart_services() {
    log_info "正在重启服务..."
    
    # 重启3x-ui服务
    if systemctl is-active --quiet "$X3UI_SERVICE"; then
        sudo systemctl restart "$X3UI_SERVICE"
        log_info "3x-ui服务已重启。"
    else
        log_warn "3x-ui服务未在运行。正在尝试启动..."
        sudo systemctl start "$X3UI_SERVICE"
    fi
    
    sleep 2
    
    # 重启xray服务
    if systemctl is-active --quiet "xray"; then
        sudo systemctl restart "xray"
        log_info "xray服务已重启。"
    elif command -v xray > /dev/null 2>&1; then
        log_warn "xray服务未在运行，但xray程序存在。正在尝试启动..."
        sudo systemctl start "xray" 2>/dev/null || log_warn "无法启动xray服务，可能由3x-ui管理。"
    else
        log_info "xray服务由3x-ui管理，无需单独重启。"
    fi
    
    log_info "服务重启完成。"
}

# 重启3x-ui服务（保持向后兼容）
restart_x3ui() {
    restart_services
}

# 清理错误的数据库记录
clean_broken_records() {
    echo -e "${BLUE}=== 清理错误的数据库记录 ===${NC}"
    log_warn "此操作将删除可能导致3x-ui面板无法打开的错误记录。"
    
    if [ ! -f "$X3UI_DB" ]; then 
        log_error "3x-ui数据库不存在。"
        return
    fi

    read -p "您确定要清理错误的记录吗? (y/n): " confirm
    if [ "$confirm" != "y" ]; then 
        log_info "操作已取消。"
        return
    fi

    backup_database

    log_info "正在查找错误的记录..."
    
    # 查找可能有问题的记录（缺少allocate字段的）
    local broken_records=$(sqlite3 "$X3UI_DB" "SELECT id, protocol, remark FROM inbounds WHERE allocate IS NULL OR allocate = '';")
    
    if [ -n "$broken_records" ]; then
        echo -e "${YELLOW}发现以下可能有问题的记录:${NC}"
        while IFS='|' read -r id protocol remark; do
            echo " - ID: $id, 协议: $protocol, 备注: $remark"
        done <<< "$broken_records"
        
        read -p "是否删除这些记录? (y/n): " delete_confirm
        if [ "$delete_confirm" = "y" ]; then
            sqlite3 "$X3UI_DB" "DELETE FROM inbounds WHERE allocate IS NULL OR allocate = '';"
            log_info "错误记录已删除。"
        fi
    else
        log_info "没有发现明显的错误记录。"
    fi

    # 检查并修复缺少必需字段的记录
    log_info "正在修复缺少字段的记录..."
    
    # 为缺少allocate字段的记录添加默认值
    sqlite3 "$X3UI_DB" "UPDATE inbounds SET allocate = '{\"strategy\":\"always\",\"refresh\":5,\"concurrency\":3}' WHERE (allocate IS NULL OR allocate = '') AND protocol IN ('shadowsocks', 'socks');"
    
    log_info "清理和修复完成。"
    restart_services
}

# 修复数据库中的数据格式问题
fix_database_format() {
    echo -e "${BLUE}=== 修复数据库格式问题 ===${NC}"
    log_warn "此操作将修复可能导致3x-ui面板无法打开的数据格式问题。"
    
    if [ ! -f "$X3UI_DB" ]; then 
        log_error "3x-ui数据库不存在。"
        return
    fi

    read -p "您确定要修复数据库格式吗? (y/n): " confirm
    if [ "$confirm" != "y" ]; then 
        log_info "操作已取消。"
        return
    fi

    backup_database

    log_info "正在修复Shadowsocks配置格式..."
    # 修复Shadowsocks settings，添加缺失的字段
    sqlite3 "$X3UI_DB" << 'EOF'
UPDATE inbounds 
SET settings = json_set(settings, '$.ivCheck', json('false'))
WHERE protocol = 'shadowsocks' 
AND json_extract(settings, '$.ivCheck') IS NULL;
EOF

    log_info "正在修复可能的enable字段问题..."
    # 确保enable字段是正确的数值类型
    sqlite3 "$X3UI_DB" "UPDATE inbounds SET enable = 1 WHERE enable IS NULL OR enable = '';"

    log_info "正在修复可能的tag重复问题..."
    # 检查并修复重复的tag
    local duplicate_tags=$(sqlite3 "$X3UI_DB" "SELECT tag FROM inbounds GROUP BY tag HAVING COUNT(*) > 1;")
    
    if [ -n "$duplicate_tags" ]; then
        while IFS= read -r dup_tag; do
            log_info "修复重复的tag: $dup_tag"
            # 获取所有使用这个tag的记录
            local records=$(sqlite3 "$X3UI_DB" "SELECT id FROM inbounds WHERE tag = '$dup_tag' ORDER BY id;")
            local first=true
            while IFS= read -r record_id; do
                if [ "$first" = true ]; then
                    first=false
                    continue  # 保留第一个记录的tag不变
                fi
                # 为其他记录生成新的唯一tag
                local new_tag="$dup_tag-fix-$record_id-$(date +%s)"
                sqlite3 "$X3UI_DB" "UPDATE inbounds SET tag = '$new_tag' WHERE id = $record_id;"
                log_info "  记录ID $record_id 的tag已更新为: $new_tag"
            done <<< "$records"
        done <<< "$duplicate_tags"
    fi

    log_info "数据库格式修复完成。"
    restart_services
}

# 检查依赖
check_dependencies() {
    local missing=()
    for cmd in sqlite3 openssl; do
        if ! command -v "$cmd" > /dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "缺少依赖项: ${missing[*]}"
        log_info "请使用以下命令安装: apt update && apt install -y ${missing[*]}"
        exit 1
    fi

    # 检查3x-ui是否安装
    if [ ! -f "$X3UI_DB" ]; then
        log_error "3x-ui数据库不存在，请先安装3x-ui"
        log_info "安装命令: bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)"
        exit 1
    fi
}

#================================================
# 数据库操作函数
#================================================

# 检查tag是否在数据库中已存在
check_tag_in_db() {
    local tag="$1"
    local count=$(sqlite3 "$X3UI_DB" "SELECT COUNT(*) FROM inbounds WHERE tag = '$tag';")
    [ "$count" -gt 0 ]
}

# 生成唯一的tag
generate_unique_tag() {
    local protocol="$1"
    local listen_ip="$2"
    local port="$3"
    
    while true; do
        local timestamp=$(date +%s%N | cut -b1-13)
        local tag="inbound-$protocol-$listen_ip-$port-$timestamp"
        if ! check_tag_in_db "$tag"; then
            echo "$tag"
            return
        fi
        sleep 0.001  # 短暂延迟避免时间戳冲突
    done
}

# 检查IP和端口组合是否已存在
check_ip_port_exists() {
    local listen_ip="$1"
    local port="$2"
    local count=$(sqlite3 "$X3UI_DB" "SELECT COUNT(*) FROM inbounds WHERE listen = '$listen_ip' AND port = $port;")
    [ "$count" -gt 0 ]
}

# 检查端口是否在数据库中已存在
check_port_in_db() {
    local port="$1"
    local count=$(sqlite3 "$X3UI_DB" "SELECT COUNT(*) FROM inbounds WHERE port = $port;")
    [ "$count" -gt 0 ]
}

# 获取下一个可用端口
get_next_port() {
    while true; do
        local new_port=$(generate_port)
        if ! check_port_in_db "$new_port"; then
            echo "$new_port"
            return
        fi
    done
}

# 备份数据库
backup_database() {
    local backup_name="x-ui_$(date +%Y%m%d_%H%M%S).db"
    cp "$X3UI_DB" "$BACKUP_DIR/$backup_name"
    log_info "数据库已备份: $backup_name"
}

# 转义JSON字符串
escape_json() {
    echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# 添加Shadowsocks入站到数据库
add_shadowsocks_to_db() {
    local listen_ip="$1"
    local port="$2"
    local password="$3"
    local method="$4"
    local remark="$5"
    
    # 转义特殊字符
    local escaped_password=$(escape_json "$password")
    local escaped_remark=$(escape_json "$remark")
    
    # 生成客户端email和subId
    local email=$(openssl rand -hex 4)
    local subId=$(openssl rand -hex 8)
    
    # 构建与3x-ui完全兼容的settings JSON（基于实际数据格式）
    local settings="{
  \"method\": \"$method\",
  \"password\": \"$escaped_password\",
  \"network\": \"tcp,udp\",
  \"clients\": [
    {
      \"method\": \"\",
      \"password\": \"$escaped_password\",
      \"email\": \"$email\",
      \"limitIp\": 0,
      \"totalGB\": 0,
      \"expiryTime\": 0,
      \"enable\": true,
      \"tgId\": \"\",
      \"subId\": \"$subId\",
      \"comment\": \"\",
      \"reset\": 0
    }
  ],
  \"ivCheck\": false
}"
    
    # 构建stream_settings JSON (基于实际3x-ui格式)
    local stream_settings="{
  \"network\": \"tcp\",
  \"security\": \"none\",
  \"externalProxy\": [],
  \"tcpSettings\": {
    \"acceptProxyProtocol\": false,
    \"header\": {
      \"type\": \"none\"
    }
  }
}"
    
    # 构建sniffing JSON (基于实际3x-ui格式)
    local sniffing="{
  \"enabled\": false,
  \"destOverride\": [
    \"http\",
    \"tls\",
    \"quic\",
    \"fakedns\"
  ],
  \"metadataOnly\": false,
  \"routeOnly\": false
}"
    
    # 构建allocate JSON (基于实际3x-ui格式)
    local allocate="{
  \"strategy\": \"always\",
  \"refresh\": 5,
  \"concurrency\": 3
}"
    
    # 生成唯一的tag
    local unique_tag=$(generate_unique_tag "ss" "$listen_ip" "$port")
    
    # 检查IP和端口组合是否已存在
    if check_ip_port_exists "$listen_ip" "$port"; then
        log_error "代理已存在: $listen_ip:$port，跳过创建。"
        return 1
    fi
    
    # 插入到数据库 (包含所有必需字段)
    sqlite3 "$X3UI_DB" "INSERT INTO inbounds (user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing, allocate) VALUES (1, 0, 0, 0, '$escaped_remark', 1, 0, '$listen_ip', $port, 'shadowsocks', '$settings', '$stream_settings', '$unique_tag', '$sniffing', '$allocate');"
    
    log_info "Shadowsocks已添加: $listen_ip:$port (方法: $method)"
}

# 添加SOCKS5入站到数据库
add_socks5_to_db() {
    local listen_ip="$1"
    local port="$2"
    local username="$3"
    local password="$4"
    local remark="$5"
    local enable_udp="${6:-true}"  # 默认启用UDP
    
    # 转义特殊字符
    local escaped_username=$(escape_json "$username")
    local escaped_password=$(escape_json "$password")
    local escaped_remark=$(escape_json "$remark")
    
    # 构建与3x-ui完全兼容的settings JSON（UDP可配置）
    local settings="{
  \"auth\": \"password\",
  \"accounts\": [
    {
      \"user\": \"$escaped_username\",
      \"pass\": \"$escaped_password\"
    }
  ],
  \"udp\": $enable_udp,
  \"ip\": \"127.0.0.1\"
}"
    
    # stream_settings为空字符串（基于实际数据）
    local stream_settings=""
    
    # 构建sniffing JSON (基于实际3x-ui格式)
    local sniffing="{
  \"enabled\": false,
  \"destOverride\": [
    \"http\",
    \"tls\",
    \"quic\",
    \"fakedns\"
  ],
  \"metadataOnly\": false,
  \"routeOnly\": false
}"
    
    # 构建allocate JSON (基于实际3x-ui格式)
    local allocate="{
  \"strategy\": \"always\",
  \"refresh\": 5,
  \"concurrency\": 3
}"
    
    # 生成唯一的tag
    local unique_tag=$(generate_unique_tag "socks" "$listen_ip" "$port")
    
    # 检查IP和端口组合是否已存在
    if check_ip_port_exists "$listen_ip" "$port"; then
        log_error "代理已存在: $listen_ip:$port，跳过创建。"
        return 1
    fi
    
    # 插入到数据库 (包含所有必需字段)
    sqlite3 "$X3UI_DB" "INSERT INTO inbounds (user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing, allocate) VALUES (1, 0, 0, 0, '$escaped_remark', 1, 0, '$listen_ip', $port, 'socks', '$settings', '$stream_settings', '$unique_tag', '$sniffing', '$allocate');"
    
    log_info "SOCKS5已添加: $listen_ip:$port (用户: $username, UDP: $enable_udp)"
}

#================================================
# 用户界面函数
#================================================

# 获取服务器本地IP列表
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

#================================================
# 代理配置管理函数
#================================================

# 添加单个代理
add_single_proxy() {
    echo -e "${BLUE}=== 添加单个代理 ===${NC}"
    
    if ! show_local_ip_menu; then 
        return
    fi

    backup_database

    echo -e "${BLUE}选择代理类型:${NC}"
    echo "[1] Shadowsocks"
    echo "[2] SOCKS5"
    echo "[0] 返回"
    read -p "请输入选项: " proxy_type

    local port=$(get_next_port)
    local remark=""

    case "$proxy_type" in
        1) 
            echo -e "${BLUE}=== Shadowsocks配置 ===${NC}"
            read -p "请输入端口 (留空使用随机端口 $port): " custom_port
            if [ -n "$custom_port" ] && [[ "$custom_port" =~ ^[0-9]+$ ]]; then
                if check_ip_port_exists "$selected_listen_ip" "$custom_port"; then
                    log_error "代理已存在: $selected_listen_ip:$custom_port"
                    return
                fi
                port="$custom_port"
            fi
            
            read -p "请输入密码 (留空随机生成): " custom_password
            local password="${custom_password:-$(generate_password)}"
            
            echo "选择加密方法:"
            echo "[1] aes-256-gcm (推荐)"
            echo "[2] chacha20-poly1305"
            echo "[3] aes-128-gcm"
            read -p "请选择: " method_choice
            
            local method="aes-256-gcm"
            case "$method_choice" in
                2) method="chacha20-poly1305" ;;
                3) method="aes-128-gcm" ;;
            esac
            
            read -p "请输入备注 (留空自动生成): " custom_remark
            remark="${custom_remark:-SS-$selected_listen_ip-$port}"
            
            add_shadowsocks_to_db "$selected_listen_ip" "$port" "$password" "$method" "$remark"
            
            echo -e "${GREEN}Shadowsocks配置信息:${NC}"
            echo "监听地址: $selected_listen_ip:$port"
            echo "密码: $password"
            echo "加密方法: $method"
            echo "备注: $remark"
            ;;
        2) 
            echo -e "${BLUE}=== SOCKS5配置 ===${NC}"
            read -p "请输入端口 (留空使用随机端口 $port): " custom_port
            if [ -n "$custom_port" ] && [[ "$custom_port" =~ ^[0-9]+$ ]]; then
                if check_ip_port_exists "$selected_listen_ip" "$custom_port"; then
                    log_error "代理已存在: $selected_listen_ip:$custom_port"
                    return
                fi
                port="$custom_port"
            fi
            
            read -p "请输入用户名 (留空随机生成): " custom_username
            local username="${custom_username:-$(generate_user_id)}"
            
            read -p "请输入密码 (留空随机生成): " custom_password
            local password="${custom_password:-$(generate_password)}"
            
            echo "是否启用UDP支持:"
            echo "[1] 启用UDP (推荐)"
            echo "[2] 禁用UDP"
            read -p "请选择: " udp_choice
            
            local enable_udp=true
            if [ "$udp_choice" = "2" ]; then
                enable_udp=false
            fi
            
            read -p "请输入备注 (留空自动生成): " custom_remark
            remark="${custom_remark:-SOCKS5-$selected_listen_ip-$port}"
            
            add_socks5_to_db "$selected_listen_ip" "$port" "$username" "$password" "$remark" "$enable_udp"
            
            echo -e "${GREEN}SOCKS5配置信息:${NC}"
            echo "监听地址: $selected_listen_ip:$port"
            echo "用户名: $username"
            echo "密码: $password"
            echo "UDP支持: $enable_udp"
            echo "备注: $remark"
            ;;
        0) return ;;
        *) log_error "无效的选择"; return ;;
    esac

    restart_x3ui
}

# 批量添加共享代理
batch_add_shared_proxies() {
    echo -e "${BLUE}=== 批量添加共享代理 ===${NC}"
    log_info "批量创建多个代理，可以使用统一配置或随机配置。"
    
    read -p "代理类型 (1-SS, 2-SOCKS5): " proxy_type
    if [ "$proxy_type" != "1" ] && [ "$proxy_type" != "2" ]; then
        log_error "无效的代理类型。"
        return
    fi

    read -p "请输入生成数量: " count
    if ! [[ "$count" =~ ^[0-9]+$ ]] || [ "$count" -lt 1 ]; then
        log_error "无效的数量。"
        return
    fi

    read -p "请输入统一监听端口 (留空则每个代理使用不同随机端口): " unified_port
    local unified_user=""
    local unified_pass=""
    local enable_udp=true  # 默认开启UDP
    
    if [ "$proxy_type" = "2" ]; then
        read -p "请输入统一用户名 (留空则每个代理使用不同用户名): " unified_user
        echo "是否为所有SOCKS5代理启用UDP支持:"
        echo "[1] 启用UDP (推荐)"
        echo "[2] 禁用UDP"
        read -p "请选择: " udp_choice
        if [ "$udp_choice" = "2" ]; then
            enable_udp=false
        fi
    fi
    read -p "请输入统一密码 (留空则每个代理使用不同密码): " unified_pass

    if ! show_local_ip_menu; then 
        return
    fi

    log_info "开始批量生成 $count 个代理..."
    backup_database

    for i in $(seq 1 $count); do
        local port
        if [ -n "$unified_port" ]; then
            port="$unified_port"
        else
            port=$(get_next_port)
        fi

        # 检查IP和端口组合是否已存在
        if check_ip_port_exists "$selected_listen_ip" "$port"; then
            log_warn "代理已存在: $selected_listen_ip:$port，跳过第 $i 个代理。"
            continue
        fi

        if [ "$proxy_type" = "1" ]; then
            # Shadowsocks
            local password="${unified_pass:-$(generate_password)}"
            local remark="SS-Batch-$i-$selected_listen_ip-$port"
            if add_shadowsocks_to_db "$selected_listen_ip" "$port" "$password" "aes-256-gcm" "$remark"; then
                log_info "第 $i 个Shadowsocks代理创建成功。"
            fi
        elif [ "$proxy_type" = "2" ]; then
            # SOCKS5
            local username="${unified_user:-user_$i}"
            local password="${unified_pass:-$(generate_password)}"
            local remark="SOCKS5-Batch-$i-$selected_listen_ip-$port"
            if add_socks5_to_db "$selected_listen_ip" "$port" "$username" "$password" "$remark" "$enable_udp"; then
                log_info "第 $i 个SOCKS5代理创建成功。"
            fi
        fi

        sleep 0.1
    done

    log_info "批量生成完成！"
    restart_x3ui
}

# 批量添加独享代理（按IP分布）
batch_add_exclusive_proxies() {
    echo -e "${BLUE}=== 批量添加独享代理 (按IP分布创建) ===${NC}"
    
    local local_ips=($(get_server_local_ips))
    local num_ips=${#local_ips[@]}
    
    if [ "$num_ips" -eq 0 ]; then
        log_error "未找到可用的本地IP地址。"
        return
    fi

    log_info "发现 ${num_ips} 个可用的本地IP地址。"
    echo

    echo "[1] 为所有 ${num_ips} 个IP创建代理 (每个IP一个代理)"
    echo "[2] 从 ${num_ips} 个IP中选择范围创建"
    echo "[0] 返回"
    read -p "请选择操作模式: " mode_choice

    local ips_to_process=()
    case "$mode_choice" in
        1)
            ips_to_process=("${local_ips[@]}")
            ;;
        2)
            echo "--- 可用IP列表 ---"
            for i in "${!local_ips[@]}"; do 
                echo "$((i+1))) ${local_ips[i]}"
            done
            read -p "请输入要创建的IP序号范围 (例如: 1-3): " range_input
            if [[ ! "$range_input" =~ ^[0-9]+-[0-9]+$ ]]; then 
                log_error "范围格式错误。"
                return
            fi
            local start=$(echo "$range_input" | cut -d- -f1)
            local end=$(echo "$range_input" | cut -d- -f2)
            if [ "$start" -gt "$end" ] || [ "$start" -lt 1 ] || [ "$end" -gt "$num_ips" ]; then 
                log_error "范围无效。请输入 1 到 ${num_ips} 之间的有效范围。"
                return
            fi
            for (( i=start-1; i<end; i++ )); do
                ips_to_process+=("${local_ips[i]}")
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
    
    log_info "此模式将为选中的 ${num_to_process} 个IP创建独享代理。"
    log_info "每个代理将监听在对应的IP地址上。"

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
    local enable_udp=true  # 默认开启UDP
    if [ "$proxy_type" = "2" ]; then 
        read -p "请输入统一用户名 (留空则每个代理使用不同用户名): " unified_user
        echo "是否为所有SOCKS5代理启用UDP支持:"
        echo "[1] 启用UDP (推荐)"
        echo "[2] 禁用UDP"
        read -p "请选择: " udp_choice
        if [ "$udp_choice" = "2" ]; then
            enable_udp=false
        fi
    fi
    read -p "请输入统一密码 (留空则每个代理使用不同密码): " unified_pass

    echo -e "${YELLOW}即将为以下 ${num_to_process} 个IP地址创建独享代理:${NC}"
    printf " %s\n" "${ips_to_process[@]}"
    echo "所有代理将监听在端口: ${unified_port}"
    read -p "您确定要继续吗? (y/n): " confirm
    if [ "$confirm" != "y" ]; then 
        log_info "操作已取消。"
        return
    fi
    
    log_info "开始为 ${num_to_process} 个IP创建独享代理..."
    backup_database
    
    for i in "${!ips_to_process[@]}"; do
        local listen_ip="${ips_to_process[i]}"
        local port="$unified_port"

        if [ "$proxy_type" = "1" ]; then
            local password
            if [ -n "$unified_pass" ]; then 
                password="$unified_pass"
            else 
                password=$(generate_password)
            fi
            local remark="SS-Exclusive-$((i+1))-$listen_ip-$port"
            add_shadowsocks_to_db "$listen_ip" "$port" "$password" "aes-256-gcm" "$remark"
        elif [ "$proxy_type" = "2" ]; then
            local username password
            if [ -n "$unified_user" ]; then 
                username="$unified_user"
            else 
                username="user_exclusive_$((i+1))"
            fi
            if [ -n "$unified_pass" ]; then 
                password="$unified_pass"
            else 
                password=$(generate_password)
            fi
            local remark="SOCKS5-Exclusive-$((i+1))-$listen_ip-$port"
            add_socks5_to_db "$listen_ip" "$port" "$username" "$password" "$remark"
        fi

        log_info "IP ${listen_ip} 已创建独享代理。"
        sleep 0.1
    done

    log_info "批量独享代理创建完成！"
    restart_x3ui
}

#================================================
# 代理删除操作函数
#================================================

# 删除单个代理
delete_single_proxy() {
    echo -e "${BLUE}=== 删除单个代理 ===${NC}"
    
    if [ ! -f "$X3UI_DB" ]; then 
        log_error "3x-ui数据库不存在。"
        return
    fi

    log_info "正在加载入站代理列表..."
    
    # 获取所有入站代理
    local proxies=$(sqlite3 "$X3UI_DB" "SELECT id, protocol, listen, port, remark FROM inbounds WHERE protocol IN ('shadowsocks', 'socks') ORDER BY id;")
    
    if [ -z "$proxies" ]; then 
        log_warn "没有找到任何可以删除的入站代理。"
        return
    fi

    echo -e "${YELLOW}请选择要删除的代理:${NC}"
    local i=1
    local ids=()
    local details=()
    
    while IFS='|' read -r id protocol listen port remark; do
        echo "[$i] $protocol | $listen:$port | $remark"
        ids+=("$id")
        details+=("$protocol | $listen:$port | $remark")
        ((i++))
    done <<< "$proxies"
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

    local id_to_delete="${ids[$((choice - 1))]}"
    local detail_to_delete="${details[$((choice - 1))]}"
    read -p "您确定要删除代理 '${detail_to_delete}' 吗? (y/n): " confirm
    if [ "$confirm" != "y" ]; then 
        log_info "操作已取消。"
        return
    fi

    backup_database
    
    # 删除代理
    sqlite3 "$X3UI_DB" "DELETE FROM inbounds WHERE id = $id_to_delete;"

    log_info "代理已删除。"
    restart_x3ui
}

# 按用户名批量删除代理
batch_delete_proxies_by_user() {
    echo -e "${BLUE}=== 按用户名批量删除代理 ===${NC}"
    log_warn "此功能仅适用于SOCKS5代理。"
    
    if [ ! -f "$X3UI_DB" ]; then 
        log_error "3x-ui数据库不存在。"
        return
    fi

    read -p "请输入要匹配的用户名: " pattern
    if [ -z "$pattern" ]; then 
        log_error "用户名模式不能为空。"
        return
    fi

    # 查找匹配的SOCKS5代理
    local matching_proxies=$(sqlite3 "$X3UI_DB" "SELECT id, remark FROM inbounds WHERE protocol = 'socks' AND settings LIKE '%\"user\":\"$pattern%';")

    if [ -z "$matching_proxies" ]; then 
        log_warn "没有找到用户匹配 '${pattern}' 的SOCKS5代理。"
        return
    fi

    local num=$(echo "$matching_proxies" | wc -l)
    echo -e "${YELLOW}以下 ${num} 个代理将被删除:${NC}"
    while IFS='|' read -r id remark; do
        echo " - ID: $id, 备注: $remark"
    done <<< "$matching_proxies"
    echo

    read -p "您确定要全部删除吗? (y/n): " confirm
    if [ "$confirm" != "y" ]; then 
        log_info "操作已取消。"
        return
    fi

    backup_database

    log_info "正在批量删除 ${num} 个代理..."
    sqlite3 "$X3UI_DB" "DELETE FROM inbounds WHERE protocol = 'socks' AND settings LIKE '%\"user\":\"$pattern%';"

    log_info "批量删除完成。"
    restart_x3ui
}

# 按端口批量删除代理
batch_delete_proxies_by_port() {
    echo -e "${BLUE}=== 按端口批量删除代理 ===${NC}"
    
    if [ ! -f "$X3UI_DB" ]; then 
        log_error "3x-ui数据库不存在。"
        return
    fi

    read -p "请输入要删除的代理所使用的端口号: " port
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then 
        log_error "无效的端口号。"
        return
    fi

    # 查找使用该端口的代理
    local matching_proxies=$(sqlite3 "$X3UI_DB" "SELECT id, protocol, listen, remark FROM inbounds WHERE port = $port AND protocol IN ('shadowsocks', 'socks');")

    if [ -z "$matching_proxies" ]; then 
        log_warn "没有找到在端口 ${port} 上运行的代理。"
        return
    fi

    local num=$(echo "$matching_proxies" | wc -l)
    echo -e "${YELLOW}以下 ${num} 个在端口 ${port} 上的代理将被删除:${NC}"
    while IFS='|' read -r id protocol listen remark; do
        echo " - 协议: $protocol, 监听IP: $listen, 备注: $remark"
    done <<< "$matching_proxies"
    echo

    read -p "您确定要全部删除吗? (y/n): " confirm
    if [ "$confirm" != "y" ]; then 
        log_info "操作已取消。"
        return
    fi

    backup_database

    log_info "正在批量删除 ${num} 个代理..."
    sqlite3 "$X3UI_DB" "DELETE FROM inbounds WHERE port = $port AND protocol IN ('shadowsocks', 'socks');"

    log_info "批量删除完成。"
    restart_x3ui
}

# 清空所有代理
clear_all_proxies() {
    echo -e "${BLUE}=== 清空所有代理 ===${NC}"
    log_warn "此操作将删除所有Shadowsocks和SOCKS5代理！"
    
    if [ ! -f "$X3UI_DB" ]; then 
        log_error "3x-ui数据库不存在。"
        return
    fi

    local total=$(sqlite3 "$X3UI_DB" "SELECT COUNT(*) FROM inbounds WHERE protocol IN ('shadowsocks', 'socks');" 2>/dev/null || echo "0")
    
    if [ "$total" -eq 0 ]; then
        log_warn "没有找到任何代理。"
        return
    fi

    echo -e "${RED}将删除所有 $total 个代理！${NC}"
    read -p "您确定要继续吗？请输入 'YES' 确认: " confirm
    if [ "$confirm" != "YES" ]; then 
        log_info "操作已取消。"
        return
    fi

    backup_database

    log_info "正在清空所有代理..."
    sqlite3 "$X3UI_DB" "DELETE FROM inbounds WHERE protocol IN ('shadowsocks', 'socks');"

    log_info "所有代理已清空。"
    restart_x3ui
}

#================================================
# 信息查看和导出函数
#================================================

# 列出现有代理
list_proxies() {
    echo -e "${BLUE}=== 现有代理列表 ===${NC}"
    
    if [ ! -f "$X3UI_DB" ]; then
        log_error "3x-ui数据库不存在。"
        return
    fi

    echo -e "${YELLOW}Shadowsocks代理:${NC}"
    sqlite3 "$X3UI_DB" "SELECT 'ID: ' || id || ' | 监听: ' || listen || ':' || port || ' | 备注: ' || remark FROM inbounds WHERE protocol = 'shadowsocks' ORDER BY id;" 2>/dev/null || echo "无"
    echo

    echo -e "${YELLOW}SOCKS5代理:${NC}"
    sqlite3 "$X3UI_DB" "SELECT 'ID: ' || id || ' | 监听: ' || listen || ':' || port || ' | 备注: ' || remark FROM inbounds WHERE protocol = 'socks' ORDER BY id;" 2>/dev/null || echo "无"
    echo

    local total=$(sqlite3 "$X3UI_DB" "SELECT COUNT(*) FROM inbounds WHERE protocol IN ('shadowsocks', 'socks');" 2>/dev/null || echo "0")
    echo -e "${GREEN}总计: $total 个代理${NC}"
}

# 显示代理详细信息
show_proxy_details() {
    echo -e "${BLUE}=== 代理详细信息 ===${NC}"
    
    if [ ! -f "$X3UI_DB" ]; then
        log_error "3x-ui数据库不存在。"
        return
    fi

    echo -e "${YELLOW}=== Shadowsocks代理详细信息 ===${NC}"
    sqlite3 "$X3UI_DB" "SELECT id, listen, port, settings, remark FROM inbounds WHERE protocol = 'shadowsocks' ORDER BY id;" | while IFS='|' read -r id listen port settings remark; do
        if [ -n "$settings" ]; then
            local method=$(echo "$settings" | grep -o '"method":"[^"]*"' | cut -d'"' -f4)
            # 从clients数组中提取密码
            local password=$(echo "$settings" | grep -o '"clients":\[{[^}]*"password":"[^"]*"' | grep -o '"password":"[^"]*"' | cut -d'"' -f4)
            
            # 如果clients中没有密码，尝试从根级别获取
            if [ -z "$password" ]; then
                password=$(echo "$settings" | grep -o '"password":"[^"]*"' | cut -d'"' -f4)
            fi
            
            echo "ID: $id | 监听: $listen:$port | 方法: $method | 密码: $password | 备注: $remark"
        fi
    done
    echo

    echo -e "${YELLOW}=== SOCKS5代理详细信息 ===${NC}"
    sqlite3 "$X3UI_DB" "SELECT id, listen, port, settings, remark FROM inbounds WHERE protocol = 'socks' ORDER BY id;" | while IFS='|' read -r id listen port settings remark; do
        if [ -n "$settings" ]; then
            local username=$(echo "$settings" | grep -o '"user":"[^"]*"' | cut -d'"' -f4)
            local password=$(echo "$settings" | grep -o '"pass":"[^"]*"' | cut -d'"' -f4)
            local udp_enabled=$(echo "$settings" | grep -o '"udp":[^,}]*' | cut -d':' -f2 | tr -d ' ')
            
            echo "ID: $id | 监听: $listen:$port | 用户: $username | 密码: $password | UDP: $udp_enabled | 备注: $remark"
        fi
    done
}

# 导出所有代理链接
export_all_links() {
    echo -e "${BLUE}=== 导出所有代理链接 ===${NC}"
    
    if [ ! -f "$X3UI_DB" ]; then 
        log_error "3x-ui数据库不存在。"
        return
    fi

    local output_file="/tmp/all_proxy_links_$(date +%Y%m%d_%H%M%S).txt"
    
    echo "# 全部代理链接导出 - $(date)" > "$output_file"
    echo "" >> "$output_file"

    echo -e "${YELLOW}Shadowsocks链接:${NC}"
    echo "# Shadowsocks链接" >> "$output_file"
    
    sqlite3 "$X3UI_DB" "SELECT listen, port, settings, remark FROM inbounds WHERE protocol = 'shadowsocks';" | while IFS='|' read -r listen port settings remark; do
        if [ -n "$settings" ]; then
            local method=$(echo "$settings" | grep -o '"method":"[^"]*"' | cut -d'"' -f4)
            # 从clients数组中提取密码
            local password=$(echo "$settings" | grep -o '"clients":\[{[^}]*"password":"[^"]*"' | grep -o '"password":"[^"]*"' | cut -d'"' -f4)
            
            # 如果clients中没有密码，尝试从根级别获取
            if [ -z "$password" ]; then
                password=$(echo "$settings" | grep -o '"password":"[^"]*"' | cut -d'"' -f4)
            fi
            
            if [ -n "$method" ] && [ -n "$password" ]; then
                local ss_link="ss://$(echo -n "$method:$password" | base64 -w 0)@$listen:$port#$remark"
                echo "$ss_link"
                echo "$ss_link" >> "$output_file"
            fi
        fi
    done

    echo
    echo -e "${YELLOW}SOCKS5链接:${NC}"
    echo "" >> "$output_file"
    echo "# SOCKS5链接" >> "$output_file"
    
    sqlite3 "$X3UI_DB" "SELECT listen, port, settings, remark FROM inbounds WHERE protocol = 'socks';" | while IFS='|' read -r listen port settings remark; do
        if [ -n "$settings" ]; then
            local username=$(echo "$settings" | grep -o '"user":"[^"]*"' | cut -d'"' -f4)
            local password=$(echo "$settings" | grep -o '"pass":"[^"]*"' | cut -d'"' -f4)
            
            if [ -n "$username" ] && [ -n "$password" ]; then
                local socks_link="socks5://$username:$password@$listen:$port#$remark"
                echo "$socks_link"
                echo "$socks_link" >> "$output_file"
            fi
        fi
    done

    echo
    log_info "所有链接已导出到: $output_file"
}

# 导出配置为JSON格式
export_config_json() {
    echo -e "${BLUE}=== 导出配置为JSON格式 ===${NC}"
    
    if [ ! -f "$X3UI_DB" ]; then 
        log_error "3x-ui数据库不存在。"
        return
    fi

    local output_file="/tmp/proxy_config_$(date +%Y%m%d_%H%M%S).json"
    
    echo "{" > "$output_file"
    echo "  \"export_time\": \"$(date)\"," >> "$output_file"
    echo "  \"shadowsocks\": [" >> "$output_file"
    
    local first_ss=true
    sqlite3 "$X3UI_DB" "SELECT listen, port, settings, remark FROM inbounds WHERE protocol = 'shadowsocks';" | while IFS='|' read -r listen port settings remark; do
        if [ -n "$settings" ]; then
            local method=$(echo "$settings" | grep -o '"method":"[^"]*"' | cut -d'"' -f4)
            # 从clients数组中提取密码
            local password=$(echo "$settings" | grep -o '"clients":\[{[^}]*"password":"[^"]*"' | grep -o '"password":"[^"]*"' | cut -d'"' -f4)
            
            # 如果clients中没有密码，尝试从根级别获取
            if [ -z "$password" ]; then
                password=$(echo "$settings" | grep -o '"password":"[^"]*"' | cut -d'"' -f4)
            fi
            
            if [ -n "$method" ] && [ -n "$password" ]; then
                if [ "$first_ss" = false ]; then
                    echo "," >> "$output_file"
                fi
                echo "    {" >> "$output_file"
                echo "      \"listen\": \"$listen\"," >> "$output_file"
                echo "      \"port\": $port," >> "$output_file"
                echo "      \"method\": \"$method\"," >> "$output_file"
                echo "      \"password\": \"$password\"," >> "$output_file"
                echo "      \"remark\": \"$remark\"" >> "$output_file"
                echo -n "    }" >> "$output_file"
                first_ss=false
            fi
        fi
    done
    
    echo "" >> "$output_file"
    echo "  ]," >> "$output_file"
    echo "  \"socks5\": [" >> "$output_file"
    
    local first_socks=true
    sqlite3 "$X3UI_DB" "SELECT listen, port, settings, remark FROM inbounds WHERE protocol = 'socks';" | while IFS='|' read -r listen port settings remark; do
        if [ -n "$settings" ]; then
            local username=$(echo "$settings" | grep -o '"user":"[^"]*"' | cut -d'"' -f4)
            local password=$(echo "$settings" | grep -o '"pass":"[^"]*"' | cut -d'"' -f4)
            
            if [ -n "$username" ] && [ -n "$password" ]; then
                if [ "$first_socks" = false ]; then
                    echo "," >> "$output_file"
                fi
                echo "    {" >> "$output_file"
                echo "      \"listen\": \"$listen\"," >> "$output_file"
                echo "      \"port\": $port," >> "$output_file"
                echo "      \"username\": \"$username\"," >> "$output_file"
                echo "      \"password\": \"$password\"," >> "$output_file"
                echo "      \"remark\": \"$remark\"" >> "$output_file"
                echo -n "    }" >> "$output_file"
                first_socks=false
            fi
        fi
    done
    
    echo "" >> "$output_file"
    echo "  ]" >> "$output_file"
    echo "}" >> "$output_file"

    log_info "配置已导出为JSON格式: $output_file"
}

# 统计信息
show_statistics() {
    echo -e "${BLUE}=== 代理统计信息 ===${NC}"
    
    if [ ! -f "$X3UI_DB" ]; then
        log_error "3x-ui数据库不存在。"
        return
    fi

    local ss_count=$(sqlite3 "$X3UI_DB" "SELECT COUNT(*) FROM inbounds WHERE protocol = 'shadowsocks';" 2>/dev/null || echo "0")
    local socks_count=$(sqlite3 "$X3UI_DB" "SELECT COUNT(*) FROM inbounds WHERE protocol = 'socks';" 2>/dev/null || echo "0")
    local total_count=$((ss_count + socks_count))
    
    echo "Shadowsocks代理数量: $ss_count"
    echo "SOCKS5代理数量: $socks_count"
    echo "总代理数量: $total_count"
    echo
    
    # 按监听IP统计
    echo -e "${YELLOW}按监听IP统计:${NC}"
    sqlite3 "$X3UI_DB" "SELECT listen, COUNT(*) FROM inbounds WHERE protocol IN ('shadowsocks', 'socks') GROUP BY listen ORDER BY COUNT(*) DESC;" | while IFS='|' read -r ip count; do
        echo "  $ip: $count 个代理"
    done
    echo
    
    # 按端口范围统计
    echo -e "${YELLOW}端口使用情况:${NC}"
    local min_port=$(sqlite3 "$X3UI_DB" "SELECT MIN(port) FROM inbounds WHERE protocol IN ('shadowsocks', 'socks');" 2>/dev/null || echo "N/A")
    local max_port=$(sqlite3 "$X3UI_DB" "SELECT MAX(port) FROM inbounds WHERE protocol IN ('shadowsocks', 'socks');" 2>/dev/null || echo "N/A")
    echo "  端口范围: $min_port - $max_port"
    
    # 数据库大小
    if [ -f "$X3UI_DB" ]; then
        local db_size=$(du -h "$X3UI_DB" | cut -f1)
        echo "  数据库大小: $db_size"
    fi
}

#================================================
# 配置管理函数
#================================================

# 修改代理配置
modify_proxy() {
    echo -e "${BLUE}=== 修改代理配置 ===${NC}"
    
    if [ ! -f "$X3UI_DB" ]; then 
        log_error "3x-ui数据库不存在。"
        return
    fi

    # 获取所有入站代理
    local proxies=$(sqlite3 "$X3UI_DB" "SELECT id, protocol, listen, port, remark FROM inbounds WHERE protocol IN ('shadowsocks', 'socks') ORDER BY id;")
    
    if [ -z "$proxies" ]; then 
        log_warn "没有找到任何代理。"
        return
    fi

    echo -e "${YELLOW}请选择要修改的代理:${NC}"
    local i=1
    local ids=()
    local protocols=()
    
    while IFS='|' read -r id protocol listen port remark; do
        echo "[$i] $protocol | $listen:$port | $remark"
        ids+=("$id")
        protocols+=("$protocol")
        ((i++))
    done <<< "$proxies"
    echo "[0] 返回主菜单"

    read -p "请输入选项: " choice
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 0 ] || [ "$choice" -gt ${#ids[@]} ]; then 
        log_error "无效的选择。"
        return
    fi

    if [ "$choice" -eq 0 ]; then 
        return
    fi

    local id_to_modify="${ids[$((choice - 1))]}"
    local protocol_to_modify="${protocols[$((choice - 1))]}"
    
    backup_database

    if [ "$protocol_to_modify" = "shadowsocks" ]; then
        # 修改Shadowsocks
        local current_data=$(sqlite3 "$X3UI_DB" "SELECT listen, port, settings, remark FROM inbounds WHERE id = $id_to_modify;")
        IFS='|' read -r current_listen current_port current_settings current_remark <<< "$current_data"
        
        local current_method=$(echo "$current_settings" | grep -o '"method":"[^"]*"' | cut -d'"' -f4)
        local current_password=$(echo "$current_settings" | grep -o '"password":"[^"]*"' | cut -d'"' -f4)
        
        echo "当前配置:"
        echo "  监听: $current_listen:$current_port"
        echo "  方法: $current_method"
        echo "  密码: $current_password"
        echo "  备注: $current_remark"
        echo
        
        read -p "新的监听IP (留空保持不变): " new_listen
        read -p "新的端口 (留空保持不变): " new_port
        read -p "新的密码 (留空保持不变): " new_password
        read -p "新的备注 (留空保持不变): " new_remark
        
        local final_listen="${new_listen:-$current_listen}"
        local final_port="${new_port:-$current_port}"
        local final_password="${new_password:-$current_password}"
        local final_remark="${new_remark:-$current_remark}"
        
        # 检查新IP和端口组合是否冲突
        if [ -n "$new_listen$new_port" ]; then
            local check_listen="${new_listen:-$current_listen}"
            local check_port="${new_port:-$current_port}"
            if [ "$check_listen:$check_port" != "$current_listen:$current_port" ]; then
                if check_ip_port_exists "$check_listen" "$check_port"; then
                    log_error "代理已存在: $check_listen:$check_port"
                    return
                fi
            fi
        fi
        
        local escaped_password=$(escape_json "$final_password")
        local escaped_remark=$(escape_json "$final_remark")
        local new_settings="{\"method\":\"$current_method\",\"password\":\"$escaped_password\",\"network\":\"tcp,udp\"}"
        
        sqlite3 "$X3UI_DB" "UPDATE inbounds SET listen = '$final_listen', port = $final_port, settings = '$new_settings', remark = '$escaped_remark' WHERE id = $id_to_modify;"
        
    elif [ "$protocol_to_modify" = "socks" ]; then
        # 修改SOCKS5
        local current_data=$(sqlite3 "$X3UI_DB" "SELECT listen, port, settings, remark FROM inbounds WHERE id = $id_to_modify;")
        IFS='|' read -r current_listen current_port current_settings current_remark <<< "$current_data"
        
        local current_username=$(echo "$current_settings" | grep -o '"user":"[^"]*"' | cut -d'"' -f4)
        local current_password=$(echo "$current_settings" | grep -o '"pass":"[^"]*"' | cut -d'"' -f4)
        
        echo "当前配置:"
        echo "  监听: $current_listen:$current_port"
        echo "  用户: $current_username"
        echo "  密码: $current_password"
        echo "  备注: $current_remark"
        echo
        
        read -p "新的监听IP (留空保持不变): " new_listen
        read -p "新的端口 (留空保持不变): " new_port
        read -p "新的用户名 (留空保持不变): " new_username
        read -p "新的密码 (留空保持不变): " new_password
        read -p "新的备注 (留空保持不变): " new_remark
        
        local final_listen="${new_listen:-$current_listen}"
        local final_port="${new_port:-$current_port}"
        local final_username="${new_username:-$current_username}"
        local final_password="${new_password:-$current_password}"
        local final_remark="${new_remark:-$current_remark}"
        
        # 检查新IP和端口组合是否冲突
        if [ -n "$new_listen$new_port" ]; then
            local check_listen="${new_listen:-$current_listen}"
            local check_port="${new_port:-$current_port}"
            if [ "$check_listen:$check_port" != "$current_listen:$current_port" ]; then
                if check_ip_port_exists "$check_listen" "$check_port"; then
                    log_error "代理已存在: $check_listen:$check_port"
                    return
                fi
            fi
        fi
        
        local escaped_username=$(escape_json "$final_username")
        local escaped_password=$(escape_json "$final_password")
        local escaped_remark=$(escape_json "$final_remark")
        local new_settings="{\"auth\":\"password\",\"accounts\":[{\"user\":\"$escaped_username\",\"pass\":\"$escaped_password\"}],\"udp\":true,\"ip\":\"127.0.0.1\"}"
        
        sqlite3 "$X3UI_DB" "UPDATE inbounds SET listen = '$final_listen', port = $final_port, settings = '$new_settings', remark = '$escaped_remark' WHERE id = $id_to_modify;"
    fi

    log_info "代理配置已修改。"
    restart_x3ui
}

#================================================
# 主菜单和程序入口
#================================================

# 主菜单
main_menu() {
    while true; do
        echo
        echo -e "${BLUE}=== 3x-ui代理管理脚本 v6.2 (基于3x-ui数据库) ===${NC}"
        echo "[1] 添加单个代理"
        echo "[2] 批量添加共享代理"
        echo "[3] 批量添加独享代理 (按IP分布)"
        echo "[4] 列出现有代理"
        echo "[5] 显示代理详细信息"
        echo "[6] 导出所有代理链接"
        echo "[7] 导出配置为JSON格式"
        echo "[8] 统计信息"
        echo "[9] 修改代理配置"
        echo -e "${RED}--- 删除操作 ---${NC}"
        echo -e "${RED}[10] 删除单个代理${NC}"
        echo -e "${RED}[11] 按用户名批量删除SOCKS5代理${NC}"
        echo -e "${RED}[12] 按端口批量删除代理${NC}"
        echo -e "${RED}[13] 清空所有代理${NC}"
        echo "-------------------------------------"
        echo "[14] 查看备份"
        echo "[15] 重启3x-ui和xray服务"
        echo "[16] 修复数据库格式问题"
        echo "[17] 清理错误的数据库记录"
        echo "[0] 退出"
        echo

        read -p "请输入选项: " choice

        case "$choice" in
            1) add_single_proxy ;;
            2) batch_add_shared_proxies ;;
            3) batch_add_exclusive_proxies ;;
            4) list_proxies ;;
            5) show_proxy_details ;;
            6) export_all_links ;;
            7) export_config_json ;;
            8) show_statistics ;;
            9) modify_proxy ;;
            10) delete_single_proxy ;;
            11) batch_delete_proxies_by_user ;;
            12) batch_delete_proxies_by_port ;;
            13) clear_all_proxies ;;
            14) ls -la "$BACKUP_DIR" ;;
            15) restart_services ;;
            16) fix_database_format ;;
            17) clean_broken_records ;;
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

    log_info "3x-ui代理管理脚本已启动"
    log_info "数据库位置: $X3UI_DB"
    
    # 启动主菜单
    main_menu
}

# 脚本执行入口
main "$@"
