#!/bin/bash

# 修复Xray配置文件中的重复标签问题
# 使用方法: bash fix_xray_tags.sh

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 配置文件路径
XRAY_CONFIG="/usr/local/etc/xray/config.json"
BACKUP_DIR="/root/xray_backups"

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

# 检查依赖
check_deps() {
    if ! command -v jq > /dev/null 2>&1; then
        log_error "缺少依赖项: jq"
        log_info "请使用以下命令安装: apt update && apt install -y jq"
        exit 1
    fi
}

# 备份配置
backup_config() {
    if [ -f "$XRAY_CONFIG" ]; then
        local bn="config_$(date +%Y%m%d_%H%M%S)_before_fix.json"
        cp "$XRAY_CONFIG" "$BACKUP_DIR/$bn"
        log_info "配置文件已备份: $BACKUP_DIR/$bn"
    fi
}

# 检测并修复重复标签
fix_duplicate_tags() {
    log_info "开始检测重复标签..."
    
    if [ ! -f "$XRAY_CONFIG" ]; then
        log_error "Xray配置文件不存在: $XRAY_CONFIG"
        exit 1
    fi
    
    # 检查JSON格式是否有效
    if ! jq empty "$XRAY_CONFIG" 2>/dev/null; then
        log_error "配置文件JSON格式无效！"
        exit 1
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
    
    if [ ${#duplicate_tags[@]} -eq 0 ]; then
        log_info "未发现重复标签。"
        
        # 检查是否有空标签
        local empty_tags=$(jq '[.inbounds[] | select(.tag == "" or .tag == null)] | length' "$XRAY_CONFIG")
        if [ "$empty_tags" -gt 0 ]; then
            log_warn "发现 $empty_tags 个空标签，开始修复..."
            fix_empty_tags
        else
            log_info "配置文件看起来正常。"
        fi
        return
    fi
    
    log_warn "发现 ${#duplicate_tags[@]} 个重复标签: ${duplicate_tags[*]}"
    
    # 备份配置
    backup_config
    
    # 修复每个重复标签
    for dup_tag in "${duplicate_tags[@]}"; do
        log_info "修复重复标签: $dup_tag"
        fix_single_duplicate_tag "$dup_tag"
    done
    
    log_info "标签修复完成！"
}

# 修复单个重复标签
fix_single_duplicate_tag() {
    local dup_tag="$1"
    local temp_file=$(mktemp)
    local counter=2
    local first_found=false
    
    # 创建一个新的配置文件，逐个处理重复的入站
    jq '.' "$XRAY_CONFIG" > "$temp_file"
    
    # 获取所有使用此标签的入站配置
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
        local new_tag="${protocol}-auto-${port}-${counter}"
        
        # 确保标签唯一
        while jq -e --arg tag "$new_tag" '.inbounds[] | select(.tag == $tag)' "$temp_file" >/dev/null 2>&1; do
            counter=$((counter + 1))
            new_tag="${protocol}-auto-${port}-${counter}"
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
    
    # 检查JSON格式
    if ! jq empty "$XRAY_CONFIG" 2>/dev/null; then
        log_error "配置文件JSON格式仍然无效！"
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
    local empty_count=$(jq '[.inbounds[] | select(.tag == "" or .tag == null)] | length' "$XRAY_CONFIG")
    if [ "$empty_count" -gt 0 ]; then
        log_error "仍然存在 $empty_count 个空标签！"
        return 1
    fi
    
    log_info "配置文件验证通过！"
    return 0
}

# 测试配置
test_config() {
    log_info "测试Xray配置..."
    
    if xray test -config "$XRAY_CONFIG" 2>/dev/null; then
        log_info "Xray配置测试通过！"
        return 0
    else
        log_error "Xray配置测试失败！"
        echo "详细错误信息："
        xray test -config "$XRAY_CONFIG"
        return 1
    fi
}

# 重启服务
restart_xray() {
    log_info "重启Xray服务..."
    
    if systemctl restart xray; then
        sleep 2
        if systemctl is-active --quiet xray; then
            log_info "Xray服务重启成功！"
        else
            log_error "Xray服务启动失败！"
            echo "查看详细错误："
            echo "sudo journalctl -u xray -e --no-pager"
            return 1
        fi
    else
        log_error "重启Xray服务失败！"
        return 1
    fi
}

# 显示统计信息
show_stats() {
    if [ ! -f "$XRAY_CONFIG" ]; then
        return
    fi
    
    local inbound_count=$(jq '.inbounds | length' "$XRAY_CONFIG" 2>/dev/null || echo "0")
    local ss_count=$(jq '[.inbounds[] | select(.protocol == "shadowsocks")] | length' "$XRAY_CONFIG" 2>/dev/null || echo "0")
    local socks_count=$(jq '[.inbounds[] | select(.protocol == "socks")] | length' "$XRAY_CONFIG" 2>/dev/null || echo "0")
    local outbound_count=$(jq '[.outbounds[] | select(.protocol == "socks")] | length' "$XRAY_CONFIG" 2>/dev/null || echo "0")
    
    echo -e "${BLUE}=== 配置统计 ===${NC}"
    echo "入站代理总数: $inbound_count"
    echo "  - Shadowsocks: $ss_count"
    echo "  - SOCKS5: $socks_count"
    echo "自定义出站: $outbound_count"
}

# 主函数
main() {
    echo -e "${BLUE}=== Xray标签冲突修复工具 ===${NC}"
    
    if [ $EUID -ne 0 ]; then
        log_error "请使用root权限运行此脚本。"
        exit 1
    fi
    
    check_deps
    
    show_stats
    echo
    
    # 修复重复标签
    fix_duplicate_tags
    
    echo
    
    # 验证配置
    if validate_config; then
        echo
        # 测试配置
        if test_config; then
            echo
            # 重启服务
            restart_xray
            echo
            log_info "修复完成！Xray服务已成功启动。"
        else
            log_error "配置测试失败，请检查配置文件。"
            exit 1
        fi
    else
        log_error "配置验证失败，请手动检查配置文件。"
        exit 1
    fi
    
    echo
    show_stats
}

main "$@"
