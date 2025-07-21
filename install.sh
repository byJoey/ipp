#!/bin/bash
# 端口转发管理器安装脚本
# 自动安装 Python3、Flask、redir、uredir 和所有依赖

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印函数
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo ""
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}======================================${NC}"
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "检测到root用户，建议使用普通用户运行此脚本"
        read -p "是否继续? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# 检测系统类型
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        DISTRO=$ID
        VERSION=$VERSION_ID
    else
        print_error "无法检测操作系统类型"
        exit 1
    fi
    
    print_info "检测到系统: $OS ($VERSION)"
}

# 更新包管理器
update_packages() {
    print_header "更新系统包管理器"
    
    case $DISTRO in
        ubuntu|debian)
            sudo apt update
            print_success "apt 包列表已更新"
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                sudo dnf update -y
            else
                sudo yum update -y
            fi
            print_success "yum/dnf 包列表已更新"
            ;;
        arch|manjaro)
            sudo pacman -Sy
            print_success "pacman 包列表已更新"
            ;;
        *)
            print_warning "未知的发行版，跳过包更新"
            ;;
    esac
}

# 检测已安装的工具
check_existing_tools() {
    print_header "检测已安装的工具"
    
    SKIP_PYTHON=false
    SKIP_REDIR=false
    SKIP_UREDIR=false
    SKIP_BASE_DEPS=false
    
    # 检测Python和Flask
    if command -v python3 &> /dev/null; then
        if python3 -c "import flask" 2>/dev/null; then
            print_success "Python3 和 Flask 已安装，跳过Python依赖安装"
            SKIP_PYTHON=true
        elif [[ -f "/opt/port-forwarder/python3-venv" ]]; then
            if /opt/port-forwarder/python3-venv -c "import flask" 2>/dev/null; then
                print_success "Python虚拟环境和Flask已存在，跳过Python依赖安装"
                SKIP_PYTHON=true
            fi
        else
            print_info "Python3已安装，但需要安装Flask"
        fi
    else
        print_info "需要安装Python3和Flask"
    fi
    
    # 检测redir
    if command -v redir &> /dev/null; then
        print_success "redir 已安装: $(redir --version 2>&1 | head -n1 || echo '$(which redir)')"
        SKIP_REDIR=true
    else
        print_info "需要安装redir"
    fi
    
    # 检测uredir
    if command -v uredir &> /dev/null; then
        print_success "uredir 已安装: $(uredir --version 2>&1 | head -n1 || echo '$(which uredir)')"
        SKIP_UREDIR=true
    else
        print_info "需要安装uredir"
    fi
    
    # 检测基础编译工具
    if command -v gcc &> /dev/null && command -v make &> /dev/null && command -v git &> /dev/null; then
        print_info "基础编译工具已安装"
        # 如果所有主要工具都已安装，可能不需要安装基础依赖
        if $SKIP_REDIR && $SKIP_UREDIR; then
            print_success "主要工具已安装，跳过基础依赖检查"
            SKIP_BASE_DEPS=true
        fi
    else
        print_info "需要安装基础编译工具"
    fi
    
    # 总结
    echo ""
    print_info "安装计划:"
    echo "  基础依赖: $(if $SKIP_BASE_DEPS; then echo "跳过"; else echo "安装"; fi)"
    echo "  Python/Flask: $(if $SKIP_PYTHON; then echo "跳过"; else echo "安装"; fi)"
    echo "  redir: $(if $SKIP_REDIR; then echo "跳过"; else echo "安装"; fi)"
    echo "  uredir: $(if $SKIP_UREDIR; then echo "跳过"; else echo "安装"; fi)"
    echo ""
}

# 安装基础依赖
install_base_dependencies() {
    if $SKIP_BASE_DEPS; then
        print_info "跳过基础依赖安装"
        return 0
    fi
    
    print_header "安装基础依赖"
    
    case $DISTRO in
        ubuntu|debian)
            sudo apt install -y \
                python3 \
                python3-pip \
                python3-venv \
                build-essential \
                git \
                autoconf \
                automake \
                libtool \
                pkg-config \
                libev-dev \
                wget \
                curl
            ;;
        centos|rhel)
            if command -v dnf &> /dev/null; then
                sudo dnf install -y \
                    python3 \
                    python3-pip \
                    gcc \
                    gcc-c++ \
                    make \
                    git \
                    autoconf \
                    automake \
                    libtool \
                    pkgconfig \
                    libev-devel \
                    wget \
                    curl
            else
                sudo yum install -y \
                    python3 \
                    python3-pip \
                    gcc \
                    gcc-c++ \
                    make \
                    git \
                    autoconf \
                    automake \
                    libtool \
                    pkgconfig \
                    libev-devel \
                    wget \
                    curl
            fi
            ;;
        fedora)
            sudo dnf install -y \
                python3 \
                python3-pip \
                gcc \
                gcc-c++ \
                make \
                git \
                autoconf \
                automake \
                libtool \
                pkgconfig \
                libev-devel \
                wget \
                curl
            ;;
        arch|manjaro)
            sudo pacman -S --needed \
                python \
                python-pip \
                base-devel \
                git \
                autoconf \
                automake \
                libtool \
                pkg-config \
                libev \
                wget \
                curl
            ;;
        *)
            print_error "不支持的发行版: $DISTRO"
            print_info "请手动安装: python3, python3-pip, build-essential, git, autoconf, automake, libtool, pkg-config, libev-dev"
            exit 1
            ;;
    esac
    
    print_success "基础依赖安装完成"
}

# 安装 redir (TCP转发工具)
install_redir() {
    if $SKIP_REDIR; then
        print_info "跳过 redir 安装 - 已存在"
        return 0
    fi
    
    print_header "安装 redir (TCP端口转发工具)"
    
    case $DISTRO in
        ubuntu|debian)
            if sudo apt install -y redir; then
                print_success "redir 通过包管理器安装成功"
                return 0
            fi
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                if sudo dnf install -y redir; then
                    print_success "redir 通过包管理器安装成功"
                    return 0
                fi
            else
                if sudo yum install -y redir; then
                    print_success "redir 通过包管理器安装成功"
                    return 0
                fi
            fi
            ;;
        arch|manjaro)
            if sudo pacman -S --needed redir; then
                print_success "redir 通过包管理器安装成功"
                return 0
            fi
            ;;
    esac
    
    # 如果包管理器安装失败，从源码编译
    print_warning "包管理器安装失败，开始从源码编译 redir"
    
    cd /tmp
    if [[ -d redir ]]; then
        rm -rf redir
    fi
    
    git clone https://github.com/troglobit/redir.git
    cd redir
    
    ./autogen.sh
    ./configure --prefix=/usr/local
    make -j$(nproc)
    sudo make install
    
    # 创建符号链接
    sudo ln -sf /usr/local/bin/redir /usr/bin/redir 2>/dev/null || true
    
    if command -v redir &> /dev/null; then
        print_success "redir 从源码编译安装成功"
    else
        print_error "redir 安装失败"
        exit 1
    fi
}

# 安装 libuEv (uredir 的依赖)
install_libuev() {
    print_header "安装 libuEv (uredir 依赖库)"
    
    # 检查是否已安装
    if pkg-config --exists libuev 2>/dev/null; then
        print_info "libuEv 已安装"
        return 0
    fi
    
    cd /tmp
    if [[ -d libuev ]]; then
        rm -rf libuev
    fi
    
    git clone https://github.com/troglobit/libuev.git
    cd libuev
    
    ./autogen.sh
    ./configure --prefix=/usr/local
    make -j$(nproc)
    sudo make install
    
    # 更新动态链接库缓存
    sudo ldconfig
    
    if pkg-config --exists libuev; then
        print_success "libuEv 安装成功"
    else
        print_warning "libuEv 安装可能有问题，但继续尝试安装 uredir"
    fi
}

# 安装 uredir (UDP转发工具)
install_uredir() {
    if $SKIP_UREDIR; then
        print_info "跳过 uredir 安装 - 已存在"
        return 0
    fi
    
    print_header "安装 uredir (UDP端口转发工具)"
    
    # 尝试包管理器安装
    case $DISTRO in
        ubuntu|debian)
            if sudo apt install -y uredir 2>/dev/null; then
                print_success "uredir 通过包管理器安装成功"
                return 0
            fi
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                if sudo dnf install -y uredir 2>/dev/null; then
                    print_success "uredir 通过包管理器安装成功"
                    return 0
                fi
            fi
            ;;
    esac
    
    # 从源码编译
    print_info "从源码编译 uredir"
    
    # 确保 libuEv 已安装
    install_libuev
    
    cd /tmp
    if [[ -d uredir ]]; then
        rm -rf uredir
    fi
    
    git clone https://github.com/troglobit/uredir.git
    cd uredir
    
    ./autogen.sh
    PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH ./configure --prefix=/usr/local
    make -j$(nproc)
    sudo make install
    
    # 创建符号链接
    sudo ln -sf /usr/local/bin/uredir /usr/bin/uredir 2>/dev/null || true
    
    # 更新动态链接库缓存
    sudo ldconfig
    
    if command -v uredir &> /dev/null; then
        print_success "uredir 从源码编译安装成功"
    else
        print_error "uredir 安装失败"
        print_info "请检查依赖库是否正确安装"
        exit 1
    fi
}

# 安装 Python 依赖
install_python_dependencies() {
    if $SKIP_PYTHON; then
        print_info "跳过 Python 依赖安装 - 已存在"
        return 0
    fi
    
    print_header "安装 Python 依赖"
    
    # 检查系统是否有externally-managed-environment限制
    if python3 -m pip install --help | grep -q "break-system-packages" 2>/dev/null; then
        print_info "检测到 PEP 668 保护，使用适当的安装方法"
        
        case $DISTRO in
            ubuntu|debian)
                # 优先尝试系统包
                print_info "尝试通过系统包管理器安装 Flask"
                if sudo apt install -y python3-flask python3-full python3-venv; then
                    print_success "通过 apt 安装 Flask 成功"
                    return 0
                fi
                
                # 如果系统包不可用，创建虚拟环境
                print_info "系统包不可用，创建虚拟环境"
                VENV_PATH="/opt/port-forwarder-venv"
                sudo python3 -m venv $VENV_PATH
                sudo $VENV_PATH/bin/pip install --upgrade pip
                sudo $VENV_PATH/bin/pip install flask
                
                # 创建包装脚本
                cat << EOF | sudo tee /opt/port-forwarder/python3-venv > /dev/null
#!/bin/bash
exec $VENV_PATH/bin/python "\$@"
EOF
                sudo chmod +x /opt/port-forwarder/python3-venv
                print_success "虚拟环境创建完成: $VENV_PATH"
                ;;
            *)
                # 其他发行版尝试使用 --break-system-packages（谨慎）
                print_warning "使用 --break-system-packages 参数安装"
                python3 -m pip install --break-system-packages --upgrade pip
                python3 -m pip install --break-system-packages flask
                ;;
        esac
    else
        # 旧系统，直接安装
        print_info "使用传统方式安装 Python 包"
        python3 -m pip install --upgrade pip
        python3 -m pip install flask
    fi
    
    print_success "Python 依赖安装完成"
}

# 创建项目目录和服务文件
setup_service() {
    print_header "设置服务和项目目录"
    
    # 创建项目目录
    PROJECT_DIR="/opt/port-forwarder"
    if [[ -d $PROJECT_DIR ]]; then
        print_info "项目目录已存在: $PROJECT_DIR"
    else
        sudo mkdir -p $PROJECT_DIR
        sudo chown $USER:$USER $PROJECT_DIR
        print_success "项目目录创建: $PROJECT_DIR"
    fi
    
    # 检测Python执行路径
    PYTHON_EXEC="/usr/bin/python3"
    if [[ -f "/opt/port-forwarder/python3-venv" ]]; then
        PYTHON_EXEC="/opt/port-forwarder/python3-venv"
        print_info "使用虚拟环境Python: $PYTHON_EXEC"
    fi
    
    # 检查服务文件是否已存在
    if [[ -f "/etc/systemd/system/port-forwarder.service" ]]; then
        print_info "systemd 服务文件已存在，检查是否需要更新"
        # 检查服务文件中的Python路径是否正确
        if grep -q "$PYTHON_EXEC" /etc/systemd/system/port-forwarder.service; then
            print_success "systemd 服务文件已是最新"
            return 0
        else
            print_info "更新 systemd 服务文件中的Python路径"
        fi
    fi
    
    # 创建 systemd 服务文件
    cat << EOF | sudo tee /etc/systemd/system/port-forwarder.service > /dev/null
[Unit]
Description=Port Forwarder Web Manager
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
WorkingDirectory=/opt/port-forwarder
ExecStart=$PYTHON_EXEC /opt/port-forwarder/port_forwarder.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    
    sudo systemctl daemon-reload
    print_success "systemd 服务文件已创建/更新"
    
    echo ""
    print_info "服务管理命令:"
    echo "  启动服务: sudo systemctl start port-forwarder"
    echo "  停止服务: sudo systemctl stop port-forwarder"
    echo "  开机自启: sudo systemctl enable port-forwarder"
    echo "  查看状态: sudo systemctl status port-forwarder"
    echo "  查看日志: journalctl -u port-forwarder -f"
}

# 测试安装
test_installation() {
    print_header "测试安装"
    
    # 测试 Python 和 Flask
    if [[ -f "/opt/port-forwarder/python3-venv" ]]; then
        # 使用虚拟环境测试
        if /opt/port-forwarder/python3-venv -c "import flask; print('Flask version:', flask.__version__)" 2>/dev/null; then
            print_success "Python 虚拟环境和 Flask 工作正常"
        else
            print_error "Python 虚拟环境或 Flask 有问题"
        fi
    else
        # 使用系统Python测试
        if python3 -c "import flask; print('Flask version:', flask.__version__)" 2>/dev/null; then
            print_success "Python 和 Flask 工作正常"
        else
            print_error "Python 或 Flask 有问题"
        fi
    fi
    
    # 测试 redir
    if command -v redir &> /dev/null; then
        print_success "redir 安装成功: $(which redir)"
    else
        print_error "redir 未找到"
    fi
    
    # 测试 uredir
    if command -v uredir &> /dev/null; then
        print_success "uredir 安装成功: $(which uredir)"
    else
        print_error "uredir 未找到"
    fi
    
    print_info "安装测试完成"
}

# 显示使用说明
show_usage() {
    print_header "安装完成 - 使用说明"
    
    echo ""
    echo -e "${GREEN}🎉 端口转发管理器安装完成！${NC}"
    echo ""
    
    # 检查是否已有配置文件
    if [[ -f "/opt/port-forwarder/port_forwarder.py" ]]; then
        print_success "检测到已存在的配置文件"
        echo ""
        echo "可以直接启动服务:"
        echo "   sudo systemctl start port-forwarder"
        echo ""
    else
        echo "接下来的步骤:"
        echo ""
        echo "1. 将你的 Python 脚本复制到项目目录:"
        echo "   cp your_port_forwarder.py /opt/port-forwarder/port_forwarder.py"
        echo ""
        echo "2. 直接运行 (前台):"
        echo "   cd /opt/port-forwarder"
        if [[ -f "/opt/port-forwarder/python3-venv" ]]; then
            echo "   ./python3-venv port_forwarder.py"
            echo ""
            echo "   注意: 使用虚拟环境Python执行"
        else
            echo "   python3 port_forwarder.py"
        fi
        echo ""
        echo "3. 或者使用系统服务 (后台):"
        echo "   sudo systemctl start port-forwarder"
        echo "   sudo systemctl enable port-forwarder  # 开机自启"
        echo ""
    fi
    
    echo "4. 访问 Web 界面:"
    echo "   http://your-server-ip:5000"
    echo ""
    echo "已安装工具版本信息:"
    command -v python3 && python3 --version
    command -v redir && echo "redir: $(which redir)"
    command -v uredir && echo "uredir: $(which uredir)"
    if [[ -f "/opt/port-forwarder/python3-venv" ]]; then
        echo "Python 虚拟环境: /opt/port-forwarder-venv"
    fi
    echo ""
    echo -e "${YELLOW}注意: 请确保防火墙允许 5000 端口访问${NC}"
    echo ""
    
    # 针对Ubuntu/Debian的额外说明
    if [[ "$DISTRO" == "ubuntu" || "$DISTRO" == "debian" ]]; then
        echo -e "${BLUE}Ubuntu/Debian 特别说明:${NC}"
        echo "由于 PEP 668 保护，我们使用了以下安装策略:"
        if [[ -f "/opt/port-forwarder/python3-venv" ]]; then
            echo "✓ 创建了虚拟环境: /opt/port-forwarder-venv"
            echo "✓ systemd 服务已配置使用虚拟环境"
        else
            echo "✓ 使用系统包 python3-flask"
        fi
        echo ""
    fi
    
    # 重复安装提示
    echo -e "${BLUE}重复运行此脚本:${NC}"
    echo "此脚本可以安全地多次运行，已安装的组件会被自动跳过。"
    echo ""
}

# 清理函数
cleanup() {
    print_info "清理临时文件..."
    cd /
    rm -rf /tmp/redir /tmp/uredir /tmp/libuev 2>/dev/null || true
}

# 主函数
main() {
    print_header "端口转发管理器安装脚本"
    echo "此脚本将安装:"
    echo "  - Python3 和 Flask"
    echo "  - redir (TCP端口转发)"
    echo "  - uredir (UDP端口转发)"
    echo "  - 所有必要的依赖"
    echo ""
    
    read -p "是否继续安装? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "安装已取消"
        exit 0
    fi
    
    # 检查root权限提醒
    check_root
    
    # 设置清理陷阱
    trap cleanup EXIT
    
    # 执行安装步骤
    detect_os
    check_existing_tools
    update_packages
    install_base_dependencies
    install_redir
    install_uredir
    install_python_dependencies
    setup_service
    test_installation
    show_usage
    
    print_success "安装脚本执行完成！"
}

# 运行主函数
main "$@"
