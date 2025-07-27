#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
专业网络端口转发工具
支持TCP/UDP转发，Web管理界面，身份验证，商用级稳定性
作者: Joey
许可: MIT License (可商用)
"""

import asyncio
import socket
import threading
import time
import hashlib
import secrets
import json
import logging
import signal
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import uuid

# Web框架
from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('port_forwarder.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SecurityManager:
    """安全管理器"""
    
    def __init__(self):
        self.failed_attempts = {}
        self.blocked_ips = {}
        self.max_attempts = 5
        self.block_time = 300  # 5分钟
        self.scanner_detection = {}
        self.honeypot_hits = {}
        
    def is_ip_blocked(self, ip: str) -> bool:
        """检查IP是否被阻止"""
        if ip in self.blocked_ips:
            if time.time() < self.blocked_ips[ip]:
                return True
            else:
                del self.blocked_ips[ip]
        return False
    
    def record_failed_attempt(self, ip: str):
        """记录失败尝试"""
        current_time = time.time()
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = []
        
        # 清理旧记录
        self.failed_attempts[ip] = [
            t for t in self.failed_attempts[ip] 
            if current_time - t < 3600  # 1小时内的记录
        ]
        
        self.failed_attempts[ip].append(current_time)
        
        # 检查是否需要阻止
        if len(self.failed_attempts[ip]) >= self.max_attempts:
            self.blocked_ips[ip] = current_time + self.block_time
            logger.warning(f"IP {ip} blocked due to multiple failed attempts")
    
    def record_scanner_behavior(self, ip: str, path: str):
        """记录扫描器行为"""
        current_time = time.time()
        if ip not in self.scanner_detection:
            self.scanner_detection[ip] = []
        
        self.scanner_detection[ip].append({
            'path': path,
            'time': current_time
        })
        
        # 清理旧记录
        self.scanner_detection[ip] = [
            entry for entry in self.scanner_detection[ip]
            if current_time - entry['time'] < 1800  # 30分钟内
        ]
        
        # 检测扫描行为 - 如果在短时间内访问多个不存在的路径
        if len(self.scanner_detection[ip]) >= 3:
            # 立即封禁扫描器
            self.blocked_ips[ip] = current_time + 3600  # 封禁1小时
            logger.warning(f"Scanner detected and blocked: {ip} - paths: {[e['path'] for e in self.scanner_detection[ip]]}")
            return True
        
        return False
    
    def record_honeypot_hit(self, ip: str, path: str):
        """记录蜜罐命中"""
        current_time = time.time()
        if ip not in self.honeypot_hits:
            self.honeypot_hits[ip] = []
        
        self.honeypot_hits[ip].append({
            'path': path,
            'time': current_time
        })
        
        # 蜜罐命中立即封禁
        self.blocked_ips[ip] = current_time + 7200  # 封禁2小时
        logger.critical(f"Honeypot triggered by {ip} accessing {path}")
    
    def clear_failed_attempts(self, ip: str):
        """清除失败尝试记录"""
        if ip in self.failed_attempts:
            del self.failed_attempts[ip]

class PortForwarder:
    """端口转发核心类"""
    
    def __init__(self):
        self.active_forwards = {}
        self.stats = {
            'total_connections': 0,
            'active_connections': 0,
            'bytes_transferred': 0,
            'start_time': time.time()
        }
        self.running = True
        self.forwards_file = Path("forwards.json")

    def save_forwards_to_disk(self):
        """Saves the current running forwards to a JSON file for persistence."""
        logger.debug("Attempting to save forwarding rules to disk.")
        try:
            restartable_forwards = []
            # Iterate over a copy of values to be thread-safe
            for f_info in list(self.active_forwards.values()):
                if f_info.get('status') == 'running':
                    restartable_forwards.append({
                        'protocol': f_info['protocol'].lower(),
                        'local_port': f_info['local_port'],
                        'remote_host': f_info['remote_host'],
                        'remote_port': f_info['remote_port'],
                    })

            # Atomic write operation
            temp_file_path = self.forwards_file.with_suffix('.json.tmp')
            with temp_file_path.open('w', encoding='utf-8') as f:
                json.dump(restartable_forwards, f, indent=4)
            temp_file_path.replace(self.forwards_file)
            
            logger.info(f"Successfully saved {len(restartable_forwards)} forwarding rules to {self.forwards_file}")
        except Exception as e:
            logger.error(f"Failed to save forwarding rules to {self.forwards_file}: {e}")

    def load_forwards_from_disk(self):
        """Loads and restarts forwarding rules from the JSON file on startup."""
        if not self.forwards_file.exists():
            logger.info(f"{self.forwards_file} not found, starting with no active forwards.")
            return

        logger.info(f"Loading forwarding rules from {self.forwards_file}...")
        try:
            with self.forwards_file.open('r', encoding='utf-8') as f:
                content = f.read()
                if not content:
                    logger.warning(f"{self.forwards_file} is empty, skipping.")
                    return
                forwards_to_load = json.loads(content)
            
            if not isinstance(forwards_to_load, list):
                logger.error(f"{self.forwards_file} is corrupted (not a list), skipping reload.")
                return
                
            count = 0
            for config in forwards_to_load:
                try:
                    port_conflict = False
                    for forward in self.active_forwards.values():
                        if forward['local_port'] == config['local_port'] and forward['protocol'].lower() == config['protocol'].lower():
                            logger.warning(f"Skipping reload of {config}: Port {config['local_port']} is already in use.")
                            port_conflict = True
                            break
                    if not port_conflict:
                        self.start_forward(
                            protocol=config['protocol'],
                            local_port=config['local_port'],
                            remote_host=config['remote_host'],
                            remote_port=config['remote_port'],
                            persist=False  # Do not re-save while loading
                        )
                        count += 1
                except Exception as e:
                    logger.error(f"Failed to restart forward {config}: {e}")
            
            if count > 0:
                logger.info(f"Successfully reloaded {count} forwarding rules.")
            
        except json.JSONDecodeError:
            logger.error(f"Could not parse {self.forwards_file}. Please check for syntax errors. Starting clean.")
        except Exception as e:
            logger.error(f"An unexpected error occurred while loading forwards: {e}")

    async def tcp_forward(self, local_port: int, remote_host: str, remote_port: int, forward_id: str):
        """TCP端口转发"""
        try:
            server = await asyncio.start_server(
                lambda r, w: self.handle_tcp_client(r, w, remote_host, remote_port, forward_id),
                '0.0.0.0', local_port
            )
            
            self.active_forwards[forward_id]['server'] = server
            logger.info(f"TCP forwarding started: 0.0.0.0:{local_port} -> {remote_host}:{remote_port}")
            
            async with server:
                await server.serve_forever()
                
        except Exception as e:
            logger.error(f"TCP forward error on port {local_port}: {e}")
            if forward_id in self.active_forwards:
                self.active_forwards[forward_id]['status'] = 'error'
                self.active_forwards[forward_id]['error'] = str(e)
    
    async def handle_tcp_client(self, reader, writer, remote_host: str, remote_port: int, forward_id: str):
        """处理TCP客户端连接"""
        client_addr = writer.get_extra_info('peername')
        logger.info(f"New TCP connection from {client_addr} for forward {forward_id}")
        
        try:
            remote_reader, remote_writer = await asyncio.open_connection(remote_host, remote_port)
            
            self.stats['total_connections'] += 1
            self.stats['active_connections'] += 1
            
            await asyncio.gather(
                self.copy_data(reader, remote_writer, forward_id),
                self.copy_data(remote_reader, writer, forward_id),
                return_exceptions=True
            )
            
        except Exception as e:
            logger.error(f"TCP client handle error: {e}")
        finally:
            self.stats['active_connections'] -= 1
            writer.close()
            await writer.wait_closed()
    
    async def copy_data(self, reader, writer, forward_id: str):
        """复制数据流"""
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
                self.stats['bytes_transferred'] += len(data)
        except ConnectionResetError:
            logger.debug(f"Connection reset by peer for forward {forward_id}")
        except Exception as e:
            logger.debug(f"Data copy ended: {e}")
    
    def udp_forward(self, local_port: int, remote_host: str, remote_port: int, forward_id: str):
        """UDP端口转发"""
        def udp_server():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', local_port))
            
            self.active_forwards[forward_id]['socket'] = sock
            logger.info(f"UDP forwarding started: 0.0.0.0:{local_port} -> {remote_host}:{remote_port}")
            
            clients = {}
            
            try:
                while self.running and forward_id in self.active_forwards:
                    try:
                        sock.settimeout(1.0)
                        data, addr = sock.recvfrom(8192)
                        
                        if addr not in clients:
                            clients[addr] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        
                        clients[addr].sendto(data, (remote_host, remote_port))
                        self.stats['bytes_transferred'] += len(data)
                        
                    except socket.timeout:
                        continue
                    except Exception as e:
                        logger.error(f"UDP forward error on port {local_port}: {e}")
                        break
                        
            finally:
                sock.close()
                for client_sock in clients.values():
                    client_sock.close()
        
        thread = threading.Thread(target=udp_server, daemon=True)
        thread.start()
        return thread
    
    def start_forward(self, protocol: str, local_port: int, remote_host: str, remote_port: int, persist: bool = True) -> str:
        """启动端口转发"""
        forward_id = str(uuid.uuid4())
        
        forward_info = {
            'id': forward_id,
            'protocol': protocol.upper(),
            'local_port': local_port,
            'remote_host': remote_host,
            'remote_port': remote_port,
            'status': 'starting',
            'created_time': datetime.now().isoformat(),
            'error': None
        }
        
        self.active_forwards[forward_id] = forward_info
        
        try:
            if protocol.lower() == 'tcp':
                loop = asyncio.new_event_loop()
                def run_tcp():
                    asyncio.set_event_loop(loop)
                    loop.run_until_complete(
                        self.tcp_forward(local_port, remote_host, remote_port, forward_id)
                    )
                
                thread = threading.Thread(target=run_tcp, daemon=True)
                thread.start()
                forward_info['thread'] = thread
                
            elif protocol.lower() == 'udp':
                thread = self.udp_forward(local_port, remote_host, remote_port, forward_id)
                forward_info['thread'] = thread
            
            forward_info['status'] = 'running'
            logger.info(f"Forward started: {forward_id}")
            if persist:
                self.save_forwards_to_disk()
            return forward_id
            
        except Exception as e:
            forward_info['status'] = 'error'
            forward_info['error'] = str(e)
            logger.error(f"Failed to start forward: {e}")
            if persist:
                self.save_forwards_to_disk()
            return forward_id
    
    def stop_forward(self, forward_id: str, persist: bool = True) -> bool:
        """停止端口转发"""
        if forward_id not in self.active_forwards:
            return False
        
        try:
            forward_info = self.active_forwards[forward_id]
            
            if 'server' in forward_info:
                forward_info['server'].close()
            
            if 'socket' in forward_info:
                forward_info['socket'].close()
            
            forward_info['status'] = 'stopped'
            del self.active_forwards[forward_id]
            
            if persist:
                self.save_forwards_to_disk()
            logger.info(f"Forward stopped: {forward_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop forward {forward_id}: {e}")
            return False
    
    def get_stats(self) -> dict:
        """获取统计信息"""
        uptime = time.time() - self.stats['start_time']
        return {
            **self.stats,
            'uptime': uptime,
            'active_forwards': len(self.active_forwards)
        }
    
    def get_serializable_forwards(self) -> list:
        """获取可序列化的转发信息"""
        forwards = []
        for forward_id, forward_info in self.active_forwards.items():
            serializable_forward = {
                'id': forward_info['id'],
                'protocol': forward_info['protocol'],
                'local_port': forward_info['local_port'],
                'remote_host': forward_info['remote_host'],
                'remote_port': forward_info['remote_port'],
                'status': forward_info['status'],
                'created_time': forward_info['created_time'],
                'error': forward_info.get('error')
            }
            forwards.append(serializable_forward)
        return forwards

# Flask Web应用
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# 配置管理器
class ConfigManager:
    """配置管理器"""
    
    def __init__(self):
        self.config_file = Path("password.txt")
        self.security_path = None
        self.admin_password_hash = None
        self.load_config()
    
    def load_config(self):
        """加载配置文件"""
        try:
            if self.config_file.exists():
                logger.info("Found password.txt, loading configuration...")
                config_data = self.config_file.read_text(encoding='utf-8').strip()
                
                lines = [line.strip() for line in config_data.split('\n') if line.strip() and not line.strip().startswith('#')]
                
                for line in lines:
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip().lower()
                        value = value.strip()
                        
                        if key == 'password':
                            self.admin_password_hash = generate_password_hash(value)
                            logger.info("Password loaded from password.txt")
                        elif key == 'path':
                            self.security_path = value.lstrip('/')
                            logger.info(f"Security path loaded from password.txt: {value}")
                
                if len(lines) == 1 and '=' not in lines[0]:
                    self.admin_password_hash = generate_password_hash(lines[0])
                    logger.info("Password loaded from password.txt (legacy format)")
                    
            else:
                logger.info("password.txt not found, creating with random credentials...")
                self.create_example_config()
                return 
                
        except Exception as e:
            logger.error(f"Error loading config: {e}")
        
        if not self.admin_password_hash:
            random_password = secrets.token_urlsafe(16)
            self.admin_password_hash = generate_password_hash(random_password)
            logger.warning(f"Using generated password: {random_password}")
        
        if not self.security_path:
            self.security_path = secrets.token_urlsafe(12)
            logger.info(f"Generated random security path: /{self.security_path}")
        else:
            logger.info(f"Using security path: /{self.security_path}")
    
    def create_example_config(self):
        """创建示例配置文件"""
        random_password = secrets.token_urlsafe(16)
        random_path = secrets.token_urlsafe(12)
        
        example_config = f"""# 端口转发工具配置文件
# 配置格式: 键=值

# 管理员密码 (自动生成，请妥善保存)
password={random_password}

# 安全路径 (自动生成，访问地址: /{random_path}/admin)
path={random_path}
"""
        try:
            self.config_file.write_text(example_config, encoding='utf-8')
            logger.info(f"Created config file with random credentials: {self.config_file}")
            
            self.admin_password_hash = generate_password_hash(random_password)
            self.security_path = random_path
            
            print("=" * 60)
            print("首次运行 - 已自动生成配置文件")
            print(f"配置文件: {self.config_file}")
            print(f"随机密码: {random_password}")
            print(f"随机路径: {random_path}")
            print(f"管理地址: http://localhost:5000/{random_path}/admin")
            print("=" * 60)
            
        except Exception as e:
            logger.error(f"Failed to create config: {e}")
            self.admin_password_hash = generate_password_hash(random_password)
            self.security_path = random_path
    
    def get_admin_path(self):
        """获取管理路径"""
        return f"/{self.security_path}/admin"
    
    def get_security_path(self):
        """获取安全路径"""
        return self.security_path
    
    def get_password_hash(self):
        """获取密码哈希"""
        return self.admin_password_hash

# 配置管理器实例
config_manager = ConfigManager()

# 获取配置
SECURITY_PATH = config_manager.get_security_path()
ADMIN_PATH = config_manager.get_admin_path()

# 重新加载配置时需要更新的全局变量
def reload_config():
    global SECURITY_PATH, ADMIN_PATH, ADMIN_PASSWORD_HASH
    config_manager.load_config()
    SECURITY_PATH = config_manager.get_security_path()
    ADMIN_PATH = config_manager.get_admin_path()
    ADMIN_PASSWORD_HASH = config_manager.get_password_hash()
    
ADMIN_PASSWORD_HASH = config_manager.get_password_hash()

# 全局对象
forwarder = PortForwarder()
security_manager = SecurityManager()

# 蜜罐路径
HONEYPOT_PATHS = {
    '/admin', '/administrator', '/wp-admin', '/phpmyadmin', '/mysql', '/login'
}

# HTML模板
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>专业端口转发管理</title>
    <style>
        body { font-family: sans-serif; background: #f0f2f5; }
        .container { max-width: 1200px; margin: 20px auto; padding: 20px; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .card { border: 1px solid #ddd; padding: 20px; margin-bottom: 20px; border-radius: 8px; }
        .form-group { margin-bottom: 15px; }
        .form-control { width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        .btn { padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; }
        .btn-primary { background: #007bff; color: white; }
        .btn-danger { background: #dc3545; color: white; }
        .table { width: 100%; border-collapse: collapse; }
        .table th, .table td { padding: 12px; border-bottom: 1px solid #ddd; text-align: left; }
        .status-running { color: green; }
        .status-stopped { color: red; }
        .status-error { color: orange; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; }
        .login-container { max-width: 400px; margin: 100px auto; padding: 20px; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    {% if session.logged_in %}
    <div class="container">
        <h1>专业端口转发管理</h1>
        <a href="/{{ security_path }}/logout" class="btn btn-danger" style="float: right;">退出登录</a>
        
        <div class="card">
            <h3>安全状态</h3>
            <div id="securityStatus"></div>
            <button onclick="reloadConfig()">重新加载配置</button>
            <span id="configStatus"></span>
        </div>

        <div class="card stats-grid" id="stats"></div>

        <div class="card">
            <h3>添加端口转发</h3>
            <form id="addForwardForm">
                <div style="display: flex; gap: 10px;">
                    <select name="protocol" class="form-control" required><option value="tcp">TCP</option><option value="udp">UDP</option></select>
                    <input type="number" name="local_port" class="form-control" placeholder="本地端口" required>
                    <input type="text" name="remote_host" class="form-control" placeholder="远程主机" required>
                    <input type="number" name="remote_port" class="form-control" placeholder="远程端口" required>
                    <button type="submit" class="btn btn-primary">添加</button>
                </div>
            </form>
        </div>

        <div class="card">
            <h3>批量转发</h3>
            <textarea id="batchConfig" class="form-control" rows="5" placeholder='每行一条: IP|远程端口|本地端口|协议(tcp/udp, 可选)'></textarea>
            <button onclick="addBatchForwards()" class="btn btn-primary" style="margin-top: 10px;">批量添加</button>
        </div>

        <div class="card">
            <h3>活动转发列表</h3>
             <div style="margin-bottom: 10px;">
                <button onclick="selectAllForwards()">全选</button>
                <button onclick="unselectAllForwards()">取消全选</button>
                <button onclick="batchStopSelected()" class="btn btn-danger">批量停止选中</button>
            </div>
            <div id="forwardsList"></div>
        </div>
    </div>

    <script>
        function loadStats() {
            fetch('/{{ security_path }}/api/stats').then(r => r.json()).then(d => {
                document.getElementById('stats').innerHTML = `
                    <div><strong>活动转发:</strong> ${d.active_forwards}</div>
                    <div><strong>总连接数:</strong> ${d.total_connections}</div>
                    <div><strong>当前连接:</strong> ${d.active_connections}</div>
                    <div><strong>传输流量:</strong> ${formatBytes(d.bytes_transferred)}</div>
                    <div><strong>运行时间:</strong> ${formatTime(d.uptime)}</div>
                `;
            });
        }
        function loadSecurityStatus() {
            fetch('/{{ security_path }}/api/security/status').then(r => r.json()).then(d => {
                document.getElementById('securityStatus').innerHTML = `
                    <p><strong>封禁IP数:</strong> ${d.blocked_ips}</p>
                    <p><strong>失败尝试IP数:</strong> ${d.failed_attempts}</p>
                `;
                document.getElementById('configStatus').innerText = d.config_loaded ? '配置文件已加载' : '使用默认/生成配置';
            });
        }
        function reloadConfig() {
            if (confirm('确定重新加载配置? 如果密码已更改，您需要重新登录。')) {
                fetch('/{{ security_path }}/api/config/reload', { method: 'POST' })
                    .then(r => r.json()).then(d => {
                        alert(d.message || d.error);
                        if (d.success) window.location.reload();
                    });
            }
        }
        function loadForwards() {
            fetch('/{{ security_path }}/api/forwards').then(r => r.json()).then(d => {
                let html = '<table class="table"><thead><tr><th><input type="checkbox" id="selectAllCheckbox"></th><th>协议</th><th>本地端口</th><th>远程地址</th><th>状态</th><th>创建时间</th><th>操作</th></tr></thead><tbody>';
                d.forwards.forEach(f => {
                    html += `<tr>
                        <td><input type="checkbox" class="forward-checkbox" value="${f.id}"></td>
                        <td>${f.protocol}</td><td>${f.local_port}</td><td>${f.remote_host}:${f.remote_port}</td>
                        <td class="status-${f.status}">${f.status}</td><td>${new Date(f.created_time).toLocaleString()}</td>
                        <td><button onclick="stopForward('${f.id}')" class="btn btn-danger">停止</button></td>
                    </tr>`;
                });
                html += '</tbody></table>';
                document.getElementById('forwardsList').innerHTML = html;
                document.getElementById('selectAllCheckbox').onchange = (e) => {
                    document.querySelectorAll('.forward-checkbox').forEach(cb => cb.checked = e.target.checked);
                };
            });
        }
        function addBatchForwards() {
            const lines = document.getElementById('batchConfig').value.trim().split('\\n');
            const forwards = lines.filter(l => l.trim()).map(line => {
                const parts = line.split('|');
                const protocol = parts[3] || 'tcp';
                return { remote_host: parts[0], remote_port: parseInt(parts[1]), local_port: parseInt(parts[2]), protocol: protocol };
            });
            fetch('/{{ security_path }}/api/forwards/batch', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ forwards: forwards })
            }).then(r => r.json()).then(d => {
                alert(`批量添加完成! 成功: ${d.success_count}, 失败: ${d.failed_count}`);
                loadData();
            });
        }
        function selectAllForwards() { document.querySelectorAll('.forward-checkbox').forEach(c => c.checked = true); }
        function unselectAllForwards() { document.querySelectorAll('.forward-checkbox').forEach(c => c.checked = false); }
        function batchStopSelected() {
            const ids = Array.from(document.querySelectorAll('.forward-checkbox:checked')).map(c => c.value);
            if (ids.length === 0 || !confirm(`确定停止选中的 ${ids.length} 个转发?`)) return;
            fetch('/{{ security_path }}/api/forwards/batch', {
                method: 'DELETE', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ forward_ids: ids })
            }).then(r => r.json()).then(d => {
                alert(`批量停止完成! 成功: ${d.success_count}, 失败: ${d.failed_count}`);
                loadData();
            });
        }
        function stopForward(id) {
            if (confirm('确定停止此转发?')) {
                fetch('/{{ security_path }}/api/forwards/' + id, { method: 'DELETE' }).then(r => r.json()).then(d => {
                    if (d.success) loadData(); else alert('停止失败: ' + d.error);
                });
            }
        }
        document.getElementById('addForwardForm').addEventListener('submit', function(e) {
            e.preventDefault();
            fetch('/{{ security_path }}/api/forwards', { method: 'POST', body: new FormData(this) })
            .then(r => r.json()).then(d => {
                if (d.success) { this.reset(); loadData(); } else { alert('添加失败: ' + d.error); }
            });
        });
        function loadData() { loadStats(); loadForwards(); loadSecurityStatus(); }
        setInterval(loadData, 5000);
        loadData();
        function formatBytes(b) { if(b===0)return'0 B';const k=1024,s=['B','KB','MB','GB'],i=Math.floor(Math.log(b)/Math.log(k));return parseFloat((b/Math.pow(k,i)).toFixed(2))+' '+s[i]; }
        function formatTime(s) { const h=Math.floor(s/3600),m=Math.floor((s%3600)/60);return `${h}h ${m}m`; }
    </script>
    {% else %}
    <div class="login-container">
        <h2>管理员登录</h2>
        {% if error %}<p style="color:red;">{{ error }}</p>{% endif %}
        <form method="post">
            <div class="form-group"><input type="password" name="password" class="form-control" placeholder="密码" required></div>
            <button type="submit" class="btn btn-primary" style="width: 100%;">登录</button>
        </form>
    </div>
    {% endif %}
</body>
</html>
'''

@app.before_request
def security_check():
    """安全检查"""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    path = request.path
    
    if security_manager.is_ip_blocked(client_ip):
        logger.warning(f"Blocked IP {client_ip} attempted to access {path}")
        return jsonify({'error': 'Access denied'}), 403
    
    if path in HONEYPOT_PATHS:
        security_manager.record_honeypot_hit(client_ip, path)
        return "Not Found", 404
        
    if not path.startswith(f'/{SECURITY_PATH}/') and path != '/':
        if security_manager.record_scanner_behavior(client_ip, path):
             return "Not Found", 404
        return "Not Found", 404

@app.route('/')
def root_path():
    """根路径 - 返回404而不是重定向"""
    return "Not Found", 404

@app.route(ADMIN_PATH, methods=['GET', 'POST'])
def admin_route():
    """管理界面和登录处理"""
    if request.method == 'POST':
        client_ip = request.remote_addr
        password = request.form.get('password')
        if check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['logged_in'] = True
            security_manager.clear_failed_attempts(client_ip)
            logger.info(f"Successful login from {client_ip}")
            return redirect(ADMIN_PATH)
        else:
            security_manager.record_failed_attempt(client_ip)
            logger.warning(f"Failed login attempt from {client_ip}")
            return render_template_string(HTML_TEMPLATE, security_path=SECURITY_PATH, error='密码错误')
    
    if not session.get('logged_in'):
        return render_template_string(HTML_TEMPLATE, security_path=SECURITY_PATH)
    
    return render_template_string(HTML_TEMPLATE, security_path=SECURITY_PATH)

@app.route(f'/{SECURITY_PATH}/logout')
def logout():
    """退出登录"""
    session.clear()
    return redirect(ADMIN_PATH)

# --- API Routes ---
@app.route(f'/{SECURITY_PATH}/api/stats')
def api_stats():
    if not session.get('logged_in'): return jsonify({'error': 'Unauthorized'}), 401
    return jsonify(forwarder.get_stats())

@app.route(f'/{SECURITY_PATH}/api/forwards', methods=['GET', 'POST'])
def api_forwards():
    if not session.get('logged_in'): return jsonify({'error': 'Unauthorized'}), 401
    if request.method == 'GET':
        return jsonify({'forwards': forwarder.get_serializable_forwards()})
    
    try: # POST
        protocol = request.form.get('protocol')
        local_port = int(request.form.get('local_port'))
        remote_host = request.form.get('remote_host')
        remote_port = int(request.form.get('remote_port'))
        
        # Validation
        if not all([protocol, local_port, remote_host, remote_port]) or protocol not in ['tcp', 'udp'] or not (1 <= local_port <= 65535 and 1 <= remote_port <= 65535):
            return jsonify({'success': False, 'error': '无效的输入'})
        
        for f in forwarder.active_forwards.values():
            if f['local_port'] == local_port and f['protocol'] == protocol.upper():
                return jsonify({'success': False, 'error': f'本地端口 {local_port} ({protocol.upper()}) 已被占用'})
        
        forward_id = forwarder.start_forward(protocol, local_port, remote_host, remote_port)
        return jsonify({'success': True, 'forward_id': forward_id})
    except Exception as e:
        logger.error(f"Add forward error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route(f'/{SECURITY_PATH}/api/forwards/batch', methods=['POST', 'DELETE'])
def api_batch_forwards():
    if not session.get('logged_in'): return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    
    if request.method == 'POST':
        configs = data.get('forwards', [])
        success_count, failed_count = 0, 0
        for config in configs:
            try:
                forwarder.start_forward(
                    config['protocol'], int(config['local_port']), 
                    config['remote_host'], int(config['remote_port']),
                    persist=False # No save in loop
                )
                success_count += 1
            except Exception:
                failed_count += 1
        if success_count > 0:
            forwarder.save_forwards_to_disk() # Save once at the end
        return jsonify({'success': True, 'success_count': success_count, 'failed_count': failed_count})

    if request.method == 'DELETE':
        ids = data.get('forward_ids', [])
        success_count = sum(1 for fid in ids if forwarder.stop_forward(fid, persist=False))
        if success_count > 0:
            forwarder.save_forwards_to_disk() # Save once at the end
        return jsonify({'success': True, 'success_count': success_count, 'failed_count': len(ids) - success_count})

@app.route(f'/{SECURITY_PATH}/api/forwards/<forward_id>', methods=['DELETE'])
def api_stop_forward(forward_id):
    if not session.get('logged_in'): return jsonify({'error': 'Unauthorized'}), 401
    success = forwarder.stop_forward(forward_id)
    return jsonify({'success': success})

@app.route(f'/{SECURITY_PATH}/api/security/status')
def api_security_status():
    if not session.get('logged_in'): return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({
        'blocked_ips': len(security_manager.blocked_ips),
        'failed_attempts': len(security_manager.failed_attempts),
        'config_loaded': config_manager.config_file.exists(),
    })

@app.route(f'/{SECURITY_PATH}/api/config/reload', methods=['POST'])
def api_reload_config():
    if not session.get('logged_in'): return jsonify({'error': 'Unauthorized'}), 401
    try:
        reload_config()
        return jsonify({'success': True, 'message': '配置已重新加载'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def signal_handler(signum, frame):
    """信号处理器"""
    logger.info("Shutting down gracefully...")
    forwarder.running = False
    sys.exit(0)

def main():
    """主函数"""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Load forwarding rules from previous session
    forwarder.load_forwards_from_disk()
    
    print("=" * 60)
    print("专业端口转发工具启动中...")
    print(f"管理界面: http://localhost:5000{ADMIN_PATH}")
    print(f"日志文件: port_forwarder.log")
    print(f"规则持久化文件: forwards.json")
    print("=" * 60)
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False)
    except Exception as e:
        logger.error(f"Application error: {e}")
    finally:
        forwarder.running = False

if __name__ == '__main__':
    main()
