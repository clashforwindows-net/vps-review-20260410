# 2026年VPS服务器安全加固完全手册

> 精选优质VPS · 安全加固 · 运维防护手册

---

## 📋 目录

- [一、安全加固概述](#一安全加固概述)
- [二、系统初始化安全配置](#二系统初始化安全配置)
- [三、SSH安全强化](#三ssh安全强化)
- [四、防火墙配置](#四防火墙配置)
- [五、入侵检测与日志监控](#五入侵检测与日志监控)
- [六、Fail2Ban防暴力破解](#六fail2ban防暴力破解)
- [七、软件安全更新](#七软件安全更新)
- [八、DDoS防护基础](#八ddos防护基础)
- [九、安全审计清单](#九安全审计清单)
- [十、推荐入口](#十推荐入口)

---

## 一、安全加固概述

### 1.1 VPS安全威胁全景

VPS服务器面临的安全威胁可分为外部威胁和内部威胁两大类。外部威胁主要包括暴力破解、端口扫描、漏洞利用、DDoS攻击和恶意软件；内部威胁则包括配置错误、权限滥用、供应链攻击和社会工程学攻击。

根据全球安全统计数据，2025年针对VPS服务器的最常见攻击类型如下：

| 攻击类型 | 占比 | 平均损失 | 防护难度 |
|---------|------|---------|---------|
| SSH暴力破解 | 45% | ¥500-5000 | ⭐ |
| Web应用攻击 | 25% | ¥2000-20000 | ⭐⭐⭐ |
| DDoS攻击 | 15% | ¥5000+ | ⭐⭐⭐⭐ |
| 恶意软件植入 | 8% | ¥1000-10000 | ⭐⭐ |
| 供应链攻击 | 4% | ¥10000+ | ⭐⭐⭐⭐ |
| 其他 | 3% | 不等 | 不等 |

### 1.2 安全加固原则

**最小权限原则**：每个用户、服务和进程只应拥有完成其任务所需的最小权限。避免使用root账户进行日常操作，使用sudo提权；Web服务不应以root运行；数据库访问遵循最小权限原则。

**纵深防御策略**：单一安全措施无法应对所有威胁，应建立多层防御体系。网络安全层（防火墙）+ 主机安全层（SELinux/AppArmor）+ 应用安全层（WAF/安全头）+ 数据安全层（加密/备份）。

**安全即代码**：所有安全配置应以代码形式保存和版本控制，便于审计、回滚和批量部署。使用Ansible、Chef、Puppet等配置管理工具自动化安全加固流程。

**持续监控原则**：安全加固不是一次性工作，而是持续的过程。建立实时监控告警体系，定期审计日志，及时更新补丁和规则。

---

## 二、系统初始化安全配置

### 2.1 系统更新与基础包

新购VPS首要是确保系统软件处于最新状态，修复已知安全漏洞。

**Debian/Ubuntu系统**：

```bash
# 更新软件包列表
apt update

# 升级所有软件到最新版本
apt upgrade -y

# 升级系统内核和关键安全更新
apt dist-upgrade -y

# 安装基础安全工具
apt install -y \
    unattended-upgrades \
    apt-listchanges \
    needrestart \
    ufw \
    fail2ban \
    rkhunter \
    chkrootkit \
    logwatch \
    auditd

# 启用自动安全更新
dpkg-reconfigure -plow unattended-upgrades

# 需要重启时自动提醒
echo 'needrestart -u "i"' >> /etc/needrestart/needrestart.conf
```

**CentOS/RHEL/AlmaLinux系统**：

```bash
# 更新所有软件包
dnf update -y

# 安装基础安全工具
dnf install -y \
    dnf-automatic \
    firewalld \
    fail2ban \
    rkhunter \
    chkrootkit \
    aide \
    osquery

# 启用自动更新
systemctl enable --now dnf-automatic.timer
```

### 2.2 用户账户安全

**创建普通用户并配置sudo**：

```bash
# 创建新用户（替换username为实际用户名）
useradd -m -s /bin/bash -c "Admin User" username

# 设置强密码
passwd username

# 添加到sudo组（Debian/Ubuntu）
usermod -aG sudo username

# 添加到wheel组（CentOS/RHEL）
usermod -aG wheel username

# 配置sudoers文件（更精细控制）
visudo

# 添加以下内容（限制sudo使用）
username ALL=(ALL) ALL
# 禁止sudo使用环境变量
username ALL=(ALL) !/usr/bin/sudo su -
# 仅允许特定命令使用sudo
username ALL=(ALL) /usr/bin/systemctl restart nginx, /usr/bin/systemctl stop nginx
```

**禁用root账户直接登录**：

```bash
# 锁定root账户（仍可通过sudo -i提升）
passwd -l root

# 或修改SSH配置禁止root登录
sed -i 's/^PermitRootLogin.*$/PermitRootLogin no/' /etc/ssh/sshd_config

# 重启SSH服务
systemctl restart sshd
```

**密码策略配置**：

```bash
# 安装libpam-pwquality
apt install -y libpam-pwquality

# 配置密码复杂度要求
cat >> /etc/security/pwquality.conf << 'EOF'
# 最小密码长度
minlen = 12
# 至少包含大写字母数
minclass = 3
# 最多连续相同字符
maxrepeat = 2
# 用户名检查（不允许包含用户名）
difok = 3
# 禁用旧密码（最近5个）
remember = 5
# 尝试次数后锁定
retry = 3
EOF

# 配置密码过期策略
cat >> /etc/login.defs << 'EOF'
# 密码最大使用天数（90天）
PASS_MAX_DAYS 90
# 密码最小使用天数（1天）
PASS_MIN_DAYS 1
# 密码过期警告天数（7天）
PASS_WARN_AGE 7
EOF
```

### 2.3 系统内核参数优化

```bash
# 创建sysctl安全配置
cat > /etc/sysctl.d/99-security.conf << 'EOF'
# ========== 网络安全参数 ==========

# 禁用IP转发（除非用作路由器）
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# 禁用源路由包
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# 禁用ICMP重定向
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# 启用SYN Cookie（防SYN洪水攻击）
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2

# 禁止ICMP ping广播
net.ipv4.icmp_echo_ignore_broadcasts = 1

# 忽略伪造ICMP错误
net.ipv4.icmp_ignore_bogus_error_responses = 1

# 禁用路由器通告
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# ========== 内存与进程安全 ==========

# 禁用core dump
kernel.core_uses_pid = 0
kernel.core_pattern = /dev/null
* hard core 0
* soft core 0

# 禁用SysRq
kernel.sysrq = 0

# 限制内存映射区域
vm.mmap_min_addr = 65536

# ========== 文件系统安全 ==========

# 禁止访问被删除文件
fs.suid_dumpable = 0

# 限制PID数量
kernel.pid_max = 65536

# 启用ASLR
kernel.randomize_va_space = 2
EOF

# 应用配置
sysctl -p /etc/sysctl.d/99-security.conf
```

---

## 三、SSH安全强化

### 3.1 SSH配置文件加固

```bash
# 备份原始配置
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# 编辑SSH配置
vim /etc/ssh/sshd_config

# 添加以下安全配置
```

```bash
# ========== SSH安全配置 ==========

# 禁止密码认证（强制使用密钥）
PasswordAuthentication no
ChallengeResponseAuthentication no

# 允许特定用户SSH登录（替换username）
AllowUsers username admin

# 禁止空密码登录
PermitEmptyPasswords no

# 禁止root登录
PermitRootLogin no

# 禁用SSH协议版本1
Protocol 2

# 限制登录尝试次数
MaxAuthTries 3

# 限制并发连接数
MaxSessions 2

# 客户端保持连接
ClientAliveInterval 300
ClientAliveCountMax 2

# 禁用X11转发
X11Forwarding no

# 禁用TCP转发
AllowTcpForwarding no

# 禁用-agent转发
AllowAgentForwarding no

# 使用指定端口（建议修改默认22端口）
Port 22022

# 空闲超时自动断开
ClientAliveInterval 300
ClientAliveCountMax 2

# 启用严格模式
StrictModes yes

# 使用DNS反向解析（建议关闭）
UseDNS no

# GSSAPI认证（建议关闭）
GSSAPIAuthentication no

# 日志级别
LogLevel VERBOSE
```

### 3.2 SSH密钥配置

**生成ED25519密钥（推荐）**：

```bash
# 在本地机器生成ED25519密钥（更安全、更小巧）
ssh-keygen -t ed25519 -C "your_email@example.com" -f ~/.ssh/id_ed25519_vps

# 或生成RSA 4096密钥（兼容性更好）
ssh-keygen -t rsa -b 4096 -C "your_email@example.com" -f ~/.ssh/id_rsa_vps

# 复制公钥到VPS
ssh-copy-id -i ~/.ssh/id_ed25519_vps.pub username@your_vps_ip -p 22022
```

**密钥安全配置**：

```bash
# 本地~/.ssh/config配置
cat > ~/.ssh/config << 'EOF'
# VPS服务器配置
Host vps-prod
    HostName your_vps_ip
    User username
    Port 22022
    IdentityFile ~/.ssh/id_ed25519_vps
    IdentitiesOnly yes
    # 禁用主机密钥自动存储（防止中间人攻击首次连接陷阱）
    # StrictHostKeyChecking accept-new
    # 绑定网络接口
    BindInterface wlan0
    
# GitHub服务器配置
Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_github
    IdentitiesOnly yes
EOF

# 设置SSH配置权限
chmod 600 ~/.ssh/config
chmod 600 ~/.ssh/id_ed25519_vps
chmod 644 ~/.ssh/id_ed25519_vps.pub
```

### 3.3 SSH双因素认证

```bash
# 安装Google Authenticator PAM模块
apt install -y libpam-google-authenticator

# 为用户配置双因素认证
su - username
google-authenticator

# 回答以下问题：
# 是否启用时间-based令牌？→ yes
# 是否更新~/.google_authenticator文件？→ yes
# 是否禁止多次使用同一令牌？→ yes
# 是否允许60秒时间窗口？→ yes（可选no提高安全性）
# 是否启用速率限制？→ yes

# 修改SSH配置启用双因素认证
cat >> /etc/pam.d/sshd << 'EOF'
# Google Authenticator双因素认证
auth required pam_google_authenticator.so nullok
EOF

# 修改/etc/ssh/sshd_config
sed -i 's/^ChallengeResponseAuthentication.*$/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config

# 重启SSH服务
systemctl restart sshd
```

### 3.4 PowerShell SSH安全检测

```powershell
# Save as: SSH-Security-Check.ps1
# SSH安全配置检测脚本

function Test-SSHSecurity {
    Write-Host "`n==== SSH安全配置检测 ====" -ForegroundColor Cyan
    
    $sshConfig = "/etc/ssh/sshd_config"
    if (-not (Test-Path $sshConfig)) {
        Write-Host "SSH配置文件不存在" -ForegroundColor Red
        return
    }
    
    $checks = @(
        @{ Name = "禁止密码认证"; Pattern = "PasswordAuthentication\s+no"; Severity = "High" },
        @{ Name = "禁止Root登录"; Pattern = "PermitRootLogin\s+no"; Severity = "High" },
        @{ Name = "禁用空密码"; Pattern = "PermitEmptyPasswords\s+no"; Severity = "High" },
        @{ Name = "使用SSH协议2"; Pattern = "Protocol\s+2"; Severity = "High" },
        @{ Name = "MaxAuthTries限制"; Pattern = "MaxAuthTries\s+[0-3]"; Severity = "Medium" },
        @{ Name = "禁用X11转发"; Pattern = "X11Forwarding\s+no"; Severity = "Medium" },
        @{ Name = "禁用TCP转发"; Pattern = "AllowTcpForwarding\s+no"; Severity = "Medium" },
        @{ Name = "空闲超时"; Pattern = "ClientAliveInterval\s+[0-9]+"; Severity = "Low" },
        @{ Name = "双因素认证"; Pattern = "ChallengeResponseAuthentication\s+yes"; Severity = "High" }
    )
    
    $configContent = Get-Content $sshConfig -Raw
    
    foreach ($check in $checks) {
        if ($configContent -match $check.Pattern) {
            Write-Host "  ✓ $($check.Name)" -ForegroundColor Green
        } else {
            $severityColor = switch ($check.Severity) {
                "High" { "Red" }
                "Medium" { "Yellow" }
                "Low" { "Cyan" }
            }
            Write-Host "  ✗ $($check.Name) [$($check.Severity)]" -ForegroundColor $severityColor
        }
    }
}

function Test-SSHBruteForceLog {
    Write-Host "`n==== SSH暴力破解日志分析 ====" -ForegroundColor Cyan
    
    # 查找最近1小时的SSH登录失败记录
    $failedLogins = Get-Content /var/log/auth.log -Tail 1000 -ErrorAction SilentlyContinue |
        Where-Object { $_ -match "Failed password" -and $_ -match "sshd" } |
        Select-Object -Last 20
    
    if ($failedLogins) {
        Write-Host "最近登录失败记录（Top 20）:" -ForegroundColor Yellow
        $failedLogins | ForEach-Object {
            Write-Host "  $_" -ForegroundColor Red
        }
        
        # 统计失败次数
        $ipCounts = @{}
        $failedLogins | ForEach-Object {
            if ($_ -match "from\s+(\d+\.\d+\.\d+\.\d+)") {
                $ip = $Matches[1]
                $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1
            }
        }
        
        Write-Host "`n攻击源Top 5:" -ForegroundColor Yellow
        $ipCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5 | ForEach-Object {
            Write-Host "  $($_.Key): $($_.Value)次" -ForegroundColor Red
        }
    } else {
        Write-Host "未发现SSH登录失败记录" -ForegroundColor Green
    }
}

# 执行检测
Write-Host "╔════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║   VPS SSH安全配置检测工具 v1.0             ║" -ForegroundColor Magenta
Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Magenta

Test-SSHSecurity
Test-SSHBruteForceLog

Write-Host "`n建议：使用 fail2ban 自动封禁暴力破解IP" -ForegroundColor Cyan
```

---

## 四、防火墙配置

### 4.1 UFW防火墙配置

UFW（Uncomplicated Firewall）是Ubuntu/Debian默认的防火墙管理工具，提供简洁的命令行界面。

```bash
# 安装UFW（如果未预装）
apt install -y ufw

# 设置默认策略
ufw default deny incoming    # 默认拒绝所有入站
ufw default allow outgoing    # 默认允许所有出站

# 允许SSH（必须先允许，否则会断开！）
ufw allow 22022/tcp comment 'SSH Port'

# 允许HTTP/HTTPS
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'

# 允许特定IP访问
ufw allow from 192.168.1.0/24 to any port 22 comment 'Local Network SSH'

# 允许特定端口范围
ufw allow 10000:20000/tcp comment 'Application Port Range'

# 删除规则
ufw delete allow 22/tcp

# 查看规则列表（带编号）
ufw status numbered

# 删除指定编号规则
ufw delete 3

# 启用防火墙
ufw enable

# 检查状态
ufw status verbose

# 查看日志
ufw logging medium  # off/low/medium/high/full
```

### 4.2 iptables完整配置

```bash
# 创建防火墙脚本
cat > /usr/local/bin/firewall.sh << 'FIREWALL_EOF'
#!/bin/bash
# VPS防火墙配置脚本

# 清空现有规则
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# 设置默认策略
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 允许本地回环
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# 允许已建立连接
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 允许SSH（指定端口）
iptables -A INPUT -p tcp --dport 22022 -m conntrack --ctstate NEW -j ACCEPT

# 允许HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# 允许Ping（可选择性禁用）
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# 限流保护（防止SYN洪水）
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP

# 防止圣诞树攻击
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# 防止圣诞老人攻击（SYN,RST,FIN全设置）
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# 记录被拦截的包（可选）
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables-dropped: " --log-level 4

echo "防火墙规则已应用"
FIREWALL_EOF

# 添加执行权限
chmod +x /usr/local/bin/firewall.sh

# 设置开机自启（创建systemd服务）
cat > /etc/systemd/system/firewall.service << 'SERVICE_EOF'
[Unit]
Description=VPS Firewall Service
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/firewall.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE_EOF

# 启用服务
systemctl daemon-reload
systemctl enable firewall.service
systemctl start firewall.service
```

### 4.3 Cloudflare用户防火墙配置

如果使用Cloudflare CDN，服务器端防火墙配置需考虑以下情况：

```bash
# 仅允许Cloudflare IP访问80/443端口
CLOUDFLARE_IPV4=(
    "173.245.48.0/20"
    "103.21.244.0/22"
    "103.22.200.0/22"
    "103.31.4.0/22"
    "141.101.64.0/18"
    "108.162.192.0/18"
    "190.93.240.0/20"
    "188.114.96.0/20"
    "197.234.240.0/22"
    "198.41.128.0/17"
    "162.158.0.0/15"
    "104.16.0.0/13"
    "104.24.0.0/14"
    "172.64.0.0/13"
)

for cf_ip in "${CLOUDFLARE_IPV4[@]}"; do
    iptables -A INPUT -p tcp -s "$cf_ip" --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp -s "$cf_ip" --dport 443 -j ACCEPT
done

# 拒绝非Cloudflare IP访问80/443（Cloudflare反代场景）
iptables -A INPUT -p tcp --dport 80 -j DROP
iptables -A INPUT -p tcp --dport 443 -j DROP
```

---

## 五、入侵检测与日志监控

### 5.1 AIDE入侵检测系统

AIDE（Advanced Intrusion Detection Environment）是主机级别的文件完整性检查工具。

```bash
# 安装AIDE
apt install -y aide

# 初始化AIDE数据库
aideinit

# 移动生成的数据库文件
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# 自定义AIDE配置（/etc/aide/aide.conf）
cat >> /etc/aide/aide.conf << 'EOF'

# 监控敏感目录
/etc/shadow Daily
/etc/passwd Daily
/etc/group Daily
/etc/ssh/sshd_config Daily
/etc/nginx Daily
/etc/letsencrypt Daily

# 监控日志目录
/var/log Daily
/var/www Daily

# 监控启动脚本
/etc/rc.local Daily
/etc/init.d Daily
EOF

# 测试配置
aide --config=/etc/aide/aide.conf --check

# 创建定时检查任务
cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
aide --check --config=/etc/aide/aide.conf | mail -s "AIDE Report $(hostname)" admin@example.com
EOF
chmod +x /etc/cron.daily/aide-check
```

### 5.2 日志集中监控

```bash
# 安装osquery（高级日志分析）
apt install -y osquery

# 配置osquery服务
cat > /etc/osquery/osquery.conf << 'EOF'
{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "pidfile": "/var/run/osqueryd.pidfile"
  },
  "schedule": {
    "system_info": {
      "query": "SELECT hostname, cpu_type, physical_memory FROM system_info;",
      "interval": 3600
    },
    "listening_ports": {
      "query": "SELECT pid, port, protocol, address FROM listening_ports WHERE port > 0;",
      "interval": 3600
    },
    "ssh_login_failures": {
      "query": "SELECT * FROM last WHERE type='LOGIN_FAILURE';",
      "interval": 300
    },
    "suspicious_processes": {
      "query": "SELECT name, path, cmdline FROM processes WHERE name NOT IN ('systemd', 'sshd', 'nginx', 'mysqld');",
      "interval": 600
    }
  },
  "filePaths": {
    "system_procs": "/proc/%%/cmdline"
  }
}
EOF

# 启用osquery服务
systemctl enable osqueryd
systemctl start osqueryd
```

### 5.3 自动安全日志分析脚本

```bash
#!/bin/bash
# Save as: /usr/local/bin/security-log-report.sh
# 安全日志自动分析报告

LOG_FILE="/var/log/security-report-$(date +%Y%m%d).txt"

exec > >(tee -a "$LOG_FILE")
exec 2>&1

echo "========================================"
echo " VPS安全日志分析报告"
echo " 生成时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================"

echo ""
echo "【1. SSH登录统计】"
echo "----------------------------------------"
echo "成功登录次数: $(grep 'Accepted' /var/log/auth.log | wc -l)"
echo "失败登录次数: $(grep 'Failed password' /var/log/auth.log | wc -l)"
echo "无效用户尝试: $(grep 'Invalid user' /var/log/auth.log | wc -l)"

echo ""
echo "【2. 攻击源分析（Top 10）】"
echo "----------------------------------------"
echo "SSH暴力破解IP统计:"
grep 'Failed password' /var/log/auth.log | grep -oP '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn | head -10

echo ""
echo "【3. 端口扫描检测】"
echo "----------------------------------------"
echo "连接同一端口不同IP数: $(grep 'Connection refused' /var/log/auth.log | grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u | wc -l)"

echo ""
echo "【4. 关键文件变更检测】"
echo "----------------------------------------"
echo "passwd文件变更: $(stat -c '%Y' /etc/passwd 2>/dev/null)"
echo "shadow文件变更: $(stat -c '%Y' /etc/shadow 2>/dev/null)"
echo "sshd_config变更: $(stat -c '%Y' /etc/ssh/sshd_config 2>/dev/null)"

echo ""
echo "【5. 资源使用情况】"
echo "----------------------------------------"
echo "内存使用率: $(free | grep Mem | awk '{printf "%.1f%%", $3/$2 * 100}')"
echo "磁盘使用率: $(df -h / | tail -1 | awk '{print $5}')"
echo "负载平均值: $(uptime | awk -F'load average:' '{print $2}')"

echo ""
echo "【6. 最近系统事件】"
echo "----------------------------------------"
journalctl -n 20 --no-pager --since "24 hours ago" | grep -iE "error|warning|failed|critical" | tail -10

echo ""
echo "========================================"
echo " 报告生成完毕"
echo "========================================"
```

---

## 六、Fail2Ban防暴力破解

### 6.1 Fail2Ban安装与配置

```bash
# 安装Fail2Ban
apt install -y fail2ban

# 复制默认配置
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# 编辑Jail配置
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# 屏蔽时间（秒）- 1小时
bantime = 3600
# 查找时间窗口（秒）- 10分钟
findtime = 600
# 最大重试次数
maxretry = 3
# 忽略指定IP
ignoreip = 127.0.0.1/8 ::1 1.2.3.4  # 添加你的IP白名单
# 忽略国家（需安装）
ignorecommand = /usr/local/bin/fail2ban-check-country

[sshd]
enabled = true
port = 22022
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400
findtime = 600

[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 5

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 3

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-nohome]
enabled = true
port = http,https
filter = nginx-nohome
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-noproxy]
enabled = true
port = http,https
filter = nginx-noproxy
logpath = /var/log/nginx/access.log
maxretry = 2
EOF

# 创建自定义过滤器
cat > /etc/fail2ban/filter.d/nginx-nohome.conf << 'EOF'
[Definition]
failregex = ^<HOST> -.*GET.*/\..* HTTP/1\.(0|1)$
          ^<HOST> -.*GET.*~.* HTTP/1\.(0|1)$
ignoreregex =
EOF

# 启动并设置开机自启
systemctl enable fail2ban
systemctl start fail2ban

# 查看状态
fail2ban-client status
fail2ban-client status sshd
```

### 6.2 Fail2Ban PowerShell监控

```powershell
# Save as: Fail2Ban-Monitor.ps1
# Fail2Ban状态监控脚本

function Get-Fail2BanStatus {
    Write-Host "`n==== Fail2Ban状态监控 ====" -ForegroundColor Cyan
    
    try {
        # 获取所有Jail状态
        $status = fail2ban-client status 2>$null
        if ($status) {
            Write-Host "Fail2Ban运行中" -ForegroundColor Green
            
            # 提取各Jail信息
            $status | Out-String -Stream | Select-Object -Skip 2 | ForEach-Object {
                if ($_ -match '^\s+\[') {
                    Write-Host $_.Trim() -ForegroundColor Yellow
                }
            }
        }
    } catch {
        Write-Host "无法获取Fail2Ban状态: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Get-BannedIPs {
    Write-Host "`n==== 已屏蔽IP列表 ====" -ForegroundColor Cyan
    
    # SSH屏蔽记录
    try {
        $sshBans = iptables -L INPUT -n --line-numbers 2>$null | Where-Object { $_ -match 'f2b-sshd' }
        if ($sshBans) {
            Write-Host "`nSSH-DDoS屏蔽列表:" -ForegroundColor Yellow
            $sshBans | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        } else {
            Write-Host "SSH无屏蔽记录" -ForegroundColor Green
        }
    } catch {
        Write-Host "无法读取iptables: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Get-FailedLoginStats {
    Write-Host "`n==== 登录失败统计 ====" -ForegroundColor Cyan
    
    $logPath = "/var/log/auth.log"
    if (Test-Path $logPath) {
        $today = Get-Date -Format "MMM dd"
        $failedCount = Select-String -Path $logPath -Pattern "Failed password" |
            Where-Object { $_.Line -match $today } |
            Measure-Object | Select-Object -ExpandProperty Count
        
        $bannedPattern = Select-String -Path $logPath -Pattern "BAN" |
            Where-Object { $_.Line -match $today } |
            Measure-Object | Select-Object -ExpandProperty Count
        
        Write-Host "今日登录失败: $failedCount 次" -ForegroundColor Yellow
        Write-Host "今日Ban操作: $bannedPattern 次" -ForegroundColor $(if ($bannedPattern -gt 0) { "Red" } else { "Green" })
    } else {
        Write-Host "日志文件不存在" -ForegroundColor Red
    }
}

# 执行监控
Write-Host "╔════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║   Fail2Ban状态监控工具 v1.0                ║" -ForegroundColor Magenta
Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Magenta

Get-Fail2BanStatus
Get-BannedIPs
Get-FailedLoginStats

Write-Host "`n建议定期检查屏蔽IP，确认真实IP未被误封。" -ForegroundColor Cyan
```

---

## 七、软件安全更新

### 7.1 自动安全更新配置

```bash
# 安装unattended-upgrades
apt install -y unattended-upgrades

# 配置自动更新
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    // 启用此行以自动升级发布版
    // "${distro_id}:${distro_codename}-updates";
    // "${distro_id}:${distro_codename}-proposed-updates";
};

Unattended-Upgrade::Mail "admin@example.com";  // 通知邮箱
Unattended-Upgrade::MailOnlyOnError "true";    // 仅错误时通知

// 自动移除不再需要的依赖
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// 自动重启（仅在必要时）
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";  // 凌晨3点重启
EOF

# 配置自动更新日程
cat > /etc/apt/apt.conf.d/02periodic << 'EOF'
APT::Periodic::Enable "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Verbose "2";
EOF
```

### 7.2 内核热更新

```bash
# 检查可用内核
dpkg --list | grep linux-image

# 安装最新内核
apt install -y linux-image-$(uname -r | sed 's/-generic//')-generic

# 更新GRUB
update-grub

# 配置自动删除旧内核
cat > /etc/kernel/postinst.d/update-grub {
    #!/bin/sh
    set -e
    /usr/sbin/update-grub
}
chmod +x /etc/kernel/postinst.d/update-grub

# 启用内核自动更新
cat >> /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Package-Blacklist {
    // 内核包不自动更新（避免启动问题）
    "linux-image-.*";
    "linux-headers-.*";
};
EOF
```

---

## 八、DDoS防护基础

### 8.1 SynFlood防护

```bash
# 添加到/etc/sysctl.conf
cat >> /etc/sysctl.conf << 'EOF'

# ========== DDoS防护 ==========

# SYN Cookie
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2

# TCP连接限制
net.ipv4.tcp_max_orphans = 262144
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_fin_timeout = 30

# IP连接数限制（防止单IP攻击）
net.ipv4.ip_conntrack_max = 1000000
net.netfilter.nf_conntrack_max = 1000000
EOF

sysctl -p
```

### 8.2 连接数限制

```bash
# 限制单IP最大连接数（80端口WEB服务）
iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 100 --connlimit-mask 32 -j DROP

# 限制单IP新建连接数（每分钟）
iptables -A INPUT -p tcp --dport 80 --syn -m recent --set --name WEB --rsource
iptables -A INPUT -p tcp --dport 80 --syn -m recent --update --seconds 60 --hitcount 30 --name WEB --rsource -j DROP

# 限制ICMP Ping量
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
```

---

## 九、安全审计清单

### 9.1 部署前检查

| 检查项 | 标准 | 操作 |
|--------|------|------|
| 系统更新 | 所有软件最新 | apt update && apt upgrade |
| SSH密钥 | 仅密钥认证 | 禁用密码登录 |
| SSH端口 | 非22端口 | 修改为22022 |
| root登录 | 已禁用 | PermitRootLogin no |
| 防火墙 | 已启用 | UFW/iptables |
| Fail2Ban | 已启用 | 防暴力破解 |
| 用户权限 | 最小权限 | sudoers配置 |
| 密码策略 | 复杂度要求 | pwquality配置 |

### 9.2 定期审计检查

```bash
#!/bin/bash
# 安全审计脚本 - 建议每周运行一次
echo "=== VPS安全审计检查 ==="

checks=(
    "SSH配置: $(grep '^PermitRootLogin no' /etc/ssh/sshd_config && echo 'OK' || echo 'FAIL')"
    "防火墙: $(ufw status | grep 'Status: active' && echo 'OK' || echo 'FAIL')"
    "Fail2Ban: $(systemctl is-active fail2ban && echo 'OK' || echo 'FAIL')"
    "系统更新: $(apt list --upgradable 2>/dev/null | grep -c 'upgradable' || echo '0') 个可更新包"
    "登录失败: $(grep -c 'Failed password' /var/log/auth.log 2>/dev/null || echo '0') 次"
    "屏蔽IP数: $(fail2ban-client status sshd | grep 'Currently banned' | grep -oE '[0-9]+')"
    "磁盘使用: $(df -h / | tail -1 | awk '{print $5}')"
    "内存使用: $(free | grep Mem | awk '{printf "%.1f%%\n", $3/$2 * 100}')"
)

for check in "${checks[@]}"; do
    echo "$check"
done
```

---

## 十、推荐入口

### 🔥 VPSVIP

> 精选VPS服务 · 全方位运维支持

| 入口 | 说明 |
|------|------|
| [VPSVIP官网](https://vpsvip.net) | 精选VPS · 专业运维 |
| [ClashVIP](https://clashvip.net) | 代理服务 |
| [导航站](https://nav.clashvip.net) | 快速入口 |
| [论坛](https://bbs.clashhub.net) | 技术社区 |

### 🛡️ 安全工具速查

| 工具 | 用途 | 优先级 |
|------|------|--------|
| Fail2Ban | 防暴力破解 | ⭐⭐⭐⭐⭐ |
| UFW/iptables | 防火墙 | ⭐⭐⭐⭐⭐ |
| AIDE | 文件完整性 | ⭐⭐⭐⭐ |
| rkhunter | Rootkit检测 | ⭐⭐⭐ |
| ClamAV | 恶意软件 | ⭐⭐⭐ |

---

**更新日期**: 2026-08-28  
**版本**: v2.1 | VPS安全加固完全手册  
**免责**: 本指南仅供技术学习参考，请遵守当地法律法规

---

*本页面内容已深度扩展，基于VPS安全加固最佳实践与运维经验，差异化聚焦"VPS安全加固"主题，涵盖从系统初始化到DDoS防护的完整安全体系。*

> 🔗 推广入口：[VPSVIP](https://vpsvip.net) | [ClashVIP](https://clashvip.net) | [导航站](https://nav.clashvip.net) | [论坛](https://bbs.clashhub.net) | [Clash for Windows](https://clash-for-windows.net)
