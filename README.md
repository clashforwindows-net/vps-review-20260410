# 2026年最新VPS安全加固与防火墙实战完整手册

> [!CAUTION]
> 本项目内容仅供学习与授权渗透测试使用。禁止用于未授权攻击、入侵他人系统或任何非法用途。使用者需自行承担风险。

---

<!-- 目录导航 -->
- [🚀 VPS安全加固与防火墙实战完整手册](#-vps安全加固与防火墙实战完整手册)
  - [一、系统初始化与基础环境](#一系统初始化与基础环境)
  - [二、SSH安全加固](#二ssh安全加固)
  - [三、防火墙架构设计](#三防火墙架构设计)
  - [四、系统日志集中分析](#四系统日志集中分析)
  - [五、入侵检测与响应](#五入侵检测与响应)
  - [六、Fail2Ban自动化防护](#六fail2ban自动化防护)
  - [七、自动安全更新](#七自动安全更新)
  - [八、DDoS防护体系](#八ddos防护体系)
  - [九、安全巡检清单](#九安全巡检清单)
  - [十、推荐工具与资源](#十推荐工具与资源)

---

## 一、系统初始化与基础环境

### 1.1 VPS基础安全配置

首次登录VPS后，建议执行以下初始化步骤，涵盖系统更新、网络优化与基础服务安装。

```bash
# 系统更新与基础工具安装（Debian/Ubuntu）
apt update && apt upgrade -y

# 安装防火墙与安全工具
apt install -y unattended-upgrades \
    ufw \
    fail2ban \
    rkhunter \
    chkrootkit \
    logwatch \
    auditd

# 安装网络分析工具
apt install -y tcpdump tshark nmap net-tools iptraf-ng
apt install -y dnsutils whois curl wget git

# 内核参数优化（/etc/sysctl.conf）
cat >> /etc/sysctl.conf << 'EOF'
# === VPS安全加固参数 ===

# IP转发禁用（除非需要NAT）
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# 关闭源路由
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# 关闭ICMP重定向
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# 开启Syn Cookie防护
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2

# ICMP Echo过滤（可选，防止ICMP flood）
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# 关闭IP数据包ID标识（隐藏系统指纹）
net.ipv4.ip_dynaddr = 0

# 内核随机化
kernel.randomize_va_space = 2

# 禁止Core Dump
kernel.core_uses_pid = 0
* hard core 0
* soft core 0

# SysRq键控制（防止意外重启）
kernel.sysrq = 0

# 虚拟内存保护
vm.mmap_min_addr = 65536

# PID最大数量限制
kernel.pid_max = 65536

# ASLR随机化
kernel.randomize_va_space = 2

# === 性能与网络参数 ===
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
EOF

# 立即生效
sysctl -p
```

### 1.2 CentOS/RHEL/AlmaLinux初始化

```bash
# CentOS/RHEL/AlmaLinux 基础安全配置
dnf update -y

dnf install -y \
    firewalld \
    fail2ban \
    rkhunter \
    aide \
    openscap-scanner \
    clamav \
    clamav-update \
    tcpdump \
    nmap

# 启用自动安全更新
systemctl enable --now dnf-automatic.timer
```

### 1.3 用户权限精细化配置

```bash
# 创建管理员用户（禁用root直接登录）
useradd -m -s /bin/bash -c "Admin User" username
passwd username

# 添加sudo权限
usermod -aG sudo username

# 为特定用户设置SSH密钥登录限制
usermod -aG ssh-only username
usermod -s /usr/sbin/nologin username

# 限制su命令使用
usermod -aG wheel username
# 启用wheel组sudo
pamwheelctl enable

# 查看谁有sudo权限
cat /etc/sudoers | grep -v '^#' | grep -v '^$'
# 查看wheel组成员
getent group wheel
# 查看所有系统用户
vipw
```

### 1.4 root权限精细管控

```bash
# 禁止root登录SSH
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# 设置SSH密钥后重启SSH
systemctl restart sshd

# 限制可执行sudo的用户组
cat >> /etc/sudoers.d/custom-limits << 'EOF'
# 仅wheel组成员可使用sudo
%wheel ALL=(ALL) ALL

# 限制特定命令的sudo执行（免密）
username ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx, /usr/bin/systemctl status nginx
username ALL=(ALL) NOPASSWD: /usr/bin/apt update, /usr/bin/apt upgrade
# 禁止使用sudo执行shell
username ALL=(ALL) !/bin/bash, !/bin/sh, !/usr/bin/passwd
EOF
chmod 440 /etc/sudoers.d/custom-limits
```

### 1.5 PowerShell安全巡检脚本

```powershell
# 保存为： System-Security-Audit.ps1
# VPS安全巡检脚本 - 自动化安全基线检查

function Test-SystemSecurity {
    Write-Host "`n#====== VPS系统安全巡检 ======#" -ForegroundColor Cyan
    Write-Host "# 时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host "#=======================================`n" -ForegroundColor Cyan

    # 1. SSH安全检查
    Test-SSHSecurity

    # 2. 防火墙状态检查
    Test-FirewallStatus

    # 3. 异常登录检测
    Test-FailedLogins

    # 4. 开放端口审计
    Test-OpenPorts

    # 5. 系统更新状态
    Test-SystemUpdates

    # 6. 关键文件完整性
    Test-FileIntegrity
}

function Test-SSHSecurity {
    Write-Host "`n[1] SSH安全配置检查" -ForegroundColor Yellow
    $sshConfig = "/etc/ssh/sshd_config"
    if (-not (Test-Path $sshConfig)) {
        Write-Host "  [ERROR] SSH配置文件未找到" -ForegroundColor Red
        return
    }

    $checks = @(
        @{ Name = "禁止密码登录"; Pattern = "PasswordAuthentication\s+no"; Severity = "High" },
        @{ Name = "禁止Root登录"; Pattern = "PermitRootLogin\s+no"; Severity = "High" },
        @{ Name = "SSH协议版本2"; Pattern = "Protocol\s+2"; Severity = "High" },
        @{ Name = "最大认证尝试次数≤3"; Pattern = "MaxAuthTries\s+[0-3]"; Severity = "High" },
        @{ Name = "X11Forwarding关闭"; Pattern = "X11Forwarding\s+no"; Severity = "Medium" },
        @{ Name = "禁止空密码"; Pattern = "PermitEmptyPasswords\s+no"; Severity = "High" },
        @{ Name = "禁用DNS查询"; Pattern = "UseDNS\s+no"; Severity = "Medium" },
        @{ Name = "GSSAPI认证关闭"; Pattern = "GSSAPIAuthentication\s+no"; Severity = "Medium" },
        @{ Name = "日志级别VERBOSE"; Pattern = "LogLevel\s+VERBOSE"; Severity = "Medium" }
    )

    $configContent = Get-Content $sshConfig -Raw

    foreach ($check in $checks) {
        if ($configContent -match $check.Pattern) {
            Write-Host "  [OK] $($check.Name)" -ForegroundColor Green
        } else {
            $color = if ($check.Severity -eq "High") { "Red" } else { "Yellow" }
            Write-Host "  [WARN] $($check.Name) [$($check.Severity)]" -ForegroundColor $color
        }
    }
}

function Test-FirewallStatus {
    Write-Host "`n[2] 防火墙状态检查" -ForegroundColor Yellow

    # UFW状态
    $ufw = ufw status 2>$null
    if ($LASTEXITCODE -eq 0) {
        $status = if ($ufw -match "Status: active") { "已启用" } else { "未启用" }
        $color = if ($ufw -match "Status: active") { "Green" } else { "Red" }
        Write-Host "  UFW防火墙: $status" -ForegroundColor $color
    }

    # iptables规则数
    $iptRules = iptables -L -n 2>$null | Select-String "Chain"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  iptables链数量: $($iptRules.Count)" -ForegroundColor Cyan
    }
}

function Test-FailedLogins {
    Write-Host "`n[3] SSH异常登录检测" -ForegroundColor Yellow

    $failedLogins = Get-Content /var/log/auth.log -Tail 1000 -ErrorAction SilentlyContinue |
        Where-Object { $_ -match "Failed password" -and $_ -match "sshd" } |
        Select-Object -Last 20

    if ($failedLogins) {
        Write-Host "  最近失败登录尝试: $($failedLogins.Count)次" -ForegroundColor Yellow

        # 统计TOP攻击IP
        $ipCounts = @{}
        $failedLogins | ForEach-Object {
            if ($_ -match 'from\s+(\d+\.\d+\.\d+\.\d+)') {
                $ip = $Matches[1]
                $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1
            }
        }

        Write-Host "`n  攻击来源TOP 5:" -ForegroundColor Cyan
        $ipCounts.GetEnumerator() | Sort-Object Value -Descending |
            Select-Object -First 5 | ForEach-Object {
                Write-Host "    $($_.Key): $($_.Value)次" -ForegroundColor Red
            }
    } else {
        Write-Host "  SSH安全：无失败登录记录" -ForegroundColor Green
    }
}

function Test-OpenPorts {
    Write-Host "`n[4] 开放端口审计" -ForegroundColor Yellow
    $listeningPorts = netstat -tulnp 2>$null | Select-Object -Skip 2

    $suspiciousPorts = @(22, 23, 21, 25, 3389, 5900)
    $foundSuspicious = $false

    foreach ($line in $listeningPorts) {
        if ($line -match ':(\d+)\s+' -and $suspiciousPorts -contains [int]$Matches[1]) {
            if (-not $foundSuspicious) {
                Write-Host "  需关注的高危端口:" -ForegroundColor Yellow
                $foundSuspicious = $true
            }
            Write-Host "    $line" -ForegroundColor Red
        }
    }

    if (-not $foundSuspicious) {
        Write-Host "  未发现高危开放端口" -ForegroundColor Green
    }
}

function Test-SystemUpdates {
    Write-Host "`n[5] 系统更新状态" -ForegroundColor Yellow
    $updates = apt list --upgradable 2>/dev/null | Select-Object -Skip 1 | Measure-Object
    if ($updates.Count -gt 0) {
        Write-Host "  待更新软件包: $($updates.Count)个" -ForegroundColor Yellow
    } else {
        Write-Host "  系统已是最新版本" -ForegroundColor Green
    }

    # 内存使用
    $mem = free | awk 'NR==2{printf "%.1f%%", $3/$2*100}'
    Write-Host "  内存使用率: $mem" -ForegroundColor Cyan

    # 磁盘使用
    $disk = df -h / | tail -1 | awk '{print $5}'
    Write-Host "  磁盘使用率: $disk" -ForegroundColor Cyan

    # 系统负载
    $load = uptime | awk -F'load average:' '{print $2}'
    Write-Host "  系统负载: $load" -ForegroundColor Cyan
}

function Test-FileIntegrity {
    Write-Host "`n[6] 关键文件完整性检查" -ForegroundColor Yellow
    $criticalFiles = @(
        "/etc/passwd",
        "/etc/shadow",
        "/etc/ssh/sshd_config",
        "/etc/group",
        "/etc/gshadow"
    )

    foreach ($file in $criticalFiles) {
        if (Test-Path $file) {
            $perms = stat -c '%a' $file 2>$null
            $color = if ($perms -eq "644" -or $perms -eq "640") { "Green" } else { "Yellow" }
            Write-Host "  $file (权限: $perms)" -ForegroundColor $color
        }
    }
}

# 执行巡检
Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host "   VPS安全巡检报告 v1.0" -ForegroundColor Magenta
Write-Host "========================================`n" -ForegroundColor Magenta

Test-SystemSecurity

Write-Host "`n#====== 巡检完成 ======#" -ForegroundColor Cyan
Write-Host "# 建议: 发现WARN项请立即修复，High优先处理" -ForegroundColor Cyan
```

---

## 二、SSH安全加固

### 2.1 SSH配置文件深度优化

```bash
# 备份原配置
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# 编辑SSH配置
vi /etc/ssh/sshd_config

# ====================== SSH安全配置详解 ======================

# === 基础安全 ===
PasswordAuthentication no                      # 禁用密码登录（必须先配置密钥）
ChallengeResponseAuthentication no             # 禁用挑战响应认证

# === 允许指定用户密钥登录 ===
AllowUsers username                            # 仅允许特定用户登录

# === 禁用空密码 ===
PermitEmptyPasswords no

# === 禁止root登录 ===
PermitRootLogin no

# === 协议版本 ===
Protocol 2

# === 空闲超时 ===
ClientAliveInterval 300                        # 300秒无活动断开
ClientAliveCountMax 2

# === 连接限制 ===
MaxAuthTries 3
MaxSessions 2

# === X11转发关闭 ===
X11Forwarding no

# === DNS关闭 ===
UseDNS no

# === GSSAPI关闭 ===
GSSAPIAuthentication no

# === 监听端口（建议改为非标准端口） ===
Port 22022

# === 严格模式 ===
StrictModes yes

# === 日志级别 ===
LogLevel VERBOSE

# === 开启公钥认证 ===
PubkeyAuthentication yes

# === 关闭agent转发 ===
AllowAgentForwarding no

# === 关闭TCP转发 ===
AllowTcpForwarding no
```

### 2.2 SSH密钥对生成与配置

```bash
# 生成Ed25519密钥（推荐，性能更高，密钥更短）
ssh-keygen -t ed25519 -C "your_email@example.com" -f ~/.ssh/id_ed25519_vps

# RSA备用方案（4096位，兼容旧系统）
ssh-keygen -t rsa -b 4096 -C "your_email@example.com" -f ~/.ssh/id_rsa_vps

# 上传公钥到VPS
ssh-copy-id -i ~/.ssh/id_ed25519_vps.pub username@your_vps_ip -p 22022

# 配置SSH客户端 ~/.ssh/config
cat > ~/.ssh/config << 'EOF'
# VPS生产环境
Host vps-prod
    HostName your_vps_ip
    User username
    Port 22022
    IdentityFile ~/.ssh/id_ed25519_vps
    IdentitiesOnly yes
    # 严格主机密钥检查
    # StrictHostKeyChecking accept-new
    # 防止多密钥冲突
    AddKeysToAgent yes

# GitHub
Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_github
    IdentitiesOnly yes
EOF

chmod 600 ~/.ssh/config
```

### 2.3 Google Authenticator双因素认证

```bash
# 安装Google Authenticator PAM模块
apt install -y libpam-google-authenticator

# 为用户配置两步验证（需配合手机APP）
su - username
google-authenticator

# 生成的二维码用Google Authenticator APP扫描
# 记录紧急验证码保存在安全位置

# 配置PAM认证规则 /etc/pam.d/sshd
# 在 /etc/pam.d/sshd 末尾添加
auth required pam_google_authenticator.so nullok

# 启用ChallengeResponse认证
# 在/etc/pam.d/sshd中取消这行注释（或添加）
# auth       substack     password-auth

# 配置/etc/ssh/sshd_config
# 启用挑战响应认证
sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config

# SSH登录测试（不要退出当前会话！）
systemctl restart sshd

# 同时验证：密钥 + Google Authenticator码才能登录
```

### 2.4 PowerShell SSH安全检测脚本

```powershell
# 保存为： SSH-Security-Check.ps1
# SSH安全配置深度检测与Fail2Ban联动

function Test-SSHSecurityHardening {
    Write-Host "`n========== SSH安全加固检测 ==========" -ForegroundColor Cyan

    $sshConfig = "/etc/ssh/sshd_config"
    if (-not (Test-Path $sshConfig)) {
        Write-Host "[ERROR] SSH配置文件未找到" -ForegroundColor Red
        return
    }

    $hardeningChecks = @(
        @{ Name = "禁用密码认证"; Pattern = "PasswordAuthentication\s+no"; Severity = "High"; Description = "防止暴力破解密码" },
        @{ Name = "禁用Root登录"; Pattern = "PermitRootLogin\s+no"; Severity = "High"; Description = "root账户是最高权限目标" },
        @{ Name = "SSH协议版本2"; Pattern = "Protocol\s+2"; Severity = "High"; Description = "SSHv1存在已知漏洞" },
        @{ Name = "最大认证次数≤3"; Pattern = "MaxAuthTries\s+[0-3]"; Severity = "High"; Description = "限制暴力破解尝试" },
        @{ Name = "X11转发关闭"; Pattern = "X11Forwarding\s+no"; Severity = "Medium"; Description = "防止X11泄露" },
        @{ Name = "禁用空密码"; Pattern = "PermitEmptyPasswords\s+no"; Severity = "High"; Description = "空密码等于无密码" },
        @{ Name = "禁用DNS查询"; Pattern = "UseDNS\s+no"; Severity = "Medium"; Description = "加速连接，防止DNS投毒" },
        @{ Name = "禁用GSSAPI"; Pattern = "GSSAPIAuthentication\s+no"; Severity = "Medium"; Description = "减少攻击面" },
        @{ Name = "日志级别VERBOSE"; Pattern = "LogLevel\s+VERBOSE"; Severity = "Low"; Description = "记录详细登录信息" },
        @{ Name = "空闲超时设置"; Pattern = "ClientAliveInterval\s+[0-9]+"; Severity = "Medium"; Description = "防止僵尸会话" }
    )

    $configContent = Get-Content $sshConfig -Raw

    $passCount = 0
    $failCount = 0

    foreach ($check in $hardeningChecks) {
        $matched = $configContent -match $check.Pattern
        $color = if ($matched) { "Green" } elseif ($check.Severity -eq "High") { "Red" } else { "Yellow" }
        $status = if ($matched) { "[PASS]" } else { "[FAIL]" }

        Write-Host "  $status $($check.Name)" -ForegroundColor $color
        if ($matched) { $passCount++ } else { $failCount++ }
    }

    Write-Host "`n  统计: 通过 $passCount / 失败 $failCount" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Yellow" })
}

function Test-SSHBruteForceLogs {
    Write-Host "`n========== SSH暴力破解检测 ==========" -ForegroundColor Cyan

    $failedLogins = Get-Content /var/log/auth.log -Tail 1000 -ErrorAction SilentlyContinue |
        Where-Object { $_ -match "Failed password" -and $_ -match "sshd" }

    if ($failedLogins) {
        Write-Host "  检测到失败登录: $($failedLogins.Count)次" -ForegroundColor Yellow

        # 提取攻击IP并统计频率
        $ipCounts = @{}
        $failedLogins | ForEach-Object {
            if ($_ -match 'from\s+(\d+\.\d+\.\d+\.\d+)') {
                $ip = $Matches[1]
                $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1
            }
        }

        Write-Host "`n  攻击来源统计（按频率排序）:" -ForegroundColor Cyan
        $sortedIPs = $ipCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
        $rank = 1
        foreach ($ip in $sortedIPs) {
            $barLen = [Math]::Min($ip.Value / 5, 40)
            $bar = "#" * $barLen
            Write-Host "    $rank. $($ip.Key): $($ip.Value)次 $bar" -ForegroundColor $(if ($ip.Value -gt 20) { "Red" } elseif ($ip.Value -gt 10) { "Yellow" } else { "Green" })
            $rank++
        }

        # 检查是否需要触发Fail2Ban
        $maxAttempts = ($ipCounts.Values | Measure-Object -Maximum).Maximum
        if ($maxAttempts -gt 5) {
            Write-Host "`n  [ALERT] 检测到持续攻击，建议检查Fail2Ban状态" -ForegroundColor Red
        }
    } else {
        Write-Host "  SSH安全状态良好：无失败登录记录" -ForegroundColor Green
    }
}

# 执行检测
Test-SSHSecurityHardening
Test-SSHBruteForceLogs

Write-Host "`n========== 检测完成 ==========" -ForegroundColor Cyan
Write-Host "建议：定期运行此脚本监控SSH安全状态" -ForegroundColor Gray
```

---

## 三、防火墙架构设计

### 3.1 UFW前端封装配置

UFW（Uncomplicated Firewall）是iptables的前端封装，适合快速部署与日常管理。

```bash
# 安装UFW
apt install -y ufw

# 设置默认策略（先禁止所有，再放行需要的）
ufw default deny incoming     # 默认拒绝入站
ufw default allow outgoing    # 默认允许出站

# 开放SSH端口（注意：先开放再启用！否则会把自己锁在外面）
ufw allow 22022/tcp comment 'SSH Port'

# 开放常用服务
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw allow 40000:50000/tcp comment 'Application Port Range'

# 从本地网络放行（192.168.x.x段）
ufw allow from 192.168.0.0/24 to any port 22 comment 'Local Network SSH'

# 限制SSH连接频率（防止暴力破解）
ufw limit 22022/tcp comment 'SSH Rate Limit'

# 删除规则
ufw delete allow 23/tcp

# 查看状态
ufw status numbered

# 日志配置
ufw logging medium  # off/low/medium/high/full

# 启用UFW
ufw enable

# 重启后自动启动
ufw auto boot

# 查看详细日志
ufw status verbose
```

### 3.2 iptables四表五链深度配置

iptables是Linux内核级防火墙，完整掌握四表五链是安全工程师的必备技能。

```bash
# 保存当前规则（备份）
iptables-save > /root/iptables.backup.$(date +%Y%m%d)

# 创建自定义防火墙脚本 /usr/local/bin/firewall.sh
cat > /usr/local/bin/firewall.sh << 'FIREWALL_EOF'
#!/bin/bash
# VPS Firewall - iptables安全防火墙脚本

# 清除现有规则
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

# === RAW表：连接追踪控制 ===
iptables -t raw -A PREROUTING -p tcp --dport 80 -m conntrack --ctstate NEW -j NOTRACK
iptables -t raw -A PREROUTING -p tcp --dport 443 -m conntrack --ctstate NEW -j NOTRACK

# === FILTER表：INPUT链 ===
# 允许本地回环
iptables -A INPUT -i lo -j ACCEPT

# 允许已建立连接
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 允许特定IP的SSH连接（白名单）
iptables -A INPUT -p tcp -s 1.2.3.4 --dport 22022 -m conntrack --ctstate NEW -j ACCEPT

# ICMP协议（允许ping，禁止flood）
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/min --limit-burst 10 -j ACCEPT

# 开放HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# DNS响应（允许已建立连接的DNS响应）
iptables -A INPUT -p udp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# === SYN-Flood防护 ===
iptables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -m recent --set --name SYN_FLOOD
iptables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 20 --name SYN_FLOOD -j DROP

# === 限流SSH防暴力破解 ===
iptables -A INPUT -p tcp --dport 22022 -m conntrack --ctstate NEW -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 22022 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
iptables -A INPUT -p tcp --dport 22022 -m conntrack --ctstate NEW -j ACCEPT

# === ICMP限流 ===
iptables -A INPUT -p icmp -m limit --limit 5/second --limit-burst 10 -j ACCEPT
iptables -A INPUT -p icmp -j DROP

# === LOG记录被丢弃的包 ===
iptables -A INPUT -m limit --limit 5/min --limit-burst 5 -j LOG --log-prefix "iptables-dropped: " --log-level 4

echo "Firewall rules applied successfully."
FIREWALL_EOF

chmod +x /usr/local/bin/firewall.sh

# 配置为系统服务 /etc/systemd/system/firewall.service
cat > /etc/systemd/system/firewall.service << 'EOF'
[Unit]
Description=VPS Firewall Service
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/firewall.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable firewall.service
systemctl start firewall.service
```

### 3.3 Cloudflare白名单与源站保护

Cloudflare是DDoS防护的重要环节，正确配置IP白名单可防止攻击者绕过CDN直接攻击源站。

```bash
# Cloudflare IP Ranges（2024年更新）
CLOUDFLARE_IPV4=(
    "173.245.48.0/20"
    "103.21.244.0/22"
    "103.22.200.0/22"
    "103.31.4.0/22"
    "141.101.64.0/18"
    "108.162.192.0/18"
    "190.93.240.0/20"
    "197.234.240.0/22"
    "198.41.128.0/17"
    "162.158.0.0/15"
    "104.16.0.0/13"
    "104.24.0.0/14"
    "172.64.0.0/13"
    "131.0.72.0/22"
)

for cf_ip in "${CLOUDFLARE_IPV4[@]}"; do
    iptables -A INPUT -p tcp -s "$cf_ip" --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp -s "$cf_ip" --dport 443 -j ACCEPT
done

# Cloudflare验证：仅允许Cloudflare IP访问80/443
# 其他IP访问80/443 → DROP（源站保护）
iptables -A INPUT -p tcp --dport 80 -j DROP
iptables -A INPUT -p tcp --dport 443 -j DROP

# 查看Cloudflare连接统计
iptables -L INPUT -v -n --line-numbers | grep -E "tcp dpt:(80|443)"
```

### 3.4 nftables新一代防火墙

nftables是iptables的下一代替代品，语法更简洁，性能更优，支持IPv4/IPv6统一语法。

```bash
# 安装nftables
apt install -y nftables

# 配置文件 /etc/nftables.conf
cat > /etc/nftables.conf << 'NFT_EOF'
#!/usr/sbin/nft -f

flush ruleset

# 定义表
table inet filter {
    # 定义链
    chain input {
        type filter hook input priority 0; policy drop;

        # 本地回环
        iif lo accept

        # 已建立连接
        ct state established,related accept

        # SSH（限流）
        ip protocol tcp ip dport 22022 ct state new limit rate 3/minute accept

        # HTTP/HTTPS（仅Cloudflare）
        ip saddr { 173.245.48.0/20, 103.21.244.0/22, 103.22.200.0/22, 103.31.4.0/22, 141.101.64.0/18, 108.162.192.0/18, 190.93.240.0/20, 197.234.240.0/22, 198.41.128.0/17, 162.158.0.0/15, 104.16.0.0/13, 104.24.0.0/14, 172.64.0.0/13, 131.0.72.0/22 } tcp dport { 80, 443 } accept

        # ICMP
        ip protocol icmp accept

        # 日志
        counter
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
NFT_EOF

# 启用nftables
systemctl enable nftables
systemctl start nftables

# 查看规则
nft list ruleset

# 测试规则
nft add rule inet filter input ip protocol tcp tcp dport 22 accept
```

---

## 四、系统日志集中分析

### 4.1 rsyslog远程日志配置

集中化日志管理是安全运营的基础，rsyslog支持本地存储与远程转发。

```bash
# 安装rsyslog
apt install -y rsyslog

# 配置rsyslog /etc/rsyslog.conf
# 取消以下行的注释以启用UDP/TCP接收：
# $ModLoad imudp
# $UDPServerRun 514
# $ModLoad imtcp
# $InputTCPServerRun 514

# 创建远程日志接收规则 /etc/rsyslog.d/remote-log.conf
cat > /etc/rsyslog.d/remote-log.conf << 'EOF'
# 接收远程客户端日志
template(name="RemoteLogs" type="string" string="/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log")
if $fromhost-ip != '127.0.0.1' then {
    action(type="omfile" dynaFile="RemoteLogs" createDir="on")
}

# SSH登录日志单独记录
if $programname == 'sshd' and $msg contains 'Failed' then {
    action(type="omfile" file="/var/log/ssh-failed.log")
}

# 内核安全日志
kern.* action(type="omfile" file="/var/log/kern.log")

# 认证日志（敏感）
auth,authpriv.* action(type="omfile" file="/var/log/auth.log")
EOF

systemctl restart rsyslog
```

### 4.2 journald持久化配置

```bash
# 配置journald /etc/systemd/journald.conf
cat >> /etc/systemd/journald.conf << 'EOF'
[Journal]
Storage=persistent           # 持久化存储（不是volatile）
SystemMaxUse=500M           # 最大占用500MB
SystemMaxFileSize=50M       # 单文件最大50MB
MaxRetentionSec=30day       # 保留30天
Compress=yes                # 压缩历史日志
EOF

systemctl restart systemd-journald

# 查看journal日志
journalctl -xe --no-pager --since "1 hour ago"
journalctl -u sshd --since "today"
journalctl -b -u fail2ban --no-pager

# 实时监控新日志
journalctl -f
```

### 4.3 PowerShell安全日志分析脚本

```powershell
# 保存为： Security-Log-Analysis.ps1
# 安全日志集中分析 - PowerShell实现

function Get-SecurityEventSummary {
    param(
        [string]$LogPath = "/var/log/auth.log",
        [int]$Hours = 24
    )

    Write-Host "`n========== 安全日志分析报告 ==========" -ForegroundColor Cyan
    Write-Host "日志文件: $LogPath" -ForegroundColor Gray
    Write-Host "分析时段: 最近 $Hours 小时" -ForegroundColor Gray
    Write-Host "分析时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray

    if (-not (Test-Path $LogPath)) {
        Write-Host "[ERROR] 日志文件不存在: $LogPath" -ForegroundColor Red
        return
    }

    $sinceTime = (Get-Date).AddHours(-$Hours)

    # 1. SSH失败登录统计
    Write-Host "[1] SSH失败登录分析" -ForegroundColor Yellow
    $failedSSH = Get-Content $LogPath -Tail 5000 |
        Where-Object { $_ -match "Failed password" -and $_ -match "sshd" }

    if ($failedSSH) {
        $totalFailed = $failedSSH.Count
        $todayFailed = $failedSSH | Where-Object {
            $_.Line.Substring(0, [Math]::Min(15, $_.Line.Length)) -match (Get-Date -Format "MMM\s+\d+")
        }

        Write-Host "  总失败次数: $totalFailed" -ForegroundColor $(if ($totalFailed -gt 100) { "Red" } elseif ($totalFailed -gt 50) { "Yellow" } else { "Green" })

        # 按小时统计
        $hourlyStats = @{}
        $failedSSH | ForEach-Object {
            if ($_ -match '(\w{3}\s+\d{1,2}\s+\d{2}:\d{2})') {
                $hour = $Matches[1] -replace '(\d{2}:\d{2})$', ''
                $hourlyStats[$hour] = ($hourlyStats[$hour] ?? 0) + 1
            }
        }

        $maxHour = ($hourlyStats.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1)
        if ($maxHour) {
            Write-Host "  高峰时段: $($maxHour.Key) - $($maxHour.Value)次攻击" -ForegroundColor Red
        }
    } else {
        Write-Host "  无SSH失败记录" -ForegroundColor Green
    }

    # 2. 恶意IP统计
    Write-Host "`n[2] 恶意IP TOP 10" -ForegroundColor Yellow
    $ipFrequency = @{}
    $failedSSH | ForEach-Object {
        if ($_ -match 'from\s+(\d+\.\d+\.\d+\.\d+)') {
            $ip = $Matches[1]
            $ipFrequency[$ip] = ($ipFrequency[$ip] ?? 0) + 1
        }
    }

    $topIPs = $ipFrequency.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
    $rank = 1
    foreach ($entry in $topIPs) {
        $threatLevel = if ($entry.Value -gt 50) { "CRITICAL" } elseif ($entry.Value -gt 20) { "HIGH" } elseif ($entry.Value -gt 10) { "MEDIUM" } else { "LOW" }
        $color = if ($entry.Value -gt 50) { "Red" } elseif ($entry.Value -gt 20) { "Yellow" } else { "Green" }
        Write-Host "  $rank. $($entry.Key) : $($entry.Value)次 [$threatLevel]" -ForegroundColor $color
        $rank++
    }

    # 3. 成功登录分析
    Write-Host "`n[3] 成功登录分析" -ForegroundColor Yellow
    $acceptedSSH = Get-Content $LogPath -Tail 5000 |
        Where-Object { $_ -match "Accepted" -and $_ -match "sshd" }

    $loginIPs = @{}
    $acceptedSSH | ForEach-Object {
        if ($_ -match 'from\s+(\d+\.\d+\.\d+\.\d+)') {
            $ip = $Matches[1]
            $loginIPs[$ip] = ($loginIPs[$ip] ?? 0) + 1
        }
    }

    $knownIPs = @("1.2.3.4", "5.6.7.8")  # 已知可信IP列表
    $unknownLogins = $loginIPs.Keys | Where-Object { $_ -notin $knownIPs }

    if ($unknownLogins) {
        Write-Host "  检测到非白名单IP登录:" -ForegroundColor Red
        foreach ($ip in $unknownLogins) {
            Write-Host "    $($ip): $($loginIPs[$ip])次" -ForegroundColor Red
        }
    } else {
        Write-Host "  所有登录均来自白名单IP" -ForegroundColor Green
    }

    # 4. 系统错误与警告
    Write-Host "`n[4] 系统错误与警告" -ForegroundColor Yellow
    $syslogPath = "/var/log/syslog"
    if (Test-Path $syslogPath) {
        $errors = Get-Content $syslogPath -Tail 200 -ErrorAction SilentlyContinue |
            Select-String -Pattern "error|warning|critical|fail" |
            Select-Object -Last 10

        if ($errors) {
            Write-Host "  最近10条系统告警:" -ForegroundColor Yellow
            $errors | ForEach-Object {
                $msg = $_.Line.Substring(0, [Math]::Min(100, $_.Line.Length))
                Write-Host "    $msg" -ForegroundColor Gray
            }
        } else {
            Write-Host "  无系统错误/警告记录" -ForegroundColor Green
        }
    }

    # 5. Fail2Ban状态
    Write-Host "`n[5] Fail2Ban防护状态" -ForegroundColor Yellow
    try {
        $banStatus = fail2ban-client status sshd 2>$null
        if ($LASTEXITCODE -eq 0) {
            $banCount = ($banStatus | Select-String "Total banned").ToString() -replace '\D', ''
            Write-Host "  SSH当前Ban数量: $banCount" -ForegroundColor $(if ([int]$banCount -gt 0) { "Green" } else { "Gray" })
        }
    } catch {
        Write-Host "  Fail2Ban状态获取失败" -ForegroundColor Red
    }
}

# 执行分析
Get-SecurityEventSummary -LogPath "/var/log/auth.log" -Hours 48

Write-Host "`n========== 分析完成 ==========" -ForegroundColor Cyan
```

---

## 五、入侵检测与响应

### 5.1 AIDE主机入侵检测

AIDE（Advanced Intrusion Detection Environment）是文件完整性检测工具，用于发现系统关键文件被篡改的情况。

```bash
# 安装AIDE
apt install -y aide

# 初始化AIDE数据库
aideinit

# 移动生成数据库到正确位置
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# 配置AIDE /etc/aide/aide.conf
cat >> /etc/aide/aide.conf << 'EOF'
# 监控敏感目录
/etc/shadow       R                           # 只读
/etc/ssh/sshd_config R                        # 只读
/etc/passwd       R
/etc/group        R
/etc/gshadow      R
/etc/sudoers      R
/etc/sudoers.d/   R

# 日志目录每日检查
/var/log          R
/etc/nginx/       R
/etc/letsencrypt/ R
/etc/cron.daily/  R

# 系统二进制文件（权限+哈希）
/sbin             p+i+n+u+g+s+m+c+md5
/bin              p+i+n+u+g+s+m+c+md5
/usr/sbin         p+i+n+u+g+s+m+c+md5
/usr/bin          p+i+n+u+g+s+m+c+md5

# 网络配置文件
/etc/hosts        R
/etc/sysctl.conf  R
/etc/firewalld/   R
/etc/iptables/    R

# Rootkit检测相关
/usr/bin/rkhunter R
/usr/bin/chkrootkit R
EOF

# 执行完整性检查
aide --check

# 更新数据库（在系统确认安全后）
aide --update

# 创建每日检查定时任务 /etc/cron.daily/aide-check
cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
aide --check | mail -s "AIDE检查报告 $(hostname)" admin@example.com
EOF
chmod +x /etc/cron.daily/aide-check
```

### 5.2 OSSEC主机入侵检测系统

OSSEC是最流行的开源HIDS，支持日志分析、文件完整性检查、入侵检测和rootkit检测。

```bash
# 安装OSSEC
cd /tmp
wget https://github.com/ossec/ossec-hids/archive/refs/heads/master.tar.gz -O ossec.tar.gz
tar -xzf ossec.tar.gz
cd ossec-hids-master

# 交互式安装（生产环境建议选择server模式）
./install.sh

# 配置文件 /var/ossec/etc/ossec.conf
# 启用主动响应
<active-response>
    <command>host-deny</command>
    <location>local</location>
    <level>6</level>
</active-response>

# 启用Rootkit检测
<rootcheck>
    <frequency>86400</frequency>
    <scan_all>yes</scan_all>
</rootcheck>

# 启动OSSEC
/var/ossec/bin/ossec-control start

# 查看告警
tail -f /var/ossec/logs/alerts/alerts.log
```

### 5.3 rkhunter与chkrootkit检测

```bash
# 安装rootkit检测工具
apt install -y rkhunter chkrootkit

# 配置rkhunter
cat > /etc/rkhunter.conf.local << 'EOF'
# 更新rootkit数据库
UPDATEHASHES=yes
UPDATEWEB=yes

# 邮件告警
MAIL-ON-WARNING=admin@example.com
MAIL_CMD=mail -s "[rkhunter] 告警 - $(hostname)" admin@example.com

# 自动更新白名单
AUTO_XPS=yes

# 扫描项
ENABLE_TESTS=ALL
DISABLE_TESTS=tests_to_disable

# 白名单（已知安全项）
ALLOW_SSH_ROOT_USER=no
ALLOW_SSH_PROT_V1=no
EOF

# 执行检测
rkhunter --checkall --rwo

# 查看报告
cat /var/log/rkhunter.log | grep -E "Warning|Suspicious"

# 创建定时任务
cat > /etc/cron.weekly/rkhunter-scan << 'EOF'
#!/bin/bash
rkhunter --update
rkhunter --checkall --rwo 2>&1 | tee /var/log/rkhunter-weekly.log
EOF
chmod +x /etc/cron.weekly/rkhunter-scan
```

### 5.4 auditd系统审计配置

auditd提供细粒度的系统调用审计，是满足合规要求和溯源分析的重要工具。

```bash
# 安装auditd
apt install -y auditd

# 配置审计规则 /etc/audit/rules.d/security.rules
cat > /etc/audit/rules.d/security.rules << 'EOF'
# 监控SSH配置变更
-w /etc/ssh/sshd_config -p wa -k sshd_config_change

# 监控密码文件
-w /etc/passwd -p wa -k passwd_change
-w /etc/shadow -p wa -k shadow_change
-w /etc/group -p wa -k group_change

# 监控sudoers变更
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/sudoers.d/ -p wa -k sudoers_change

# 监控网络配置
-w /etc/hosts -p wa -k hosts_change
-w /etc/sysctl.conf -p wa -k sysctl_change

# 监控cron任务
-w /etc/cron.d/ -p wa -k cron_change
-w /etc/cron.daily/ -p wa -k cron_change

# 监控启动服务
-w /etc/systemd/ -p wa -k systemd_change

# 监控用户认证
-w /var/log/auth.log -p r -k auth_log
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k sudo_exec

# 监控敏感命令执行
-a always,exit -F arch=b64 -S execve -F path=/bin/bash -F uid=0 -k root_commands
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/wget -k network_download
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/curl -k network_download
EOF

# 重启auditd应用规则
auditctl -R /etc/audit/rules.d/security.rules

# 查看审计日志
ausearch -k sshd_config_change -i
ausearch -k passwd_change -i
ausearch -f /etc/shadow -i

# 搜索root用户执行的命令
ausearch -x /bin/bash -ui 0 -i

# 生成每日审计报告
cat > /etc/cron.daily/audit-report << 'EOF'
#!/bin/bash
# 审计日志每日摘要
echo "=== 审计日志摘要 $(date) ===" > /var/log/audit-summary.log
echo "" >> /var/log/audit-summary.log
echo "=== SSH配置变更 ===" >> /var/log/audit-summary.log
ausearch -k sshd_config_change -i --start today >> /var/log/audit-summary.log 2>/dev/null
echo "" >> /var/log/audit-summary.log
echo "=== 密码文件变更 ===" >> /var/log/audit-summary.log
ausearch -k passwd_change -i --start today >> /var/log/audit-summary.log 2>/dev/null
echo "" >> /var/log/audit-summary.log
echo "=== Root用户命令执行 ===" >> /var/log/audit-summary.log
ausearch -x /bin/bash -ui 0 --start today >> /var/log/audit-summary.log 2>/dev/null
EOF
chmod +x /etc/cron.daily/audit-report
```

---

## 六、Fail2Ban自动化防护

### 6.1 Fail2Ban深度配置

Fail2Ban是自动化入侵防御工具，通过分析日志自动封禁恶意IP。

```bash
# 安装Fail2Ban
apt install -y fail2ban

# 备份默认配置
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# 编辑本地配置 /etc/fail2ban/jail.local
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# 全局设置
bantime = 3600              # 封禁1小时
findtime = 600              # 10分钟内超过阈值则封禁
maxretry = 3                # 最多尝试3次

# 忽略IP（本地网络和白名单）
ignoreip = 127.0.0.1/8 ::1 1.2.3.4/32
ignorecommand =

# 邮件通知
destemail = admin@example.com
sender = fail2ban@example.com
mta = sendmail
action = %(action_mwl)s      # 封禁+邮件+日志

[sshd]
enabled = true
port = 22022
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400             # SSH暴力破解封禁24小时
findtime = 600
backend = auto

[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 5
bantime = 3600

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 6
bantime = 7200

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2
bantime = 86400

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
bantime = 86400

[wordpress-login]
enabled = true
port = http,https
filter = wordpress-login
logpath = /var/log/nginx/access.log
maxretry = 5
bantime = 3600
findtime = 600

# 自定义SSH过滤器：检测各类SSH攻击
[definition]
failregex = ^<HOST> - .*\[preauth\]*
            ^<HOST> - .*Invalid user.*
            ^<HOST> - .*Failed password.*
            ^<HOST> - .*BREAK-IN.*

ignoreregex =
EOF

# 自定义过滤器 /etc/fail2ban/filter.d/wordpress-login.conf
cat > /etc/fail2ban/filter.d/wordpress-login.conf << 'EOF'
[Definition]
failregex = ^<HOST> - - .*POST /wp-login.php.* HTTP/1\.(0|1)" 200
            ^<HOST> - - .*POST /xmlrpc.php.* HTTP/1\.(0|1)" 200
            ^<HOST> - - .*GET /wp-admin/.* HTTP/1\.(0|1)" 200
ignoreregex =
EOF

# 启用Fail2Ban
systemctl enable fail2ban
systemctl start fail2ban

# 查看状态
fail2ban-client status
fail2ban-client status sshd

# 手动解封IP
fail2ban-client set sshd unbanip 1.2.3.4

# 查看被封禁的IP
iptables -L f2b-sshd -n --line-numbers
```

### 6.2 PowerShell Fail2Ban监控脚本

```powershell
# 保存为： Fail2Ban-Monitor.ps1
# Fail2Ban自动化监控与告警

function Get-Fail2BanStatus {
    Write-Host "`n========== Fail2Ban监控面板 ==========" -ForegroundColor Cyan

    try {
        # 获取所有监狱状态
        $status = fail2ban-client status 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[ERROR] Fail2Ban服务未运行" -ForegroundColor Red
            return
        }

        # 解析状态输出
        $lines = $status -split "`n"

        # 获取Jail列表
        $jails = @()
        $inJails = $false
        foreach ($line in $lines) {
            if ($line -match "Jail list") {
                $inJails = $true
                continue
            }
            if ($inJails -and $line.Trim()) {
                $jails += $line.Trim().TrimEnd(',').TrimEnd('"').TrimStart('"')
            }
        }

        Write-Host "  活跃Jail数量: $($jails.Count)" -ForegroundColor Cyan

        # 遍历每个Jail
        foreach ($jail in $jails) {
            $jailName = $jail.Trim().TrimEnd(',')
            Write-Host "`n  --- $jailName ---" -ForegroundColor Yellow

            $jailStatus = fail2ban-client status $jailName 2>$null
            if ($LASTEXITCODE -eq 0) {
                # 提取各项指标
                $jailStatus -split "`n" | ForEach-Object {
                    if ($_ -match "Status") { Write-Host "    $_" -ForegroundColor White }
                    if ($_ -match "|- Currently banned") {
                        $bannedCount = $_ -replace '\D', ''
                        $color = if ([int]$bannedCount -gt 0) { "Green" } else { "Gray" }
                        Write-Host "    $_" -ForegroundColor $color
                    }
                    if ($_ -match "|- Total banned") {
                        $totalCount = $_ -replace '\D', ''
                        Write-Host "    $_" -ForegroundColor White
                    }
                }
            }
        }
    } catch {
        Write-Host "[ERROR] 获取Fail2Ban状态失败: $_" -ForegroundColor Red
    }
}

function Get-RecentlyBannedIPs {
    Write-Host "`n========== 近期被封IP列表 ==========" -ForegroundColor Cyan

    try {
        $sshdStatus = fail2ban-client status sshd 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  SSH Jail状态不可用" -ForegroundColor Red
            return
        }

        $banLines = $sshdStatus | Select-String "Banned IP"

        if ($banLines) {
            Write-Host "  SSH Jail被封禁IP:" -ForegroundColor Yellow
            $banLines | ForEach-Object {
                $ip = ($_ -replace '^\|\-\s*Banned\s+IP\s*:\s*', '').Trim()
                Write-Host "    - $ip" -ForegroundColor Red
            }
        } else {
            Write-Host "  当前无被封禁IP" -ForegroundColor Green
        }
    } catch {
        Write-Host "  获取被封IP失败" -ForegroundColor Red
    }
}

function Test-Fail2BanHealth {
    Write-Host "`n========== Fail2Ban健康检查 ==========" -ForegroundColor Cyan

    # 检查服务状态
    $serviceStatus = systemctl is-active fail2ban 2>$null
    if ($serviceStatus -eq "active") {
        Write-Host "  服务状态: 运行中" -ForegroundColor Green
    } else {
        Write-Host "  服务状态: 未运行!" -ForegroundColor Red
    }

    # 检查规则是否生效
    $iptRules = iptables -L -n 2>$null | Select-String "f2b-"
    if ($LASTEXITCODE -eq 0 -and $iptRules) {
        Write-Host "  iptables规则数: $($iptRules.Count)" -ForegroundColor Green
    } else {
        Write-Host "  iptables规则: 未找到Fail2Ban规则" -ForegroundColor Red
    }

    # 检查日志文件
    $logPath = "/var/log/fail2ban.log"
    if (Test-Path $logPath) {
        $recentBans = Get-Content $logPath -Tail 100 -ErrorAction SilentlyContinue |
            Select-String "Ban\s+" | Select-Object -Last 10
        if ($recentBans) {
            Write-Host "  最近封禁记录: $($recentBans.Count)条" -ForegroundColor Yellow
        }
    }
}

# 执行监控
Get-Fail2BanStatus
Get-RecentlyBannedIPs
Test-Fail2BanHealth

Write-Host "`n========== 监控完成 ==========" -ForegroundColor Cyan
```

---

## 七、自动安全更新

### 7.1 unattended-upgrades自动更新

Debian/Ubuntu系统推荐使用unattended-upgrades实现自动安全更新。

```bash
# 安装unattended-upgrades
apt install -y unattended-upgrades

# 配置自动更新 /etc/apt/apt.conf.d/50unattended-upgrades
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    // Ubuntu安全更新
    // "${distro_id}:${distro_codename}-updates";
    // "${distro_id}:${distro_codename}-proposed";
    // "${distro_id}:${distro_codename}-backports";
};

# 邮件通知
Unattended-Upgrade::Mail "admin@example.com";
Unattended-Upgrade::MailOnlyOnError "true";

# 自动移除未使用的依赖
Unattended-Upgrade::Remove-Unused-Dependencies "true";

# 自动重启（凌晨3点）
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";

# 仅安全更新
Unattended-Upgrade::Update-Package-Lists "true";
Unattended-Upgrade::Package-Blacklist {};
EOF

# 启用自动更新
dpkg-reconfigure -plow unattended-upgrades

# 配置更新频率 /etc/apt/apt.conf.d/10periodic
cat > /etc/apt/apt.conf.d/10periodic << 'EOF'
APT::Periodic::Update-Package-Lists "1";     # 每天检查更新
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";       # 每天自动更新
APT::Periodic::AutocleanInterval "7";        # 每周清理缓存
EOF
```

### 7.2 内核更新与GRUB安全

```bash
# 检查可用内核更新
apt-cache search linux-image | grep generic

# 安全升级内核
apt install -y linux-image-generic

# 锁定当前内核版本（防止自动升级导致问题）
apt-mark hold linux-image-$(uname -r)
apt-mark hold linux-headers-$(uname -r)

# 配置GRUB安全
cat >> /etc/default/grub << 'EOF'
# 内核安全参数
GRUB_CMDLINE_LINUX="ipv6.disable=1 audit=1"
EOF
update-grub

# 查看已安装内核
dpkg -l | grep linux-image
```

---

## 八、DDoS防护体系

### 8.1 Syn Cookie与连接限制

DDoS防护的第一道防线是内核级别的Syn Cookie机制。

```bash
# 编辑 /etc/sysctl.conf 添加以下内容

cat >> /etc/sysctl.conf << 'EOF'
# ==================== DDoS防护参数 ====================

# SYN Cookie启用
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2

# TCP连接超时优化
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 3

# 网络设备队列长度
net.core.netdev_max_backlog = 5000
net.core.somaxconn = 1024

# 本地端口范围
net.ipv4.ip_local_port_range = 10000 65535

# TIME_WAIT复用
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30

# 最大连接数优化
net.ipv4.ip_conntrack_max = 200000
net.netfilter.nf_conntrack_max = 200000
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
EOF

sysctl -p
```

### 8.2 iptables流量限制规则

```bash
# Web流量限制（防止CC攻击）
iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 100 --connlimit-mask 32 -j DROP
iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above 100 --connlimit-mask 32 -j DROP

# 每IP连接数限制（防止爬虫和CC）
iptables -A INPUT -p tcp --dport 80 -m iplimit --iplimit-above 50 -j DROP

# ICMP限流（防止ICMP Flood）
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p icmp -j DROP

# DNS Query限流
iptables -A INPUT -p udp --dport 53 -m hashlimit --hashlimit-above 20/sec --hashlimit-burst 50 --hashlimit-name DNS -j DROP

# 碎片包过滤（防止碎片攻击）
iptables -A INPUT -f -j DROP

# 异常TCP标志位过滤
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
```

### 8.3 上游黑洞路由配置

当DDoS攻击超过本地处理能力时，需要联系ISP启用黑洞路由。

```bash
# 查看当前路由表
ip route show

# 查看BGP邻居（如果使用BGP）
ip bgp neighbor

# 本地限速脚本示例
cat > /usr/local/bin/ddos-protection.sh << 'EOF'
#!/bin/bash
# DDoS自动化防御脚本

THRESHOLD=1000      # 每分钟连接数阈值
BAN_TIME=3600       # 封禁时间（秒）

# 统计最近1分钟连接数TOP IP
TOP_IP=$(netstat -an | grep ':80' | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')

# 获取该IP的连接数
CONN_COUNT=$(netstat -an | grep ':80' | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -1 | awk '{print $1}')

if [ "$CONN_COUNT" -gt "$THRESHOLD" ]; then
    echo "[ALERT] 检测到可疑IP: $TOP_IP ($CONN_COUNT 连接)" | tee /var/log/ddos-alert.log
    # 封禁IP
    iptables -I INPUT -s $TOP_IP -j DROP
    # 记录封禁
    echo "$(date): Banned $TOP_IP ($CONN_COUNT connections)" >> /var/log/ddos-bans.log
fi
EOF
chmod +x /usr/local/bin/ddos-protection.sh

# 加入cron，每分钟执行
echo "* * * * * root /usr/local/bin/ddos-protection.sh" >> /etc/crontab
```

---

## 九、安全巡检清单

### 9.1 VPS安全基线自动化检查脚本

| 检查项 | 描述 | 严重级别 | 命令示例 |
|--------|------|----------|----------|
| SSH密码认证 | 检查是否禁用密码登录 | High | `grep 'PasswordAuthentication no' /etc/ssh/sshd_config` |
| SSH Root登录 | 检查是否禁止root登录 | High | `grep 'PermitRootLogin no' /etc/ssh/sshd_config` |
| 防火墙状态 | 检查UFW是否启用 | High | `ufw status \| grep Status:` |
| Fail2Ban | 检查SSH Jail是否运行 | High | `fail2ban-client status sshd` |
| 系统更新 | 检查待更新软件包数量 | Medium | `apt list --upgradable 2>/dev/null \| wc -l` |
| SSH失败登录 | 检查失败登录次数 | Medium | `grep 'Failed password' /var/log/auth.log \| wc -l` |
| Fail2Ban封禁 | 检查当前被封IP数量 | Medium | `fail2ban-client status sshd \| grep "Banned"` |
| 内存使用 | 检查内存使用率 | Low | `free \| awk 'NR==2{printf "%.1f%%", $3/$2*100}'` |
| 磁盘使用 | 检查磁盘使用率 | Low | `df -h / \| tail -1 \| awk '{print $5}'` |
| 系统负载 | 检查系统负载 | Low | `uptime \| awk -F'load average:' '{print $2}'` |

```bash
#!/bin/bash
# 安全巡检脚本 - 批量检查VPS安全状态
# 保存为: /usr/local/bin/security-check.sh

echo "========== VPS安全基线巡检 =========="
echo "时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "======================================"

checks=(
    "SSH密码认证:grep 'PasswordAuthentication no' /etc/ssh/sshd_config && echo 'OK' || echo 'FAIL'"
    "SSH Root禁止:grep 'PermitRootLogin no' /etc/ssh/sshd_config && echo 'OK' || echo 'FAIL'"
    "UFW防火墙:ufw status | grep 'Status: active' && echo 'OK' || echo 'FAIL'"
    "Fail2Ban:systemctl is-active fail2ban | grep active && echo 'OK' || echo 'FAIL'"
    "系统更新:apt list --upgradable 2>/dev/null | grep -c upgradable"
    "AIDE数据库:aide --check 2>&1 | grep -c 'No changes'"
    "rkhunter检查:rkhunter --check --rwo 2>&1 | grep -c 'No warnings'"
    "SSH失败登录:grep 'Failed password' /var/log/auth.log | wc -l"
    "磁盘使用率:df -h / | tail -1 | awk '{print \$5}'"
    "内存使用率:free | awk 'NR==2{printf \"%.1f%%\", \$3/\$2*100}'"
)

for check in "${checks[@]}"; do
    name="${check%%:*}"
    cmd="${check#*:}"
    echo -n "[*] $name: "
    result=$(eval "$cmd" 2>/dev/null)
    echo "$result"
done

echo "======================================"
echo "巡检完成"
```

### 9.2 安全配置自动化Ansible脚本

```yaml
# ansible/vps_security.yml
# Ansible自动化安全配置

---
- hosts: vps_servers
  become: yes
  vars:
    ssh_port: 22022
    admin_users:
      - username

  tasks:
    - name: 更新系统
      apt:
        update_cache: yes
        upgrade: yes

    - name: 安装安全工具
      apt:
        name:
          - unattended-upgrades
          - fail2ban
          - ufw
          - rkhunter
          - chkrootkit
          - logwatch
          - auditd
          - aide
        state: present

    - name: 配置SSH（禁用密码+禁止Root）
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
      loop:
        - { regexp: "^PasswordAuthentication", line: "PasswordAuthentication no" }
        - { regexp: "^PermitRootLogin", line: "PermitRootLogin no" }
        - { regexp: "^Port", line: "Port {{ ssh_port }}" }
        - { regexp: "^X11Forwarding", line: "X11Forwarding no" }
        - { regexp: "^MaxAuthTries", line: "MaxAuthTries 3" }
        - { regexp: "^ClientAliveInterval", line: "ClientAliveInterval 300" }

    - name: 配置UFW默认策略
      ufw:
        direction: "{{ item.direction }}"
        policy: "{{ item.policy }}"
      loop:
        - { direction: 'incoming', policy: 'deny' }
        - { direction: 'outgoing', policy: 'allow' }

    - name: 开放SSH端口
      ufw:
        rule: allow
        port: "{{ ssh_port }}"
        proto: tcp

    - name: 启用UFW
      ufw:
        state: enabled

    - name: 配置Fail2Ban SSH Jail
      template:
        src: jail.local.j2
        dest: /etc/fail2ban/jail.local

    - name: 启用unattended-upgrades
      command: dpkg-reconfigure -plow unattended-upgrades
      creates: /etc/apt/apt.conf.d/20auto-upgrades
```

---

## 十、推荐工具与资源

### 10.1 端口扫描与暴露面管理

| 工具 | 用途 | 命令示例 |
|------|------|----------|
| nmap | 全端口扫描 | `nmap -p- -T4 -Pn -v <target>` |
| masscan | 高速端口扫描 | `masscan -p1-65535 <target> --rate=10000` |
| netstat | 监听端口检查 | `netstat -tulnp` |
| ss | Socket统计 | `ss -tulnp` |
| lsof | 文件进程关联 | `lsof -i -P -n` |
| Shodan | 资产搜索引擎 | 网页搜索你的公网IP |

```bash
# nmap全端口深度扫描
nmap -p- -T4 -Pn -sV -sC -O -v -oA nmap_full_scan <target_ip>

# 检查是否有意外开放端口
nmap -sT -p 1-1000 <target_ip> | grep -E "open|filtered"

# 检查SSL/TLS配置
nmap --script ssl-enum-ciphers -p 443 <target_ip>

# 检测Heartbleed漏洞
nmap -p 443 --script ssl-heartbleed <target_ip>

# 检查Web服务器指纹
nmap -sV --script http-enum,http-title -p 80,443 <target_ip>
```

### 10.2 威胁情报与IOC检测

```bash
# VirusTotal API查询（需要API Key）
curl -s "https://www.virustotal.com/api/v3/ip_addresses/<IP>" \
  -H "x-apikey: YOUR_API_KEY" | jq '.data.attributes.last_analysis_stats'

# AbuseIPDB查询IP信誉
curl -s "https://api.abuseipdb.com/api/v2/check" \
  -H "Key: YOUR_API_KEY" \
  -H "Accept: application/json" \
  --data-urlencode "ipAddress=<IP>"

# AlienVault OTX脉冲查询
curl -s "https://otx.alienvault.com/api/v1/indicators/IPv4/<IP>/general" \
  -H "X-OTX-API-KEY: YOUR_API_KEY"
```

---

## 📚 推荐学习资源

| 类别 | 资源 | 说明 |
|------|------|------|
| 网络安全 | [OWASP Top 10](https://owasp.org/Top10/) | Web应用安全风险指南 |
| 渗透测试 | [Kali Linux官方文档](https://www.kali.org/docs/) | 渗透测试工具集 |
| 合规标准 | [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) | 安全配置基线 |
| 防火墙 | [netfilter官方文档](https://www.netfilter.org/) | iptables/nftables核心 |
| 入侵检测 | [OSSEC官方文档](https://www.ossec.net/docs/) | HIDS配置指南 |

---

## ⚙️ 社区工具

> VPSVIP · ClashVIP · Nav.ClashVIP · ClashHub · Clash For Windows

| 工具 | 地址 | 说明 |
|------|------|------|
| [VPSVIP](https://vpsvip.net) | vpsvip.net | VPS安全与网络工具导航 |
| [ClashVIP](https://clashvip.net) | clashvip.net | Clash配置与节点分享 |
| [Nav.ClashVIP](https://nav.clashvip.net) | nav.clashvip.net | 网络工具聚合导航 |
| [ClashHub](https://clashhub.net) | clashhub.net | 开源代理社区 |
| [BBS.ClashHub](https://bbs.clashhub.net) | bbs.clashhub.net | 论坛与技术交流 |
| [Clash For Windows](https://clash-for-windows.net) | clash-for-windows.net | CFW官方下载 |

---

> **特别声明**: 本项目内容仅供授权学习研究使用。请勿将相关技术用于未授权入侵、破解或任何违法活动。违规使用后果自负。
>
> *维护日期: 2026-10-08*

