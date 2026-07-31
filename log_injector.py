"""
============================================================
KaiPokPok SIEM - Attack Scenario Engine (log_injector.py)
============================================================
จำลองการโจมตีแบบสมจริงตาม Cyber Kill Chain
สร้าง log แบบ dynamic พร้อม timestamp ปัจจุบัน
ฉีดเข้า live_stream.log เพื่อให้ Wazuh Agent อ่านและวิเคราะห์

Pipeline: log_injector → live_stream.log → Wazuh Agent → Wazuh Manager
         → alerts.json → Filebeat → Kafka → SIEM Router → OpenSearch
============================================================
"""

import time
import os
import sys
import json
import random
from datetime import datetime, timedelta

sys.stdout.reconfigure(encoding='utf-8')

# --- CONFIGURATION ---
TARGET_LOG_FILE = "./victim_server/logs/live_stream.log"

# --- IP ADDRESS POOLS ---
NORMAL_IPS = ["192.168.1.50", "192.168.1.51", "192.168.1.52", "192.168.1.100", "10.0.0.15"]
ATTACKER_IPS = ["114.23.45.12", "198.51.100.45", "203.0.113.88", "203.0.113.150", "198.51.100.22"]
SCANNER_IP = "45.33.22.11"
WINDOWS_ATTACKER_IP = "198.51.100.77"
C2_SERVER_IP = "185.220.101.99"

# --- NORMAL PAGES ---
NORMAL_PAGES = [
    ("GET", "/index.html", 200, random.randint(2000, 6000)),
    ("GET", "/about-us.html", 200, random.randint(2000, 5000)),
    ("GET", "/contact.html", 200, random.randint(1500, 3000)),
    ("GET", "/assets/css/style.css", 200, random.randint(800, 2000)),
    ("GET", "/assets/js/main.js", 200, random.randint(500, 1500)),
    ("GET", "/assets/images/logo.png", 200, random.randint(10000, 50000)),
    ("GET", "/products.html", 200, random.randint(3000, 8000)),
    ("GET", "/services.html", 200, random.randint(2500, 6000)),
]

# --- RECON PATHS ---
RECON_PATHS = [
    "/admin/", "/backup/", "/wp-admin/", "/config.php.bak",
    "/.env", "/phpmyadmin/", "/server-status", "/wp-login.php",
    "/api/debug", "/test/", "/.git/config", "/database.sql",
]

# --- BRUTE FORCE USERNAMES ---
BRUTE_FORCE_USERS = ["admin", "root", "administrator", "test", "user", "guest", "operator"]

# --- HELPER FUNCTIONS ---

def now_apache():
    """สร้าง timestamp ในรูปแบบ Apache access log"""
    return datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0700")

def now_syslog():
    """สร้าง timestamp ในรูปแบบ Syslog (Cisco ASA)"""
    return datetime.now().strftime("%b %d %H:%M:%S")

def inject_log(log_line):
    """เขียน log 1 บรรทัดลงไฟล์ live_stream.log"""
    with open(TARGET_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_line + "\n")

def apache_log(ip, method, path, status, size):
    """สร้าง Apache Combined Log Format"""
    return f'{ip} - - [{now_apache()}] "{method} {path} HTTP/1.1" {status} {size}'

# ============================================================
# ATTACK PHASES
# ============================================================

def phase_normal_traffic():
    """Phase 1: Normal Traffic - สร้าง background traffic ปกติ"""
    print("\n" + "=" * 60)
    print("🌐 Phase 1: Normal Traffic — จำลองผู้ใช้งานปกติ")
    print("=" * 60)

    count = random.randint(5, 8)
    for i in range(count):
        ip = random.choice(NORMAL_IPS)
        method, path, status, size = random.choice(NORMAL_PAGES)
        size = random.randint(800, 8000)  # randomize size each time
        log = apache_log(ip, method, path, status, size)
        inject_log(log)
        print(f"  ✅ [{i+1}/{count}] {log[:80]}...")
        time.sleep(random.uniform(1.0, 3.0))


def phase_recon():
    """Phase 2: Reconnaissance - สแกนหาช่องโหว่"""
    print("\n" + "=" * 60)
    print("🔍 Phase 2: Reconnaissance — Directory Scanning")
    print("=" * 60)

    attacker_ip = random.choice(ATTACKER_IPS)
    paths = random.sample(RECON_PATHS, k=random.randint(6, 10))

    for i, path in enumerate(paths):
        log = apache_log(attacker_ip, "GET", path, 404, random.randint(100, 300))
        inject_log(log)
        print(f"  🔎 [{i+1}/{len(paths)}] {log[:80]}...")
        time.sleep(random.uniform(0.3, 0.6))  # เร็วเหมือนเครื่องมือ scan


def phase_sqli():
    """Phase 3: SQL Injection - โจมตี Web Application"""
    print("\n" + "=" * 60)
    print("💉 Phase 3: SQL Injection Attack")
    print("=" * 60)

    attacker_ip = random.choice(ATTACKER_IPS)
    sqli_payloads = [
        ("/index.php?id=1'%20UNION%20SELECT%20username,%20password%20FROM%20users--", 200, 5420),
        ("/login.php?user=admin'%20OR%20'1'='1'", 200, 4125),
        ("/search.php?q=1%27%20AND%20(SELECT%20COUNT(*)%20FROM%20information_schema.tables)>0--", 200, 3200),
        ("/products.php?cat=1'%20UNION%20SELECT%20NULL,table_name%20FROM%20information_schema.tables--", 200, 6800),
    ]

    for i, (path, status, size) in enumerate(sqli_payloads):
        log = apache_log(attacker_ip, "GET", path, status, size)
        inject_log(log)
        print(f"  💉 [{i+1}/{len(sqli_payloads)}] {log[:80]}...")
        time.sleep(random.uniform(0.8, 1.5))


def phase_xss():
    """Phase 4: XSS Attack"""
    print("\n" + "=" * 60)
    print("🎭 Phase 4: Cross-Site Scripting (XSS) Attack")
    print("=" * 60)

    attacker_ip = random.choice(ATTACKER_IPS)
    xss_payloads = [
        ("GET", "/search.php?q=<script>alert(1)</script>", 200, 3410),
        ("POST", "/comment.php?user=anon&msg=<iframe+src='javascript:alert(document.cookie)'>", 400, 250),
        ("GET", "/profile.php?name=<img+src=x+onerror=alert('XSS')>", 200, 2800),
    ]

    for i, (method, path, status, size) in enumerate(xss_payloads):
        log = apache_log(attacker_ip, method, path, status, size)
        inject_log(log)
        print(f"  🎭 [{i+1}/{len(xss_payloads)}] {log[:80]}...")
        time.sleep(random.uniform(0.5, 1.0))


def phase_path_traversal():
    """Phase 4.5: Path Traversal Attack"""
    print("\n" + "=" * 60)
    print("📂 Phase 4.5: Path Traversal Attack")
    print("=" * 60)

    attacker_ip = random.choice(ATTACKER_IPS)
    traversal_payloads = [
        ("GET", "/download.php?file=../../../../etc/passwd", 403, 0),
        ("GET", "/view?page=..\\..\\..\\..\\windows\\win.ini", 404, 210),
        ("GET", "/include.php?file=....//....//....//etc/shadow", 403, 0),
    ]

    for i, (method, path, status, size) in enumerate(traversal_payloads):
        log = apache_log(attacker_ip, method, path, status, size)
        inject_log(log)
        print(f"  📂 [{i+1}/{len(traversal_payloads)}] {log[:80]}...")
        time.sleep(random.uniform(0.5, 1.0))


def phase_data_exfiltration():
    """Phase 5: Data Exfiltration - ดาวน์โหลดข้อมูลขนาดใหญ่"""
    print("\n" + "=" * 60)
    print("📦 Phase 5: Data Exfiltration — ขโมยข้อมูล")
    print("=" * 60)

    attacker_ip = random.choice(ATTACKER_IPS)

    # ดาวน์โหลดไฟล์ฐานข้อมูลขนาดใหญ่ (~940MB)
    log = apache_log(attacker_ip, "GET", "/download.php?file=secret_backup_db.sql", 200, 985420100)
    inject_log(log)
    print(f"  📦 [1/2] {log[:80]}...")
    time.sleep(1.0)

    # API access ด้วย automated tool
    log2 = apache_log(attacker_ip, "POST", "/api/v1/user/profile", 200, 1040)
    log2 += ' "user_agent: python-requests/2.31.0" "user: somchai_staff"'
    inject_log(log2)
    print(f"  📦 [2/2] {log2[:80]}...")
    time.sleep(1.0)


def phase_brute_force():
    """Phase 6: Brute Force + Account Compromise"""
    print("\n" + "=" * 60)
    print("🔨 Phase 6: Brute Force Attack — เดารหัสผ่าน")
    print("=" * 60)

    attacker_ip = random.choice(ATTACKER_IPS)
    attempts = random.randint(8, 12)

    # Step 1: ยิง login ผิดซ้ำ ๆ (401)
    for i in range(attempts):
        log = apache_log(attacker_ip, "POST", "/api/v1/auth/login", 401, random.randint(8, 120))
        inject_log(log)
        print(f"  🔨 [{i+1}/{attempts}] FAILED LOGIN ➔ {log[:70]}...")
        time.sleep(random.uniform(0.3, 0.7))  # เร็วเหมือน brute force tool

    # Step 2: สำเร็จ! (200)
    time.sleep(random.uniform(0.5, 1.0))
    log = apache_log(attacker_ip, "POST", "/api/v1/auth/login", 200, 1420)
    inject_log(log)
    print(f"  ✅ [SUCCESS] Account compromised! ➔ {log[:70]}...")
    time.sleep(1.0)


def phase_windows_post_exploitation():
    """Phase 7: Windows Post-Exploitation — JSON Events"""
    print("\n" + "=" * 60)
    print("🪟 Phase 7: Windows Post-Exploitation")
    print("=" * 60)

    events = [
        {
            "emoji": "🔑",
            "label": "Failed Logon",
            "data": {
                "EventID": 4625,
                "ProviderName": "Microsoft-Windows-Security-Auditing",
                "Channel": "Security",
                "Message": "An account failed to log on.",
                "targetUserName": "administrator",
                "ipAddress": WINDOWS_ATTACKER_IP,
                "status": "0xC000006A"
            }
        },
        {
            "emoji": "🦠",
            "label": "Ransomware PowerShell",
            "data": {
                "EventID": 4104,
                "ProviderName": "Microsoft-Windows-PowerShell",
                "Channel": "PowerShell",
                "scriptBlockText": "vssadmin.exe delete shadows /all /quiet ; Get-ChildItem C:\\SharedDocs\\ -Recurse | ForEach-Object { Rename-Item $_.FullName ($_.Name + '.locked') }",
                "user": "SYSTEM"
            }
        },
        {
            "emoji": "👤",
            "label": "Backdoor Account Created",
            "data": {
                "EventID": 4720,
                "ProviderName": "Microsoft-Windows-Security-Auditing",
                "Channel": "Security",
                "Message": "A user account was created.",
                "targetUserName": random.choice(["hacker_admin", "svc_backdoor", "temp_admin"]),
                "subjectUserName": "SYSTEM"
            }
        },
        {
            "emoji": "⬆️",
            "label": "Privilege Escalation",
            "data": {
                "EventID": 4732,
                "ProviderName": "Microsoft-Windows-Security-Auditing",
                "Channel": "Security",
                "Message": "A member was added to a security-enabled local group.",
                "targetUserName": "hacker_admin",
                "targetSid": "S-1-5-32-544",
                "subjectUserName": "SYSTEM"
            }
        },
        {
            "emoji": "🦠",
            "label": "Malware PowerShell (Disable Defender)",
            "data": {
                "EventID": 4104,
                "ProviderName": "Microsoft-Windows-PowerShell",
                "Channel": "PowerShell",
                "scriptBlockText": 'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Get-ChildItem C:\\Users\\*\\Documents -Recurse | ForEach-Object { $_.Delete() } ; Stop-Service -Name WinDefend"',
                "user": "SYSTEM"
            }
        },
        {
            "emoji": "🧹",
            "label": "Audit Log Cleared (Anti-Forensics)",
            "data": {
                "EventID": 1102,
                "ProviderName": "Microsoft-Windows-Eventlog",
                "Channel": "Security",
                "Message": "The audit log was cleared.",
                "subjectUserName": "administrator",
                "subjectDomainName": "ATTACKRANGE"
            }
        },
        {
            "emoji": "✅",
            "label": "Successful Logon (Lateral Movement)",
            "data": {
                "EventID": 4624,
                "ProviderName": "Microsoft-Windows-Security-Auditing",
                "Channel": "Security",
                "Message": "An account was successfully logged on.",
                "targetUserName": "somchai_staff",
                "targetDomainName": "ATTACKRANGE",
                "logonType": "3",
                "ipAddress": "192.168.1.115"
            }
        },
    ]

    for i, event in enumerate(events):
        log = json.dumps(event["data"], ensure_ascii=False)
        inject_log(log)
        print(f"  {event['emoji']} [{i+1}/{len(events)}] {event['label']} ➔ EventID {event['data']['EventID']}")
        time.sleep(random.uniform(1.0, 2.0))


def phase_cisco_asa():
    """Phase 8: Cisco ASA Firewall Alerts"""
    print("\n" + "=" * 60)
    print("🔥 Phase 8: Cisco ASA Firewall — Network Attacks")
    print("=" * 60)

    ts = now_syslog()

    # Port Scan (denied connections to multiple ports)
    scan_ports = [21, 22, 23, 80, 443, 3389, 8080]
    selected_ports = random.sample(scan_ports, k=random.randint(4, 6))

    for i, port in enumerate(selected_ports):
        src_port = random.randint(40000, 60000)
        log = f"{ts} cisco-fw %ASA-4-106103: access-list inbound denied tcp for user 'none' {SCANNER_IP}({src_port}) -> 172.16.10.5({port})"
        inject_log(log)
        print(f"  🛡️ [{i+1}/{len(selected_ports)}] Port Scan Blocked: {SCANNER_IP}:{src_port} → ::{port}")
        time.sleep(random.uniform(0.2, 0.4))

    # IPS Alert
    time.sleep(0.5)
    random_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    log_ips1 = f"{ts} cisco-fw %ASA-4-400000: IPS:1000 IP options-Bad Option List {random_ip} -> 88.6.197.89"
    inject_log(log_ips1)
    print(f"  ⚠️ IPS Alert: Bad IP Options from {random_ip}")
    time.sleep(0.3)

    # DDoS / Flood
    log_ips2 = f"{ts} cisco-fw %ASA-4-400014: IPS:2004 ICMP Echo Request flood drop rate exceeded from MULTIPLE_IPS to 172.16.10.100"
    inject_log(log_ips2)
    print(f"  🌊 IPS Alert: ICMP Flood Detected!")
    time.sleep(0.3)

    # C2 Outbound Connection (blocked)
    log_c2 = f"{ts} cisco-fw %ASA-4-106103: access-list outbound denied tcp inside:172.16.10.50({random.randint(50000,60000)}) -> outside:{C2_SERVER_IP}(4444)"
    inject_log(log_c2)
    print(f"  🚫 C2 Connection Blocked: → {C2_SERVER_IP}:4444")
    time.sleep(0.5)


def phase_cooldown():
    """Phase 9: Cooldown — พักก่อนเริ่มรอบใหม่"""
    print("\n" + "=" * 60)
    print("😴 Phase 9: Cooldown — รอ 10 วินาทีก่อนเริ่มรอบใหม่...")
    print("=" * 60)

    # ฉีด normal traffic เล็กน้อยระหว่างรอ
    for _ in range(random.randint(2, 4)):
        ip = random.choice(NORMAL_IPS)
        method, path, status, _ = random.choice(NORMAL_PAGES)
        size = random.randint(800, 5000)
        log = apache_log(ip, method, path, status, size)
        inject_log(log)
        time.sleep(random.uniform(2.0, 4.0))


# ============================================================
# MAIN LOOP
# ============================================================

def main():
    print("=" * 60)
    print("🚀 KaiPokPok SIEM — Attack Scenario Engine")
    print("   จำลองการโจมตีตาม Cyber Kill Chain (รัน 1 รอบ)")
    print("=" * 60)

    os.makedirs(os.path.dirname(TARGET_LOG_FILE), exist_ok=True)

    try:
        print(f"\n{'#' * 60}")
        print(f"### 🚀 เริ่มจำลองการโจมตี ###")
        print(f"### ⏰ เวลา: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ###")
        print(f"{'#' * 60}")

        phase_normal_traffic()
        phase_recon()
        phase_sqli()
        phase_xss()
        phase_path_traversal()
        phase_data_exfiltration()
        phase_brute_force()
        phase_windows_post_exploitation()
        phase_cisco_asa()
        
        print(f"\n\n{'=' * 60}")
        print(f"✅ จำลองการโจมตีเสร็จสมบูรณ์")
        print(f"{'=' * 60}")

    except KeyboardInterrupt:
        print(f"\n\n{'=' * 60}")
        print(f"⛔ ถูกยกเลิกโดยผู้ใช้")
        print(f"{'=' * 60}")
        sys.exit(0)


if __name__ == "__main__":
    main()