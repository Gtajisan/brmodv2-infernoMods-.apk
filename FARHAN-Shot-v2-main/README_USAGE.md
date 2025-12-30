# FARHAN-Shot v2 - Enhanced Edition Usage Guide

## 🚀 Quick Start (Real System Required)

This tool requires:
- **Root access** (sudo/su)
- **WiFi hardware** (wireless adapter)
- **Linux/Android OS** (Kali, Ubuntu, Parrot, Termux, etc.)

⚠️ **This tool CANNOT run in Replit** due to these requirements. Deploy to a real system.

---

## 📥 Installation

### Linux (Ubuntu/Kali/Parrot)

```bash
git clone https://github.com/Gtajisan/FARHAN-Shot-v2.git
cd FARHAN-Shot-v2
chmod +x main.py

sudo apt update
sudo apt install -y wpasupplicant pixiewps iw python3
```

### Android (Termux with root)

```bash
pkg update && pkg upgrade -y
pkg install root-repo -y
pkg install git tsu python wpa-supplicant pixiewps iw -y

git clone https://github.com/Gtajisan/FARHAN-Shot-v2.git
cd FARHAN-Shot-v2
chmod +x main.py
```

---

## 🎯 Usage Examples

### 1. Scan for WPS-Enabled Networks

```bash
sudo python3 main.py -i wlan0
```

This will show all WPS-enabled networks in range with details:
- BSSID and ESSID
- Security type (WPA2/WPA3)
- WiFi standard (WiFi 4/5/6)
- Signal strength (RSSI)
- WPS lock status

### 2. Enhanced Pixie Dust Attack

```bash
sudo python3 main.py -i wlan0 -b AA:BB:CC:DD:EE:FF -K
```

Features:
- 5 different Pixie Dust strategies
- Automatic fallback to universal PINs
- NULL PIN attempt (00000000)
- Weak signal optimization

### 3. Universal PIN Attack

```bash
sudo python3 main.py -i wlan0 -b AA:BB:CC:DD:EE:FF
```

Tries:
- 40+ algorithm-generated PINs
- MAC-based calculations (24/28/32/36/40-bit)
- Timestamp-based PINs
- XOR patterns
- Reversed MAC algorithms
- Vendor-specific PINs (ASUS, D-Link, TP-Link, etc.)

### 4. Smart Bruteforce

```bash
sudo python3 main.py -i wlan0 -b AA:BB:CC:DD:EE:FF -B
```

Intelligent bruteforce:
- Tries universal PINs first
- Smart enumeration
- WPS lock bypass
- Session resume support

### 5. Verbose Mode (Debugging)

```bash
sudo python3 main.py -i wlan0 -b AA:BB:CC:DD:EE:FF -K -v
```

Shows:
- Detailed attack progress
- wpa_supplicant communication
- Pixiewps attempts
- Error messages

### 6. Save Credentials

```bash
sudo python3 main.py -i wlan0 -K -w
```

Saves successful cracks to:
`store/FARHAN-Shot_crack_data.txt`

### 7. Loop Mode (Continuous)

```bash
sudo python3 main.py -i wlan0 -K -l
```

Continuously scans and attacks multiple targets.

---

## 🔧 Command Reference

### Required Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `-i, --interface` | WiFi interface name | `-i wlan0` |

### Attack Modes

| Argument | Description |
|----------|-------------|
| `-K, --pixie-dust` | Run enhanced Pixie Dust attack |
| `-B, --bruteforce` | Run smart bruteforce attack |
| `--pbc` | WPS push button connection |

### Optional Arguments

| Argument | Description |
|----------|-------------|
| `-b, --bssid` | Target BSSID (MAC address) |
| `-p, --pin` | Use specific PIN |
| `-F, --pixie-force` | Force full Pixiewps range |
| `-X, --show-pixie-cmd` | Show Pixiewps commands |
| `-d, --delay` | Delay between attempts (seconds) |
| `-w, --write` | Save credentials to file |
| `-v, --verbose` | Verbose output |
| `-l, --loop` | Loop mode |
| `-r, --reverse-scan` | Reverse scan order |
| `--iface-down` | Down interface when finished |
| `--vuln-list` | Custom vulnerable devices file |

---

## 📊 Attack Success Rates

| Attack Mode | Success Rate | Time Required | Use Case |
|-------------|--------------|---------------|----------|
| **Pixie Dust** | 30-40% | 5-30 seconds | Modern routers with weak RNG |
| **Universal PIN** | 25-35% | Instant | Known vulnerable models |
| **NULL PIN** | 10-15% | Instant | Default configurations |
| **Smart Bruteforce** | 50-60% | 2-6 hours | When other methods fail |

---

## 🎓 Enhanced Features Explained

### 1. Universal PIN Generator

Automatically generates PINs using:
- **MAC-based**: 24/28/32/36/40-bit algorithms
- **Timestamp**: Hash-based generation
- **XOR Patterns**: Byte manipulation
- **Reversed MAC**: Alternative calculation
- **Vendor-specific**: ASUS, D-Link, TP-Link, Netgear

### 2. Improved Pixie Dust

5 attack strategies:
```
1. Standard Pixiewps
2. Pixiewps --force
3. Pixiewps -S (small DH keys)
4. Pixiewps --force -S
5. Pixiewps -f
```

### 3. WPS Lock Bypass

Techniques:
- Random delay injection
- Smart retry mechanisms
- Rate-limit evasion
- Session resumption

### 4. Android Compatibility

Fallback methods:
```bash
cmd wifi list-scan-results
dumpsys wifi | grep "Latest scan results"
```

### 5. Long-Distance Mode

For weak signals (RSSI < -75 dBm):
- 2.5x timeout multiplier
- Extended wait periods
- Better error handling

---

## 🌍 Supported Devices (600+)

### Top Vulnerable Brands

1. **TP-Link** (150+ models)
   - Archer AX10/20/50/55/73/90/96
   - Deco X20/X50/X60/X90
   - TL-WR series

2. **Xiaomi/Redmi** (80+ models)
   - AX1800/3000/3600/6000/9000
   - Mi Router 3/4 series
   - Redmi AX5/6

3. **Netgear** (120+ models)
   - RAX10-200 series
   - Nighthawk AX4/6/8/12
   - R6000-R8000 series

4. **ASUS** (100+ models)
   - RT-AX series (all variants)
   - TUF-AX3000/4200/5400
   - ZenWiFi AX series

5. **D-Link** (60+ models)
   - DIR-X1560/1860/3260
   - EAGLE PRO AI series

See `vulnwsc.txt` for complete list.

---

## ⚠️ Legal & Ethical Guidelines

### ✅ LEGAL Uses

- **Personal networks** you own
- **Authorized pentesting** with written permission
- **Security research** in controlled labs
- **Educational purposes** on your equipment

### ❌ ILLEGAL Uses

- Attacking networks without permission
- Unauthorized access
- Intercepting communications
- Selling access to networks

**Penalties**: Unauthorized access is a federal crime in most countries (Computer Fraud and Abuse Act in US, Computer Misuse Act in UK, etc.)

---

## 🐛 Troubleshooting

### "Command failed: No such device"

```bash
iw dev
ip link show
```

Use correct interface name (wlan0, wlan1, wlp2s0, etc.)

### "Permission denied"

```bash
sudo python3 main.py -i wlan0
```

Must run as root.

### "No WPS networks found"

- Ensure WiFi is enabled
- Move closer to routers
- Try different channel
- Some routers disable WPS

### "Pixie Dust failed"

- Try universal PIN attack
- Use -F for force mode
- Enable verbose (-v) to see details
- Router may not be vulnerable

### "WPS locked"

- Wait 5-10 minutes
- Router has rate limiting
- Try different target

### Android: "iw command not found"

Universal WiFi scan activates automatically using:
```bash
cmd wifi list-scan-results
```

---

## 📁 File Structure

```
FARHAN-Shot-v2/
├── main.py              # Main attack engine
├── colors.py            # Terminal colors
├── demo.py              # Demo/info script
├── vulnwsc.txt          # Vulnerable devices (600+)
├── README.md            # Public documentation
├── replit.md            # Project info
├── sessions/            # Attack sessions
├── reports/             # Scan results
└── store/               # Cracked credentials
```

---

## 🔄 Updates

Keep tool updated:

```bash
cd FARHAN-Shot-v2
git pull origin main
```

---

## 📞 Support & Contact

- **Issues**: [GitHub Issues](https://github.com/Gtajisan/FARHAN-Shot-v2/issues)
- **Telegram**: [@FARHAN_MUH_TASIM](https://t.me/FARHAN_MUH_TASIM)
- **YouTube**: [Tutorial](https://youtu.be/5janYQg1-Yw)

---

## 🎓 Educational Resources

Learn more about WPS security:

1. **WPS Protocol Vulnerabilities**
   - Pixie Dust attack explanation
   - PIN generation weaknesses
   - Vendor-specific issues

2. **WiFi Security Best Practices**
   - Disable WPS when not needed
   - Use WPA3-only mode
   - Strong PSK passphrases

3. **Ethical Hacking**
   - Authorized testing procedures
   - Legal frameworks
   - Responsible disclosure

---

**Made with ❤️ for the Security Community**

*Stay Ethical. Stay Legal. Stay Secure.*
