# FARHAN-Shot v2 - Enhanced WiFi WPS Security Testing Tool

## Project Overview
Advanced WiFi WPS (WiFi Protected Setup) security testing tool rebuilt with modern algorithms and enhanced attack capabilities for 2025.

## Purpose
Educational security testing framework designed for:
- Authorized penetration testing
- Personal network security auditing
- Security research and education

## Recent Changes (2025-01-24)
- **Rebuilt main.py** with modern Python 3.11
- **Enhanced PIN generation** algorithms (40+ new algorithms)
- **Universal PIN generator** with MAC-based, timestamp-based, XOR patterns
- **Improved Pixie Dust attack** with multiple fallback techniques
- **WPS lock bypass** capabilities
- **Better Android compatibility** with universal WiFi scanning
- **Extended database** with 600+ vulnerable devices (2024-2025 routers)
- **WiFi 6/6E detection** and WPA3 identification
- **Long-distance optimization** with adaptive timeouts

## Project Architecture

### Core Components
1. **main.py** - Main attack engine with enhanced algorithms
2. **colors.py** - Terminal color output formatting
3. **vulnwsc.txt** - Vulnerable devices database (600+ entries)
4. **EnhancedWPSpin** - Universal PIN generation class
5. **Companion** - WPS attack orchestration
6. **WiFiScanner** - Network discovery with Android fallback

### Attack Modes
- **Pixie Dust** - Offline attack exploiting weak randomness
- **Universal PIN** - Algorithm-based PIN generation
- **NULL PIN** - Automatic 00000000 fallback
- **Smart Bruteforce** - Intelligent PIN enumeration

### Enhanced Features
- 40+ PIN generation algorithms
- WPS lock bypass techniques
- Android WiFi API fallback
- RSSI-based timeout adaptation
- Multiple Pixiewps strategies
- Comprehensive error handling

## Dependencies
- Python 3.11+
- wpa_supplicant
- pixiewps
- iw / wireless-tools
- Root access (required)

## User Preferences
- **Attack style**: Automated with intelligent fallbacks
- **Timeout handling**: Adaptive based on signal strength
- **PIN generation**: Universal algorithms with vendor-specific optimizations
- **Android support**: Termux compatibility with cmd wifi fallback

## Technical Notes
- Uses wpa_supplicant socket communication
- No monitor mode required
- Works on rooted Android devices
- Supports WiFi 4/5/6/6E standards
- WPA2/WPA3 detection

## Legal & Ethical Use
⚠️ **FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**
- Only test networks you own or have written permission to test
- Unauthorized access is illegal
- Tool is for security research and authorized pentesting

## Project Structure
```
FARHAN-Shot-v2/
├── main.py                 # Enhanced attack engine
├── colors.py               # Terminal output
├── vulnwsc.txt            # 600+ device database
├── replit.md              # This file
├── README.md              # Public documentation
├── sessions/              # Attack session storage
├── reports/               # Results storage
└── store/                 # Cracked credentials
```

## Status
✅ Fully rebuilt and modernized for 2025
✅ Enhanced PIN algorithms operational
✅ Android compatibility implemented
✅ Universal PIN generator active
✅ Extended device database loaded
