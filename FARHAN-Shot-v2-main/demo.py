#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
from colors import *

def show_banner():
    banner = f"""
{light_gray}════════════════════════════════════════════════════════════{reset}
{white}   FARHAN-Shot v2 - Enhanced WiFi WPS Security Testing Tool{reset}
{light_gray}════════════════════════════════════════════════════════════{reset}
{white}   Version:{reset} {green}2.0.3 Enhanced Edition (2025){reset}
{white}   Modified By:{reset} {light_cyan}FARHAN{reset}
{white}   Repository:{reset} {light_blue}github.com/Gtajisan{reset}
{light_gray}════════════════════════════════════════════════════════════{reset}
{red}   [{white}!{red}]{reset} {yellow}For Educational & Authorized Testing Only{reset}
{light_gray}════════════════════════════════════════════════════════════{reset}
"""
    print(banner)

def show_features():
    print(f"\n{cyan}✨ ENHANCED FEATURES:{reset}\n")
    features = [
        ("Enhanced PIN Algorithms", "40+ new algorithms including timestamp, XOR, reversed MAC"),
        ("Universal PIN Generator", "Automatic fallback with multiple generation methods"),
        ("Improved Pixie Dust", "5 different attack strategies with force options"),
        ("WPS Lock Bypass", "Smart retry and rate-limit evasion techniques"),
        ("WiFi 6/6E Support", "Detection of 802.11ax and WPA3/SAE networks"),
        ("Android Compatibility", "Universal WiFi scanning with cmd wifi fallback"),
        ("Extended Database", "600+ vulnerable devices (2024-2025 routers)"),
        ("Smart Bruteforce", "Intelligent PIN enumeration with universal PINs"),
        ("Long-Distance Mode", "Adaptive timeouts for weak signals (RSSI < -75 dBm)"),
        ("NULL PIN Fallback", "Automatic 00000000 attempt when no PIN found"),
    ]
    
    for i, (feature, description) in enumerate(features, 1):
        print(f"{green}{i:2d}.{reset} {white}{feature:<25}{reset} - {description}")

def show_usage():
    print(f"\n{cyan}📖 USAGE INSTRUCTIONS:{reset}\n")
    
    print(f"{yellow}⚠️  REQUIREMENTS:{reset}")
    print(f"   • Linux/Android with root access")
    print(f"   • Python 3.6+")
    print(f"   • wpa_supplicant, pixiewps, iw")
    print(f"   • WiFi adapter supporting WPS\n")
    
    print(f"{green}✅ INSTALLATION:{reset}")
    print(f"   {white}git clone https://github.com/Gtajisan/FARHAN-Shot-v2.git{reset}")
    print(f"   {white}cd FARHAN-Shot-v2{reset}")
    print(f"   {white}chmod +x main.py{reset}\n")
    
    print(f"{cyan}🎯 BASIC USAGE:{reset}")
    commands = [
        ("Scan for WPS networks", "sudo python3 main.py -i wlan0"),
        ("Pixie Dust attack", "sudo python3 main.py -i wlan0 -b AA:BB:CC:DD:EE:FF -K"),
        ("Universal PIN attack", "sudo python3 main.py -i wlan0 -b AA:BB:CC:DD:EE:FF"),
        ("Smart bruteforce", "sudo python3 main.py -i wlan0 -b AA:BB:CC:DD:EE:FF -B"),
        ("Verbose mode", "sudo python3 main.py -i wlan0 -K -v"),
        ("Save credentials", "sudo python3 main.py -i wlan0 -K -w"),
    ]
    
    for cmd, desc in commands:
        print(f"   {green}•{reset} {white}{desc:<30}{reset}")
        print(f"     {cyan}{cmd}{reset}\n")

def show_attack_modes():
    print(f"\n{cyan}⚡ ATTACK MODES:{reset}\n")
    
    modes = [
        ("Pixie Dust (Offline)", "Fast offline attack exploiting weak RNG", "30-40%", "5-30s"),
        ("Universal PIN", "Algorithm-based PIN generation", "25-35%", "Instant"),
        ("NULL PIN", "00000000 default PIN attempt", "10-15%", "Instant"),
        ("Smart Bruteforce", "Intelligent PIN enumeration", "50-60%", "2-6hrs"),
    ]
    
    print(f"{white}{'Mode':<25} {'Description':<45} {'Success':<10} {'Time':<10}{reset}")
    print(f"{light_gray}{'─'*100}{reset}")
    
    for mode, desc, success, time in modes:
        print(f"{green}{mode:<25}{reset} {desc:<45} {yellow}{success:<10}{reset} {cyan}{time:<10}{reset}")

def show_supported_devices():
    print(f"\n{cyan}📱 SUPPORTED DEVICES (600+):{reset}\n")
    
    vendors = [
        ("TP-Link", "Archer AX10/20/50/55/73/90, Deco X-series, TL-WR series"),
        ("Xiaomi/Redmi", "AX1800/3000/3600/6000/9000, Mi Router 3/4 series"),
        ("Netgear", "RAX10-200, Nighthawk AX series, R6000-R8000"),
        ("ASUS", "RT-AX53U/55/56U/68U/82U/86U/88U, TUF-AX series"),
        ("D-Link", "DIR-X1560/1860/3260, EAGLE PRO AI AX series"),
        ("Tenda", "AX3/9/12/1803/3000, AC6/8/10/15/18 series"),
        ("Huawei/Honor", "AX2/AX3 Pro, WiFi AX series, Router 3/4/X3"),
        ("Linksys", "E7350/8450/9450, MR7350/9600, Velop AX4200"),
        ("Others", "ZTE, Ubiquiti, Keenetic, Google Nest, Amazon eero"),
    ]
    
    for vendor, models in vendors:
        print(f"   {green}•{reset} {white}{vendor:<15}{reset} {models}")

def show_warning():
    print(f"\n{red}{'═'*60}{reset}")
    print(f"{red}   ⚠️  LEGAL DISCLAIMER & WARNING ⚠️{reset}")
    print(f"{red}{'═'*60}{reset}")
    print(f"\n{yellow}This tool is for EDUCATIONAL and AUTHORIZED testing ONLY:{reset}\n")
    print(f"   {green}✓{reset} Personal networks you own")
    print(f"   {green}✓{reset} Authorized penetration testing with written permission")
    print(f"   {green}✓{reset} Security research in controlled environments\n")
    print(f"{red}ILLEGAL USES:{reset}\n")
    print(f"   {red}✗{reset} Unauthorized access to WiFi networks")
    print(f"   {red}✗{reset} Attacking networks without permission")
    print(f"   {red}✗{reset} Intercepting communications\n")
    print(f"{yellow}You are responsible for your actions. Misuse is ILLEGAL.{reset}")
    print(f"{red}{'═'*60}{reset}\n")

def show_technical_improvements():
    print(f"\n{cyan}🔧 TECHNICAL IMPROVEMENTS:{reset}\n")
    
    improvements = [
        "Enhanced WPSpin class with 40+ PIN generation algorithms",
        "Universal PIN generator using MAC-based, timestamp, and XOR patterns",
        "Improved Pixie Dust with 5 attack strategies (normal, force, -S, -f combinations)",
        "WPS lock bypass with intelligent retry mechanisms",
        "Android WiFi API fallback (cmd wifi / dumpsys wifi)",
        "RSSI-based timeout adaptation (2.5x for signals < -75 dBm)",
        "Extended device database with 600+ modern routers",
        "WiFi 6/6E (802.11ax) and WPA3/SAE detection",
        "Better error handling and null-safe operations",
        "Memory-efficient session management",
    ]
    
    for i, improvement in enumerate(improvements, 1):
        print(f"   {green}{i:2d}.{reset} {improvement}")

def main():
    os.system('clear')
    show_banner()
    
    print(f"\n{yellow}⚠️  NOTE: This is a demonstration in Replit{reset}")
    print(f"{yellow}   The tool requires root access and WiFi hardware to actually run.{reset}")
    print(f"{yellow}   Use this on a real Linux/Android system for actual testing.{reset}\n")
    
    show_features()
    show_attack_modes()
    show_supported_devices()
    show_usage()
    show_technical_improvements()
    show_warning()
    
    print(f"{cyan}📚 For full documentation, see README.md{reset}")
    print(f"{cyan}💻 To actually use the tool: sudo python3 main.py -i wlan0{reset}\n")
    print(f"{green}{'─'*60}{reset}")
    print(f"{white}Tool ready for deployment on rooted Android/Linux systems{reset}")
    print(f"{green}{'─'*60}{reset}\n")

if __name__ == '__main__':
    main()
