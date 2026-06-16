#!/usr/bin/env python

#  oneshot (WPS penetration testing utility) is a fork of the tool with extra features
#  Copyright (C) 2026 chickendrop89

import os
import sys
import subprocess

# pylint: disable=wrong-import-position
if sys.version_info < (3, 10):
    sys.exit('Python 3.10 or higher is required to run this script.')

from shutil import which
from pathlib import Path
from src import logger

import src.wifi.android
import src.wifi.scanner
import src.wps.connection
import src.wps.bruteforce
import src.utils
import src.args

VERSION = "1.1.0"

def checkUpdates():
    """Check for updates from GitHub"""
    logger.info("[*] Verificando atualizações no Beach Hub...")
    try:
        # Tenta dar um git pull silencioso
        result = subprocess.run(
            ['git', 'pull', 'origin', 'master'],
            capture_output=True, text=True, cwd=os.path.dirname(__file__)
        )
        if "Already up to date" in result.stdout:
            logger.success("[+] O script já está na versão mais recente.")
        else:
            logger.success("[!] Script atualizado automaticamente! Reinicie para aplicar.")
            sys.exit(0)
    except Exception as e:
        logger.error(f"[-] Falha ao verificar atualizações: {e}")

def checkRequirements():
    """Verify requirements are met"""

    required_binaries = [
        'pixiewps',
        'wpa_supplicant',
        'iw', 'ip'
    ]
    missing = [b for b in required_binaries if not which(b)]

    if missing:
        src.utils.die(f"Missing required utilities: {', '.join(missing)}")

    if os.getuid() != 0:
        src.utils.die('Run it as root')

def setupDirectories():
    """Create required directories"""
    for directory in [src.utils.SESSIONS_DIR, src.utils.PIXIEWPS_DIR]:
        if not os.path.exists(directory):
            os.makedirs(directory)

def setupAndroidWifi(android_network: src.wifi.android.AndroidNetwork, enable: bool = False):
    """Configure Android-specific WiFi settings"""
    if enable:
        android_network.enableWifi()
    else:
        android_network.storeAlwaysScanState()
        android_network.disableWifi()

def scanForNetworks(interface: str, vuln_list: list[str]) -> tuple[str, dict] | None:
    """Scan, and prompt user to select network"""
    scanner = src.wifi.scanner.WiFiScanner(interface, vuln_list)
    return scanner.promptNetwork()

def handleConnection(args):
    """Main connection logic"""
    network_info = {}
    if args.bruteforce:
        connection = src.wps.bruteforce.Initialize(args.interface)
    else:
        connection = src.wps.connection.Initialize(args.interface)

    if args.pbc:
        connection.singleConnection(pbc_mode=True)
    else:
        if not args.bssid:
            try:
                with open(args.vuln_list, 'r', encoding='utf-8') as file:
                    vuln_list = file.read().splitlines()
            except FileNotFoundError:
                vuln_list = []

            result = scanForNetworks(args.interface, vuln_list)
            if result is None:
                return
            args.bssid, network_info = result

        if args.bssid:
            if args.bruteforce or args.wordlist:
                brute = src.wps.bruteforce.Initialize(args.interface)
                if args.pixie_dust:
                    conn = src.wps.connection.Initialize(args.interface)
                    if conn.singleConnection(args.bssid, args.pin):
                        if network_info:
                            src.utils.addVulnerableAP(network_info, args.vuln_list)
                        return
                if args.wordlist:
                    if brute.wordlistAttack(args.bssid, args.wordlist):
                        return
                if args.bruteforce:
                    brute.smartBruteforce(args.bssid, args.pin)
            else:
                connection = src.wps.connection.Initialize(args.interface)
                if connection.singleConnection(args.bssid, args.pin):
                    if args.pixie_dust and network_info:
                        src.utils.addVulnerableAP(network_info, args.vuln_list)

def main():
    """Main oneshot code"""
    checkRequirements()
    setupDirectories()

    args = src.args.parseArgs()
    logger.initialize_logging(verbose=args.verbose)

    # Auto-update check
    if hasattr(args, 'update') and args.update:
        checkUpdates()
        sys.exit(0)

    # Android-specific interference check
    if not args.dont_touch_settings:
        logger.info('[*] Verificando interferência do sistema Android...')
        android_network = src.wifi.android.AndroidNetwork()
        setupAndroidWifi(android_network)

    if args.kill:
        # No Android, isso avisa sobre processos no Termux, mas evita processos do sistema
        src.utils.killInterfering()

    while True:
        try:
            android_network = src.wifi.android.AndroidNetwork()
            if args.clear:
                src.utils.clearScreen()

            if not args.dont_touch_settings:
                setupAndroidWifi(android_network)

            if src.utils.ifaceCtl(args.interface, action='up'):
                src.utils.die(f'Unable to up interface \'{args.interface}\'')

            handleConnection(args)
            if not args.loop:
                break
            args.bssid = None
        except KeyboardInterrupt:
            logger.info('Aborting…')
            break
        finally:
            if not args.dont_touch_settings:
                setupAndroidWifi(android_network, enable=True)
            if args.iface_down:
                src.utils.ifaceCtl(args.interface, action='down')
            if args.restore:
                src.utils.restoreProcesses()

if __name__ == '__main__':
    main()
