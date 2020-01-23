#!/usr/bin/env python3

# nmap
nmapCmd = ['sudo', 'nmap', '-Pn']
retries = '2'
tcpScanType = '-sS'
timing = '-T5'
includeFiltered = False
nmapOSFile = "/OS_from_nmap"
maxRTT = "500ms"
minRate = "500"

# wfuzz
wfuzzExtensions1 = "/usr/share/wordlists/dirb/extensions.txt"
wfuzzWordlist1 = "/usr/share/wordlists/dirb/common.txt"
wfuzzoutputFormat = "raw"
wfuzzthreads = "50"

# ping
pingCmd = ['ping']
pingOSFile = "/OS_from_ttl"

# ssh brute forcing
sshUsers1 = "/usr/share/wordlists/sshUsers1.txt"
sshPasswords1 = "/usr/share/wordlists/sshPasswords1.txt"

# hydra
hydrasshTasks = 16

# snmpcheck
snmpcheckcmd = ['snmpcheck-1.8.pl']

# snmpwalk
snmpwalkcmd = ['snmp-walk.py']
