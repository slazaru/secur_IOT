#!/usr/bin/env python3

# nmap
nmapCmd = ['nmap', '-Pn']
retries = '2'
tcpScanType = '-sS'
timing = '-T5'
includeFiltered = False
nmapOSFile = "OS_from_nmap"
maxRTT = "500ms"
minRate = "500"

# wfuzz
wfuzzExtensions1 = "/usr/share/wordlists/dirb/extensions.txt"
wfuzzWordlist1 = "/usr/share/wordlists/dirb/common.txt"
wfuzzoutputFormat = "raw"
wfuzzthreads = "50"
wfuzzcmd = ['wfuzz']

# ping
pingCmd = ['ping']
pingOSFile = "OS_from_ttl"

# ssh brute forcing
sshUsers1 = "/usr/share/wordlists/sshUsers1.txt"
sshPasswords1 = "/usr/share/wordlists/sshPasswords1.txt"

# hydra
hydrasshTasks = 16

# snmpcheck
snmpcheckcmd = ['snmpcheck-1.8.pl']

# snmpwalk
snmpwalkcmd = ['snmp-walk.py']

# smbmap
smbmapcmd = ['smbmap.py']

# smbclient
smbclientcmd = ['smbclient']

# sslscan
sslscancmd = ['sslscan']

# joomscan
joomscancmd = ['joomscan.pl']

# wpscan
wpscancmd = ['wpscan']

# droopescan
droopescancmd = ['droopescan']

# hydra
hydracmd = ['hydra']

# enum4linux
enum4linuxcmd = ['enum4linux']


















