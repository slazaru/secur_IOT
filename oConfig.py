#!/usr/bin/env python3

# nmap
nmapCmd = ['sudo', 'nmap', '-Pn']
retries = '2'
tcpScanType = '-sS'
timing = '-T5'
includeFiltered = False
nmapOSFile = "/OS_from_nmap"
maxRTT = "100ms"

# wfuzz
wfuzzExtensions1 = "/usr/share/wordlists/dirb/extensions.txt"
wfuzzWordlist1 = "/usr/share/wordlists/dirb/common.txt"
outputFormat = "html"

# ping
pingCmd = ['ping']
pingOSFile = "/OS_from_ttl"

# portfiles
udpPortFile = "/udp_ports"
tcpPortFile = "/tcp_ports"
allPortFile = "/allPorts"

# ssh brute forcing
sshUsers1 = "/usr/share/wordlists/sshUsers1.txt"
sshPasswords1 = "/usr/share/wordlists/sshPasswords1.txt"

# hydra
hydrasshTasks = 4
