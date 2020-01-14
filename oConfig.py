#!/usr/bin/env python3

# nmap
nmapCmd = ['sudo', 'nmap', '-Pn']
retries = '2'
tcpScanType = '-sS'
timing = '-T5'
includeFiltered = False
nmapOSFile = "/OS_from_nmap"

# wfuzz
fileExtensionLocation = "/usr/share/wordlists/dirb/extensions.txt"
wordlistLocation = "/usr/share/wordlists/dirb/"
outputFormat = "html"

# ping
pingCmd = ['ping']
pingFile = "/OS_from_ttl"

# portfiles
udpPortFile = "/udp_ports"
tcpPortFile = "/tcp_ports"
allPortFile = "/allPorts"

# ssh brute forcing
sshUsers1 = "./sshUsers1.txt"
sshPasswords1 = "./sshPasswords1.txt"
