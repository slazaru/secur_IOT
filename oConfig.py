#!/usr/bin/env python3

# nmap
nmapCmd = ['sudo', 'nmap', '-Pn']
retries = '2'
tcpScanType = '-sS'
timing = '-T5'
includeFiltered = False

# wfuzz
fileExtensionLocation = "/usr/share/wordlists/dirb/extensions.txt"
wordlistLocation = "/usr/share/wordlists/dirb/"
outputFormat = "html"
