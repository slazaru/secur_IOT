# omni map

# configuration
import oConfig as cfg

import os
import re
from pathlib import Path
import subprocess

def runAllTests(dir, ip):
    udpPortFile = dir + "/udp_ports"
    tcpPortFile = dir + "/tcp_ports"
    allPortFile = dir + "/allPorts"
    resetFile(udpPortFile)
    resetFile(tcpPortFile)
    resetFile(allPortFile)
    #nmapQuickScan(dir, ip, 1, 1000, 'tcp')
    #nmapQuickScan(dir, ip, 1, 1000, 'udp')
    #nmapBasicScan(dir, ip, 1, 1000, 'tcp')
    #nmapBasicScan(dir, ip, 1, 1000, 'udp')
    nmapDepthScan(dir, ip, 1, 1000, 'tcp')
    nmapDepthScan(dir, ip, 1, 1000, 'udp')

# given a file containing nmap output, extracts the port/protocol
# returns a list of port:protocol pairs
def extractPorts(file):
    f = open(file, "r")
    ports = []
    for line in f:
        if "open" in line:
            if "filtered" in line and not cfg.includeFiltered:
                continue
            res = re.match("^[\d]*/[\w]{3}", line)
            if res is not None:
                ports.append(res[0])
    f.close()
    return ports

# given a file containing nmap, extracts port:state:service:version lines
# returns a list of these lines
def extractAll(file):
    f = open(file, "r")
    lines = []
    for line in f:
        print(line)
        if "open" in line:
            if "filtered" in line and not cfg.includeFiltered:
                continue
            lines.append(line.strip())
    f.close()
    return lines

# find open ports given port range and service
def nmapQuickScan(dir, ip, lo, hi, service):
    # construct file name
    outf = dir + "/" + service + "_" + str(lo) + "-" + str(hi) + "_quick"
    # construct command
    cmd = []
    for el in cfg.nmapCmd:
        cmd.append(el)
    if service == 'udp':
        cmd.append('-sU')
    else:
        cmd.append(cfg.tcpScanType)
    cmd.append("--max-retries")
    cmd.append(cfg.retries)
    cmd.append(cfg.timing)
    cmd.append("-p")
    cmd.append(str(lo) + "-" + str(hi))
    cmd.append('-oN')
    cmd.append(outf)
    cmd.append(ip)
    print("Running " + ' '.join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    p.wait()
    for line in p.stdout:
        line=line.decode('ascii').strip()
        print(line, flush=True)
    ports = extractPorts(outf)
    if len(ports) == 0:
        return
    # write results if open ports found
    if service == 'udp':
        print("Writing open ports to " + dir + "/udp_ports")
        pfile = open(dir + "/udp_ports", "a")
    else:
        print("Writing open ports to " + dir + "/tcp_ports")
        pfile = open(dir + "/tcp_ports", "a")
    tfile = open(dir + "/allPorts", "a")
    for port in ports:
        pfile.write(port + "\n")
        tfile.write(port + "\n")
    pfile.close()
    tfile.close()

# performs basic scans, relies on previous quickscan output
def nmapBasicScan(dir, ip, lo, hi, service):
    prevf = dir + "/" + service + "_" + str(lo) + "-" + str(hi) + "_quick"
    if not os.path.exists(prevf):
        # havent performed a port scan yet, do this before continuing
        nmapQuickScan(dir, ip, lo, hi, service)
    pairs = extractPorts(prevf)
    if len(pairs) == 0:
        return
    # filename
    outf = dir + "/" + service + "_" + str(lo) + "-" + str(hi) + "_basic"
    resetFile(outf)
    # construct command
    cmd = []
    for el in cfg.nmapCmd:
        cmd.append(el)
    if service == 'udp':
        cmd.append('-sU')
    else:
        cmd.append(cfg.tcpScanType)
    cmd.append("-sC")
    cmd.append("-sV")
    portarg = "-p"
    curr = 0
    for pair in pairs:
        res = pair.split("/")
        if curr != 0:
            portarg += ","
        curr = curr + 1
        portarg += res[0]
    cmd.append(portarg)
    cmd.append("--max-retries")
    cmd.append(cfg.retries)
    cmd.append(cfg.timing)
    cmd.append('-oN')
    cmd.append(outf)
    cmd.append(ip)
    print("Running " + ' '.join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    p.wait()
    for line in p.stdout:
        line=line.decode('ascii').strip()
        print(line, flush=True)

# performs depth scans, relies on previous basic output
def nmapDepthScan(dir, ip, lo, hi, service):
    prevf = dir + "/" + service + "_" + str(lo) + "-" + str(hi) + "_basic"
    if not os.path.exists(prevf):
        # havent performed a basic scan yet, do this before continuing
        nmapBasicScan(dir, ip, lo, hi, service)
    outf = dir + "/" + service + "_" + str(lo) + "-" + str(hi) + "_depth"
    resetFile(outf)
    f = open(outf, "w")
    lines = extractAll(prevf)
    for line in lines:
        if "http" in line:
            fuzz(dir, ip, line, "common.txt", False, False, False)
    f.close()

def fuzz(dir, ip, line, wordlist, https=False, useExtensions=False, recursive=False):
    info = line.split(" ")
    port = info[0].split("/")[0]
    print("fuzz got port " + port)
    cmd = []
    cmd.append("wfuzz")
    cmd.append("-w")
    cmd.append(cfg.wordlistLocation + wordlist)
    if useExtensions == True:
        cmd.append("-w")
        cmd.append(cfg.fileExtensionLocation)
    cmd.append("--hc")
    cmd.append("404")
    if recursive == True:
        cmd.append("-R1")
    cmd.append("-o")
    cmd.append(cfg.outputFormat)
    target = ""
    if https == True:
        target = "https://"
    else:
        target = "http://"
    target += ip
    target += ":" + port + "/"
    target += "FUZZ"
    if useExtensions == True:
        target += "FUZ2Z"
    cmd.append(target)
    #cmd.append(">")
    #cmd.append(dir + "/" + port + "_fuzz_common" + "." + cfg.outputFormat)
    print("Running " + ' '.join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    p.wait()
    outf = open(dir + "/" + port + "_" + wordlist + "." + cfg.outputFormat, "w")
    for line in p.stdout:
        line=line.decode('ascii').strip()
        print(line, flush=True)
        outf.write(line)
    outf.close()

def resetFile(fname):
    f = open(fname, "w")
    f.close()
