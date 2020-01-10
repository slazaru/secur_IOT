# omni map

# configuration
import oConfig as cfg

import os
import re
from pathlib import Path
import subprocess

# given a file containing nmap output, extracts the port:protocol pairs
# returns a list of port:protocol pairs
def extractPorts(file):
    f = open(file, "r")
    ports = []
    for line in f:
        if "open" in line:
            res = re.match("^[\d]*/[\w]{3}", line)
            if res is not None:
                ports.append(res[0])
    f.close()
    return ports

# find open ports given port range and service
# and prints the results to a file
def nmapPortScan(dir, ip, lo, hi, service):
    # construct file name
    outf = dir + "/" + service + "_" + str(lo) + "-" + str(hi)
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
    print("Writing open ports to " + dir + "/ports")
    pfile = open(dir + "/ports", "a")
    tfile = open(dir + "/tempPorts", "a")
    for port in ports:
        pfile.write(port + "\n")
        tfile.write(port + "\n")
    pfile.close()
    tfile.close()

# use a file containing a list of open port/service pairs
def nmapDepthScan(dir, ip, fname):
    f = open(fname, "r")
    for pair in f:
        pass

def resetFile(fname):
    f = open(fname, "w")
    f.close()

def runAllTests(dir, ip):
    portFile = dir + "/ports"
    tempPortFile = dir + "/tempPorts"
    resetFile(portFile)
    resetFile(tempPortFile)
    nmapPortScan(dir, ip, 1, 1000, 'tcp')
    nmapPortScan(dir, ip, 1, 1000, 'udp')
    nmapDepthScan(dir, ip, tempPortFile)
    os.remove(tempPortFile)
