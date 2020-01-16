import os
import re
from pathlib import Path
import subprocess
from ftplib import FTP
# config file
import oConfig as cfg

dir = ""
ip = ""
TTLOS = "Unknown"
nmapOS = "Unknown"
udpPortFile = ""
tcpPortFile = ""
allPortFile = ""

def runAllTests(directory, ipaddr):
    global dir
    global ip
    dir = directory
    ip = ipaddr
    global udpPortFile
    udpPortFile = dir + cfg.udpPortFile
    global tcpPortFile
    tcpPortFile = dir + cfg.tcpPortFile
    global allPortFile
    allPortFile = dir + cfg.allPortFile
    #nmapQuickScan(dir, ip, 1, 1000, 'tcp')
    #nmapQuickScan(dir, ip, 1, 1000, 'udp')
    #nmapBasicScan(dir, ip, 1, 1000, 'tcp')
    #nmapBasicScan(dir, ip, 1, 1000, 'udp')
    nmapDepthScan(dir, ip, 1, 1000, 'tcp')
    nmapDepthScan(dir, ip, 1, 1000, 'udp')
    #getOSFromTTL(dir, ip)
    #getOSFromNmap()
    print("\nAll tests finished!\n")

def getOSFromTTL(dir, ip):
    global TTLOS
    cmd = []
    cmd.append("ping")
    cmd.append("-c")
    cmd.append("1")
    cmd.append("-w")
    cmd.append("5")
    cmd.append(ip)
    print("Running " + ' '.join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    p.wait()
    outf = open(dir + cfg.pingOSFile, "w")
    for line in p.stdout:
        line=line.decode('ascii')
        outf.write(line)
        line = line.strip()
        print(line, flush=True)
        if "ttl=" in line:
            res = line.split(" ")
            res = res[5][4:]
            print("ttl is " + res)
            ttl = int(res)
            if ttl == 64:
                TTLOS = "Linux"
            elif ttl == 128:
                TLLOS = "Windows"
            elif ttl == 254:
                TTLOS = "Solaris"
    if TTLOS == "Unknown":
        print("Couldn't determine the OS from ping ttl")
        outf.write("\nCouldn't determine the OS from ping ttl")
    else:
        print("ttl from ping suggests the OS is " + TTLOS)
        outf.write("\nttl from ping suggests the OS is " + TTLOS)
    outf.close()

def getOSFromNmap():
    cmd = []
    for el in cfg.nmapCmd:
        cmd.append(el)
    cmd.append("-O")
    cmd.append(ip)
    print("Running " + ' '.join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    p.wait()
    global nmapOS
    outf = open(dir + cfg.nmapOSFile, "w")
    for line in p.stdout:
        line=line.decode('ascii')
        outf.write(line)
        print(line.strip(), flush=True)
        res = re.search("linux", line, re.IGNORECASE)
        if res is not None:
            print("got linux")
            nmapOS = "Linux"
        res = re.search("windows", line, re.IGNORECASE)
        if res is not None:
            nmapOS = "Windows"
    if nmapOS == "Unknown":
        print("Could not determine the OS from nmap -O")
        outf.write("\nCould not determine the OS from nmap -O")
    else:
        print("nmap -O suggests the OS is " + nmapOS)
        outf.write("\nnmap -O suggests the OS is " + nmapOS)
    outf.close()

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
    if cfg.maxRTT is not None:
        cmd.append("--max-rtt-timeout")
        cmd.append(cfg.maxRTT)
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
        print("Writing open ports to " + udpPortFile)
        pfile = open(udpPortFile, "a")
    else:
        print("Writing open ports to " + tcpPortFile)
        pfile = open(tcpPortFile, "a")
    tfile = open(allPortFile, "a")
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
    if cfg.maxRTT is not None:
        cmd.append("--max-rtt-timeout")
        cmd.append(cfg.maxRTT)
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
    if not os.path.exists(prevf):
        # wasn't able to extract any ports
        return
    lines = extractAll(prevf)
    for line in lines:
        if "https" in line:
            #wfuzz(dir, ip, line, cfg.wfuzzWordlist1, cfg.wfuzzExtensions1, False, False, False)
            #sslscan(dir, ip, line)
            #nikto(dir, ip, line, True)
            pass
        elif "http" in line:
            #wfuzz(dir, ip, line, cfg.wfuzzWordlist1, cfg.wfuzzExtensions1, False, False, False)
            #nikto(dir, ip,line, False)
            pass
        if "Joomla" in line:
            joomscan(dir, ip, line)
        if "WordPress" in line:
            wpscan(dir, ip, line)
        if "Drupal" in line:
            droopescan(dir, ip, line)
        if re.search("ssh", line, re.IGNORECASE) is not None:
            hydra(cfg.sshUsers1, cfg.sshPasswords1, line, "ssh")
        if re.search("ftps", line, re.IGNORECASE) is not None:
            hydra(cfg.sshUsers1, cfg.sshPasswords1, line, "ftps")
        elif re.search("ftp", line, re.IGNORECASE) is not None:
            hydra(cfg.sshUsers1, cfg.sshPasswords1, line, "ftp")

def hydra(userfile, passfile, line, protocol):
    info = line.split(" ")
    port = info[0].split("/")[0]
    print(protocol + " service detected on port " + port)
    cmd = []
    cmd.append("hydra")
    cmd.append("-L")
    cmd.append(userfile)
    cmd.append("-P")
    cmd.append(passfile)
    cmd.append("-t")
    cmd.append(str(cfg.hydrasshTasks))
    target = protocol
    target += "://"
    target += ip
    cmd.append(target)
    userbase = os.path.basename(userfile)
    passbase = os.path.basename(passfile)
    outfname = dir + "/" + "hydra_" + port + "_" + protocol + "_" + userbase + "_" + passbase
    print("Running " + ' '.join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    outf = open(outfname, "w")
    for line in p.stdout:
        line=line.decode('ascii')
        print(line, flush=True)
        outf.write(line)
    for line in p.stderr:
        line=line.decode('ascii')
        print(line, flush=True)
        outf.write(line)
    outf.close()

def nikto(dir, ip, line, https=False):
    info = line.split(" ")
    port = info[0].split("/")[0]
    cmd = []
    cmd.append("nikto")
    cmd.append("-host")
    target = ""
    if https:
        target += "https://"
    else:
        target += "http://"
    target += ip + ":" + port
    cmd.append(target)
    print("Running " + ' '.join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    p.wait()
    outfname = dir + "/" + "nikto_" + port + "_"
    if https:
        outfname += "https"
    else:
        outfname += "http"
    outf = open(outfname, "w")
    for line in p.stdout:
        line=line.decode('ascii')
        print(line, flush=True)
        outf.write(line)
    outf.close()

def joomscan(dir, ip, line):
    info = line.split(" ")
    port = info[0].split("/")[0]
    cmd = []
    cmd.append("joomscan.pl")
    cmd.append("--url")
    target = ""
    target += ip + ":" + port
    cmd.append(target)
    print("Running " + ' '.join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    p.wait()
    outfname = dir + "/" + "joomscan_" + port + "_"
    outf = open(outfname, "w")
    for line in p.stdout:
        line=line.decode('ascii')
        print(line, flush=True)
        outf.write(line)

def wpscan(dir, ip, line):
    info = line.split(" ")
    port = info[0].split("/")[0]
    cmd = []
    cmd.append("wpscan")
    cmd.append("--url")
    target = ""
    target += ip + ":" + port
    cmd.append(target)
    cmd.append("--enumerate")
    cmd.append("-p")
    print("Running " + ' '.join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    p.wait()
    outfname = dir + "/" + "wordpress_" + port + "_"
    outf = open(outfname, "w")
    for line in p.stdout:
        line=line.decode('ascii')
        print(line, flush=True)
        outf.write(line)

def droopescan(dir, ip, line):
    info = line.split(" ")
    port = info[0].split("/")[0]
    cmd = []
    cmd.append("droopescan")
    cmd.append("scan")
    cmd.append("drupal")
    cmd.append("-u")
    target = ""
    target += ip + ":" + port
    cmd.append(target)
    print("Running " + ' '.join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    p.wait()
    outfname = dir + "/" + "droopescan_" + port + "_"
    outf = open(outfname, "w")
    for line in p.stdout:
        line=line.decode('ascii')
        print(line, flush=True)
        outf.write(line)

def sslscan(dir, ip, line):
    info = line.split(" ")
    port = info[0].split("/")[0]
    cmd = []
    cmd.append("sslscan")
    target = ip + ":" + port
    cmd.append(target)
    print("Running " + ' '.join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    p.wait()
    outf = open(dir + "/" + "sslscan_" + port, "w")
    for line in p.stdout:
        line=line.decode('ascii').strip()
        print(line, flush=True)
        outf.write(line)
    outf.close()

def wfuzz(dir, ip, line, wordlist, extensions, https=False, useExtensions=False, recursive=False):
    info = line.split(" ")
    port = info[0].split("/")[0]
    cmd = []
    cmd.append("wfuzz")
    cmd.append("-w")
    cmd.append(wordlist)
    if useExtensions == True:
        cmd.append("-w")
        cmd.append(extensions)
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
    print("Running " + ' '.join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    p.wait()
    outfname = dir + "/" + "wfuzz_" + port + "_"
    if https == True:
        outfname += "https_"
    else:
        outfname += "http_"
    if recursive:
        outfname += "recursive_"
    if useExtensions:
        outfname += "extensions_"
    outfname += wordlist + "." + cfg.outputFormat
    outf = open(outfname, "w")
    for line in p.stdout:
        line=line.decode('ascii').strip()
        print(line, flush=True)
        outf.write(line)
    outf.close()

def resetFile(fname):
    f = open(fname, "w")
    f.close()
