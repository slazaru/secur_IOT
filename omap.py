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
enum4linuxDone = False
debug = False
reportFile = ""

def runAllTests(directory, ipaddr, debugFlag=False):
    global debug
    if debugFlag: debug = True
    global dir
    global ip
    dir = directory
    ip = ipaddr
    global reportFile
    reportFile = os.path.join(directory, "Report.html")
    reportf = open(reportFile, "w")
    reportf.write("<html>\n")
    reportf.close()
    if debug: print("reportFile is " + reportFile)
    if debug: print("dir is " + dir)
    if debug: print("ip is " + ip)
    nmapQuickScan(1, 1000, 'tcp')
    nmapQuickScan(1, 1000, 'udp')
    nmapBasicScan(1, 1000, 'tcp')
    nmapBasicScan(1, 1000, 'udp')
    getOSFromTTL()
    getOSFromNmap()
    nmapDepthScan(1, 1000, 'tcp')
    nmapDepthScan(1, 1000, 'udp')
    reportf = open(reportFile, "a")
    reportf.write("</html>\n")
    reportf.close()
    print("\nAll tests finished!\n")

def appendToReport(fname, cmd):
    reportf = open(reportFile, "a")
    reportf.write("<h3>" + ' '.join(cmd) + "</h3>")
    f = open(fname, "r")
    for line in f:
        if "<script" in line:
            continue
        reportf.write(line + "<br>")
    reportf.write("<br>")
    reportf.close()
    f.close()

def getOSFromTTL():
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
    outf = open(os.path.join(dir, cfg.pingOSFile), "w")
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
    appendToReport(os.path.join(dir, cfg.pingOSFile), cmd)

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
    outf = open(os.path.join(dir, cfg.nmapOSFile), "w")
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
    appendToReport(os.path.join(dir, cfg.nmapOSFile), cmd)

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
def nmapQuickScan(lo, hi, service):
    if debug: print("dir is " + dir)
    # construct file name
    outf = service + "_" + str(lo) + "-" + str(hi) + "_quick"
    outf = os.path.join(dir, outf)
    if debug: print("nmapquickscan outf is " + outf)
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
    cmd.append("--min-rate")
    cmd.append(cfg.minRate)
    cmd.append("--max-rtt-timeout")
    cmd.append(cfg.maxRTT)
    cmd.append(cfg.timing)
    cmd.append("-p")
    cmd.append(str(lo) + "-" + str(hi))
    cmd.append('-oN')
    cmd.append(outf)
    cmd.append(ip)
    print("Running nmap quick scan: " + ' '.join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    p.wait()
    for line in p.stdout:
        line=line.decode('ascii').strip()
        print(line, flush=True)
    ports = extractPorts(outf)
    if len(ports) == 0:
        return
    appendToReport(outf, cmd)

# performs basic scans, relies on previous quickscan output
def nmapBasicScan(lo, hi, service):
    prevf = os.path.join(dir, service + "_" + str(lo) + "-" + str(hi) + "_quick")
    if not os.path.exists(prevf):
        # havent performed a port scan yet, do this before continuing
        nmapQuickScan(dir, ip, lo, hi, service)
    pairs = extractPorts(prevf)
    if len(pairs) == 0:
        return
    # filename
    outf = os.path.join(dir, service + "_" + str(lo) + "-" + str(hi) + "_basic")
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
    cmd.append("--max-rtt-timeout")
    cmd.append(cfg.maxRTT)
    cmd.append("--min-rate")
    cmd.append(cfg.minRate)
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
    appendToReport(outf, cmd)

# performs depth scans, relies on previous basic output
def nmapDepthScan(lo, hi, service):
    prevf = os.path.join(dir, service + "_" + str(lo) + "-" + str(hi) + "_basic")
    if not os.path.exists(prevf):
        # havent performed a basic scan yet, do this before continuing
        nmapBasicScan(dir, ip, lo, hi, service)
    if not os.path.exists(prevf):
        # wasn't able to extract any ports
        return
    lines = extractAll(prevf)
    global enum4linuxDone
    for line in lines:
        if "https" in line:
            wfuzz(line, cfg.wfuzzWordlist1, cfg.wfuzzExtensions1, True, False, False)
            sslscan(line)
            nikto(line, True)
        elif "http" in line:
            wfuzz(line, cfg.wfuzzWordlist1, cfg.wfuzzExtensions1, False, False, False)
            nikto(line, False)
        elif "Joomla" in line:
            joomscan(line)
        elif "WordPress" in line:
            wpscan(line)
        elif "Drupal" in line:
            droopescan(line)
        elif re.search("ssh", line, re.IGNORECASE) is not None:
            hydra(cfg.sshUsers1, cfg.sshPasswords1, line, "ssh")
        elif re.search("ftps", line, re.IGNORECASE) is not None:
            hydra(cfg.sshUsers1, cfg.sshPasswords1, line, "ftps")
        elif re.search("ftp", line, re.IGNORECASE) is not None:
            hydra(cfg.sshUsers1, cfg.sshPasswords1, line, "ftp")
        elif re.search("telnet", line, re.IGNORECASE) is not None:
            hydra(cfg.sshUsers1, cfg.sshPasswords1, line, "telnet")
        elif "445/tcp" in line:
            # now we know it's windows 
            smbmap(line)
            if enum4linuxDone == False:
                enum4linux()
                enum4linuxDone = True
            smbclient()
            nmapScript("vuln", "445")
            hydra(cfg.sshUsers1, cfg.sshPasswords1, line, "smb")
        elif "139/tcp" in line:
            if enum4linuxDone == False:
                enum4linux()
                enum4linuxDone = True
        elif "161/udp" in line:
            snmpcheck()
            snmpwalk()
        elif "53/tcp" in line:
            dnsrecon("10.10.10.0", "24")
            dnsrecon("127.0.0.1", "24")
            dnsrecon("192.168.1.0", "24")
            dnsrecon("192.168.0.0", "24")
        elif "554/tcp" in line:
            nmapScript("rtsp-url-brute", "554")

def dnsrecon(subnet, bits):
    outfname = os.path.join(dir, "dnsrecon_" + subnet + "_" + bits)
    cmd = []
    cmd.append("dnsrecon")
    cmd.append("-r")
    cmd.append(subnet + "/" + bits)
    cmd.append("-n")
    cmd.append(ip)
    print("Running " + ' '.join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    outf = open(outfname, "w")
    for line in p.stdout:
        line=line.decode('ascii')
        outf.write(line)
        print(line, flush=True)
    outf.close()
    appendToReport(outfname, cmd)

def snmpcheck():
    outfname = os.path.join(dir, "snmpcheck")
    if debug: print("snmpcheck() outfname is " + outfname)
    cmd = []
    for c in cfg.snmpcheckcmd:
        cmd.append(c)
    cmd.append("-t")
    cmd.append(ip)
    print("Running " + ' '.join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    outf = open(outfname, "w")
    for line in p.stdout:
        line=line.decode('ascii')
        outf.write(line)
        print(line, flush=True)
    for line in p.stderr:
        line=line.decode('ascii')
        outf.write(line)
        print(line, flush=True)
    outf.close()
    appendToReport(outfname, cmd)

def snmpwalk():
    outfname = os.path.join(dir, "snmpwalk")
    cmd = []
    for c in cfg.snmpwalkcmd:
        cmd.append(c)
    cmd.append("-c")
    cmd.append("public")
    cmd.append("-version")
    cmd.append("2")
    cmd.append("-ip")
    cmd.append(ip)
    print("Running " + ' '.join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    outf = open(outfname, "w")
    for line in p.stdout:
        line=line.decode('ascii')
        outf.write(line)
        print(line, flush=True)
    for line in p.stderr:
        line=line.decode('ascii')
        outf.write(line)
        print(line, flush=True)
    outf.close()
    appendToReport(outfname, cmd)

def nmapScript(script, port):
    cmd = []
    outfname = os.path.join(dir, "nmapScript_" + script + "_" + port)
    for el in cfg.nmapCmd:
        cmd.append(el)
    cmd.append("-p")
    cmd.append(port)
    cmd.append("--script")
    cmd.append(script)
    cmd.append("-oN")
    cmd.append(outfname)
    cmd.append(ip)
    print("Running " + ' '.join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    for line in p.stdout:
        line=line.decode('ascii')
        print(line, flush=True)
    appendToReport(outfname, cmd)

def smbclient():
    cmd = []
    cmd.append("smbclient")
    cmd.append("-L")
    target = "//"
    target += ip
    cmd.append(target)
    cmd.append("-U")
    cmd.append("\"\"%")
    print("Running " + ' '.join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    outfname = os.path.join(dir, "smbclient_login")
    outf = open(outfname, "w")
    for line in p.stdout:
        line=line.decode('ascii')
        print(line, flush=True)
        outf.write(line)
    appendToReport(outfname, cmd)

def enum4linux():
    cmd = []
    cmd.append("enum4linux")
    cmd.append("-a")
    cmd.append(ip)
    print("Running " + ' '.join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    outfname = os.path.join(dir, "enum4linux")
    outf = open(outfname, "w")
    for line in p.stdout:
        line=line.decode('ascii')
        print(line, flush=True)
        outf.write(line)
    appendToReport(outfname, cmd)

def smbmap(line):
    info = line.split(" ")
    port = info[0].split("/")[0]
    cmd = []
    cmd.append("smbmap")
    cmd.append("-H")
    cmd.append(ip)
    print("Running " + ' '.join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    outfname = os.path.join(dir, "smbmap_" + port)
    outf = open(outfname, "w")
    for line in p.stdout:
        line=line.decode('ascii')
        print(line, flush=True)
        outf.write(line)
    appendToReport(outfname, cmd)

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
    cmd.append("-V")
    userbase = os.path.basename(userfile)
    passbase = os.path.basename(passfile)
    outfname = os.path.join(dir, "hydra_" + port + "_" + protocol + "_" + userbase + "_" + passbase)
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
    appendToReport(outfname, cmd)

def nikto(line, https=False):
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
    outfname = os.path.join(dir, "nikto_" + port + "_")
    if https:
        outfname += "https"
    else:
        outfname += "http"
    outf = open(outfname, "w")
    for line in p.stdout:
        line=line.decode('ascii')
        print(line.strip(), flush=True)
        outf.write(line)
    outf.close()
    appendToReport(outfname, cmd)

def joomscan(line):
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
    outfname = os.path.join(dir, "joomscan_" + port + "_")
    outf = open(outfname, "w")
    for line in p.stdout:
        line=line.decode('ascii')
        print(line, flush=True)
        outf.write(line)
    appendToReport(outfname, cmd)

def wpscan(line):
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
    outfname = os.path.join(dir, "wordpress_" + port + "_")
    outf = open(outfname, "w")
    for line in p.stdout:
        line=line.decode('ascii')
        print(line, flush=True)
        outf.write(line)
    appendToReport(outfname, cmd)

def droopescan(line):
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
    outfname = os.path.join(dir, "droopescan_" + port + "_")
    outf = open(outfname, "w")
    for line in p.stdout:
        line=line.decode('ascii')
        print(line, flush=True)
        outf.write(line)
    appendToReport(outfname, cmd)

def sslscan(line):
    info = line.split(" ")
    port = info[0].split("/")[0]
    cmd = []
    cmd.append("sslscan")
    target = ip + ":" + port
    cmd.append(target)
    print("Running " + ' '.join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    p.wait()
    outfname = os.path.join(dir, "sslscan_" + port, "w")
    outf = open(outfname, "w")
    for line in p.stdout:
        line=line.decode('ascii').strip()
        print(line, flush=True)
        outf.write(line)
    outf.close()
    appendToReport(outfname, cmd)

def wfuzz(line, wordlist, extensions, https=False, useExtensions=False, recursive=False):
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
    cmd.append(cfg.wfuzzoutputFormat)
    cmd.append("-t")
    cmd.append(cfg.wfuzzthreads)
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
    outfname = os.path.join(dir, "wfuzz_" + port + "_")
    if https == True:
        outfname += "https_"
    else:
        outfname += "http_"
    if recursive:
        outfname += "recursive_"
    if useExtensions:
        outfname += "extensions_"
    outfname += os.path.basename(wordlist) + "." + cfg.wfuzzoutputFormat
    outf = open(outfname, "w")
    for line in p.stdout:
        line=line.decode('ascii')
        print(line.strip(), flush=True)
        outf.write(line)
    outf.close()
    appendToReport(outfname, cmd)

def resetFile(fname):
    f = open(fname, "w")
    f.close()
