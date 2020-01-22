# coordinator for makeclouds and pcapgrok

# location of pcapgrok main.py
pcapgrokmain = "/home/pi/opt/pcapGrok/pcapGrok.py"
# location of pcapgrok hosts file
hostsfile = "/home/pi/secur_IOT/pcapgrok_hosts.xls"
# location of makeclouds.py
makeclouds = "/home/pi/secur_IOT/makeclouds.py"

# add name:mac addresses pairs of devices you want to graph here
# mac addresses can be retrieved from zeek dhcp logs, or by using nmap
addresses = [("device_under_test","00:0c:43:9d:3d:25"),
("Phone","00:ec:0a:ca:e9:ea"),
("Laptop", "a0:d3:7a:d9:d1:90")]

import argparse
import os
import subprocess
from pathlib import Path
from shutil import rmtree

parser = argparse.ArgumentParser(description='Pcap report generator')
parser.add_argument('pcap', help='the pcap to process')
parser.add_argument('dir', help='the directory to save the output')
args = parser.parse_args()
dir = os.path.abspath(args.dir)
infname = os.path.abspath(args.pcap)

def wordclouds():
    cmd = []
    cmd.append("python3")
    cmd.append(makeclouds)
    cmd.append(infname)
    cmd.append(dir)
    print("Running " + " ".join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr = subprocess.PIPE)
    p.wait()
    if p.stderr:
	    for line in p.stderr:
	        print(line.strip())

def pcapgrok(hf=None, maxnodes=None, restrictmac=None):
    if restrictmac == None:
        suffix = "AllDevices"
    else:
        suffix = restrictmac[0] + "_" +restrictmac[1]
    newdir = os.path.join(dir, suffix)
    if os.path.exists(newdir):
        rmtree(newdir)
    p = Path(newdir)
    p.mkdir(mode=0o755, parents=True, exist_ok=True)
    cmd = []
    cmd.append("python3")
    cmd.append(pcapgrokmain)
    cmd.append("-i")
    cmd.append(infname)
    cmd.append("-o")
    cmd.append(newdir)
    cmd.append("-E")
    cmd.append("fdp")
    cmd.append("-s")
    cmd.append("box")
    if hf is not None:
        cmd.append("-hf")
        cmd.append(hf)
    if maxnodes is not None:
        cmd.append("-n")
        cmd.append(str(maxnodes))
    if restrictmac is not None:
        cmd.append("-r")
        cmd.append(restrictmac[1])
    cmd.append("-p")
    if restrictmac is not None:
        cmd.append("_" + restrictmac[0] + ".pdf")
    else:
        cmd.append(".pdf")
    print("Running " + " ".join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr = subprocess.PIPE)
    p.wait()
    for line in p.stdout:
        print(line.decode('ascii').strip())
    if p.stderr:
        for line in p.stderr:
            print(line.strip())
    if restrictmac is not None:
        reportfname = os.path.join(dir, restrictmac[0] + ".html")
    else:
        reportfname = os.path.join(dir, "AllDevices" + ".html")
    f = open(reportfname, "w")
    f.write("<html>\n")
    for file in os.listdir(newdir):
        f.write("<h3>" + file + "</h3>\n")
        f.write("<embed src=\"" + suffix + "/" + file + "\" type=\"application/pdf\" width=\"98%\" height=\"100%\">\n")
    f.write("<\/html>")
    f.close()

# delete all existing files
if os.path.exists(dir):
    rmtree(dir)
# make path if it doesn't exist
p = Path(dir)
p.mkdir(mode=0o755, parents=True, exist_ok=True)

#main

#wordclouds()
pcapgrok(hostsfile,2)
for pair in addresses:
    pcapgrok(hostsfile,2,pair)
