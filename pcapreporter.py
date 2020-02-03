#!/usr/bin/env python3

# coordinator for makeclouds and pcapgrok
# location of pcapgrok main.py
pcapgrokmain = "/root/pcapGrok/pcapGrok.py"
# location of makeclouds.py
makeclouds = "/root/secur_IOT/makeclouds.py"
# columns in reports
cols = 3

import argparse
import os
import subprocess
from pathlib import Path
from shutil import rmtree
import re

parser = argparse.ArgumentParser(description='Pcap report generator')
parser.add_argument('pcap', help='The pcap to process. Can be a single file, multiple files with *, or an amount of time, for example \'1h10m\' would be the last 1 hour and 10 minutes of pcaps captured on the testbed')
parser.add_argument('mac', help='The mac address of the device under test')
parser.add_argument('-hf', '--hostsfile', help='The hostsfile to use. The hostsfile labels the nodes in the graphs produced. By default, the hostsfile in /root/exampe_hostsfile will be used')
args = parser.parse_args()

infname = os.path.abspath(args.pcap)
pcaplist = []
if ".pcap" not in infname:
    # assume the user wants a time interval instead
    match = re.search('[\d]{1,2}m', infname) # minutes
    if match:
        print(match[0][:2])
    match = re.search('[\d]{1,2}h', infname) # hours
    if match:
        print(match[0][:2])
    exit() # TODO
else:
    pcaplist.append(infname)
dir = os.path.join('/var/www/html/')

def wordclouds():
    cmd = []
    cmd.append("python3")
    cmd.append(makeclouds)
    cmd.append(infname)
    cmd.append(dir)
    print("Running " + " ".join(cmd))
    subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr = subprocess.PIPE, shell=False)

def pcapgrok(hf=None, maxnodes=None, restrictmac=None):
    if restrictmac == None:
        suffix = "AllDevices"
    else:
        suffix = restrictmac[0] + "_" +restrictmac[1]
    newdir = os.path.join(dir, suffix)
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
    print("\nRunning " + " ".join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr = subprocess.PIPE, shell=False)
    p.wait()
    if restrictmac is not None:
        reportfname = os.path.join(dir, restrictmac[0] + ".html")
    else:
        reportfname = os.path.join(dir, "AllDevices" + ".html")
    for file in os.listdir(newdir):
        if file[-3:] != "pdf": #only grab pdfs
            continue
        cmd = []
        cmd.append("pdftoppm")
        cmd.append(os.path.join(newdir, file))
        cmd.append(os.path.join(newdir, file))
        cmd.append("-png")
        print("running " + " ".join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr = subprocess.PIPE, shell=False)
        p.wait()
    f = open(reportfname, "w")
    f.write("<html>\n<table border=\"1\">\n")
    curr = 0
    for file in os.listdir(newdir):
        if file[-3:] != "pdf": #only grab pdfs
            continue
        if curr == 0:
            f.write("<tr style=\"height:100%;\">\n")
        f.write("<th><a href=\"" + os.path.join(suffix,file) + "\"><img src=\"" + os.path.join(suffix,file) + "-1.png" + "\" style=\"width:100%;\"></a></th>")
        curr = curr +1
        if curr % cols == 0:
            curr = 0
    f.write("</table>\n</html>")
    f.close()
    print("\nreportfname : " + reportfname)
    print("\nnewdir : " + newdir)
    print("\nreport written to " + reportfname)

# the pcap for a report based on mac + pcaptimeframe
dirname = os.path.basename(args.mac) + "_" + os.path.basename(args.pcap)
dir = os.path.join(dir, dirname)
p = Path(dir)
p.mkdir(mode=0o755, parents=True, exist_ok=True)

# run wordclouds
#wordclouds()

# run pcapgrok
hostsfile = ''
if args.hostsfile:
    hostsfile = args.hostsfile
else:
    hostsfile = '/root/example_hostsfile'
# run with MAC address restrictions per line in hostsfile
f = open(os.path.abspath(hostsfile), 'r')
for line in f:
    line = line.split(',')
    if line[0] == 'ip':
        continue # skip header line
    if len(line) != 6:
        print("\nimproperly formatted line in supplied hostsfile!")
        continue
    ipaddr = line[0].strip()
    macaddr = line[5].strip()
    name = line[1].strip()
    pair = (name, macaddr)
    pcapgrok(hostsfile, 2, pair)
# run once without MAC address restrictions
pcapgrok(args.hostsfile,2)

# copy pcaps over for safekeeping
for pcap in pcaplist:
    cmd = []
    cmd.append("cp")
    cmd.append(pcap) # careful abs path vs relative
    cmd.append(dir)
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr = subprocess.PIPE, shell=False)
    p.wait()

# regenerate home page
cmd = []
cmd.append("python3")
cmd.append("/root/secur_iot/generate.py")
p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr = subprocess.PIPE, shell=False)

print("\ndone!")
