# coordinator for makeclouds and pcapgrok

# location of pcapgrok main.py
pcapgrokmain = "/home/pi/opt/pcapGrok/pcapGrok.py"
# location of pcapgrok hosts file
hostsfile = "/home/pi/secur_IOT/pcapgrok_hosts.xls"
# location of makeclouds.py
makeclouds = "/home/pi/secur_IOT/makeclouds.py"

# add name:mac addresses pairs of devices you want to graph here
# mac addresses can be retrieved from zeek dhcp logs, or by using nmap
addresses = [("device_under_test","00:0c:43:9d:3d:25")]
#device_under_test_mac = "00:0c:43:9d:3d:25"
#phone_mac = "00:ec:0a:ca:e9:ea"
#laptop_mac = ""
#homeassistant_mac = ""

import argparse
import os
import subprocess
from pathlib import Path

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
    cmd = []
    cmd.append("python3")
    cmd.append(pcapgrokmain)
    cmd.append("-i")
    cmd.append(infname)
    cmd.append("-o")
    cmd.append(dir)
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

# make path if it doesn't exist
p = Path(dir)
p.mkdir(mode=0o755, parents=True, exist_ok=True)

# delete existing files
filelist = [ f for f in os.listdir(dir) ]
for f in filelist:
    print("Removing existing file " + f)
    os.remove(os.path.join(dir, f))

#wordclouds()
for pair in addresses:
    pcapgrok(hostsfile,1000,pair)
