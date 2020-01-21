# coordinator for makeclouds and pcapgrok

# location of pcapgrok main.py
pcapgrokmain = "/home/pi/opt/pcapGrok/pcapGrok.py"
# location of makeclouds.py
makeclouds = "/home/pi/secur_IOT/makeclouds.py"
# location of hosts file
hostsfile = "/home/pi/secur_IOT/pcapgrok_hosts.xls"

# add mac addresses of devices here
# these can be retrieved from zeek dhcp logs, or by using nmap
router_mac = "dc:a6:32:41:12:99"
device_under_test_mac = "00:0c:43:9d:3d:25"
phone_mac = "00:ec:0a:ca:e9:ea"
laptop_mac = ""
homeassistant_mac = ""

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

# make path if it doesn't exist
p = Path(dir)
p.mkdir(mode=0o755, parents=True, exist_ok=True)
os.chdir(dir)

# run!
# wordclouds
'''
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
'''
# pcapgrok

# no whitelisting
cmd = []
cmd.append("python3")
cmd.append(pcapgrokmain)
cmd.append("-i")
cmd.append(infname)
cmd.append("-o")
cmd.append(dir)
cmd.append("-hf")
cmd.append(hostsfile)
cmd.append("-n")
cmd.append("2")
cmd.append("-p")
cmd.append(".pdf")
print("Running " + " ".join(cmd))
p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr = subprocess.PIPE)
p.wait()
for line in p.stdout:
    print(line.decode('ascii').strip())
if p.stderr:
    for line in p.stderr:
        print(line.strip())
'''
# device under test whitelisting
if device_under_test_mac != "":
    cmd = []
    cmd.append("python3")
    cmd.append(pcapgrokmain)
    cmd.append("-i")
    cmd.append(infname)
    cmd.append("-o")
    cmd.append(dir)
    cmd.append("-n")
    cmd.append("2")
    cmd.append("-p")
    cmd.append("_dut_" +".pdf")
    cmd.append("-r")
    cmd.append(device_under_test_mac)
    cmd.append("-d")
    print("Running " + " ".join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr = subprocess.PIPE)
    p.wait()
    for line in p.stdout:
        print(line.decode('ascii').strip())
    if p.stderr:
        for line in p.stderr:
            print(line.strip())

# with phone whitelisting
if phone_mac != "":
    cmd = []
    cmd.append("python3")
    cmd.append(pcapgrokmain)
    cmd.append("-i")
    cmd.append(infname)
    cmd.append("-o")
    cmd.append(dir)
    cmd.append("-n")
    cmd.append("2")
    cmd.append("-p")
    cmd.append("_phone_" +".pdf")
    cmd.append("-r")
    cmd.append(phone_mac)
    cmd.append("-d")
    print("Running " + " ".join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr = subprocess.PIPE)
    p.wait()
    for line in p.stdout:
        print(line.decode('ascii').strip())
    if p.stderr:
        for line in p.stderr:
            print(line.strip())
'''
