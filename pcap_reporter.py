# coordinator for makeclouds and pcapviz

# location of pcapviz main.py
pcapvizmain = "/home/pi/opt/PcapViz/main.py"
# location of makeclouds.py
makeclouds = "/home/pi/secur_IOT/makeclouds.py"

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
'''
# wordclouds
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
# pcapviz
# python main.py -i ../packet_captures/yoosee03.pcap -o yoosee03_3.pdf --layer3
cmd = []
cmd.append("python3")
cmd.append(pcapvizmain)
cmd.append("-i")
cmd.append(infname)
cmd.append("-o")
cmd.append(dir + infname + ".pdf")
cmd.append("--layer3")
print("Running " + " ".join(cmd))
p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr = subprocess.PIPE)
p.wait()
if p.stderr:
    for line in p.stderr:
        print(line.strip())
