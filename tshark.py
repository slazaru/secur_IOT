#!/usr/bin/env python3

# script interface: tshark.py [pcap] [dir to put report in]

import argparse
import os
import subprocess
from pathlib import Path
import re
from datetime import datetime, timedelta
from time import localtime,time
import dateutil
import pathlib

parser = argparse.ArgumentParser(description='Tshark report generator')
parser.add_argument('pcap', help='The pcap to process')
parser.add_argument('outdir', help='The directory to write the report and related artifacts to')
args = parser.parse_args()

# protocols to file carve from
protocols = ['http']
# separator to use in the reports. tabs are a terrible choice.
separator = ','
# directory to put the file carved objects into
fileDir = os.path.join(args.outdir, "tshark_files")
# make this dir if it does not yet exist
p = Path(fileDir)
p.mkdir(mode=0o755, parents=True, exist_ok=True)

def doTshark():
    # log files
    rclist = ["-z hosts","-z dns,tree", "-z conv,tcp", "-z conv,udp", "-z conv,ip", "-z endpoints,udp", "-z io,phs","-z http,tree","-P"]
    rfnames = ['hosts','dns','dhcpstat','tcpconv','udpconv','ipconv','udpendpoints','iophs','httptree','pdump']
    for i,com in enumerate(rclist):
         ofn = "%s_%s.txt" % (rfnames[i], os.path.basename(args.pcap))
         cl = "tshark -q %s -r %s > %s" % (com,args.pcap, os.path.join(args.outdir, ofn))
         print("Running: " + cl)
         os.system(cl)
    # file carving
    for protocol in protocols:
        cmd = []
        cmd.append("tshark")
        cmd.append("-r")
        cmd.append(args.pcap)
        cmd.append("-E")
        cmd.append("separator=" + separator)
        cmd.append("--export-objects")
        cmd.append(protocol + "," + fileDir)
        print("Running: " + str(cmd))
        

doTshark()
