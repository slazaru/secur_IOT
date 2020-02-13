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
# make the tshark file carve dir
fileDir = os.path.join(args.outdir, "tshark_files")
p = Path(fileDir)
p.mkdir(mode=0o755, parents=True, exist_ok=True)
# make the tshark log dir
logDir = os.path.join(args.outdir, "tshark_logs")
p = Path(logDir)
p.mkdir(mode=0o755, parents=True, exist_ok=True)

def doLogs():
    # log files
    os.chdir(logDir)
    rclist = ["-z hosts","-z dns,tree", "-z conv,tcp", "-z conv,udp", "-z conv,ip", "-z endpoints,udp", "-z io,phs","-z http,tree",]
    rfnames = ['hosts','dns','dhcpstat','tcpconv','udpconv','ipconv','udpendpoints','iophs','httptree','pdump']
    for i,com in enumerate(rclist):
        ofn = "%s_%s.txt" % (rfnames[i], os.path.basename(args.pcap))
        cl = "tshark -q %s -r %s" % (com, args.pcap)
        print("Running: " + cl)
        cmd = cl.split(' ')
        with open(ofn, "w") as outf:
            subprocess.call(cmd, stdout=outf)
#        res.wait()
        #print(res.communicate()[1].decode('utf-8'))

def doFiles():
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
        print("Running: " + " ".join(cmd))
        res = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        if res[1]: print(res[1].decode('utf-8'))

def writeReport():
    # write a report in the directory that was supplied to us
    reportf = open(os.path.join(args.outdir, "tshark_report.html"), "w")
    reportf.write("<!DOCTYPE html>\n <html lang=\"en\">\n <head>\n <title>Tshark Report</title>\n  <meta charset=\"utf-8\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <link rel=\"stylesheet\" href=\"../bootstrap.min.css\">\n </head>\n <body>\n")
    for file in os.listdir(logDir):
        reportf.write("<h3><a href=\"" + os.path.join(os.path.basename(logDir), file)  + "\">" + file + "</a> </h3>\n")
        reportf.write("<pre>")
        f = open(file, "r")
        for line in f:
            reportf.write(line)
        f.close()
        reportf.write("</pre>\n <br>\n")
    reportf.close()

doLogs()
doFiles()
writeReport()
