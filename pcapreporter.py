#!/usr/bin/env python3

# coordinator for makeclouds and pcapgrok

# location of pcapgrok main.py
pcapgrokmain = "/root/pcapGrok/pcapGrok.py"
# location of tshark.py
tsharkLocation = "/root/secur_IOT/tshark.py"
# columns in pcapgrok pdf reports
cols = 3
# date format for interval input
FSDTFORMAT = '%Y-%m-%d-%H:%M:%S'
# pcapstore location
pcapstoreLocation = '/captures'
# zeek binary location
zeekLocation = "/opt/zeek/bin/zeek"
# location of zeek script to extract files
fileExtractLocation = "/opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek"
# location of html generator script
generatorLocation = "/root/secur_IOT/generate.py"
# location of the suricata binary
suricataLocation = "suricata"
# location of the suricata configuration file
suricataConfLocation = "/etc/suricata/suricata.yaml"

import argparse
import os
import subprocess
from pathlib import Path
from shutil import rmtree
import re
import pcap_period_extract
from datetime import datetime, timedelta
from time import localtime,time
import dateutil
from scapy.all import *
import bisect
import pathlib

parser = argparse.ArgumentParser(description='Pcap report generator')
parser.add_argument('pcap', help='The pcap to process. Can be a single .pcap file or a timeinterval delineated with \'=\' (eg 2020-02-03-18:30:00=2020-02-03-19:00:00) or an amount of time, for example \'1h10m\' would be the last 1 hour and 10 minutes of pcaps captured on the testbed')
parser.add_argument('name', help='The the name of the test so you can identify it on the home page')
parser.add_argument('-hf', '--hostsfile', help='The hostsfile to use. The hostsfile labels the nodes in the graphs produced. By default, the hostsfile in /root/exampe_hostsfile will be used')
args = parser.parse_args()

# run suricata with pcap input and spit out the files in a dir called "suricata"
def suricata():
    cmd = []
    cmd.append(suricataLocation)
    cmd.append("-c")
    cmd.append(suricataConfLocation)
    cmd.append("-r")
    cmd.append(pcapLocation)
    cmd.append("-l")
    suffix = "suricata"
    newdir = os.path.join(dir, suffix)
    p = Path(newdir)
    p.mkdir(mode=0o755, parents=True, exist_ok=True)
    cmd.append(newdir)
    print("Running " + " ".join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    p.wait()
    for line in p.stdout:
        print(line)
    for line in p.stderr:
        print(line)
    # write the suricata logs report
    os.chdir(newdir)
    reportf = open(os.path.join(dir, "suricata.html"), "w")
    reportf.write("<!DOCTYPE html>\n <html lang=\"en\">\n <head>\n <title>Suricata Report</title>\n  <meta charset=\"utf-8\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <link rel=\"stylesheet\" href=\"../bootstrap.min.css\">\n </head>\n <body>\n")
    for file in os.listdir(newdir):
        if os.path.getsize(file) == 0: continue # ignore empty files
        f = open(file, "r")
        reportf.write("<h3><a href=\"" + os.path.join(os.path.basename(newdir), file)  + "\">" + file + "</a></h3>\n")
        reportf.write("<pre>\n")
        for i,line in enumerate(f):
            reportf.write(line)
        reportf.write("</pre>\n")
        f.close()
    reportf.write("</body>\n")
    reportf.close()

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
    cmd.append(pcapLocation)
    cmd.append("-o")
    cmd.append(newdir)
    cmd.append("-E")
    cmd.append("fdp")
    cmd.append("-s")
    cmd.append("box")
    #cmd.append("-S") -S argument disables port squishing
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
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    p.wait()
    for line in p.stdout:
        print(line.decode('ascii'))
    for line in p.stderr:
        print(line.decode('ascii'))
    # the pcapgrok report
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
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        p.wait()
    #print("number of items in dir:" + str(len(os.listdir(newdir))))
    if len(os.listdir(newdir)) < 2: return # pcapgrok has logs in cwd ..
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

# run zeek with pcap input and spit out the files in a dir called "zeek"
def zeek():
    cmd = []
    cmd.append(zeekLocation)
    cmd.append("-Cr")
    suffix = "zeek"
    newdir = os.path.join(dir, suffix)
    p = Path(newdir)
    p.mkdir(mode=0o755, parents=True, exist_ok=True)
    cmd.append(pcapLocation)
    cmd.append(fileExtractLocation)
    print("Running " + " ".join(cmd))
    os.chdir(newdir)
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    p.wait()
    for line in p.stdout:
        print(line)
    for line in p.stderr:
        print(line)
    # write the zeek logs report
    reportf = open(os.path.join(dir, "zeek.html"), "w")
    reportf.write("<!DOCTYPE html>\n <html lang=\"en\">\n <head>\n <title>Zeek Report</title>\n  <meta charset=\"utf-8\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <link rel=\"stylesheet\" href=\"../bootstrap.min.css\">\n </head>\n <body>\n")
    for file in os.listdir(newdir):
        if ".html" in file: continue # skip the report itself
        if "extract" in file: continue # skip the extract files dir
        reportf.write("<h3><a href=\"" + os.path.join(os.path.basename(newdir), file)  + "\">" + file + "</a></h3>\n")
        f = open(file, "r")
        if "conn" in file: #conn.log is big, dont display it in a table
            continue
        reportf.write("<table class=\"table table-striped\">\n <tbody>\n ")
        f.close()
        f = open(file, "r")
        for i,line in enumerate(f):
            line = line.split() # tab separated log file
            reportf.write("<tr>\n")
            for j,el in enumerate(line):
                if el[0] == '#': # without this, table with be misaligned
                    continue
                # the 8th slot is the mime, the 22nd slot in the file name
                if "files.log" in file and j == 8 and "analyzers" not in line[8] and "set[string]" not in line[8]: # hack to select the right elements
                    # make a link to the actual file
                    #print("mime: " + line[8])
                    #print("filename: " + line[22])
                    reportf.write("<td>\n <a href=\"" + "./zeek/extract_files/" + line[22] + "\">" + line[8] + "</a>\n </td>\n")
                else:
                    reportf.write("<td>\n " + el + "</td>\n")
            reportf.write("</tr>\n")
        reportf.write("</tbody>\n </table>\n")
    reportf.write("</body>\n")

def tshark():
    # interface for tshark.py: tshark.py [pcap] [dir to put report in]
    cmd = []
    cmd.append(tsharkLocation)
    cmd.append(pcapLocation)
    cmd.append(dir)
    print("Running " + " ".join(cmd))
    res = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    for el in res:
        print(el.decode('utf-8'))

# the pcap report dir
dir = os.path.join('/var/www/html/')
dirname = os.path.basename(args.name) + "_" + os.path.basename(args.pcap) + "_" + "pcapreport"
dir = os.path.join(dir, dirname)
p = Path(dir)
p.mkdir(mode=0o755, parents=True, exist_ok=True)

# if user specifies multiple pcaps, merge them together, put it in report
# dir, and then use this merged pcap for processing
inputtype = ''
pcapLocation = ''
# determine type of pcap input
if ".pcap" in args.pcap: # single pcap
    inputtype = "s" # single pcap input
    infname = os.path.abspath(args.pcap)
    cmd = []
    cmd.append("cp")
    cmd.append(infname) # careful abs path vs relative
    pcapLocation = os.path.join(dir, args.name + "_" + os.path.basename(infname))
    cmd.append(pcapLocation)
    print("Running: " + " ".join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    p.wait()
    for line in p.stdout:
        print(line)
    for line in p.stderr:
        print(line)
elif re.search('[\d]{1,3}m', args.pcap) or re.search('[\d]{1,3}h', args.pcap):
    print("human time input detected")
    # assume the user wants a "most recent" time interval
    numminutes = 0
    numhours = 0
    match = re.search('[\d]{1,3}m', args.pcap) # minutes
    if match:
        numminutes = int(match[0][:-1])
    match = re.search('[\d]{1,3}h', args.pcap) # hours
    if match:
        numhours = int(match[0][:-1])
    # convert to timeinterval and then just do what the below block does
    currtime = datetime.now()
    res = currtime - timedelta(hours=numhours, minutes=numminutes)
    print("interval is " + str(res) + "=" + str(currtime))
    ps = pcap_period_extract.pcapStore(pcapstoreLocation)
    pcapLocation = os.path.join(dir, args.name + "_" + args.pcap + ".pcap")
    ps.writePeriod(res, currtime, pcapLocation)
else: # time interval separated by = eg 2020-02-03-18:30:00=2020-02-03-19:00:00
    interval = args.pcap.split('=')
    print("interval is " + str(interval))
    ps = pcap_period_extract.pcapStore(pcapstoreLocation)
    sdt = datetime.strptime(interval[0], FSDTFORMAT)
    edt = datetime.strptime(interval[1], FSDTFORMAT)
    pcapLocation = os.path.join(dir, args.name + "_" + args.pcap + ".pcap")
    ps.writePeriod(sdt, edt, pcapLocation)

# run zeek
zeek()

# run tshark file extraction
tshark()

# run pcapgrok
hostsfile = ''
if args.hostsfile:
    hostsfile = os.path.abspath(args.hostsfile)
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

# run suricata
suricata()

# regenerate home page
cmd = []
cmd.append("python3")
cmd.append(generatorLocation)
p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
if p.stderr:
    for line in p.stderr:
        print(line)

print("\ndone!")
