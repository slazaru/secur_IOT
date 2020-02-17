#!/usr/bin/env python3

import os
import re
from datetime import datetime

basepath = '/var/www/html'
apipath = "http://localhost:8000"

templatestr = '''
<!DOCTYPE html>
<html lang="en">
<head>
  <title>IoT Testbed</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="bootstrap.min.css">
</head>
<body>
<nav class="navbar navbar-inverse">
  <div class="container">
    <div class="navbar-header">
      <button type="button" class="navbar-toggle" data-toggle="collapse" data-target="#myNavbar">
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
      </button>
      <a class="navbar-brand" href="index.html">IoT Testbed</a>
    </div>
    <div class="collapse navbar-collapse" id="myNavbar">
      <ul class="nav navbar-nav">
        <li><a href="index.html">Results</a></li>
        <li><a href="upload.html">Upload</a></li>
        <li><a href="attack.html">Attack</a></li>
        <li><a href="pcapreporter.html">Pcapreporter</a></li>
        <li><a href="https://github.com/slazaru/iottestbed">Git</a></li>
      </ul>
    </div>
  </div>
</nav>
<div class="container">
<div class="page-header"><h3 style=\"font-weight:bold\">{0}</h3></div>
<p>{1}</p>
{2}
{3}
<br>
</div>
<footer class="container-fluid text-center">
  <p>Deploying An IoT Testbed</p>
</footer>
</body>
</html>
'''

# templatestr:
# {0}: page title
# {1}: page info
# {2}: page content

# pcap reports
f = open(os.path.join(basepath, "index.html"), "w")
resultstr = "<div class=\"page-header\">\n<h4>Pcap Reports</h4>\n</div>\n<br><table class=\"table\" border=\"0\">\n"
resultstr += "<thead>\n <tr>\n <th scope=\"col\">Date</th>\n <th scope=\"col\">Test</th>\n <th scope=\"col\">Pcap</th>\n <th scope=\"col\">Reports</th>\n  </tr>\n </thead>\n <tbody>\n"
for file in os.listdir(basepath): #grab pcapreport dirs
    if not os.path.isdir(os.path.join(basepath, file)): continue
    if "pcap" not in file: continue
    if len(os.listdir(os.path.join(basepath,file))) < 1: continue
    resultstr += "<tr style=\"height:100%;\">"
    name = file.split("_")
    resultstr += "<th scope=\"row\"><p class=\"font-weight-bold\">" +  datetime.utcfromtimestamp(int(os.path.getmtime(os.path.join(basepath, file)))).strftime('%Y-%m-%d %H:%M:%S') + "</p></th>\n"
    resultstr += "<td><p>" + name[0] + "</p></td>"
    # get the pcap file first
    for el in os.listdir(os.path.join(basepath,file)):
        if ".pcap" in el:
            resultstr += "<td><a href=\"./" + os.path.join(file, el) + "\">" + el + "</a></td>\n"
    # found a pcapreport dir, search for reports
    for el in os.listdir(os.path.join(basepath,file)):
        if "zeek.html" in el:
            resultstr += "<td><a href=\"./" + os.path.join(file, el) + "\">" + "Zeek Report" + "</a></td>\n"
        elif "suricata.html" in el:
            resultstr += "<td><a href=\"./" + os.path.join(file, el) + "\">" + "Suricata Report" + "</a></td>\n"
        elif "tshark_report.html" in el:
            resultstr += "<td><a href=\"./" + os.path.join(file, el) + "\">" + "Tshark Report" + "</a></td>\n"
        elif ".html" in el: #everything else
            resultstr += "<td><a href=\"./" + os.path.join(file, el) + "\">" + el[:-5] + "</a></td>\n"
        # hack for extracting wordclouds from pcapgrok 
        #elif "wordclouds" in el:
    resultstr+= "</tr>\n"
resultstr += "</table>"

# attack script reports
attackstr = "<div class=\"page-header\">\n<h4>Attack Reports</h4>\n</div><br><table class=\"table\" border=\"0\">\n"
attackstr += "<thead>\n <tr>\n <th scope=\"col\">Date</th>\n <th scope=\"col\">Device</th>\n <th scope=\"col\">Report</th>\n <th scope=\"col\">Files</th>\n </tr>\n </thead>\n <tbody>\n"
for file in os.listdir(basepath): #grab attack script dirs
    if not os.path.isdir(os.path.join(basepath, file)): continue
    if "attack" not in file: continue # directories with "attack" in it are attack results
    attackstr += "<tr>\n"
    attackstr += "<th scope=\"row\"><p class=\"font-weight-bold\">" +  datetime.utcfromtimestamp(int(os.path.getmtime(os.path.join(basepath, file)))).strftime('%Y-%m-%d %H:%M:%S') + "</p></th>\n"
    attackstr += "<td><p class=\"font-weight-bold\">" + file + "</p></td>\n"
    for el in os.listdir(os.path.join(basepath,file)):
        if ".html" in el:
            attackstr += "<td><a href=\"./" + os.path.join(file, el) + "\">" + el + "</a></td>\n"
    attackstr += "<td><a href=\"./" + file + "\">" + "Tests" + "</a></td>\n"
    attackstr+= "</tr>\n"
attackstr += "</tbody>\n </table>\n"

f.write(templatestr.format('Results', '', resultstr, attackstr))
f.close()

# about page
#f = open(os.path.join(basepath, "about.html"), "w")
#f.write(templatestr.format('About', 'A testbed for IoT devices', '', ''))
#f.close()

# help page
#f = open(os.path.join(basepath, "help.html"), "w")
#f.write(templatestr.format('Help', 'The best way to get help is to follow the instructions on the git page', '', ''))
#f.close()

# upload page
f = open(os.path.join(basepath, "upload.html"), "w")
uploadForm = '''
<form action="http://localhost:8000/api/upload_pcap/" method="post" enctype="multipart/form-data">
    <input type="file" name="file" id="file">
    <input type="submit" value="Upload Pcap" name="submit">
</form>
'''
f.write(templatestr.format('Upload', uploadForm, "", ""))
f.close()

# attack page
f = open(os.path.join(basepath, "attack.html"), "w")
attackForm = '''
<form action="http://localhost:8000/api/attack/" method="get">
    <label for="ip">IP Address: </label>
    <input type="text" id="ip" name="ip"><br>
    <input type="submit">
</form>
'''
f.write(templatestr.format('Attack', attackForm, "", ""))
f.close()


# pcapreporter page
f = open(os.path.join(basepath, "pcapreporter.html"), "w")
pcapreporterForm = '''
<form action="http://localhost:8000/api/pcapreporter/" method="get">
    <label for="ip">Pcap: </label>
    <input type="text" id="pcap" name="pcap"><br>
    <label for="ip">Name: </label>
    <input type="text" id="name" name="name"><br>
    <input type="submit">
</form>
'''
f.write(templatestr.format('Pcapreporter', pcapreporterForm, "", ""))
f.close()


