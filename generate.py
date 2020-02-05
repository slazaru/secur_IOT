#!/usr/bin/env python3

import os
import re

basepath = '/var/www/html'
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
  <div class="container-fluid">
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
        <li><a href="about.html">About</a></li>
        <li><a href="help.html">Help</a></li>
        <li><a href="https://github.com/slazaru/iottestbed">Git</a></li>
      </ul>
    </div>
  </div>
</nav>
<div class="container text-center">
<h3>{0}</h3>
<p>{1}</p>
</div>
<div class="container-fluid bg-3 text-center">
{2}
{3}
</div>
<br>
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
resultstr = "<h4>Pcap reports</h4><br><table class=\"table\" border=\"0\">\n"
for file in os.listdir(basepath): #grab pcapreport dirs
    if not os.path.isdir(os.path.join(basepath, file)): continue
    if "pcap" not in file: continue
    resultstr += "<tr style=\"height:100%;\">"
    name = file.split("_")
    resultstr += "<th><p class=\"font-weight-bold\">" + name[0] + "</p></th>"
    resultstr += "<th><p class=\"font-weight-bold\">" + name[1] + "</p></th>"
    for el in os.listdir(os.path.join(basepath,file)):
        if ".html" in el:
            resultstr += "<th><a href=\"./" + os.path.join(file, el) + "\">" + el[:-5] + "</a></th>\n"
        if ".pcap" in el:
            resultstr += "<th><a href=\"./" + os.path.join(file, el) + "\">" + el.split(".")[1] + "</a></th>\n"
    resultstr+= "</tr>\n"
resultstr += "</table>"

# attack script reports
attackstr = "<h4>Attack script reports</h4><br><table class=\"table\" border=\"0\">\n"
for file in os.listdir(basepath): #grab attack script dirs
    if not os.path.isdir(os.path.join(basepath, file)): continue
    if "attack" not in file: continue
    attackstr += "<tr style=\"height:100%;\">"
    attackstr += "<th><p class=\"font-weight-bold\">" + file + "</p></th>"
    for el in os.listdir(os.path.join(basepath,file)):
        if ".html" in el:
            attackstr += "<th><a href=\"./" + os.path.join(file, el) + "\">" + el + "</a></th>\n"
    attackstr += "<th><a href=\"./" + file + "\">" + "Tests" + "</a></th>\n"
    attackstr+= "</tr>\n"
attackstr += "</table>"

f.write(templatestr.format('Results', '', resultstr, attackstr))
f.close()

# about page
f = open(os.path.join(basepath, "about.html"), "w")
f.write(templatestr.format('About', 'A testbed for IoT devices', '', ''))
f.close()

# help page
f = open(os.path.join(basepath, "help.html"), "w")
f.write(templatestr.format('Help', 'The best way to get help is to follow the instructions on the git page', '', ''))
f.close()

