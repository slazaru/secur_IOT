#!/usr/bin/env python3

import os
import re
from pathlib import Path
import subprocess
import omap
import argparse

# where reports are saved
htmlRoot = "/var/www/html"

parser = argparse.ArgumentParser(description='Attack script')
parser.add_argument('ip', help='ip address to run attack script against')
args = parser.parse_args()

# quick sanity check for ipv4 address formatting
valid = True
split = args.ip.split('.')
if len(split) != 4:
   valid = False
for el in split:
    if int(el) < 0 or int(el) > 255:
        valid = False
if not valid:
    print("Invalid ipv4 address")
    exit()

# make the report dir
dir = os.path.join(htmlRoot, args.ip + "_" + "attack")
p = Path(dir)
p.mkdir(mode=0o755, parents=True, exist_ok=True)

# run the attack script
omap.runAllTests(dir, args.ip, True)
# regenerate home page
cmd = []
cmd.append("generate.py")
p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr = subprocess.PIPE, shell=False)
if p.stderr:
    for line in p.stderr:
        print(line)
