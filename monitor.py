#!/usr/bin/env python3

import time
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
import os
import re
from pathlib import Path
import subprocess
import omap

dhcplogDir = "/opt/zeek/logs/current"

def run_tests(dir, id, debugFlag=False):
    ip = id.split('_')[0]
    print("A device [ " + id + " ] just made a DHCP request.")
    txt = input("Would you like to run tests on this device? (y/n)")
    if txt != 'Y' and txt != 'y':
        print("Not running tests")
        return
    omap.runAllTests(dir,ip,debugFlag)
    # regenerate home page
    cmd = []
    cmd.append("generate.py")
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr = subprocess.PIPE, shell=False)
    if p.stderr:
        for line in p.stderr:
            print(line)

if __name__ == "__main__":
    os.chdir(dhcplogDir)
    patterns = ["./dhcp.log"]
    ignore_patterns = ""
    ignore_directories = False
    case_sensitive = True
    my_event_handler = PatternMatchingEventHandler(patterns, ignore_patterns, ignore_directories, case_sensitive)
    # for testing vvv 
'''
    dir = "/var/www/html/192.168.4.1_dc:a6:32:41:12:99_attack"
    id = "192.168.4.1_00:dc:a6:32:41:12:99"
    p = Path(dir)
    p.mkdir(mode=0o755, parents=True, exist_ok=True)
    run_tests(dir,id,True)
    exit()
'''
    # testing ^^^

def process_new_line():
    try:
        f = open(os.path.join(dhcplogDir, "dhcp.log"), "r")
    except Exception as e:
        print("Couldn't open dhcp.log: " + str(e))
        return
    lines = f.readlines()
    new_line = lines[-1]
    if new_line[0] == '#':
        # it's a comment line, skip it
        return
    #print("New line in dhcp.log: " + new_line)
    vals = new_line.split()
    #print("values in dhcp.log: " + str(vals))
    id = vals[8] + "_" + vals[4]
    dir = os.path.join('/var/www/html/', id + "_" + "attack")
    p = Path(dir)
    p.mkdir(mode=0o755, parents=True, exist_ok=True)
    run_tests(dir, id)

def on_modified(event):
    process_new_line()

my_event_handler.on_modified = on_modified

path = "."
go_recursively = True
my_observer = Observer()
my_observer.schedule(my_event_handler, path, recursive=go_recursively)

my_observer.start()
print("Waiting for DHCP requests ..")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
        my_observer.stop()
        my_observer.join()
