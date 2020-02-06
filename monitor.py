#!/usr/bin/env python3

import time
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
import os
import re
from pathlib import Path
import subprocess
import omap

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
    os.chdir('/opt/zeek/logs/current')
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
    if not os.path.isfile('/opt/zeek/logs/current/dhcp.log'):
        print("process new line in monitor says not file")
        return
    f = open('/opt/zeek/logs/current/dhcp.log', 'r')
    lines = f.readlines()
    new_line = lines[-1]
    vals = new_line.split()
    print("values in dhcp.log: " + str(vals))
    id = vals[8] + "_" + vals[4]
    dir = os.path.join('/var/www/html/', id + "_" + "attack")
    p = Path(dir)
    p.mkdir(mode=0o755, parents=True, exist_ok=True)
    run_tests(dir, id)

def on_created(event):
    print("%s has been created!" %(event.src_path))

def on_deleted(event):
    print("deleted %s!" %(event.src_path))

def on_modified(event):
    print("%s has been modified" %(event.src_path))
    process_new_line()

def on_moved(event):
    print("moved %s to %s" %(event.src_path, event.dest_path))

my_event_handler.on_created = on_created
my_event_handler.on_deleted = on_deleted
my_event_handler.on_modified = on_modified
my_event_handler.on_moved = on_moved

path = "."
go_recursively = True
my_observer = Observer()
my_observer.schedule(my_event_handler, path, recursive=go_recursively)

my_observer.start()
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
        my_observer.stop()
        my_observer.join()
