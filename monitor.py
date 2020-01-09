
import time
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
import os
import re
from pathlib import Path
import subprocess

def process_new_line():
    if not os.path.isfile('/usr/local/zeek/logs/current/dhcp.log'):
        return
    f = open('/usr/local/zeek/logs/current/dhcp.log', 'r')
    lines = f.readlines()
    new_line = lines[-1]
    vals = re.split(r'\t+', new_line)
    id = vals[2] + "_" + vals[4]
    dir = '/var/www/html/' + id
    p = Path(dir)
    p.mkdir(mode=0o755, parents=True, exist_ok=True)
    run_tests(id)

def run_tests(id):
    ip = id.split('_')[0]
    print("A device [ " + id + " ] just made a DHCP request.")
    txt = input("Would you like to run tests on this device? (y/n)")
    if txt != 'Y' and txt != 'y':
        print("Not running tests")
        return
    dir = '/var/www/html/' + id + '/nmap'
    p = Path(dir)
    p.mkdir(mode=0o755, parents=True, exist_ok=True)
    #scans = ['Quick', 'Basic', 'Vulns', 'Recon']
    scans = ['Recon']
    for scan in scans:
        dir = '/var/www/html/' + id + '/nmap/' + scan
        cmd = ['sudo', 'nmapTests.sh', ip, scan]
        print("Running " + ' '.join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        f = open(dir, "w+")
        for line in p.stdout:
            line=line.decode('ascii')
            print(line)
            f.write(line)
        p.wait()
        f.close()
    # note that nmapTests.sh will spit some files out in the cwd
    # could clear them up here if necessary ..

if __name__ == "__main__":
    os.chdir('/usr/local/zeek/logs/current')
    patterns = ["./dhcp.log"]
    ignore_patterns = ""
    ignore_directories = False
    case_sensitive = True
    my_event_handler = PatternMatchingEventHandler(patterns, ignore_patterns, ignore_directories, case_sensitive)
    # test 
    run_tests("192.168.4.1_00:ec:0a:ca:e9:ea/")

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
