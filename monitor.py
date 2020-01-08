import time
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
import os
import re

# set of device ip:mac addresses that we've seen already
seen = set()

# if there's a device in dhcp.log that doesn't have a corresponding directory
# in /var/www/html, create the directory and run some tests
def check_for_new():
    f = open('/usr/local/zeek/logs/current/dhcp.log', 'r')
    for el in f:
        if el[0] == '#': #its a comment, skip 
            continue
        vals = re.split(r'\t+',el)
        id = vals[2] + "_" + vals[4]
        if id not in seen:
            print("new device found: " + id)
            dir = '/var/www/html/' + id
            print("making directory: " + dir)
            os.mkdir(dir)
            run_tests(id)

def run_tests(id):
    # nmap
    # TODO: prompt for which tests to run, for now just do them all
    ip = id.split(_)
    print("ip: " + ip)
    print("cwd: " + os.getcwd())
    cmd = "sudo nmap " + ip + " > /var/www/html/" + id + "/nmap" 
    print(cmd)
    os.system(cmd)

if __name__ == "__main__":
    os.chdir('/usr/local/zeek/logs/current')
    patterns = ["./dhcp.log"]
    ignore_patterns = ""
    ignore_directories = False
    case_sensitive = True
    my_event_handler = PatternMatchingEventHandler(patterns, ignore_patterns, ignore_directories, case_sensitive)
    dirs = os.listdir('/var/www/html')
    for el in dirs:
        seen.add(el)
    print("seen:")
    print(seen)
    if os.path.isfile('/usr/local/zeek/logs/current/dhcp.log'):
        check_for_new()

def on_created(event):
    print("%s has been created!" %(event.src_path))

def on_deleted(event):
    print("deleted %s!" %(event.src_path))

def on_modified(event):
    print("%s has been modified" %(event.src_path))
    if os.path.isfile('/usr/local/zeek/logs/current/dhcp.log'):
        check_for_new()

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
