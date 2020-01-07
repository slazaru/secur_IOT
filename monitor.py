import time
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
import os

if __name__ == "__main__":
    print(os.getcwd())
    os.chdir('/usr/local/zeek/logs/current')
    print(os.getcwd())
    patterns = ["./dhcp.log"]
    ignore_patterns = ""
    ignore_directories = False
    case_sensitive = True
    my_event_handler = PatternMatchingEventHandler(patterns, ignore_patterns, ignore_directories, case_sensitive)

def on_created(event):
    print("%s has been created!" %(event.src_path))

def on_deleted(event):
    print("deleted %s!" %(event.src_path))

def on_modified(event):
    print("%s has been modified" %(event.src_path))

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
