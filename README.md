# secur_IOT

### Description

### Requirements

A computer capable of running Debian-based Linux with atleast 2 network interfaces.
One of the interfaces needs to be wireless to act as an access point that the other devices connect to.
I used a Raspberry Pi 4.

### Setup

For the setup instructions I'll assume you're using a RPI 2/3/4, but any Debian-based distro should work.

Set up the wireless access point.
https://github.com/SurferTim/documentation/blob/6bc583965254fa292a470990c40b145f553f6b34/configuration/wireless/access-point.md
There are copies of all of the config files necessary for this in this repo to make it easier.
(TODO: shell script for setup)

Once you're connected, set up ssh key access to the Pi.
https://www.raspberrypi.org/documentation/remote-access/ssh/passwordless.md

Set up Zeek.
https://docs.zeek.org/en/stable/install/install.html

After setting up Zeek, set up kyd, a library for Zeek for DHCP fingerprinting
https://github.com/fatemabw/kyd#usage--installation

Set up nginx.
https://www.raspberrypi.org/documentation/remote-access/web-server/nginx.md
Stop after "Testing the webserver" section.
Use the nginx config files supplied in this repo

Run the monitor.py script.

....
