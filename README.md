# secur_IOT

### Description

An environment to test sketchy IoT devices. When the IoT device sends a DHCP request to the router, several tests are run and are published on the router's web server. This project is WIP, don't expect any of it to work.

### Requirements

A computer capable of running Debian-based Linux with atleast 2 network interfaces.

One of the interfaces needs to be wireless to act as an access point that the other devices connect to.

I used a Raspberry Pi 4.

### Setup

For the setup instructions I'll assume you're using a RPI 2/3/4, but any Debian-based distro should work.

#### Python setup

`sudo apt-get install python-pip`

`sudo apt-get install python3-pip`

#### For wordclouds.py
`sudo apt-get install libatlas-base-dev`

`sudo apt-get install libopenjp2-7`

`sudo apt-get install python3-tk `

`sudo apt-get install tshark`

`pip3 install scapy`

`pip3 install wordcloud`

`pip3 install networkx`

#### nmap

`sudo apt-get install nmap`

find where the nmap scripts live `find / -name "*.nse" 2>/dev/null`

add https://github.com/vulnersCom/nmap-vulners/blob/master/http-vulners-regex.nse to scripts dir (there's a copy in this repo)

`wget https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/http-vulners-regex.nse -O /usr/share/nmap/scripts/http-vulners-regex.nse`

Make symbolic link so nmapTests.sh can be run anywhere
`sudo ln -s /home/pi/secur_IOT/nmapTests.sh /usr/local/bin/`

Add execute permission to nmapTests.sh
`chmod +x nmapTests.sh`

#### gobuster
`sudo apt-get install gobuster`

#### nikto
`sudo apt-get install nikto`

#### Wireless access point
https://github.com/SurferTim/documentation/blob/6bc583965254fa292a470990c40b145f553f6b34/configuration/wireless/access-point.md

There are copies of all of the config files necessary for this in this repo to make it easier.

#### SSH access

Once you're connected, set up ssh key access to the Pi.

https://www.raspberrypi.org/documentation/remote-access/ssh/passwordless.md

#### Zeek
Set up Zeek.

https://docs.zeek.org/en/stable/install/install.html

Turn log rotation off in /usr/local/zeek/etc/zeekctl.cfg

`LogRotationInterval = 0`

#### Kyd

After setting up Zeek, set up kyd, a library for Zeek for DHCP fingerprinting

https://github.com/fatemabw/kyd#usage--installation

#### Nginx
Set up nginx.

https://www.raspberrypi.org/documentation/remote-access/web-server/nginx.md

Stop after "Testing the webserver" section.

Use the nginx config files supplied in this repo

Make a symlink from /var/www/html/zeek_logs to /usr/local/zeek/logs/current so they're browsable
`sudo ln -s /usr/local/zeek/logs/current zeek_logs`

Run the monitor.py script.

....
