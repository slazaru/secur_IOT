# secur_IOT

### Description

An environment to test sketchy IoT devices. When the IoT device sends a DHCP request to the router, several tests are run and are published on the router's web server. This project is WIP.

### Requirements

A computer capable of running Debian-based Linux with atleast 2 network interfaces.

One of the interfaces needs to be wireless to act as an access point that the other devices connect to.

I used a Raspberry Pi 4.

### Setup

For the setup instructions I'll assume you're using a RPI 2/3/4, but any Debian-based distro should work with some fiddling.

#### Python setup

`sudo apt-get install python-pip`

`sudo apt-get install python3-pip`

#### For monitor.py
`pip3 install watchdog`

#### For pcap_reporter.py
Put location of pcapviz main.py and makeclouds.py in file

#### For makeclouds.py
`sudo apt-get install libatlas-base-dev`

`sudo apt-get install libopenjp2-7`

`sudo apt-get install python3-tk `

`sudo apt-get install tshark`

`pip3 install scapy`

`pip3 install wordcloud`

`pip3 install networkx`

#### pcapgrok (pcap viz variant)
`git clone https://github.com/fubar2/pcapGrok.git`
Put absolute path of main.py in pcap_reporter.py
`pip3 install -r requirements.txt`
`sudo apt-get install -y graphviz-dev`
`sudo apt-get install -y graphviz`

#### nmap

`sudo apt-get install nmap`

Find where the nmap scripts live `find / -name "*.nse" 2>/dev/null`

Add https://github.com/vulnersCom/nmap-vulners/blob/master/vulners.nse to the scripts dir above (there's a copy in this repo), or
`wget https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/http-vulners-regex.nse -O /usr/share/nmap/scripts/vulners.nse`
`sudo ln -s /home/pi/secur_IOT/nmapTests.sh /usr/local/bin/`

#### wfuzz
`pip3 install wfuzz`
Move common.txt to and directory-list-2.3-medium.txt /usr/share/wordlists/dirb/
Move extensions.txt to /usr/share/wordlists/dirb/extensions.txt

#### smbmap
Follow instructions https://github.com/ShawnDEvans/smbmap
Will probably need to add a symlink in a $PATH dir

#### smbclient
`sudo apt-get install smbclient`

#### sslscan
`sudo apt-get install sslscan`
To enable old openssl protocols (dangerous) https://gist.github.com/bmaupin/8caca3a1e8c3c5686141

#### snmpcheck 
https://github.com/pwnieexpress/pwn_plug_sources/blob/master/src/snmpcheck/snmpcheck-1.8.pl
Add symlink to $PATH
`chmod +x snmpcheck-1.8.pl`
`ln -s /home/pi/opt/snmpcheck-1.8.pl /usr/local/bin`
Get rid of /usr/bin/perl^M: bad interpreter: change shebang (the first line) in joomscan.pl to #!/usr/bin/perl --
`sudo perl -MCPAN -e 'install Net::SNMP'`
`sudo perl -MCPAN -e 'install Crypt::CBC'`
`sudo perl -MCPAN -e 'install Number::Bytes::Human' `

#### snmpwalk
https://github.com/curesec/tools/blob/master/snmp/snmp-walk.py
`pip install pysnmp`
Add to $PATH
`chmod +x snmp-walk.py`
`ln -s /home/pi/snmp-walk.py /usr/local/bin`

#### nikto
`sudo apt-get install nikto`

#### sslscan
`sudo apt-get install sslscan`

#### joomscan
`git clone https://github.com/rezasp/joomscan.git`
`cd joomscan`
`apt-get install libwww-perl`
Allow to be run anywhere: 
`sudo ln -s /home/pi/opt/joomscan/joomscan.pl /usr/local/bin/`
Get rid of /usr/bin/perl^M: bad interpreter: change shebang (the first line) in joomscan.pl to #!/usr/bin/perl --


#### wpscan
`sudo apt-get install gem`
`sudo apt-get install rubygems`
`sudo apt-get install ruby-dev`
`gem install wpscan`

#### droopescan
`pip3 install droopescan`

#### enum4linux
`git clone https://github.com/portcullislabs/enum4linux.git`
Will need to add symlink to $PAT

#### hydra
`sudo apt-get install hydra`

#### dnsrecon
https://github.com/darkoperator/dnsrecon/wiki/Installation-Instructions
`pip install netaddr`
`pip install dnspython`
`sudo apt-get install python-lxml`
`git clone https://github.com/darkoperator/dnsrecon.git`
`cp dnsrecon.py dnsrecon`
`sudo ln -s /home/pi/opt/dnsrecon/dnsrecon /usr/bin` (or wherever you put the git repo)
You should now be able to run dnsrecon from bash in any directory

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
