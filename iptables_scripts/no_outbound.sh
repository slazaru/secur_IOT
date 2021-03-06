
iptables -F
iptables --table nat --flush
iptables --delete-chain

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

iptables -A INPUT -i eth0 -j DROP
iptables -A OUTPUT -o eth0 -j DROP
iptables -A FORWARD -o eth0 -j DROP
