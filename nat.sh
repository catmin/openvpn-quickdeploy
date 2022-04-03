

iptables -t nat -A POSTROUTING -s 10.99.66.0/24 -d 10.6.0.0/24 -j MASQUERADE
