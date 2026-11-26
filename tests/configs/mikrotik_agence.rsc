# 2026-11-20 10:12:44 by RouterOS 6.48.6
# software id = ABCD-1234
#
# model = RB4011iGS+
# serial number = HD0123456789
/interface bridge
add name=bridge-lan
/interface vlan
add interface=bridge-lan name=vlan-invites vlan-id=30
/interface list
add name=WAN
add name=LAN
/interface list member
add interface=ether1 list=WAN
add interface=bridge-lan list=LAN
add interface=vlan-invites list=LAN
/ip address
add address=192.168.88.1/24 interface=bridge-lan network=192.168.88.0
add address=192.168.30.1/24 interface=vlan-invites network=192.168.30.0
/ip dhcp-client
add disabled=no interface=ether1
/ip firewall address-list
add address=192.168.88.0/24 list=admins
/ip firewall filter
add action=accept chain=input comment="accept established" connection-state=established,related
add action=accept chain=input protocol=icmp
add action=accept chain=input comment="winbox depuis partout" dst-port=8291 protocol=tcp
add action=accept chain=forward connection-state=established,related
add action=accept chain=forward comment="tout le LAN" src-address=192.168.88.0/24
add action=accept chain=forward comment="doublon LAN web" dst-port=80,443 protocol=tcp src-address=192.168.88.0/24
add action=drop chain=forward comment="invites vers LAN" dst-address=192.168.88.0/24 src-address=192.168.30.0/24
add action=drop chain=forward connection-nat-state=!dstnat connection-state=new in-interface-list=WAN
/ip firewall nat
add action=masquerade chain=srcnat out-interface-list=WAN
add action=dst-nat chain=dstnat comment="NAS" dst-port=5000-5001 in-interface=ether1 protocol=tcp to-addresses=192.168.88.20 to-ports=5000-5001
add action=dst-nat chain=dstnat comment="SSH serveur" dst-port=2222 in-interface=ether1 protocol=tcp src-address=203.0.113.99 to-addresses=192.168.88.21 to-ports=22
/ip service
set ftp disabled=yes
set www-ssl disabled=yes
set api disabled=yes
set api-ssl disabled=yes
/ip upnp
set enabled=yes
/ip dns
set allow-remote-requests=yes servers=1.1.1.1
/snmp
set enabled=yes
/snmp community
set [ find default=yes ] name=public
/interface pptp-server server
set enabled=yes
/ip ipsec profile
set [ find default=yes ] dh-group=modp1024 enc-algorithm=3des hash-algorithm=md5
/ip ipsec peer
add address=198.51.100.60/32 name=siege
/system identity
set name=RB-AGENCE
