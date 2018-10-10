#!/bin/bash
# This script will allow 2 clients to talk if they are both on a ProtectedPorts or PVLANs enabled switch.
# For more details please check out the talk "The Layer2 Nightmare @ DerbyCon2018"

# This is usefull in a ZeroTrust network as it allows you to MicroSegment each box
# without any crazy subnetting or having a "Zone" for each box.

modprobe ip_tables
modprobe ip_conntrack

# The internet iface or "The Internet"
iNET=eth0
# The internal iface connected to your ProtectedPorts switch
iLAN=eth1


flush_all()
{
    /etc/init.d/networking stop
    killall dhclient
    killall dnsmasq
    killall wireshark
    ifconfig $iNET down
    ifconfig $iLAN down
    # remove the assigned IP
    ifconfig $iNET 0.0.0.0
    ifconfig $iLAN 0.0.0.0
    # Remove forwarding
    echo 0 > /proc/sys/net/ipv4/ip_forward
    # default accept and reply for ICMP redirects
    echo 1 > /proc/sys/net/ipv4/conf/$iLAN/accept_redirects
    echo 1 > /proc/sys/net/ipv4/conf/$iLAN/send_redirects

    # the magic settings for LOCAL_proxy_arp
    if [ ! -f /proc/sys/net/ipv4/conf/$iLAN/proxy_arp_pvlan ]; then
        echo "PROXY_ARP_PVLAN NOT FOUND!"
        echo "Please use choparp.... exiting"
        exit
    fi
    echo 0 > /proc/sys/net/ipv4/conf/$iLAN/proxy_arp_pvlan
    # Deleting all the rules in INPUT, OUTPUT and FILTER   
    iptables --flush
    # Flush all the rules in nat table 
    iptables --table nat --flush
    # Delete all existing chains
    iptables --delete-chain
    # Delete all chains that are not in default filter and nat table
    iptables --table nat --delete-chain
}

disable_redirect()
{
    # disable accept and reply for ICMP redirects (this will happen with proxy_arp)
    # You MUST enable redirects on both all and the iface name, but you should ALREADY have this!!!
    echo 0 > /proc/sys/net/ipv4/conf/$iLAN/accept_redirects
    echo 0 > /proc/sys/net/ipv4/conf/$iLAN/send_redirects
    echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
    echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
    # echo | tee /proc/sys/net/ipv4/conf/*/send_redirects
    # echo | tee /proc/sys/net/ipv4/conf/*/accept_redirects
}

enable_natfw()
{
    # Enable forwarding 
    echo "1" > /proc/sys/net/ipv4/ip_forward
    iNET="eth0"
    iLAN="eth1"
    # Enable nat on our external iface
    iptables -t nat -A POSTROUTING -o $iNET -j MASQUERADE
    # allow forwarding connections from inet->ilan if its in the state table
    iptables -A FORWARD -i $iNET -o $iLAN -m state --state RELATED,ESTABLISHED -j ACCEPT
    # allow forwarding from ilan-> inet
    iptables -A FORWARD -i $iLAN -o $iNET -j ACCEPT

    # this will allow all intersubnet traffic, traffic will NOT be blocked by the cleanup rule!
    # iptables -A FORWARD -i $iLAN -o $iLAN -j ACCEPT

    # Allow web traffic from clientA to clientB
    iptables -A FORWARD -i $iLAN -o $iLAN -p tcp -s $clientA -d $clientB --dport 80 -m state --state NEW,ESTABLISHED -j LOG --log-prefix "PROXYARP_AtoB_80 "
    iptables -A FORWARD -i $iLAN -o $iLAN -p tcp -s $clientA -d $clientB --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
    # Allow returl traffic from clientB to clientA
    iptables -A FORWARD -i $iLAN -o $iLAN -p tcp -s $clientB -d $clientA --sport 80 -m state --state ESTABLISHED -j LOG --log-prefix "PROXYARP_BrplyA_80 "
    iptables -A FORWARD -i $iLAN -o $iLAN -p tcp -s $clientB -d $clientA --sport 80 -m state --state ESTABLISHED -j ACCEPT
    # No reason to mess with loopback today... but this can be bad.
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    # our cleanup rule, DROP EVERYTHING!
    iptables -A INPUT -j DROP
    iptables -A OUTPUT -j DROP
    iptables -A FORWARD -j DROP
}


enable_dhcp()
{
    # setup ip address on ilan
    ifconfig $iLAN up 10.10.10.1 netmask 255.255.255.0
    # set routing on ilan
    route add -net 10.10.10.0 netmask 255.255.255.0 gw 10.10.10.1
    # dnsmasq configuration
    echo "interface=$iLAN
    dhcp-range=10.10.10.100,10.10.10.150,255.255.255.0,1h # dhcp address range 100-150
    dhcp-option=3,10.10.10.1 # gateway IP
    dhcp-option=6,10.10.10.1 # DNS IP
    # server=8.8.8.8    # override /etc/resolv.conf DNS? 
    log-queries
    log-dhcp
    dhcp-host=00:00:00:AA:AA:AA, 10.10.10.11
    dhcp-host=00:00:00:BB:BB:BB, 10.10.10.22
    # listen-address=127.0.0.1" > /tmp/dns.conf
    # start dnsmasq with our settings.
    dnsmasq -C /tmp/dns.conf
}


enable_proxyarp()
{
    if [ ! -f /proc/sys/net/ipv4/conf/$iLAN/proxy_arp_pvlan ]; then
        echo "PROXY_ARP_PVLAN NOT FOUND!"
        echo "Please use choparp.... exiting"
        exit
    fi
    echo "Setting proxy_arp_pvlan... lets cross those fingers!"
    # the magic settings for LOCAL_proxy_arp
    echo 1 > /proc/sys/net/ipv4/conf/$iLAN/proxy_arp_pvlan
}


rload()
{
    killall wireshark
    ifconfig $iLAN up
    wireshark -k -i $ilan &
    ifconfig $iNET up
    wireshark -k -i $inet &
}


flush_all
# rload
enable_proxyarp
disable_redirect
enable_dhcp
enable_natfw
