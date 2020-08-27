# centos_router

Readme
Version 1.0 Aug 2020 Robert Thomas

Please read this.

If you're running a Linux host and want to find out quickly if you have ipv6 support, here's a quick way:
type in "ip addr list". You should see your interfaces. Look for two lines that say ipv6. The second one should
say fe80. The other one will likely start with 2001 if you're a comcast customer. Great news so far. Become root. Type in:
dhclient -N -P -pf /var/run/dhclient.pid ens224
This of course means that ens224 is the interface that you see your external ipv6 address on, change as needed.
If you have a block of ipv6 numbers you'll see something like

Prefix REBIND6 old=NONE new=2600:100:4400:200::/64

That's your set of ip addresses, a whole /64 out of /128. In other words, many many times what ipv4 has. If you don't get
that your provider doesn't supply ipv6 blocks as part of your service. Sorry.


You made it this far, sounds like you're in the running! Cool.

This software comes with no warranty, No guarantee. It may not be how you'd do it. Constructive criticism welcome.

Requirements: Centos 8 VM. Physical host access to two ethernet interfaces. Why centos 8? You want your router to be
running something stable and not something like Fedora. Don't use debian or ubuntu. You're asking for trouble if you do.
Nothing religious, RedHat makes a really good, reliable, stable OS and distro. Might as well take advantage of it.


Tested setup: Centus 8 VM running on vmware 6.5 running on a DL380 G5. Cable device is a Motorola Surfboard. Inside I'm running a
cisco switch, other Gig switches, Cisco wifi. Set the first interface to your internal network. Set the second interface
to the network going to the internet interface (surfboard).

Overall topology:
ipv4 - NAT from the internal network to the Internet.
ipv6 - Flat network. How flat? If you're in another country you can get to my internal devices using ipv6. Why
in the world would I do that? It's great! Now you can have internal machines that can get certificates
and they're accessible outside. No proxy, no other pain in the butt work arounds. You have a real honest to
goodness Internet Address! Things like let's encrypt work with ipv6!

Risks: ipv4 is minimal risk. Traffic is stopped at the firewall. For ipv6 it's a router. You can add rules to allow or deny
traffic via the forward rules. Anything you have on your internal network running ipv6 had better be up to date and
not dependent on being on a separate network. It's good to adopt Zero Trust architecture. Don't have BS passwords
anymore - like "Rat", "Password", "foo". Make them more like "Surf Nazis Must Die,$2400". Cell phones - if you're connecting
your cell phone to your local wifi, beware that it'll also get a IPV6 address that is routable from the internet if
you told your router to allow ipv6.

IPV6 addresses: An Internet provider such as Comcast is providing a /64 address space. I've read where you can get an even larger
block though a /64 is way larger than ipv4 ever was. Many many times larger. Your inside devices will get a DHCP address
and it appears to be random. So your machines inside your network while addressable it's very unlikely anyone will find your
machine.


How to load:
Load up a VM. I have mine set to 200 Gig of storage and 8 gig of memory and two CPUs. Load with CENTOS 8. Update.
Now you're going to want to have the two interfaces configured with a stock firewall. I alwasy get an ens192 and ens224.
ens192 is always set to 192.168.2.1/24 network. If you set it to something else you're not wrong as long as you use
a network that is not routable. Your ens224 should be set to dhcp. Don't disable ipv6 of course. As long as you
see an ipv6 address that is NOT a fe80: address, it's likely a live address. fe80 by the way is the same as localhost
used to be. It's more complicated than that, however just think of it as localhost.

Here is ifcfg-ens192:
TYPE="Ethernet"
PROXY_METHOD="none"
BROWSER_ONLY="no"
BOOTPROTO="none"
DEFROUTE="yes"
IPV4_FAILURE_FATAL="no"
NOZEROCONF=yes
IPV6INIT="yes"
IPV6_AUTOCONF="yes"
IPV6_DEFROUTE="no"
IPV6_FAILURE_FATAL="no"
IPV6_ADDR_GEN_MODE="stable-privacy"
NAME="ens192"
UUID="a0c4e869-8d0c-42b5-9368-b123a36fa71e"
DEVICE="ens192"
ONBOOT="yes"
IPADDR="192.168.2.1"
PREFIX="24"
IPV6_PRIVACY="no"

Here is ifcfg-ens224:

TYPE=Ethernet
PROXY_METHOD=none
BROWSER_ONLY=no
BOOTPROTO=dhcp
DEFROUTE=yes
IPV4_FAILURE_FATAL=no
IPV6INIT=yes
IPV6_AUTOCONF=yes
IPV6_DEFROUTE=yes
IPV6_FAILURE_FATAL=no
IPV6_ADDR_GEN_MODE=stable-privacy
NAME=ens224
UUID=b04f678a-d1d4-426a-9574-eafe2c7026f2
DEVICE=ens224
ONBOOT=yes
DHCPV6C=yes
DHCPV6C_OPTIONS="-P -cf /etc/dhcp/dhclient6.conf"

# Disable make_resolv_conf function in /sbin/dhclient-script.
PEERDNS=no



Append to /etc/sysctl.conf:
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding = 1
net.ipv6.conf.all.forwarding = 1

Type in:
sysctl -p


crontab:
@reboot /root/nft.bash


What the hell is nft? It's the latest firewall stuff. I made some good money with ipchains back in the 1990s. Then iptables.
Now it's nft. Two files. nfrules.bash is a stock set of rules that has masq already set up for interface 192 - 224. I have
some private rules as well. You can easily block port 22 to your internal machines via the forward rule. I allow things to my router
like sendmail. I have a github on how to set up sendmail in two stages to handle e-mail. Of course you could have mail
routed to ipv6 host in the back someplace. A squirrelmail host could be set up on another machine for web access. Once
you get off ipv4 things will really open up for you.


Make sure you chkconfig your radvd daemon on after you fix the prefix line.


Now go to one of your internal machines. Type in "ip addr list" and like magic you should see a new ipv6 address!
If you do a "netstat -6 -rn" you should see your routing tables and you should see that prefix as the second line.
Give 'er a try! You can force things. host google.com

$ host google.com
google.com has address 172.217.13.78
google.com has IPv6 address 2607:f8b0:4004:80a::200e
google.com mail is handled by 10 aspmx.l.google.com.
google.com mail is handled by 50 alt4.aspmx.l.google.com.
google.com mail is handled by 30 alt2.aspmx.l.google.com.
google.com mail is handled by 20 alt1.aspmx.l.google.com.
google.com mail is handled by 40 alt3.aspmx.l.google.com.
[robert@firefox firewall]$ ping -6 2607:f8b0:4004:80a::200e
PING 2607:f8b0:4004:80a::200e(2607:f8b0:4004:80a::200e) 56 data bytes
64 bytes from 2607:f8b0:4004:80a::200e: icmp_seq=1 ttl=115 time=11.2 ms
64 bytes from 2607:f8b0:4004:80a::200e: icmp_seq=2 ttl=115 time=11.7 ms

If you want to pull up a web site in a browser, put the ipv6 address inside of [].
You can also fire up wireshark and you'll start seeing ipv6 addresses.




What can go wrong? UGH... What can go wrong... Comcast or whoever your provider is could decide - you know what, our
customer needs some excitement in his life. Let's change his block of addresses. No kidding, they've done that to me
three times. However as I've been using it more they don't seem to change it. If you fire up another virtual machine
and it has access to your outside connection and it's running dhclient? There's your problem. It can take comcast a while
to settle back down.

DNS. I use zonedit. Unfortunately the software for it seems to deal with just ipv4. I wanted to let ddclient automatically
update things. Maybe we can fix that in the future. For now I login and fix all the addresses that I want the outside
to know about.

If you are running a Linux desktop and want to access one of your local VMs via ipv6? That's spotty. I've had it work and
work well, other times it doesn't want to cooperate. Probably something I did, or forgot to change. Your mileage may
vary.
