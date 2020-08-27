#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/root/bin
export PATH
nft flush ruleset *
/root/nfrules.bash
#/usr/sbin/nft add rule inet firewalld filter_IN_public_allow tcp dport 25 ct state { new, untracked } accept
#/usr/sbin/nft add rule inet firewalld filter_IN_public_allow tcp dport 80 ct state { new, untracked } accept
#/usr/sbin/nft add rule inet firewalld filter_IN_public_allow tcp dport 443 ct state { new, untracked } accept
#/usr/sbin/nft add rule inet firewalld filter_IN_public_allow tcp dport 993 ct state { new, untracked } accept
#/usr/sbin/nft add rule inet firewalld filter_IN_public_allow tcp dport 24 ct state { new, untracked } accept
#/usr/sbin/nft add rule inet firewalld filter_IN_public_allow udp dport 1812 ct state { new, untracked } accept
#/usr/sbin/nft add rule inet firewalld filter_IN_public_allow udp dport 1813 ct state { new, untracked } accept
#/usr/sbin/nft add rule ip6 security INPUT tcp dport 24 ct state { new, untracked } accept
service fail2ban restart
