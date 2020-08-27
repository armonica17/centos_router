#!/usr/sbin/nft -f
table ip filter {
        chain INPUT {
                type filter hook input priority filter; policy accept;
        }

        chain FORWARD {
                type filter hook forward priority filter; policy accept;
        }

        chain OUTPUT {
                type filter hook output priority filter; policy accept;
        }
}
table ip6 filter {
        chain INPUT {
                type filter hook input priority filter; policy accept;
        }

        chain FORWARD {
            # Don't allow outside people to ssh in.
            tcp dport 22 ct state { new, untracked } drop
                type filter hook forward priority filter; policy accept;
        }

        chain OUTPUT {
                type filter hook output priority filter; policy accept;
        }
}
table bridge filter {
        chain INPUT {
                type filter hook input priority filter; policy accept;
        }

        chain FORWARD {
                type filter hook forward priority filter; policy accept;
        }

        chain OUTPUT {
                type filter hook output priority filter; policy accept;
        }
}
table ip security {
        chain INPUT {
                type filter hook input priority 150; policy accept;
        }

        chain FORWARD {
                type filter hook forward priority 150; policy accept;
        }

        chain OUTPUT {
                type filter hook output priority 150; policy accept;
        }
}
table ip raw {
        chain PREROUTING {
                type filter hook prerouting priority raw; policy accept;
        }

        chain OUTPUT {
                type filter hook output priority raw; policy accept;
        }
}
table ip mangle {
        chain PREROUTING {
                type filter hook prerouting priority mangle; policy accept;
        }

        chain INPUT {
                type filter hook input priority mangle; policy accept;
        }

        chain FORWARD {
                type filter hook forward priority mangle; policy accept;
        }

        chain OUTPUT {
                type route hook output priority mangle; policy accept;
        }

        chain POSTROUTING {
                type filter hook postrouting priority mangle; policy accept;
        }
}
table ip nat {
        chain PREROUTING {
                type nat hook prerouting priority dstnat; policy accept;
        }

        chain INPUT {
                type nat hook input priority 100; policy accept;
        }

        chain POSTROUTING {
                type nat hook postrouting priority srcnat; policy accept;
        }

        chain OUTPUT {
                type nat hook output priority -100; policy accept;
        }
}
table ip6 security {
        chain INPUT {
                type filter hook input priority 150; policy accept;
        }

        chain FORWARD {
                type filter hook forward priority 150; policy accept;
        }

        chain OUTPUT {
                type filter hook output priority 150; policy accept;
        }
}
table ip6 raw {
        chain PREROUTING {
                type filter hook prerouting priority raw; policy accept;
        }

        chain OUTPUT {
                type filter hook output priority raw; policy accept;
        }
}
table ip6 mangle {
        chain PREROUTING {
                type filter hook prerouting priority mangle; policy accept;
        }

        chain INPUT {
                type filter hook input priority mangle; policy accept;
        }

        chain FORWARD {
                type filter hook forward priority mangle; policy accept;
        }

        chain OUTPUT {
                type route hook output priority mangle; policy accept;
        }

        chain POSTROUTING {
                type filter hook postrouting priority mangle; policy accept;
        }
}
table ip6 nat {
        chain PREROUTING {
                type nat hook prerouting priority dstnat; policy accept;
        }

        chain INPUT {
                type nat hook input priority 100; policy accept;
        }

        chain POSTROUTING {
                type nat hook postrouting priority srcnat; policy accept;
        }

        chain OUTPUT {
                type nat hook output priority -100; policy accept;
        }
}
table bridge nat {
        chain PREROUTING {
                type filter hook prerouting priority dstnat; policy accept;
        }

        chain OUTPUT {
                type filter hook output priority out; policy accept;
        }

        chain POSTROUTING {
                type filter hook postrouting priority srcnat; policy accept;
        }
}
table inet firewalld {
        ct helper helper-tftp-udp {
                type "tftp" protocol udp
                l3proto inet
        }

        chain raw_PREROUTING {
                type filter hook prerouting priority raw + 10; policy accept;
                icmpv6 type { nd-router-advert, nd-neighbor-solicit } accept
                meta nfproto ipv6 fib saddr . iif oif missing drop
                jump raw_PREROUTING_ZONES_SOURCE
                jump raw_PREROUTING_ZONES
        }

        chain raw_PREROUTING_ZONES_SOURCE {
        }

        chain raw_PREROUTING_ZONES {
                iifname "ens224" goto raw_PRE_public
                iifname "virbr0" goto raw_PRE_libvirt
                iifname "ens192" goto raw_PRE_public
                goto raw_PRE_public
        }

        chain mangle_PREROUTING {
                type filter hook prerouting priority mangle + 10; policy accept;
                jump mangle_PREROUTING_ZONES_SOURCE
                jump mangle_PREROUTING_ZONES
        }

        chain mangle_PREROUTING_ZONES_SOURCE {
        }

        chain mangle_PREROUTING_ZONES {
                iifname "ens224" goto mangle_PRE_public
                iifname "virbr0" goto mangle_PRE_libvirt
                iifname "ens192" goto mangle_PRE_public
                goto mangle_PRE_public
        }

        chain filter_INPUT {
                type filter hook input priority filter + 10; policy accept;
                ct state { established, related } accept
                ct status dnat accept
                iifname "lo" accept
                jump filter_INPUT_ZONES_SOURCE
                jump filter_INPUT_ZONES
                ct state { invalid } drop
                reject with icmpx type admin-prohibited
        }

        chain filter_FORWARD {
                type filter hook forward priority filter + 10; policy accept;
                ct state { established, related } accept
                ct status dnat accept
                iifname "lo" accept
                ip6 daddr { ::/96, ::ffff:0.0.0.0/96, 2002::/24, 2002:a00::/24, 2002:7f00::/24, 2002:a9fe::/32, 2002:ac10::/28, 2002:c0a8::/32, 2002:e000::/19 } reject with icmpv6 type addr-unreachable
                jump filter_FORWARD_IN_ZONES_SOURCE
                jump filter_FORWARD_IN_ZONES
                jump filter_FORWARD_OUT_ZONES_SOURCE
                jump filter_FORWARD_OUT_ZONES
                ct state { invalid } drop
                reject with icmpx type admin-prohibited
        }

        chain filter_OUTPUT {
                type filter hook output priority filter + 10; policy accept;
                oifname "lo" accept
                ip6 daddr { ::/96, ::ffff:0.0.0.0/96, 2002::/24, 2002:a00::/24, 2002:7f00::/24, 2002:a9fe::/32, 2002:ac10::/28, 2002:c0a8::/32, 2002:e000::/19 } reject with icmpv6 type addr-unreachable
        }

        chain filter_INPUT_ZONES_SOURCE {
        }

        chain filter_INPUT_ZONES {
#                iifname "ens224" goto filter_IN_public
                iifname "virbr0" goto filter_IN_libvirt
                iifname "ens192" goto filter_IN_private
                goto filter_IN_public
        }

        chain filter_FORWARD_IN_ZONES_SOURCE {
        }

        chain filter_FORWARD_IN_ZONES {
                iifname "ens224" goto filter_FWDI_public
                iifname "virbr0" goto filter_FWDI_libvirt
                iifname "ens192" goto filter_FWDI_public
                goto filter_FWDI_public
        }

        chain filter_FORWARD_OUT_ZONES_SOURCE {
        }

        chain filter_FORWARD_OUT_ZONES {
                oifname "ens224" goto filter_FWDO_public
                oifname "virbr0" goto filter_FWDO_libvirt
                oifname "ens192" goto filter_FWDO_public
                goto filter_FWDO_public
        }

        chain raw_PRE_public {
                jump raw_PRE_public_pre
                jump raw_PRE_public_log
                jump raw_PRE_public_deny
                jump raw_PRE_public_allow
                jump raw_PRE_public_post
        }

        chain raw_PRE_public_pre {
        }

        chain raw_PRE_public_log {
        }

        chain raw_PRE_public_deny {
        }

        chain raw_PRE_public_allow {
        }

        chain raw_PRE_public_post {
        }

        chain filter_IN_public {
                jump filter_IN_public_pre
                jump filter_IN_public_log
                jump filter_IN_public_deny
                jump filter_IN_public_allow
                jump filter_IN_public_post
                meta l4proto { icmp, ipv6-icmp } accept
        }

        chain filter_IN_private {
                jump filter_IN_public_pre
                jump filter_IN_public_log
                jump filter_IN_public_deny
                jump filter_IN_private_allow
                jump filter_IN_public_post
                meta l4proto { icmp, ipv6-icmp } accept
        }

        chain filter_IN_public_pre {
        }

        chain filter_IN_public_log {
        }

        chain filter_IN_public_deny {
        }

        chain filter_IN_public_allow {
            tcp dport 24 ct state { new, untracked } accept
#           tcp dport 22 ct state { new, untracked } accept
            ip6 daddr fe80::/64 udp dport 546 ct state { new, untracked } accept
            tcp dport 80 ct state { new, untracked } accept
            tcp dport 443 ct state { new, untracked } accept
            tcp dport 25 ct state { new, untracked } accept
            tcp dport 993 ct state { new, untracked } accept
            tcp dport 994 ct state { new, untracked } accept
        }

        chain filter_IN_private_allow {
                tcp dport 24 ct state { new, untracked } accept
                ip6 daddr fe80::/64 udp dport 546 ct state { new, untracked } accept
                tcp dport 9090 ct state { new, untracked } accept
                tcp dport 53 ct state { new, untracked } accept
                tcp dport 80 ct state { new, untracked } accept
                tcp dport 993 ct state { new, untracked } accept
                tcp dport 994 ct state { new, untracked } accept
                tcp dport 25 ct state { new, untracked } accept
                tcp dport 443 ct state { new, untracked } accept
                udp dport 53 ct state { new, untracked } accept
                udp dport 67 ct state { new, untracked } accept
                udp dport 1812 ct state { new, untracked } accept
                udp dport 1813 ct state { new, untracked } accept
        }

        chain filter_IN_public_post {
        }

        chain filter_FWDO_public {
                jump filter_FWDO_public_pre
                jump filter_FWDO_public_log
                jump filter_FWDO_public_deny
                jump filter_FWDO_public_allow
                jump filter_FWDO_public_post
        }

        chain filter_FWDO_public_pre {
        }

        chain filter_FWDO_public_log {
        }

        chain filter_FWDO_public_deny {
        }

        chain filter_FWDO_public_allow {
                ct state { new, untracked } accept
        }

        chain filter_FWDO_public_post {
        }

        chain filter_FWDI_public {
                jump filter_FWDI_public_pre
                jump filter_FWDI_public_log
                jump filter_FWDI_public_deny
                jump filter_FWDI_public_allow
                jump filter_FWDI_public_post
                meta l4proto { icmp, ipv6-icmp } accept
        }

        chain filter_FWDI_public_pre {
        }

        chain filter_FWDI_public_log {
        }

        chain filter_FWDI_public_deny {
        }

        chain filter_FWDI_public_allow {
        }

        chain filter_FWDI_public_post {
        }

        chain mangle_PRE_public {
                jump mangle_PRE_public_pre
                jump mangle_PRE_public_log
                jump mangle_PRE_public_deny
                jump mangle_PRE_public_allow
                jump mangle_PRE_public_post
        }

        chain mangle_PRE_public_pre {
        }

        chain mangle_PRE_public_log {
        }

        chain mangle_PRE_public_deny {
        }

        chain mangle_PRE_public_allow {
        }

        chain mangle_PRE_public_post {
        }

        chain raw_PRE_libvirt {
                jump raw_PRE_libvirt_pre
                jump raw_PRE_libvirt_log
                jump raw_PRE_libvirt_deny
                jump raw_PRE_libvirt_allow
                jump raw_PRE_libvirt_post
        }

        chain raw_PRE_libvirt_pre {
        }

        chain raw_PRE_libvirt_log {
        }

        chain raw_PRE_libvirt_deny {
        }

        chain raw_PRE_libvirt_allow {
        }

        chain raw_PRE_libvirt_post {
        }

        chain filter_IN_libvirt {
                jump filter_IN_libvirt_pre
                jump filter_IN_libvirt_log
                jump filter_IN_libvirt_deny
                jump filter_IN_libvirt_allow
                jump filter_IN_libvirt_post
                accept
        }

        chain filter_IN_libvirt_pre {
        }

        chain filter_IN_libvirt_log {
        }

        chain filter_IN_libvirt_deny {
        }

        chain filter_IN_libvirt_allow {
                udp dport 67 ct state { new, untracked } accept
                udp dport 547 ct state { new, untracked } accept
                tcp dport 53 ct state { new, untracked } accept
                udp dport 53 ct state { new, untracked } accept
                tcp dport 22 ct state { new, untracked } accept
                udp dport 69 ct helper set "helper-tftp-udp"
                udp dport 69 ct state { new, untracked } accept
                meta l4proto icmp ct state { new, untracked } accept
                meta l4proto ipv6-icmp ct state { new, untracked } accept
        }

        chain filter_IN_libvirt_post {
                reject
        }

        chain mangle_PRE_libvirt {
                jump mangle_PRE_libvirt_pre
                jump mangle_PRE_libvirt_log
                jump mangle_PRE_libvirt_deny
                jump mangle_PRE_libvirt_allow
                jump mangle_PRE_libvirt_post
        }

        chain mangle_PRE_libvirt_pre {
        }

        chain mangle_PRE_libvirt_log {
        }

        chain mangle_PRE_libvirt_deny {
        }

        chain mangle_PRE_libvirt_allow {
        }

        chain mangle_PRE_libvirt_post {
        }

        chain filter_FWDI_libvirt {
                jump filter_FWDI_libvirt_pre
                jump filter_FWDI_libvirt_log
                jump filter_FWDI_libvirt_deny
                jump filter_FWDI_libvirt_allow
                jump filter_FWDI_libvirt_post
                accept
        }

        chain filter_FWDI_libvirt_pre {
        }

        chain filter_FWDI_libvirt_log {
        }

        chain filter_FWDI_libvirt_deny {
        }

        chain filter_FWDI_libvirt_allow {
        }

        chain filter_FWDI_libvirt_post {
        }

        chain filter_FWDO_libvirt {
                jump filter_FWDO_libvirt_pre
                jump filter_FWDO_libvirt_log
                jump filter_FWDO_libvirt_deny
                jump filter_FWDO_libvirt_allow
                jump filter_FWDO_libvirt_post
                accept
        }

        chain filter_FWDO_libvirt_pre {
        }

        chain filter_FWDO_libvirt_log {
        }

        chain filter_FWDO_libvirt_deny {
        }

        chain filter_FWDO_libvirt_allow {
        }

        chain filter_FWDO_libvirt_post {
        }
}
table ip firewalld {
        chain nat_PREROUTING {
                type nat hook prerouting priority dstnat + 10; policy accept;
                jump nat_PREROUTING_ZONES_SOURCE
                jump nat_PREROUTING_ZONES
        }

        chain nat_PREROUTING_ZONES_SOURCE {
        }

        chain nat_PREROUTING_ZONES {
                iifname "ens224" goto nat_PRE_public
                iifname "virbr0" goto nat_PRE_libvirt
                iifname "ens192" goto nat_PRE_public
                goto nat_PRE_public
        }

        chain nat_POSTROUTING {
                type nat hook postrouting priority srcnat + 10; policy accept;
                jump nat_POSTROUTING_ZONES_SOURCE
                jump nat_POSTROUTING_ZONES
        }

        chain nat_POSTROUTING_ZONES_SOURCE {
        }

        chain nat_POSTROUTING_ZONES {
                oifname "ens224" goto nat_POST_public
                oifname "virbr0" goto nat_POST_libvirt
                oifname "ens192" goto nat_POST_public
                goto nat_POST_public
        }

        chain nat_POST_public {
                jump nat_POST_public_pre
                jump nat_POST_public_log
                jump nat_POST_public_deny
                jump nat_POST_public_allow
                jump nat_POST_public_post
        }

        chain nat_POST_public_pre {
        }

        chain nat_POST_public_log {
        }

        chain nat_POST_public_deny {
        }

        chain nat_POST_public_allow {
                oifname != "lo" masquerade
        }

        chain nat_POST_public_post {
        }

        chain nat_PRE_public {
                jump nat_PRE_public_pre
                jump nat_PRE_public_log
                jump nat_PRE_public_deny
                jump nat_PRE_public_allow
                jump nat_PRE_public_post
        }

        chain nat_PRE_public_pre {
        }

        chain nat_PRE_public_log {
        }

        chain nat_PRE_public_deny {
        }

        chain nat_PRE_public_allow {
        }

        chain nat_PRE_public_post {
        }

        chain nat_PRE_libvirt {
                jump nat_PRE_libvirt_pre
                jump nat_PRE_libvirt_log
                jump nat_PRE_libvirt_deny
                jump nat_PRE_libvirt_allow
                jump nat_PRE_libvirt_post
        }

        chain nat_PRE_libvirt_pre {
        }

        chain nat_PRE_libvirt_log {
        }

        chain nat_PRE_libvirt_deny {
        }

        chain nat_PRE_libvirt_allow {
        }

        chain nat_PRE_libvirt_post {
        }

        chain nat_POST_libvirt {
                jump nat_POST_libvirt_pre
                jump nat_POST_libvirt_log
                jump nat_POST_libvirt_deny
                jump nat_POST_libvirt_allow
                jump nat_POST_libvirt_post
        }

        chain nat_POST_libvirt_pre {
        }

        chain nat_POST_libvirt_log {
        }

        chain nat_POST_libvirt_deny {
        }

        chain nat_POST_libvirt_allow {
        }

        chain nat_POST_libvirt_post {
        }
}
table ip6 firewalld {
        chain nat_PREROUTING {
                type nat hook prerouting priority dstnat + 10; policy accept;
                jump nat_PREROUTING_ZONES_SOURCE
                jump nat_PREROUTING_ZONES
        }

        chain nat_PREROUTING_ZONES_SOURCE {
        }

        chain nat_PREROUTING_ZONES {
                iifname "ens224" goto nat_PRE_public
                iifname "virbr0" goto nat_PRE_libvirt
                iifname "ens192" goto nat_PRE_public
                goto nat_PRE_public
        }

        chain nat_POSTROUTING {
                type nat hook postrouting priority srcnat + 10; policy accept;
                jump nat_POSTROUTING_ZONES_SOURCE
                jump nat_POSTROUTING_ZONES
        }

        chain nat_POSTROUTING_ZONES_SOURCE {
        }

        chain nat_POSTROUTING_ZONES {
                oifname "ens224" goto nat_POST_public
                oifname "virbr0" goto nat_POST_libvirt
                oifname "ens192" goto nat_POST_public
                goto nat_POST_public
        }

        chain nat_POST_public {
                jump nat_POST_public_pre
                jump nat_POST_public_log
                jump nat_POST_public_deny
                jump nat_POST_public_allow
                jump nat_POST_public_post
        }

        chain nat_POST_public_pre {
        }

        chain nat_POST_public_log {
        }

        chain nat_POST_public_deny {
        }

        chain nat_POST_public_allow {
        }

        chain nat_POST_public_post {
        }

        chain nat_PRE_public {
                jump nat_PRE_public_pre
                jump nat_PRE_public_log
                jump nat_PRE_public_deny
                jump nat_PRE_public_allow
                jump nat_PRE_public_post
        }

        chain nat_PRE_public_pre {
        }

        chain nat_PRE_public_log {
        }

        chain nat_PRE_public_deny {
        }

        chain nat_PRE_public_allow {
        }

        chain nat_PRE_public_post {
        }

        chain nat_PRE_libvirt {
                jump nat_PRE_libvirt_pre
                jump nat_PRE_libvirt_log
                jump nat_PRE_libvirt_deny
                jump nat_PRE_libvirt_allow
                jump nat_PRE_libvirt_post
        }

        chain nat_PRE_libvirt_pre {
        }

        chain nat_PRE_libvirt_log {
        }

        chain nat_PRE_libvirt_deny {
        }

        chain nat_PRE_libvirt_allow {
        }

        chain nat_PRE_libvirt_post {
        }

        chain nat_POST_libvirt {
                jump nat_POST_libvirt_pre
                jump nat_POST_libvirt_log
                jump nat_POST_libvirt_deny
                jump nat_POST_libvirt_allow
                jump nat_POST_libvirt_post
        }

        chain nat_POST_libvirt_pre {
        }

        chain nat_POST_libvirt_log {
        }

        chain nat_POST_libvirt_deny {
        }

        chain nat_POST_libvirt_allow {
        }

        chain nat_POST_libvirt_post {
        }
}
