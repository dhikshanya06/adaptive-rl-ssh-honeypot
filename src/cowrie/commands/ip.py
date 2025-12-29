# Copyright (c) 2010 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand
try:
    from cowrie.commands.ifconfig import HWaddr, inet6
except ImportError:
    # Fallback if ifconfig is not available for some reason
    HWaddr = "00:16:3e:00:00:01" 
    inet6 = "fe80::216:3eff:fe00:1/64"

commands = {}


class Command_ip(HoneyPotCommand):
    """
    Simulated 'ip' command, widely used replacement for ifconfig.
    """
    
    def call(self) -> None:
        args = " ".join(self.args) if self.args else "addr"
        
        # 'ip' by itself usually prints help, but 'ip a' or 'ip addr' prints interfaces.
        # We'll default to 'addr' if the user types 'ip addr' or just 'ip a' or variants.
        
        if "addr" in args or " a" in args or not self.args:
            self.do_ip_addr()
        elif "link" in args or " l" in args:
            self.do_ip_link()
        elif "route" in args or " r" in args:
            self.do_ip_route()
        else:
            self.write("Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n")
            self.write("       ip [ -force ] -batch filename\n")
            self.write("where  OBJECT := { link | address | addrlabel | route | rule | neigh | ntable |\n")
            self.write("                   tunnel | tuntap | maddress | mroute | mrule | monitor | xfrm |\n")
            self.write("                   netns | l2tp | fou | macsec | tcp_metrics | token | netconf }\n")

    def do_ip_addr(self) -> None:
        # Loopback
        self.write("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n")
        self.write("    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n")
        self.write("    inet 127.0.0.1/8 scope host lo\n")
        self.write("       valid_lft forever preferred_lft forever\n")
        self.write("    inet6 ::1/128 scope host \n")
        self.write("       valid_lft forever preferred_lft forever\n")
        
        # Eth0
        # Use shared HWaddr/inet6 from ifconfig for consistency
        kippo_ip = getattr(self.protocol, "kippoIP", "192.168.0.100")
        
        self.write(f"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n")
        self.write(f"    link/ether {HWaddr} brd ff:ff:ff:ff:ff:ff\n")
        self.write(f"    inet {kippo_ip}/24 brd 192.168.0.255 scope global dynamic eth0\n")
        self.write("       valid_lft 86354sec preferred_lft 86354sec\n")
        self.write(f"    inet6 {inet6} scope link \n")
        self.write("       valid_lft forever preferred_lft forever\n")

    def do_ip_link(self) -> None:
        self.write("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n")
        self.write("    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n")
        self.write(f"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\n")
        self.write(f"    link/ether {HWaddr} brd ff:ff:ff:ff:ff:ff\n")

    def do_ip_route(self) -> None:
        kippo_ip = getattr(self.protocol, "kippoIP", "192.168.0.100")
        gateway = kippo_ip.rsplit(".", 1)[0] + ".1"
        self.write(f"default via {gateway} dev eth0 proto dhcp src {kippo_ip} metric 100 \n")
        self.write(f"{kippo_ip.rsplit('.', 1)[0]}.0/24 dev eth0 proto kernel scope link src {kippo_ip} \n")


commands["/sbin/ip"] = Command_ip
commands["/usr/sbin/ip"] = Command_ip # Just in case
commands["ip"] = Command_ip
