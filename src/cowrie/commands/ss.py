# Copyright (c) 2010 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_ss(HoneyPotCommand):
    """
    Simulated 'ss' command (socket statistics), replacement for netstat
    """
    
    def call(self) -> None:
        # Default behavior: display listening ports like 'ss -tuln' which is common for recon
        # If args are present, we could parse them, but for now we default to a standard listener output
        # if the user asks for listeners.
        
        args = " ".join(self.args) if self.args else ""
        
        # Simple heuristic: if 'l' is in args or args is empty/default, show listeners.
        # Otherwise, show established connections.
        
        if not self.args or "l" in args:
             self.do_ss_listeners()
        else:
             self.do_ss_established()

    def do_ss_listeners(self) -> None:
        self.write("State      Recv-Q Send-Q        Local Address:Port          Peer Address:Port \n")
        
        # SSH is always listening
        self.write("LISTEN     0      128                       *:22                       *:*     \n")
        self.write("LISTEN     0      128                      :::22                      :::*     \n")
        
        # Maybe some other services if we want to be interesting
        # e.g. Telnet or MySQL if configured? 
        # For now, let's keep it clean but consistent with standard Linux
        
    def do_ss_established(self) -> None:
        self.write("State      Recv-Q Send-Q        Local Address:Port          Peer Address:Port \n")
        
        # Show the current connection
        client_ip = self.protocol.clientIP
        # Try to resolve or just use IP. 'ss' usually shows IPs unless -r is used. 
        # We'll just use the IP for simplicity and realism.
        
        self.write(f"ESTAB      0      0             192.168.0.100:22              {client_ip}:54321 \n")


commands["/usr/bin/ss"] = Command_ss
commands["/bin/ss"] = Command_ss
commands["ss"] = Command_ss
