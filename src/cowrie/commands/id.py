# Copyright (c) 2010 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_id(HoneyPotCommand):
    def call(self) -> None:
        user_name = self.protocol.user.username
        uid = self.protocol.user.uid
        gid = self.protocol.user.gid
        
        # Default to root attributes if not set
        if uid is None:
            uid = 0
        if gid is None:
            gid = 0
            
        # In a real system, these would be looked up. Here we fake common ones.
        group_name = user_name 
        if uid == 0:
            group_name = "root"
            
        if self.interaction_level >= 2:
            output = f"uid={uid}({user_name}) gid={gid}({group_name}) groups={gid}({group_name}),27(sudo),1001(admin)\n"
        else:
            output = f"uid={uid}({user_name}) gid={gid}({group_name}) groups={gid}({group_name})\n"
            
        self.write(output)


commands["/usr/bin/id"] = Command_id
commands["/bin/id"] = Command_id
commands["id"] = Command_id
