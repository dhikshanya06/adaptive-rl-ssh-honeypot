# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains code to run a command
"""

from __future__ import annotations

import shlex
from typing import Any, TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Callable

from twisted.internet import error
from twisted.python import failure, log


class HoneyPotCommand:
    """
    This is the super class for all commands in cowrie/commands
    """

    def __init__(self, protocol, *args):
        self.protocol = protocol
        self.args = list(args)
        self.environ = self.protocol.cmdstack[-1].environ
        self.fs = self.protocol.fs
        self.data: bytes = b""  # output data
        self.input_data: None | (
            bytes
        ) = None  # used to store STDIN data passed via PIPE
        pp: Any = getattr(self.protocol, "pp", None)
        self.writefn: Callable[[bytes], None]
        self.errorWritefn: Callable[[bytes], None]
        if pp and hasattr(pp, "write_stdout") and hasattr(pp, "write_stderr"):
            self.writefn = cast("Callable[[bytes], None]", pp.write_stdout)
            self.errorWritefn = cast("Callable[[bytes], None]", pp.write_stderr)
        else:
            self.writefn = cast("Callable[[bytes], None]", self.protocol.pp.outReceived)
            self.errorWritefn = cast(
                "Callable[[bytes], None]", self.protocol.pp.errReceived
            )
        log.msg(f"[ADAPTIVE] HoneyPotCommand init for {self.__class__.__name__}")
        self.interaction_level = self.get_interaction_level()

    def get_interaction_level(self) -> int:
        """
        Reads the current session's interaction level from the shared policy file.
        """
        import json
        import os
        policy_file = os.path.join(os.getcwd(), "var/lib/cowrie/session_policies.json")
        if not os.path.exists(policy_file):
            policy_file = "/home/dhikshanya06/cowrie/var/lib/cowrie/session_policies.json"
            
        if os.path.exists(policy_file):
            try:
                with open(policy_file, 'r') as f:
                    policies = json.load(f)
                    session_id = getattr(self.protocol, 'session_id', 'unknown')
                    level = policies.get(str(session_id), {}).get('level', 0)
                    return level
            except Exception as e:
                pass
        return 0

    def write(self, data: str) -> None:
        """
        Write a string to the user on stdout, filtered by interaction level.
        """
        # if self.interaction_level == 0:
        #    # Stealth: Don't write anything or very limited
        #    return
        self.writefn(data.encode("utf8"))

    def writeBytes(self, data: bytes) -> None:
        """
        Like write() but input is bytes, filtered by interaction level.
        """
        # if self.interaction_level == 0:
        #    return
        self.writefn(data)

    def errorWrite(self, data: str) -> None:
        """
        Write errors to the user on stderr
        """
        self.errorWritefn(data.encode("utf8"))

    def check_arguments(self, application, args):
        files = []
        for arg in args:
            path = self.fs.resolve_path(arg, self.protocol.cwd)
            if self.fs.isdir(path):
                self.errorWrite(
                    f"{application}: error reading `{arg}': Is a directory\n"
                )
                continue
            files.append(path)
        return files

    def set_input_data(self, data: bytes) -> None:
        self.input_data = data

    def start(self) -> None:
        self.call()
        self.exit()

    def call(self) -> None:
        self.write(f"Hello World! [{self.args!r}]\n")

    def exit(self) -> None:
        """
        Sometimes client is disconnected and command exits after. So cmdstack is gone
        """
        if (
            self.protocol
            and self.protocol.terminal
            and hasattr(self.protocol, "pp")
            and getattr(self.protocol.pp, "redirect_real_files", None)
        ):
            for real_path, virtual_path in self.protocol.pp.redirect_real_files:
                self.protocol.terminal.redirFiles.add((real_path, virtual_path))

        if len(self.protocol.cmdstack):
            self.protocol.cmdstack.remove(self)

            if len(self.protocol.cmdstack):
                self.protocol.cmdstack[-1].resume()
        else:
            ret = failure.Failure(error.ProcessDone(status=""))
            # The session could be disconnected already, when his happens .transport is gone
            try:
                self.protocol.terminal.transport.processEnded(ret)
            except AttributeError:
                pass

    def handle_CTRL_C(self) -> None:
        log.msg("Received CTRL-C, exiting..")
        self.write("^C\n")
        self.exit()

    def lineReceived(self, line: str) -> None:
        log.msg(f"QUEUED INPUT: {line}")
        # FIXME: naive command parsing, see lineReceived below
        # line = "".join(line)
        self.protocol.cmdstack[0].cmdpending.append(shlex.split(line, posix=True))

    def resume(self) -> None:
        pass

    def handle_TAB(self) -> None:
        pass

    def handle_CTRL_D(self) -> None:
        pass

    def __repr__(self) -> str:
        return str(self.__class__.__name__)
