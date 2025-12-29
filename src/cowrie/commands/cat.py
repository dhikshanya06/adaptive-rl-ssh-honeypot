# Copyright (c) 2010 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
cat command

"""

from __future__ import annotations


import getopt

from twisted.python import log

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import FileNotFound

commands = {}


class Command_cat(HoneyPotCommand):
    """
    cat command
    """

    number = False
    linenumber = 1

    def start(self) -> None:
        try:
            optlist, args = getopt.gnu_getopt(
                self.args, "AbeEnstTuv", ["help", "number", "version"]
            )
        except getopt.GetoptError as err:
            self.errorWrite(
                f"cat: invalid option -- '{err.opt}'\nTry 'cat --help' for more information.\n"
            )
            self.exit()
            return

        for o, _a in optlist:
            if o in ("--help"):
                self.help()
                self.exit()
                return
            elif o in ("-n", "--number"):
                self.number = True

        if len(args) > 0:
            for arg in args:
                if arg == "-":
                    self.output(self.input_data)
                    continue

                pname = self.fs.resolve_path(arg, self.protocol.cwd)

                if self.fs.isdir(pname):
                    self.errorWrite(f"cat: {arg}: Is a directory\n")
                    continue

                try:
                    # Adaptive Deceptive Content
                    filename = arg.split('/')[-1]
                    # Deceptive Content Logic
                    if ".db_creds" in filename:
                        if self.interaction_level >= 2:
                            content = "DB_NAME=production\nDB_USER=admin\nDB_PASS=P@ssw0rd123!\n"
                        else:
                            content = "DB_NAME=production\nDB_USER=admin\nDB_PASS=*****\n"
                        self.write(content)
                        self.exit()
                        return
                    elif "README.txt" in filename:
                        self.write("Welcome to the internal backup server.\n")
                        self.write("Unauthorized access is strictly prohibited.\n")
                        self.write("Please contact the system administrator for assistance.\n")
                        self.exit()
                        return
                    elif ".bash_history" in filename:
                        if self.interaction_level >= 3:
                            self.write("mysql -u root -p\n")
                            self.write("scp backup.tar.gz admin@192.168.1.20:/tmp\n")
                            self.write("rm -rf /var/log/apache2/*.log\n")
                        else:
                            self.write("ls -la\ncd /home\npwd\nexit\n")
                        self.exit()
                        return
                    elif "backup.tar.gz" in filename:
                        self.errorWrite(f"cat: {filename}: cannot display binary file\n")
                        self.exit()
                        return
                    elif filename == ".ssh" and self.interaction_level >= 3:
                        self.errorWrite(f"cat: {arg}: Is a directory\n")
                        continue

                    contents = self.fs.file_contents(pname)
                    self.output(contents)
                except FileNotFound:
                    self.errorWrite(f"cat: {arg}: No such file or directory\n")
            self.exit()
        elif self.input_data is not None:
            self.output(self.input_data)
            self.exit()

    def output(self, inb: bytes | None) -> None:
        """
        This is the cat output, with optional line numbering
        """
        if inb is None:
            return

        lines = inb.split(b"\n")
        if lines[-1] == b"":
            lines.pop()
        for line in lines:
            if self.number:
                self.write(f"{self.linenumber:>6}  ")
                self.linenumber = self.linenumber + 1
            self.writeBytes(line + b"\n")

    def lineReceived(self, line: str) -> None:
        """
        This function logs standard input from the user send to cat
        """
        log.msg(
            eventid="cowrie.session.input",
            realm="cat",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )

        self.output(line.encode("utf-8"))

    def handle_CTRL_D(self) -> None:
        """
        ctrl-d is end-of-file, time to terminate
        """
        self.exit()

    def help(self) -> None:
        self.write(
            """Usage: cat [OPTION]... [FILE]...
Concatenate FILE(s) to standard output.

With no FILE, or when FILE is -, read standard input.

    -A, --show-all           equivalent to -vET
    -b, --number-nonblank    number nonempty output lines, overrides -n
    -e                       equivalent to -vE
    -E, --show-ends          display $ at end of each line
    -n, --number             number all output lines
    -s, --squeeze-blank      suppress repeated empty output lines
    -t                       equivalent to -vT
    -T, --show-tabs          display TAB characters as ^I
    -u                       (ignored)
    -v, --show-nonprinting   use ^ and M- notation, except for LFD and TAB
        --help     display this help and exit
        --version  output version information and exit

Examples:
    cat f - g  Output f's contents, then standard input, then g's contents.
    cat        Copy standard input to standard output.

GNU coreutils online help: <http://www.gnu.org/software/coreutils/>
Full documentation at: <http://www.gnu.org/software/coreutils/cat>
or available locally via: info '(coreutils) cat invocation'
"""
        )


commands["/bin/cat"] = Command_cat
commands["cat"] = Command_cat
