# Copyright (c) 2010 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

from twisted.python import log
from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_mysql(HoneyPotCommand):
    def start(self) -> None:
        self.mysql_shell_active = False
        self.call()
        # If we entered interactive mode, we don't exit yet.
        # If we just printed help/error, we exit.
        if not self.mysql_shell_active:
            self.exit()

    def call(self) -> None:
        # Consistency: This command always behaves realistically. 
        # Sudden behavior changes (like from "not found" to "welcome") are unrealistic.
        # We assume the binary is present and works consistently.

        self.write("Welcome to the MySQL monitor.  Commands end with ; or \\g.\n")
        self.write("Your MySQL connection id is 42\n")
        self.write("Server version: 5.5.43-0+deb7u1 (Debian)\n\n")
        self.write("Copyright (c) 2000, 2015, Oracle and/or its affiliates. All rights reserved.\n\n")
        self.write("Oracle is a registered trademark of Oracle Corporation and/or its\n")
        self.write("affiliates. Other names may be trademarks of their respective\n")
        self.write("owners.\n\n")
        self.write("Type 'help;' or '\\h' for help. Type '\\c' to clear the current input statement.\n\n")
        self.write("mysql> ")
        
        self.mysql_shell_active = True

    def lineReceived(self, line: str) -> None:
        if not self.mysql_shell_active:
            return

        cmd = line.strip().lower()
        
        if cmd == "exit" or cmd == "quit" or cmd == "\\q":
            self.write("Bye\n")
            self.exit()
            return
            
        if cmd == "help" or cmd == "\\h" or cmd == "?":
            self.write("\nFor information about MySQL products and services, visit:\n")
            self.write("   http://www.mysql.com/\n")
            self.write("For developer information, including the MySQL Reference Manual, visit:\n")
            self.write("   http://dev.mysql.com/\n")
            self.write("To buy MySQL Enterprise Support, visit:\n")
            self.write("   https://shop.mysql.com/\n\n")
            self.write("List of all MySQL commands:\n")
            self.write("Note that all text commands must be first on line and end with ';'\n")
            self.write("?         (\\?) Synonym for `help'.\n")
            self.write("clear     (\\c) Clear the current input statement.\n")
            self.write("connect   (\\r) Reconnect to the server. Optional arguments are db and host.\n")
            self.write("delimiter (\\d) Set statement delimiter.\n")
            self.write("edit      (\\e) Edit command with $EDITOR.\n")
            self.write("ego       (\\G) Send command to mysql server, display result vertically.\n")
            self.write("exit      (\\q) Exit mysql. Same as quit.\n")
            self.write("go        (\\g) Send command to mysql server.\n")
            self.write("help      (\\h) Display this help.\n")
            self.write("nopager   (\\n) Disable pager, print to stdout.\n")
            self.write("notee     (\\t) Don't write into outfile.\n")
            self.write("pager     (\\P) Set PAGER [to_pager]. Print the query results via PAGER.\n")
            self.write("print     (\\p) Print current command.\n")
            self.write("prompt    (\\R) Change your mysql prompt.\n")
            self.write("quit      (\\q) Quit mysql.\n")
            self.write("rehash    (\\#) Rebuild completion hash.\n")
            self.write("source    (\\.) Execute an SQL script file. Takes a file name as an argument.\n")
            self.write("status    (\\s) Get status information from the server.\n")
            self.write("system    (\\!\) Execute a system shell command.\n")
            self.write("tee       (\\T) Set outfile [to_outfile]. Append everything into given outfile.\n")
            self.write("use       (\\u) Use another database. Takes database name as argument.\n")
            self.write("charset   (\\C) Switch to another charset. Might be needed for processing binlog with multi-byte charsets.\n")
            self.write("warnings  (\\W) Show warnings after every statement.\n")
            self.write("nowarning (\\w) Don't show warnings after every statement.\n\n")
            self.write("For server side help, type 'help contents'\n\n")
            self.write("mysql> ")
            return

        if cmd and not cmd.endswith(";") and not cmd.startswith("\\"):
            self.write("    -> ")
            return

        if cmd:
            if "show databases" in cmd:
                 self.write("+--------------------+\n")
                 self.write("| Database           |\n")
                 self.write("+--------------------+\n")
                 self.write("| information_schema |\n")
                 self.write("| mysql              |\n")
                 self.write("| performance_schema |\n")
                 self.write("| test               |\n")
                 self.write("+--------------------+\n")
                 self.write("4 rows in set (0.00 sec)\n\n")
            else:
                 self.write("Empty set (0.00 sec)\n\n")

        self.write("mysql> ")

    def handle_CTRL_C(self) -> None:
        self.write("Aborted\n")
        self.exit()
    
    def handle_CTRL_D(self) -> None:
        self.write("Bye\n")
        self.exit()


commands["/usr/bin/mysql"] = Command_mysql
commands["mysql"] = Command_mysql
