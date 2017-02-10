#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

    Cracking utilities
    ----------------

    This module contains everything related to cracking.
    Actually, this makes:

        - Aircrack
        - Wesside

    That's so because wesside has its own cracking option.

"""
import os
import re
import tempfile
from . import Air, WrongArgument
from subprocess import run, Popen, DEVNULL, PIPE, STDOUT
from contextlib import suppress


class Aircrack(Air):
    """
        Introduction
        ------------


        Aircrack-ng is a powerful wireless cracking tool.
        Supporting two main attack types (against wep or wpa) it accepts
        different options for each.

        That means you'll only be able to use specific options for specific
        attacks.

        .. param attack: Chosen attack (wep|wpa)
        .. param file_: CAP or IVS file to crack

        The rest of the params are gotten using *args, **kwargs magic,
        so you'll need to manually consult them here.

        General options (Note that you can combine these with wpa or wep)

        ::

            Aircrack('wep|wpa', 'file_foo.ivs', a=false, essid=false,
                     bssid=false, p=false, E=false, q=false, combine=false,
                     l=false, w=false)

        WEP options:

        ::

            Aircrack('wep', 'file_foo.ivs' c=False, t=False, h=False,
                      debug=False, m=False, n=False, i=False, f=False,
                      k=False, x=False, x1=False, x2=False, X=False,
                      y=False, K=False, s=False, M=False, wep_decloack=False,
                      ptw_debug=False, oneshot=False)

        WPA options:

        ::

            Aircrack('wpa', 'file_foo.cap', S=False, r=False)


        Don't forget these are context managers, but also can be called
        manually

        ::

            foo = Aircrack('wpa', 'file')
            foo.start()
            time.sleep(1000)
            print(foo.result)
            foo.stop()

        ::

            with Aircrack('wpa', 'foo'):
                time.sleep(1000)
                print(_.result)

     """

    tmpfile = tempfile.TemporaryDirectory()
    _stop = False
    _allowed_arguments = (
        ('a', False),
        ('essid', False),
        ('bssid', False),
        ('p', False),
        ('q', False),
        ('combine', False),
        ('E', False),
        ('l', False),
        ('w', False),
    )

    _allowed_arguments_wep = (
        ('c', False),
        ('t', False),
        ('h', False),
        ('debug', False),
        ('m', False),
        ('n', False),
        ('i', False),
        ('f', False),
        ('k', False),
        ('x', False),
        ('x1', False),
        ('x2', False),
        ('X', False),
        ('y', False),
        ('K', False),
        ('s', False),
        ('M', False),
        ('wep_decloack', False),
        ('ptw_debug', False),
        ('oneshot', False)
    )

    _allowed_arguments_wpa = (
        ('S', False),
        ('r', False),
    )

    _allowed_attacks = (
        'wpa', 'wep',
    )

    def __init__(self, attack=False, file_=False, **kwargs):
        self.file_ = file_
        self._program = "key"
        if attack not in self._allowed_attacks:
            raise WrongArgument

        self.attack = attack
        extra = tuple()
        with suppress(AttributeError):
            extra = getattr(self, "_allowed_arguments_{}".format(attack))
        self._allowed_arguments = self._allowed_arguments + \
            extra
        super().__init__(**kwargs)

    def start(self):
        """
            Start process.
        """
        tmpfile = tempfile.mkstemp()[1]
        params = self.flags + self.arguments
        if self.attack == 'wpa':
            params.extend(('-l', tmpfile))
        line = ["aircrack-ng"] + params + [self.file_]
        self._proc = run(line, bufsize=0,
                         env={'PATH': os.environ['PATH']},
                         stderr=DEVNULL, stdin=DEVNULL, stdout=DEVNULL)
        os.system('stty sane')
        with open(tmpfile) as key:
            return key.read()

    def stop(self):
        """
            Stop proc.
        """
        self._writepath = ''
        return True


class Wesside(Air):
    """
        Introduction
        ------------

        Wesside-ng is an auto-magic tool to obtain a WEP key
        with as less interaction from the user as possible.

        The only actual required option is the interface,
        as if no interface specified, it'll try to crack any.

        This is only for WEP networks and does not need anything
        out of the ordinary

        Usage example:

        ::

            Wesside('mon0', n="192.168.1.3", m="192.168.1.2",
                    a="aa:bb:cc:dd:ee:ff", c=False, p=128, v="WLAN_FOO",
                    t=10000, f=11)


        Don't forget these are context managers, but also can be called
        manually

        ::

            foo = Wesside('mon0', n="192.168.1.3", m="192.168.1.2",
                          a="aa:bb:cc:dd:ee:ff", c=False, p=128,
                          v="WLAN_FOO", t=10000, f=11)

            foo.start()
            time.sleep(1000)
            print(_.result)
            foo.stop()

        ::

            with Wesside('mon0', n="192.168.1.3", m="192.168.1.2",
                          a="aa:bb:cc:dd:ee:ff", c=False, p=128,
                          v="WLAN_FOO", t=10000, f=11):
                time.sleep(1000)
                print(_.result)



    """

    _stop = False

    _allowed_arguments = (
        ('n', False),
        ('m', False),
        ('a', False),
        ('c', False),
        ('p', False),
        ('v', False),
        ('t', False),
        ('f', False),
    )

    def __init__(self, interface=False, **kwargs):
        self.interface = interface
        super().__init__(**kwargs)

    def start(self):
        """
            Start process.
        """
        params = self.flags + self.arguments
        line = ["wesside-ng"] + params + ["-i", self.interface]
        self._proc = Popen(line, bufsize=0,
                           env={'PATH': os.environ['PATH']},
                           stderr=DEVNULL, stdin=DEVNULL, stdout=PIPE)
        os.system('stty sane')

    @property
    def result(self):
        """
            Searches for a key in wesside-ng's output to stdout.
        """
        with suppress(IndexError):
            data = self._proc.communicate().decode()
            return re.match("KEY=\((.*)\)", data).groups()[0]
        return False


class Besside(Air):
    """
        Introduction
        ------------

        Wesside-ng is an auto-magic tool to obtain a WEP key
        with as less interaction from the user as possible.

        The only actual required option is the interface,
        as if no interface specified, it'll try to crack any.

        This is only for WEP networks and does not need anything
        out of the ordinary

        Usage example:

        ::

            Wesside('mon0', n="192.168.1.3", m="192.168.1.2",
                    a="aa:bb:cc:dd:ee:ff", c=False, p=128, v="WLAN_FOO",
                    t=10000, f=11)


        Don't forget these are context managers, but also can be called
        manually

        ::

            foo = Wesside('mon0', n="192.168.1.3", m="192.168.1.2",
                          a="aa:bb:cc:dd:ee:ff", c=False, p=128,
                          v="WLAN_FOO", t=10000, f=11)

            foo.start()
            time.sleep(1000)
            print(_.result)
            foo.stop()

        ::

            with Wesside('mon0', n="192.168.1.3", m="192.168.1.2",
                          a="aa:bb:cc:dd:ee:ff", c=False, p=128,
                          v="WLAN_FOO", t=10000, f=11):
                time.sleep(1000)
                print(_.result)



    """

    _stop = False
    _allowed_arguments = (
        ('n', False),
        ('m', False),
        ('a', False),
        ('c', False),
        ('p', False),
        ('v', False),
        ('t', False),
        ('f', False),
    )

    def __init__(self, interface, bssid, **kwargs):
        self.interface = interface
        self.bssid = bssid
        super().__init__(**kwargs)

    def start(self):
        """
            Start process.
        """
        self.tempdir = tempfile.TemporaryDirectory()
        params = ["-b", self.bssid, self.interface]
        line = ["besside-ng"] + params
        self._proc = Popen(line, bufsize=0,
                           cwd=self.tempdir.name,
                           stderr=STDOUT, stdin=DEVNULL, stdout=PIPE)
        os.system('stty sane')

    @property
    def result(self):
        """
            Searches for a key in wesside-ng's output to stdout.
        """
        if self._proc.poll() is not None:
            with open(os.path.join(self.tempdir.name, "besside.log")) as file:
                lines = file.readlines()
                return lines[1].split("|")[1].strip()

    def stop(self):
        self._proc.kill()


class Reaver(Air):
    """docstring for Reaver"""

    def __init__(self, iface, bssid, channel, pixie=False, **kwargs):
        self._iface = iface
        self._bssid = bssid
        self._channel = channel
        _, self._filename = tempfile.mkstemp(text=True, prefix="xDD")
        self._pixie = pixie
        super().__init__(**kwargs)

    _seek = 0
    _failures = 0

    def start(self):
        if self._pixie:
            self._proc = Popen([
                "reaver",
                "-i", self._iface,
                "-c", self._channel,
                "-b", self._bssid,
                "-a",
                "-v",
                "-K", "1",
                "-o", self._filename,
                "-s", "notexistingfile"],
                stdout=PIPE, stderr=STDOUT)
        else:
            self._proc = Popen([
                "reaver",
                "-i", self._iface,
                "-c", self._channel,
                "-b", self._bssid,
                "-a",
                "-v",
                "-o", self._filename,
                "-s", "notexistingfile"],
                stdout=PIPE, stderr=STDOUT)

    def stop(self):
        self._proc.kill()
        os.remove(self._filename)

    @property
    def check_progress(self):
        if self._failures >= 10:
            return {"status": "attack failed"}
        with open(self._filename) as reaverlog:
            reaverlog.seek(self._seek)
            content = reaverlog.read()
            self._seek = reaverlog.tell()
            if content.find("[!] WARNING") != -1:
                self._failures += 1
                return {"status": "failed " + str(self._failures) + " times"}
            if content.find("[!] WPS transaction failed (code: 0x0") != -1:
                self._failures += 1
                return {"status": "failed " + str(self._failures) + " times"}
            if content.find("[+] Pin count advanced") != -1:
                self._failures = 0
            if self._proc.poll():
                if content.find("[+] WPA PSK: "):
                    key = content.split()[3].strip("'")
                    if content.find("[+] WPS PIN: "):
                        wps = content.split()[3].strip("'")
                        return {"status": "success",
                                "key": key,
                                "wps": wps}
            return {"status": "progress"}


class Mdk3(Air):
    """docstring for mdk3"""

    _counter = 0

    def __init__(self, bssid, iface):
        self._bssid = bssid
        self._iface = iface

    def start(self):
        self._proc = Popen([
            "mdk3",
            self._iface,
            "a",
            "-a", self._bssid,
            "-m"],
            stdout=PIPE, stderr=DEVNULL)

    def stop(self):
        self._proc.kill()

    @property
    def check_progress(self):
        output = self._proc.stdout.read(1000)
        self._counter += output.count(b"seems to be INVULNERABLE!")

        if self._counter > 10:
            self.stop()
            return "failed"
        if output.find(b"got authentication frame: from wrong AP or failed authentication!") != -1:
            self.stop()
            return "success"
        else:
            return "progress"
