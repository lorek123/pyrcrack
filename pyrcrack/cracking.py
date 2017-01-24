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
from subprocess import run, Popen, DEVNULL, PIPE
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
        self._directory.cleanup()
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
        super(self.__class__, self).__init__(**kwargs)

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

class Reaver(object):
    """docstring for Reaver"""
    def __init__(self, iface, bssid, channel=False):
        self._iface = iface
        self._bssid = bssid
        self._channel = channel
        self._filename = tempfile.mkstemp()

    _seek = 0
    _failures = 0

    def start():
        self._proc = Popen([
            "reaver",
            "-i", self._iface,
            "-c", self._channel,
            "-b", self._bssid,
            "--no-nacks",
            "-L", "-w", "-v", "-K 1"
            "-o", _filename],
                    stdout=DEVNULL, stderr=DEVNULL)

    def stop():
        self._proc.kill()
        os.remove(self._filename)
    def check_progress():
        if self._failures>=10:
            self.stop()
            return {"status":"attack failed"} 
        with open(self._filename) as reaverlog:
            reaverlog.seek(self._seek)
            content = reaverlog.read()
            self._seek = reaverlog.tell()
            if content.find("[!] WARNING: 10 failed connections in a row"):
                self._failures+=1
                return {"status":"failed " + str(self._failures) + "times"}
            if content.find("[!] WPS transaction failed (code: 0x04), re-trying last pin"):
                self._failures+=1
                return {"status":"failed " + str(self._failures) + "times"}
            if content.find("[+] Estimated Remaining time:"):
                return {"status":"in progress"}
            if reaverproc.poll():
                if content.find("[+] WPA PSK: "):
                    key = content.split()[3].strip("'")
                    if content.find("[+] WPS PIN: "):
                        wps = content.split()[3].strip("'")
                        self.stop()
                        return {"status":"success",
                                "key":key,
                                "wps":wps}

### NEEDS IMPLEMENTATION OF AIRODUMP PCAP DUMP!!!!!
class WPAcrack(object):
    def __init__(self, iface, essid, bssid, channel=False):
        self._iface = iface
        self._bssid = bssid
        self._essid = essid
        self._channel = channel
        self._filename = tempfile.mkstemp()

    def has_handshake(capfile):
        """
            Uses pyrit to check for a handshake.
            Returns "True" if handshake is found, false otherwise.
        """
        cmd = ['pyrit', '-r', capfile, 'analyze'] #Call pyrit to "Analyze" the cap file's handshakes.
        proc = run(cmd, stdout=PIPE, stderr=DEVNULL)
        hit_essid = False
        for line in proc.stdout.decode("utf-8").split("\n"):
            # Iterate over every line of output by Pyrit
            if line == '' or line is None:
                continue
            if line.find("AccessPoint") != -1:
                hit_essid = (line.find("('" + self._ssid + "')") != -1) and \
                            (line.lower().find(self._bssid.lower()) != -1)
            else:
                if hit_essid and (line.find(', good, ') != -1 or
                                  line.find(', workable, ') != -1):
                    return True
        return False


    def strip_handshake(capfile):
        """
            Uses Tshark or Pyrit to strip all non-handshake packets
            from a .cap file.
            File in location 'capfile' will be overwritten!
        """
        output_file = capfile + "temp"
        cmd = ['pyrit',
               '-r', capfile,
               '-o', output_file,
               'strip']
        run(cmd, stdout=DEVNULL, stderr=DEVNULL)
        rename(capfile + '.temp', output_file)

    def start():
        aircrack = Aircrack('wpa', self._filename)
        aircrack.start()