#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    Aircrack-ng basic attacks
    This module handles as gracefully as it can be common
    aircrack-ng commands.
"""

import os
import tempfile
import logging

__version__ = "0.1.1"

logging.basicConfig(level=logging.INFO)

PATH = os.environ['PATH']  #: TODO: Make this configurable


def format_arg(arg):
    if len(arg) > 1:
        return "--{}".format(arg)
    else:
        return "-{}".format(arg)


class LaunchError(Exception):
    """
        Generic process launch error
    """
    pass


class WrongArgument(Exception):
    """
        Wrong argument has been passed to a call
    """
    pass


class Air:
    """
        This is the base class for most aircrack-ng classes.
        Used mainly because its argument handling and writepath.
    """
    _writepath = False
    _allowed_arguments = False
    _current_execution = 0
    _proc = False
    _exec_args = {}
    _program = "airodump"

    def __init__(self, **kwargs):
        """
            We actually allow only kwargs.
            The arguments must be implicit
            to the action...
        """
        self._exec_args = kwargs.items()

    @property
    def flags(self):
        """
            Returns flags
            yields a tuple
        """
        return [format_arg(arg) for arg, value in self._exec_args
                if isinstance(value, bool)]

    @property
    def arguments(self):
        """
            Return arguments
            yields a tuple
        """
        result = []
        for arg, value in self._exec_args:
            if not isinstance(value, bool):
                result.extend([format_arg(arg), value])
        return result

    @property
    def writepath(self):
        """
            Where to write things to.
        """
        if not self._writepath:
            self._tempdir = tempfile.TemporaryDirectory()
            pid = os.getpid()
            name = "{}_{}".format(self._program, pid)
            self._writepath = os.path.join(self._tempdir.name, name)
        return self._writepath

    @property
    def current_execution(self):
        """
            Returns current execution number formatted for usual
            aircrack output
        """
        return str(self._current_execution).zfill(2)

    @property
    def curr_csv(self):
        """
            Return current execution's csv location
        """
        return "{}-{}.csv".format(self.writepath, self.current_execution)

    @property
    def curr_pcap(self):
        """
            Return current execution's csv location
        """
        return "{}-{}.pcap".format(self.writepath, self.current_execution)


    def stop(self):
        """
            Stop proc.
        """
        self._stop = True
        result = self._proc.kill()
        self._tempdir.cleanup()
        return result

    def __enter__(self, *args, **kwargs):
        self.start(*args, **kwargs)
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()
