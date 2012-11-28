# Taken from PyCrypto 2.6, public domain code.
# Thanks to Dwayne C. Litzenberger <dlitz@dlitz.net>

import sys
import errno
import os
import stat

class BaseRNG(object):

    def __init__(self):
        self.closed = False
        self._selftest()

    def __del__(self):
        self.close()

    def _selftest(self):
        # Test that urandom can return data
        data = self.read(16)
        if len(data) != 16:
            raise AssertionError("read truncated")

        # Test that we get different data every time (if we don't, the RNG is
        # probably malfunctioning)
        data2 = self.read(16)
        if data == data2:
            raise AssertionError("OS RNG returned duplicate data")

    # PEP 343: Support for the "with" statement
    def __enter__(self):
        pass
    def __exit__(self):
        """PEP 343 support"""
        self.close()

    def close(self):
        if not self.closed:
            self._close()
        self.closed = True

    def flush(self):
        pass

    def read(self, N=-1):
        """Return N bytes from the RNG."""
        if self.closed:
            raise ValueError("I/O operation on closed file")
        if not isinstance(N, int):
            raise TypeError("an integer is required")
        if N < 0:
            raise ValueError("cannot read to end of infinite stream")
        elif N == 0:
            return ""
        data = self._read(N)
        if len(data) != N:
            raise AssertionError("%s produced truncated output (requested %d, got %d)" % (self.name, N, len(data)))
        return data

    def _close(self):
        raise NotImplementedError("child class must implement this")

    def _read(self, N):
        raise NotImplementedError("child class must implement this")

class DevURandomRNG(BaseRNG):

    def __init__(self, devname=None):
        if devname is None:
            self.name = "/dev/urandom"
        else:
            self.name = devname

        # Test that /dev/urandom is a character special device
        f = open(self.name, "rb", 0)
        fmode = os.fstat(f.fileno())[stat.ST_MODE]
        if not stat.S_ISCHR(fmode):
            f.close()
            raise TypeError("%r is not a character special device" % (self.name,))

        self.__file = f

        BaseRNG.__init__(self)

    def _close(self):
        self.__file.close()

    def _read(self, N):
        # Starting with Python 3 open with buffering=0 returns a FileIO object.
        # FileIO.read behaves like read(2) and not like fread(3) and thus we
        # have to handle the case that read returns less data as requested here
        # more carefully.
        data = b""
        while len(data) < N:
            try:
                d = self.__file.read(N - len(data))
            except IOError as e:
                # read(2) has been interrupted by a signal; redo the read
                if e.errno == errno.EINTR:
                    continue
                raise

            if d is None:
                # __file is in non-blocking mode and no data is available
                return data
            if len(d) == 0:
                # __file is in blocking mode and arrived at EOF
                return data

            data += d
        return data

def new(*args, **kwargs):
    return DevURandomRNG(*args, **kwargs)

