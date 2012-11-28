# Taken from PyCrypto 2.6, public domain code.
# Thanks to Dwayne C. Litzenberger <dlitz@dlitz.net>

import sys
import os

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

class WindowsRNG(BaseRNG):

    name = "<CryptGenRandom>"

    def __init__(self):
        self.__winrand = os.urandom
        BaseRNG.__init__(self)

    def flush(self):
        """Work around weakness in Windows RNG.

        The CryptGenRandom mechanism in some versions of Windows allows an
        attacker to learn 128 KiB of past and future output.  As a workaround,
        this function reads 128 KiB of 'random' data from Windows and discards
        it.

        For more information about the weaknesses in CryptGenRandom, see
        _Cryptanalysis of the Random Number Generator of the Windows Operating
        System_, by Leo Dorrendorf and Zvi Gutterman and Benny Pinkas
        http://eprint.iacr.org/2007/419
        """
        if self.closed:
            raise ValueError("I/O operation on closed file")
        data = self.__winrand.read(128*1024)
        assert (len(data) == 128*1024)
        BaseRNG.flush(self)

    def _close(self):
        self.__winrand = None

    def _read(self, N):
        # Unfortunately, research shows that CryptGenRandom doesn't provide
        # forward secrecy and fails the next-bit test unless we apply a
        # workaround, which we do here.  See http://eprint.iacr.org/2007/419
        # for information on the vulnerability.
        self.flush()
        data = self.__winrand.read(N)
        self.flush()
        return data

def new(*args, **kwargs):
    if os.name == "nt":
        # Windows has a shitty RNG, so PyCrypto included workarounds to fix.
        # These used to use winrandom module but os.urandom calls cryptgenrandom
        # so external module is no longer necessary, just python workarounds.
        return WindowsRNG(*args, **kwargs)
    else:
        return os.urandom(*args, **kwargs)

