import logging
import types


logger = logging.getLogger(__name__)


class Fprinter(object):
    """
    Does nothing in this tool chain
    """
    def __init__(self):
        pass

    def fprint(self, moduli):
        return []

    def fprint16(self, moduli, base=16):
        return []

    def magic16(self, moduli, base=16):
        return []

    def test16(self, moduli, base=16):
        return False

    def test(self, moduli):
        return False


