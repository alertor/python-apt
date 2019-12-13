"""Common testing stuff"""

import apt_pkg

import sys
import unittest


class TestCase(unittest.TestCase):
    """Base class for python-apt unittests"""

    def setUp(self):
        self.resetConfig()

    def resetConfig(self):
        apt_pkg.config.clear("")
        for key in apt_pkg.config.list():
            apt_pkg.config.clear(key)

        apt_pkg.init_config()
        apt_pkg.init_system()

    if (sys.version_info.major, sys.version_info.minor) < (3, 2):
        def assertRaisesRegex(self, exc_typ, regex, func, *args, **kwds):
            """Compatibility helper"""
            try:
                func(*args, **kwds)
            except Exception as exc:
                self.assertIsInstance(exc, exc_typ)
                self.assertRegexpMatches(str(exc), regex)
            else:
                self.fail("Did not raise exception")
