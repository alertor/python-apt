#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 Canonical Ltd
#
# SPDX-License-Identifier: GPL-2.0+


import base64
import os
import shutil
import tempfile
import unittest

import apt_pkg
import apt
import apt.progress.base
import apt.progress.text

import testcommon


class TestSignedUsable(testcommon.TestCase):
    """Test fetch_binary() and fetch_source() signature checking."""

    def setUp(self):
        testcommon.TestCase.setUp(self)
        apt_pkg.config.clear("APT::Update::Post-Invoke")
        apt_pkg.config.clear("APT::Update::Post-Invoke-Success")
        self.chroot_path = chroot_path = tempfile.mkdtemp()
        repo_path = os.path.abspath("./data/test-signed-usable-repo/")
        # Inits the dirs for us
        apt.cache.Cache(rootdir=chroot_path)
        # Change directory
        self.cwd = os.getcwd()
        os.chdir(chroot_path)
        with open(
            os.path.join(self.chroot_path, "etc/apt/sources.list"), "w"
        ) as sources_list:
            # key checking does not work on apt 1.2, because apt 1.2's
            # apt-key always picks up the host keys, so we make it explictly
            # trusted.
            sources_list.write(
                "deb [trusted=yes] copy:%s/signed/ /\n" % repo_path
            )
            sources_list.write("deb copy:%s/unsigned/ /\n" % repo_path)
            sources_list.write(
                "deb-src [trusted=yes] copy:%s/signed/ /\n" % repo_path
            )
            sources_list.write("deb-src copy:%s/unsigned/ /\n" % repo_path)

        with open(os.path.join(repo_path, "key.gpg.base64"), "rb") as pubkey64:
            with open(
                os.path.join(self.chroot_path, "etc/apt/trusted.gpg"), "wb"
            ) as tgt:
                tgt.write(base64.b64decode(pubkey64.read()))

        self.cache = apt.cache.Cache(rootdir=chroot_path)
        apt_pkg.config["Acquire::AllowInsecureRepositories"] = "true"
        self.cache.update()
        apt_pkg.config["Acquire::AllowInsecureRepositories"] = "false"
        self.cache.open()

        self.progress = apt.progress.text.AcquireProgress
        apt.progress.text.AcquireProgress = apt.progress.base.AcquireProgress

        # Disable actual installation of downloaded items
        self.cache.install_archives = (
            lambda *a, **b: apt_pkg.PackageManager.RESULT_COMPLETED
        )

    def tearDown(self):
        # this resets the rootdir apt_pkg.config to ensure it does not
        # "pollute" the later tests
        apt.cache.Cache(rootdir="/")
        os.chdir(self.cwd)
        shutil.rmtree(self.chroot_path)

        apt.progress.text.AcquireProgress = self.progress

    def doInstall(self, name, bargs):
        install_progress = apt.progress.base.InstallProgress()
        self.cache[name].mark_install()
        try:
            self.cache.commit(install_progress=install_progress, **bargs)
        finally:
            # Workaround install progress leaking files
            install_progress.write_stream.close()
            install_progress.status_stream.close()
            for fname in os.listdir(
                os.path.join(self.chroot_path, "var/cache/apt/archives")
            ):
                if os.path.isfile(
                    os.path.join(
                        self.chroot_path, "var/cache/apt/archives", fname
                    )
                ):
                    os.unlink(
                        os.path.join(
                            self.chroot_path, "var/cache/apt/archives", fname
                        )
                    )
            self.cache[name].mark_keep()

    def doFetchArchives(self, name, bargs):
        fetcher = apt_pkg.Acquire()
        self.cache[name].mark_install()
        try:
            self.cache.fetch_archives(fetcher=fetcher, **bargs)
        finally:
            for fname in os.listdir(
                os.path.join(self.chroot_path, "var/cache/apt/archives")
            ):
                if fname.endswith(".deb"):
                    os.unlink(
                        os.path.join(
                            self.chroot_path, "var/cache/apt/archives", fname
                        )
                    )
            self.cache[name].mark_keep()

    def testDefaultDenyButExplicitAllowUnauthenticated(self):
        """Deny by config (default), but pass allow_unauthenticated=True"""

        bargs = dict(allow_unauthenticated=True)
        sargs = dict(allow_unauthenticated=True, unpack=False)

        self.doInstall("signed-usable", bargs)
        self.doInstall("signed-not-usable", bargs)
        self.doInstall("unsigned-usable", bargs)
        self.doInstall("unsigned-unusable", bargs)

        self.doFetchArchives("signed-usable", bargs)
        self.doFetchArchives("signed-not-usable", bargs)
        self.doFetchArchives("unsigned-usable", bargs)
        self.doFetchArchives("unsigned-unusable", bargs)

        self.cache["signed-usable"].candidate.fetch_binary(**bargs)
        self.cache["signed-usable"].candidate.fetch_source(**sargs)
        self.cache["signed-not-usable"].candidate.fetch_binary(**bargs)
        self.cache["signed-not-usable"].candidate.fetch_source(**sargs)
        self.cache["unsigned-usable"].candidate.fetch_binary(**bargs)
        self.cache["unsigned-usable"].candidate.fetch_source(**sargs)
        self.cache["unsigned-unusable"].candidate.fetch_binary(**bargs)
        self.cache["unsigned-unusable"].candidate.fetch_source(**sargs)

    def testDefaultAllow(self):
        """Allow by config APT::Get::AllowUnauthenticated = True"""
        apt_pkg.config["APT::Get::AllowUnauthenticated"] = "true"

        bargs = dict()
        sargs = dict(unpack=False)

        self.doInstall("signed-usable", bargs)
        self.doInstall("signed-not-usable", bargs)
        self.doInstall("unsigned-usable", bargs)
        self.doInstall("unsigned-unusable", bargs)

        self.doFetchArchives("signed-usable", bargs)
        self.doFetchArchives("signed-not-usable", bargs)
        self.doFetchArchives("unsigned-usable", bargs)
        self.doFetchArchives("unsigned-unusable", bargs)

        self.cache["signed-usable"].candidate.fetch_binary(**bargs)
        self.cache["signed-usable"].candidate.fetch_source(**sargs)
        self.cache["signed-not-usable"].candidate.fetch_binary(**bargs)
        self.cache["signed-not-usable"].candidate.fetch_source(**sargs)
        self.cache["unsigned-usable"].candidate.fetch_binary(**bargs)
        self.cache["unsigned-usable"].candidate.fetch_source(**sargs)
        self.cache["unsigned-unusable"].candidate.fetch_binary(**bargs)
        self.cache["unsigned-unusable"].candidate.fetch_source(**sargs)

    def testDefaultDeny(self):
        """Test APT::Get::AllowUnauthenticated = False (default)"""
        self.doInstall("signed-usable", {})
        self.doInstall("signed-not-usable", {})
        self.assertRaisesRegex(
            apt.cache.UntrustedException,
            "Untrusted packages:",
            self.doInstall,
            "unsigned-usable",
            {},
        )
        self.assertRaisesRegex(
            apt.cache.UntrustedException,
            "Untrusted packages:",
            self.doInstall,
            "unsigned-unusable",
            {},
        )

        self.doFetchArchives("signed-usable", {})
        self.doFetchArchives("signed-not-usable", {})
        self.assertRaisesRegex(
            apt.cache.UntrustedException,
            "Untrusted packages:",
            self.doFetchArchives,
            "unsigned-usable",
            {},
        )
        self.assertRaisesRegex(
            apt.cache.UntrustedException,
            "Untrusted packages:",
            self.doFetchArchives,
            "unsigned-unusable",
            {},
        )

        self.cache["signed-usable"].candidate.fetch_binary()
        self.cache["signed-usable"].candidate.fetch_source(unpack=False)
        self.assertRaisesRegex(
            apt.package.UntrustedError,
            ": No trusted hash",
            self.cache["signed-not-usable"].candidate.fetch_binary,
        )
        self.assertRaisesRegex(
            apt.package.UntrustedError,
            ": No trusted hash",
            self.cache["signed-not-usable"].candidate.fetch_source,
            unpack=False,
        )
        self.assertRaisesRegex(
            apt.package.UntrustedError,
            ": Source",
            self.cache["unsigned-usable"].candidate.fetch_binary,
        )
        self.assertRaisesRegex(
            apt.package.UntrustedError,
            ": Source",
            self.cache["unsigned-usable"].candidate.fetch_source,
            unpack=False,
        )
        self.assertRaisesRegex(
            apt.package.UntrustedError,
            ": Source",
            self.cache["unsigned-unusable"].candidate.fetch_binary,
        )
        self.assertRaisesRegex(
            apt.package.UntrustedError,
            ": Source",
            self.cache["unsigned-unusable"].candidate.fetch_source,
            unpack=False,
        )

    def testDefaultAllowButExplicitDeny(self):
        """Allow by config, but pass allow_unauthenticated=False"""
        apt_pkg.config["APT::Get::AllowUnauthenticated"] = "true"

        bargs = dict(allow_unauthenticated=False)
        sargs = dict(allow_unauthenticated=False, unpack=False)

        self.doInstall("signed-usable", bargs)
        self.doInstall("signed-not-usable", bargs)

        self.assertRaisesRegex(
            apt.cache.UntrustedException,
            "Untrusted packages:",
            self.doInstall,
            "unsigned-usable",
            bargs,
        )
        self.assertRaisesRegex(
            apt.cache.UntrustedException,
            "Untrusted packages:",
            self.doInstall,
            "unsigned-unusable",
            bargs,
        )

        self.doFetchArchives("signed-usable", bargs)
        self.doFetchArchives("signed-not-usable", bargs)
        self.assertRaisesRegex(
            apt.cache.UntrustedException,
            "Untrusted packages:",
            self.doFetchArchives,
            "unsigned-usable",
            bargs,
        )
        self.assertRaisesRegex(
            apt.cache.UntrustedException,
            "Untrusted packages:",
            self.doFetchArchives,
            "unsigned-unusable",
            bargs,
        )

        self.cache["signed-usable"].candidate.fetch_binary(**bargs)
        self.cache["signed-usable"].candidate.fetch_source(**sargs)
        self.assertRaisesRegex(
            apt.package.UntrustedError,
            ": No trusted hash",
            self.cache["signed-not-usable"].candidate.fetch_binary,
            **bargs
        )
        self.assertRaisesRegex(
            apt.package.UntrustedError,
            ": No trusted hash",
            self.cache["signed-not-usable"].candidate.fetch_source,
            **sargs
        )
        self.assertRaisesRegex(
            apt.package.UntrustedError,
            ": Source",
            self.cache["unsigned-usable"].candidate.fetch_binary,
            **bargs
        )
        self.assertRaisesRegex(
            apt.package.UntrustedError,
            ": Source",
            self.cache["unsigned-usable"].candidate.fetch_source,
            **sargs
        )
        self.assertRaisesRegex(
            apt.package.UntrustedError,
            ": Source",
            self.cache["unsigned-unusable"].candidate.fetch_binary,
            **bargs
        )
        self.assertRaisesRegex(
            apt.package.UntrustedError,
            ": Source",
            self.cache["unsigned-unusable"].candidate.fetch_source,
            **sargs
        )


if __name__ == "__main__":
    unittest.main()
