#!/usr/bin/python
# example how to deal with the depcache

import apt
import apt_pkg
import sys, os
import copy

from progress import TextFetchProgress, TextInstallProgress
from apt.progress import OpTextProgress

class TextInstallProgress(InstallProgress):
	def __init__(self):
		InstallProgress.__init__(self)
		self.status = None
	def StartUpdate(self):
		print "StartUpdate: %s" % self.statusfd
		self.status = os.fdopen(self.statusfd, "r")
		print self.status
	def UpdateInterface(self):
		if self.status != None:
			s = self.status.readline()
			if s:
				print s
	def FinishUpdate(self):
		self.status.close()

# init
apt_pkg.init()

progress = OpTextProgress()
cache = apt_pkg.GetCache(progress)
print "Available packages: %s " % cache.PackageCount

# get depcache
depcache = apt_pkg.GetDepCache(cache)
depcache.ReadPinFile()
depcache.Init(progress)

# do something
fprogress = TextFetchProgress()
iprogress = TextInstallProgress()

# can be used to set a custom fork method (like vte.Terminal.forkpty)
#iprogress.fork = os.fork

iter = cache["base-config"]
print "\n%s"%iter

# install or remove, the importend thing is to keep us busy :)
if iter.CurrentVer == None:
	depcache.MarkInstall(iter)
else:
	depcache.MarkDelete(iter)
res = depcache.Commit(fprogress, iprogress)
print res

print "Exiting"
sys.exit(0)



