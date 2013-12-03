import json
import os, sys, inspect

from ..common import crypto
from ..public_key_repo import public_key_repo_func
# use for testing purposes only


class dummykeydist:
	def __init__(self):
		self.file = "./project_dummykeydist/userkeys.key"
		try:
			self.allusers = json.load(open(self.file,'rb'))
		except:
			self.allusers = {}
		

	def get_public_key(self,userid):
		
		try:
			return self.allusers[userid]["pkey"]
		except:
			print "dummykeydist: error while reading public encryption key"
			return None

	def get_verification_key(self,userid):
		try:
			return self.allusers[userid]["skey"]
		except:
			print "dummykeydist: error while reading public signing key",sys.exc_info()[0]
			return None
	def set_public_key(self,userid,key):
		if userid not in self.allusers:
			self.allusers[userid] = {}
		self.allusers[userid]["pkey"] = key

	def set_verification_key(self,userid,key):
		if userid not in self.allusers:
			self.allusers[userid] = {}
		self.allusers[userid]["skey"] = key

	def __del__(self):
		print "keyrepo object is being destroyed"
		json.dump(self.allusers,open(self.file,'wb'))