import pickle
import os, sys, inspect

from ..common import crypto
from ..public_key_repo import public_key_repo_func
# use for testing purposes only


class dummykeydist:
	def __init__(self):
		self.allusers = {}
		self.file = "../../project_dummykeydist/userkeys.key"
		try:
			self.allusers = pickle.load(open(self.file,'rb'))
		except:
			pass
'''
	def register(self,userid):
		if userid in self.allusers:
			return None # user already exist
		MEK = crypto.generate_user_encryption_keypair()
		MSK = crypto.generate_user_signature_keypair()
		self.allusers[userid] = (MEK[0:2], MSK[0:2]) # save only public part of the key
		return MEK, MSK
'''
	def get_public_key(self,userid):
		try:
			return self.allusers[userid]["pkey"]
		except:
			return None

	def get_verification_key(self,userid):
		try:
			return self.allusers[userid]["skey"]
		except:
			return None
	def set_public_key(self,userid,key):
		self.allusers[userid]["pkey"] = key

	def set_verification_key(self,userid,key):
		self.allusers[userid]["skey"] = key

	def __del__(self):
		pickle.dump(self.allusers,open(self.file,'wb'))