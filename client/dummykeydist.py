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

	def register(self,userid):
		if userid in self.allusers:
			return None # user already exist
		MEK = crypto.generate_user_encryption_keypair()
		MSK = crypto.generate_user_signature_keypair()
		self.allusers[userid] = (MEK[0:2], MSK[0:2]) # save only public part of the key
		return MEK, MSK

	def getPublicKey(self,userid):
		try:
			return self.allusers[userid][0]
		except:
			return None
	def getSigningKey(self,userid):
		try:
			return self.allusers[userid][1]
		except:
			return None
	def __del__(self):
		pickle.dump(self.allusers,open(self.file,'wb'))