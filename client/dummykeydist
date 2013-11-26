import pickle
import os, sys, inspect
sys.path.append("../common")
import crypto
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
		key = crypto.generate_user_encryption_keypair()
		self.allusers[userid] = key[0:2] # save only public part of the key
		return key

	def getPublicKey(self,userid):
		try:
			return self.allusers[userid]
		except:
			return None

	def __del__(self):
		pickle.dump(self.allusers,open(self.file,'wb'))