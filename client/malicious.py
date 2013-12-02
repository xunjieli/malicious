import sys, os
import shell
import xmlrpclib
import dummykeydist
import dummyfileserver
import json

from ..common import metadata, crypto
from ..public_key_repo import public_key_repo_func

client = 0
# key_repo = xmlrpclib.ServerProxy('http://localhost:8008')
# fileserver = xmlrpclib.ServerProxy('http://localhost:8000')
# keep the test local now so I don't have to run separate process to test this
key_repo = dummykeydist.dummykeydist()
fileserver = dummyfileserver

def register(name,privatefile):
	keydist = dummykeydist.dummykeydist()
	credential = {"max_inode":0L,"MEK":None,"MSK":None}
	print "creating encryption keys..."
	MEK = crypto.generate_user_encryption_keypair()
	MSK = crypto.generate_user_signature_keypair()
	print "keys generation successful"
	if MEK is None or MSK is None:
		print "Error registering the user, nothing has been done"
		return 1
	credential['MEK'] = MEK
	credential["MSK"] = MSK
	# upload key to repo
	key_repo.set_public_key(name,MEK[0:2])
	key_repo.set_verification_key(name,MSK[0:2])
	json.dump(credential,open(privatefile,'wb'))
	print "registration succesful"
	return 0

def getcmd():
	global client
	cmd = raw_input(client.getPath()+">>")
	return cmd.split(' ')

def execcmd(cmd):
	global client
	if cmd[0] == 'cd':
		if len(cmd) < 2:
			print "usage: cd [remote directory]"
			return
		client.cd(cmd[1])
	elif cmd[0] == 'pwd':
		client.pwd()
	elif cmd[0] == 'mkdir':
		if len(cmd) < 2:
			print "usage: mkdir [directory name]"
		client.mkdir(cmd[1])
	elif cmd[0] == 'ls':
		client.ls()
	elif cmd[0] == 'debug_see_dir' or cmd[0] == "dsd":
		client.debug_see_dir()
	else:
		print 'Command not found'

def authenticate(userid,privatekeyfile):
	return "pass"
	'''
	s = xmlrpclib.ServerProxy('http://localhost:8000')
	return s.beginAuthenticate(userid)
	'''
if __name__ =="__main__":
	print "Welcome to malicious file sharing system"
	if len(sys.argv) > 2:
		name = sys.argv[1]
		privatefile = sys.argv[2]
		print "Name and password file supplied from command line:"
		print name
		print privatefile
	else:
		print "please log in:"
		name = raw_input("username:")
		privatefile = raw_input("private key file:")
	while not os.path.exists(privatefile):
		print "cannot find the private key file, do you want to register for a new account (y/n)?"
		ans = raw_input()
		if ans == 'y':
			stat = register(name,privatefile)
			if stat:
				print "error while registering for an account, please restart the program"
				sys.exit(1)
		else:
			privatefile = raw_input("re-enter private key file:")

	client = shell.maliciousClient(name,privatefile,fileserver,key_repo)

	if client.msg != "pass":
		print "Failed to authenticate: ",client.msg
		sys.exit(1)
	else:
		print "Authentication succeeded, begin typing your first command"

	cmd = getcmd()
	while cmd[0] != "quit" and cmd[0] != "exit":
		execcmd(cmd)
		cmd = getcmd()



