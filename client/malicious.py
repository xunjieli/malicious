import sys, os
import shell
import xmlrpclib
import dummykeydist
import dummyfileserver
import json
import base64

from ..common import metadata, crypto
from ..public_key_repo import public_key_repo_func

client = 0
#key_repo = xmlrpclib.ServerProxy('http://localhost:8008')
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
	credential['MEK'] = base64.b64encode(crypto.export_key(MEK))
	credential["MSK"] = base64.b64encode(crypto.export_key(MSK))
	# upload key to repo
	key_repo.set_public_key(name,base64.b64encode(crypto.export_key(MEK[0:2])))
	key_repo.set_verification_key(name,base64.b64encode(crypto.export_key(MSK[0:2])))
	#key_repo.set_verification_key(name,xmlrpclib.Binary("hahaha2"))
	#key_repo.set_public_key(name,xmlrpclib.Binary("hahaha"))
	print "registration succesful"
	
	json.dump(credential,open(privatefile,'wb'))
	
	return 0

def getcmd():
	global client
	cmd = raw_input(client.getPath()+">>")
	return cmd.split(' ')

def execcmd(cmd):
	try:
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
				return
			client.mkdir(cmd[1])
		elif cmd[0] == 'ls':
			client.ls()
		elif cmd[0] == "ul":
			if len(cmd) < 2:
				print "usage: ul [local source] [optional:remote name]"
				return
			client.upload(cmd[1:])
		elif cmd[0] == "dl":
			if len(cmd) < 2:
				print "usage: dl [remote name] [optional:local]"
				return
			client.download(cmd[1:])
		elif cmd[0] == "rename":
			if len(cmd) < 2:
				print "usage: rename [remote source] [new name]"
				return
			client.rename(cmd[1],cmd[2])
		elif cmd[0] == "shr": # share read access
			if len(cmd) < 3:
				print "usage: shr [remote file] [user1] [user2] [user3] ..."
				return
			client.share(cmd[1],cmd[2:],1)
		elif cmd[0] == "shw":
			if len(cmd) < 3:
				print "usage: shw [remote file] [user1] [user2] [user3] ..."
				return
			client.share(cmd[1],cmd[2:],2)
		elif cmd[0] == "unshare":
			if len(cmd) < 3:
				print "usage: unshare [remote file] [user1] [user2] [user3] ..."
				return
			client.share(cmd[1],cmd[2:],0)
		elif cmd[0] == "rm":
			if len(cmd) < 2:
				print "usage: rm [remote file]"
				return
			client.delete(cmd[1])
		elif cmd[0] == 'debug_see_dir' or cmd[0] == "dsd":
			client.debug_see_dir()
		elif cmd[0] == 'debug_see_credential' or cmd[0] == "dsc":
			client.debug_see_credential()
		else:
			print 'Command not found'
	except shell.ShellException as e:
		print e.value

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
	if len(sys.argv) > 3:
		print "Entering script mode"
		scriptfile = open(sys.argv[3],'r').read()
		cmd = scriptfile.split('\n')
		for i in range(len(cmd)):
			execcmd(cmd[i])
	else:	
		cmd = getcmd()
		while cmd[0] != "quit" and cmd[0] != "exit":
			execcmd(cmd)
			cmd = getcmd()



