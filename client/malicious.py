import sys
import shell
import xmlrpclib


client = 0

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
	print "your username: ", sys.argv[1]
	print "private key file: ", sys.argv[2]
	global client
	client = shell.maliciousClient(sys.argv[1],sys.argv[2])

	if client.msg != "pass":
		print "Failed to authenticate: ",client.msg
		sys.exit(1)
	else:
		print "Authentication succeeded, begin typing your first command"

	cmd = getcmd()
	while cmd[0] != "quit" and cmd[0] != "exit":
		execcmd(cmd)
		cmd = getcmd()



