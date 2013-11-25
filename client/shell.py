import json
import dummyfileserver
# this module define behavior of the client program

# http://stackoverflow.com/questions/279237/import-a-module-from-a-relative-path
import os, sys, inspect
sys.path.append("../common")
import metadata
import crypto
'''
specification:
	directory file:
		json object with fields: name, files, dir
	user credential file:
		json object with fields: private_key, max_inode
'''
class DirectoryFormatException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)
    __repr__ = __str__

class ShellException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)
    __repr__ = __str__


class maliciousClient:
	############# helper function ##################
	def verifyDir(self,d):
		# check if name exist
		if "name" not in d:
			return "directory name missing"
		if "files" not in d or "dir" not in d:
			return "directory content missing"
		return "pass"

	def authenticate(self,name,privatekey):
		return ("pass",'token')

	def __init__(self,name,privatefile):
		# need to download root dir from the server
		with open(privatefile,'r') as f:

			self.user_credential = json.loads(f.read())

		(msg,token) = self.authenticate(name,self.user_credential["privatekey"])
		self.msg = msg
		if msg != "pass":
			return
		self.token = token
		(meta,dirfile) = dummyfileserver.read_file(name,0,self.token)
		# need to do some check on metadata

		self.name = name
		self.dir = json.loads(dirfile)
		self.inodepath = [0]
		self.path = ['~']
		# create temporary folder

		msg = self.verifyDir(self.dir)
		if msg != "pass":
			raise DirectoryFormatException(msg)

	def setToken(self,token):
		self.token = token

	def cdOneStep(self,path):
		if not len(path):
			return
		# figure out what's the next inode number
		if path == "..":
			if len(self.inodepath) > 1:
				pathinode = self.inodepath[-2]
			else:
				return # already at root, can't cd .. anymore
		elif path == ".":
			return
		elif path =="~":
			pathinode = 0
		else:
			if self.dir["dir"][path] is none:
				raise ShellException("The given directory in the path does not exist: " + path)
			else:
				pathinode = self.dir["dir"][path]
		# get metadata from the server
		(meta,dirfile) = self.getData(pathinode)
		self.dir = json.loads(dirfile)
		# update internal state
		if path == "..":
			self.path.pop()
			self.inodepath.pop()
		elif path == "~":
			self.path = ['~']
			self.inodepath = [0]
		else:
			self.path.push(path)
			self.inodepath.push(pathinode)

			

	def getData(self,inode):
		# need to download then check integrity
		(meta,data) = dummyfileserver.read_file(self.name,inode,self.token)
		# need to check integrity
		return (meta,data)

	def getMetadata(self,inode):
		# need to download then check integrity
		meta = dummyfileserver.read_metadata(self.name,inode,self.token)
		# need to check integrity
		# need to do some decoding but I don't have some real metadata to work on now yet.
		# should return as dictionary
		return meta

	def getPath(self):
		return self.path[-1]

	def createMetadata(self,inode):
		pass

	def createFile(self,src):
		if type(src) is str:

		else: # it's a file, need to find a way to handle this

	############# shell command function ##################
	def ls(self,path = '.'):
		oldpath = self.paths
		oldinodes = self.inodepath
		olddir = self.dir
		self.cd(path)
		for key in self.dir["files"]:
			print "f:"+key
		for key in self.dir["dir"]:
			print "d:"+key
		self.paths = oldpath
		self.inodepath = oldinodes
		self.dir = olddir

	def upload(self,src,dst="."):
		print "usage: ul [local source] [optional:remote destination]"
		pass

	def download(self,src,dst="."):
		print "usage: dl [remote source] [optional:local destination]"
		pass

	def rename(self,src,dst):
		print "usage: rename [remote source] [new name]"
		pass

	def delete(self,file):
		print "usage: rm [remote file]"
		pass

	def share(self,cmd):
		print "usage: share [remote file] user1 user2 user3 ..."
		pass

	def pwd(self):
		# print "usage: pwd"
		print '/'.join(self.path)
		pass

	def cd(self,path):
		paths = path.split('/')
		paths = [p for p in paths if len(p)]
		for i in range(len(paths)):
			self.cdOneStep(paths[i])

	def mkdir(self,name):
		print "usage: mkdir [directory name]"
		if self.dir["dir"][name] is not None:
			# need to check if the directory exists
			raise ShellException("Directory already exists: " + name)
		newdirfile = {"name":name,"files":{},"dir":{}};
		newdirfile = json.dumps(newdirfile);
		inode = self.createFile(newdirfile)
		self.dir["dir"][name] = inode
		self.uploadData() # update the current directory

	def quit(self,name):
		# this saves persistent state onto disk
		pass




