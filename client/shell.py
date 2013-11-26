import json
import dummyfileserver
# this module define behavior of the client program

# http://stackoverflow.com/questions/279237/import-a-module-from-a-relative-path
import os, sys, inspect
from ..common import metadata, crypto

'''
specification:
	directory file:
		json object with fields: name, files, dir
	user credential file:
		json object with fields: MEK,MSK, max_inode
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

	def __init__(self,name,privatefile,first_time = False,fileserver,keyrepo):
		# need to download root dir from the server
		try:
			with open(privatefile,'r') as f:
				self.user_credential = json.loads(f.read())
		except:
			raise ShellException("failed to load credential file")
		self.fileserver = fileserver
		self.keyrepo = keyrepo
		# need to do authentication properly
		(msg,token) = self.authenticate(name,self.user_credential["MEK"])
		if first_time:
			# create root directory
			rootfile = {"name":"root","files":{},"dir":{}}
			self.createFile(src=rootfile,isdir=True,inode=0)

		self.msg = msg
		if msg != "pass":
			raise ShellException("failed to authenticate user")

		self.token = token
		data = self.fileserver.read_file(name,name,0,self.token)
		# check if data
		if data is None: # no root directory
			raise ShellException("root directory does not exist!")
		meta = data[0]
		dirfile = data[1]
		# need to do some check on metadata

		self.name = name
		self.dir = json.loads(dirfile)
		self.inodepath = [0]
		self.path = ['root']
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
		else:
			if path not in self.dir["dir"]:
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
		else:
			self.path.push(path)
			self.inodepath.push(pathinode)

			

	def getData(self,owner = None,inode):
		if owner is None:
			owner = self.name
		# need to download then check integrity
		(meta,data) = self.fileserver.read_file(self.name,owner,inode,self.token)
		# need to check integrity
		return (meta,data)

	def getMetadata(self,owner=None,inode):
		if owner is None:
			owner = self.name
		# need to download then check integrity
		meta = self.fileserver.read_metadata(self.name,owner,inode,self.token)
		# need to check integrity
		# need to do some decoding but I don't have some real metadata to work on now yet.
		# should return as dictionary
		owner = metadata.extract_owner_from_metadata(metadata)
		# get the verification key
		try:
			metadata = 
		except MetadataFormatException as e:
			raise ShellException("Metadata Malformed: "+e.value)
		return meta

	def getPath(self):
		return self.path[-1]

	def createMetadata(self,inode,isdir,users=[]):
		file_id = self.name + '_' + str(inode)
		is_folder = isdir
		file_key = crypto.generate_symmetric_key()
		file_sig_key = crypto.generate_file_signature_keypair()
		owner_sig_key = self.user_credential["MSK"]
		owner = self.name
		users=[(self.name,True,self.user_credential["MEK"][0:2])]
		return metadata_encode(file_id,is_folder,file_key,file_sig_key,owner_sig_key,owner,users)

	def getNewInode():
		inode = self.max_inode
		self.max_inode = self.max_inode + 1
		return inode
	# need to return inode created
	# specify inode only if you're sure it's available, otherwise the file will be over written!
	def createFile(self,src,isdir,inode=None):
		if inode is None:
			inode = getNewInode():
		users = [(self.name,True,self.user_credential["MEK"][0:2])] # add self to lsit of users 
		if type(src) is str:
			# need to create metadata
			metadata = self.createMetadata(inode,isdir,users)
			file_encryption_key = "??" # need to extract this from metadata
			src = crypto.symmetric_encrypt(src,file_encryption_key)
			data_sig = crypto.asymmetric_sign(self.user_credential["MSK"],src)

			data_with_sig = metadata.pack_data(data_sig,src)
			# need to handle error if file transmission fail
			self.fileserver.upload_file(self.name,inode,metadata,data_with_sig,self.token)
		else: # it's a file, need to find a way to handle this
			pass
		return inode

	def modify_file(client_id, fileID, data_file, token):
		pass
	def updateFile(self,src,owner=None,inode):
		if owner is None:
			owner = self.name
		# download metadata for the file encryption key
		# I need to know who the owner of the file is, otherwise cannot verify the file
		# how to access file from different user, if the inode is an integer?
		metadata = self.getMetadata(owner,inode)
		# read the owner out
		
		if not crypto.asymmetric_verify(metadata,)
		file_encryption_key = "??" # need to extract this from metadata
		src = crypto.symmetric_encrypt(src,file_encryption_key)
		data_sig = crypto.asymmetric_sign(self.user_credential["MSK"],src)
		data_with_sig = metadata.pack_data(data_sig,src)
		# need to handle error if file transmission fail
		self.fileserver.modify_file(self.name,inode,data_with_sig,self.token)

	def updateMetadata(self,metadata,inode):
		self.fileserver.modify_metadata(self.name,inode,metadata,self.token)

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
		if not len(path):
			path = '~'
		paths = path.split('/')
		# go to home
		if paths[0] == '' or paths[0] == '~':
			self.path = ['~']
			self.inodepath = [0]
			(meta,dirfile) = self.getData(pathinode)
			self.dir = json.loads(dirfile)
			paths.pop(0)
		paths = [p for p in paths if len(p)]
		for i in range(len(paths)):
			self.cdOneStep(paths[i])

	def mkdir(self,name):
		print "usage: mkdir [directory name]"
		if name in self.dir["dir"] or name in self.dir["files"]:
			# need to check if the directory exists
			raise ShellException("name already exists: " + name)
		newdirfile = {"name":name,"files":{},"dir":{}};
		newdirfile = json.dumps(newdirfile);
		inode = self.createFile(newdirfile)
		self.dir["dir"][name] = inode
		self.uploadData() # update the current directory

	def quit(self,name):
		# this saves persistent state onto disk
		pass




