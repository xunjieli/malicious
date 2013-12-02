import json
import dummyfileserver
# this module define behavior of the client program

# http://stackoverflow.com/questions/279237/import-a-module-from-a-relative-path
import os, sys, inspect
from ..common import metadata, crypto

'''
specification:
	directory file:
		json object with fields: name, content
			the content is a dictionary whose key is the filename, and value is
			a3-tuple, the first indicate if it's directory, and the second 
			indicate the inode number, and the third indicate the owner of the file
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
		if "content" not in d:
			return "directory content missing"
		return "pass"

	def authenticate(self,name,privatekey):
		return ("pass",'token')
	def directory_prototype(self,name):
		return {"name":name,"content":{}}
	def __init__(self,name,privatefile,fileserver,keyrepo):
		# need to download root dir from the server
		self.name = name
		self.privatefile = privatefile
		self.privatefile_loaded = False
		# get credential
		try:
			with open(privatefile,'r') as f:
				self.user_credential = json.loads(f.read())
				for i in range(len(self.user_credential["MEK"])):
					self.user_credential["MEK"][i] = long(self.user_credential["MEK"][i])
				for i in range(len(self.user_credential["MSK"])):
					self.user_credential["MSK"][i] = long(self.user_credential["MSK"][i])
			self.privatefile_loaded = True
		except:
			raise ShellException("failed to load credential file")
		# authenticate
		(msg,token) = self.authenticate(name,self.user_credential["MEK"])
		self.msg = msg
		if msg != "pass":
			raise ShellException("failed to authenticate user")

		self.token = token

		self.fileserver = fileserver
		self.keyrepo = keyrepo
		# need to do authentication properly
		
		if self.user_credential["max_inode"] == 0:
			self.getNewInode()
			# create root directory
			rootfile = json.dumps(self.directory_prototype("root"))
			print "This is your first time.. setting up root directory.."
			try:
				self.createFile(src=rootfile,isdir=True,inode=0)
			except ShellException as e:
				raise ShellException("Error while trying to create root directory for the first time: "+e.value)

		print "fetching root directory"
		meta,data = self.getData(0)
		print "done"
		# check if data
		if data is None: # no root directory
			raise ShellException("root directory does not exist!")
	
		dirfile = data
		# need to do some check on metadata

		self.dir = json.loads(dirfile)
		self.inodepath = [(0,self.name)]
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
			if self.dir["content"][path][0] != "dir":
				raise ShellException("The given directory in the path does not exist: " + path)
			else:
				pathinode = self.dir["content"][path][1:3]
		# get metadata from the server
		(meta,dirfile) = self.getData(inode=pathinode[0],owner=pathinode[1])
		self.dir = json.loads(dirfile)
		# update internal state
		if path == "..":
			self.path.pop()
			self.inodepath.pop()
		else:
			self.path.append(path)
			self.inodepath.append(pathinode)

			

	def getData(self,inode,owner = None):
		if owner is None:
			owner = self.name
		# need to download then check integrity
		(meta,data) = self.fileserver.read_file(self.name,owner,inode,self.token)
		# need to check integrity of meta data
		owner = metadata.extract_owner_from_metadata(meta)
		# get the verification key
		verification_key = self.keyrepo.get_verification_key(owner)
		try:
			meta = metadata.metadata_decode(meta,verification_key,self.name,self.user_credential["MEK"])
		except MetadataFormatException as e:
			raise ShellException("Metadata Malformed: "+e.value)

		file_encryption_key = meta[3]
		file_signing_key = meta[2]
		# verify file
		(data_sig,src) = metadata.unpack_data(data,2)
		if not crypto.asymmetric_verify(file_signing_key,src,data_sig):
			raise ShellException("File Signature Verification Failed")
		# need to check file id
		if meta[0] != owner+'_'+str(inode):
			raise ShellException("The server returned the wrong file (expected: %s, received %s)"% (owner+'_'+str(inode),meta[0]))
		data = crypto.symmetric_decrypt(src,file_encryption_key)
		return (meta,data)

	def getMetadata(self,inode,owner=None):
		if owner is None:
			owner = self.name
		# need to download then check integrity
		meta = self.fileserver.read_metadata(self.name,owner,inode,self.token)
		# need to do some decoding but I don't have some real metadata to work on now yet.
		# should return as dictionary
		owner = metadata.extract_owner_from_metadata(meta)
		# get the verification key
		verification_key = self.keyrepo.get_verification_key(owner)
		try:
			meta = metadata.metadata_decode(meta,verification_key,self.name,self.user_credential["MEK"])
		except MetadataFormatException as e:
			raise ShellException("Metadata Malformed: "+e.value)
		if meta[0] != owner+'_'+str(inode):
			raise ShellException("The server returned the wrong metadata (expected: %s, received %s)"% (owner+'_'+str(inode),meta[0]))

		return meta

	def getPath(self):
		return self.path[-1]

	def createMetadata(self,inode,isdir,users=[]):
		file_id = self.name + '_' + str(inode)
		is_folder = isdir
		file_key = crypto.generate_symmetric_key()
		file_sig_key = crypto.generate_file_signature_keypair()
		owner_sig_key = self.user_credential["MSK"]
		owner_pub_ekey = self.user_credential["MEK"][0:2]
		owner = (self.name,owner_pub_ekey)
		metadata_with_sig = metadata.metadata_encode(file_id,is_folder,file_key,file_sig_key,owner_sig_key,owner,users)
		return metadata_with_sig, file_key, file_sig_key

	def getNewInode(self):
		inode = self.user_credential["max_inode"]
		self.user_credential["max_inode"]= self.user_credential["max_inode"] + 1
		return inode

	# need to return inode created
	# specify inode only if you're sure it's available, otherwise the file will be over written!
	def createFile(self,src,isdir,inode=None,users = []):
		if inode is None:
			inode = self.getNewInode()
		if type(src) is str:
			# need to create metadata
			meta,file_encryption_key,file_sig_key = self.createMetadata(inode,isdir,users)
			src = crypto.symmetric_encrypt(src,file_encryption_key)
			data_sig = crypto.asymmetric_sign(file_sig_key,src)

			data_with_sig = metadata.pack_data(data_sig,src)
			# need to handle error if file transmission fail

			result = self.fileserver.upload_file(self.name,inode,meta,data_with_sig,self.token)

			if result != "success":
				raise ShellException("Error uploading file: "+result)
		else: # it's a file, need to find a way to handle this
			pass
		return inode

	def updateFile(self,src,inode,owner=None):
		if owner is None:
			owner = self.name
		# download metadata for the file encryption key
		# I need to know who the owner of the file is, otherwise cannot verify the file
		# how to access file from different user, if the inode is an integer?
		meta = self.getMetadata(inode,owner)
		file_encryption_key = meta[3]
		file_signing_key = meta[4]
		src = crypto.symmetric_encrypt(src,file_encryption_key)
		data_sig = crypto.asymmetric_sign(file_signing_key,src)
		data_with_sig = metadata.pack_data(data_sig,src)
		# need to handle error if file transmission fail
		result = self.fileserver.modify_file(self.name,owner,inode,data_with_sig,self.token)
		if result != "success":
				raise ShellException("Error modifying file: "+result)

	def updateMetadata(self,meta,inode):
		# assume meta is the same as the one returned by getMetadata
		# might need to do conversion from list to cell
		userslist = []
		for key in meta[6]:
			userslist.append(meta[6][key])
		meta[6] = userslist
		meta_withsig = metadata.metadata_encode(meta[0],meta[1],meta[2],meta[3],meta[4],meta[5],meta[6])
		result = self.fileserver.modify_metadata(self.name,inode,meta_withsig,self.token)
		if result != "success":
				raise ShellException("Error modifying metadata: "+result)

	############# shell command function ##################
	def ls(self,path = '.'):
		oldpath = self.path
		oldinodes = self.inodepath
		olddir = self.dir
		self.cd(path)
		for key in self.dir["content"]:
			if self.dir["content"][key][0] == "dir":
				print "d:"+key
			else:
				print "f:"+key
		self.path = oldpath
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
		oldpath = self.path
		oldinodes = self.inodepath
		olddir = self.dir
		try:
			if not len(path):
				path = '~'
			paths = path.split('/')
			# go to home
			if paths[0] == '' or paths[0] == '~':
				self.path = ['root']
				self.inodepath = [(0,self.name)]
				(meta,dirfile) = self.getData(0)
				self.dir = json.loads(dirfile)
				paths.pop(0)
			paths = [p for p in paths if len(p)]
			for i in range(len(paths)):
				self.cdOneStep(paths[i])
			
		except ShellException as e:
			self.path = oldpath
			self.inodepath = oldinodes
			self.dir = olddir
			raise ShellException("Error while cd: "+ e.value)
		


	def mkdir(self,name):
		# need to sanitize name
		oldpath = self.path
		oldinodes = self.inodepath
		olddir = self.dir

		try:
			path = name.split('/')
			name = path[-1]
			path.pop()
			path = [p for p in path if len(p)]
			path = '/'.join(path)
			if len(path):
				pass#self.cd(path)

			if name in self.dir["content"]:
				# need to check if the directory exists
				raise ShellException("name already exists: " + name)
			newdirfile = self.directory_prototype(name);
			newdirfile = json.dumps(newdirfile);
			inode = self.createFile(newdirfile,True)
			self.dir["content"][name] = ("dir",inode,self.name)
			self.updateFile(json.dumps(self.dir),self.inodepath[-1][0],self.inodepath[-1][1])
			'''
			self.path = oldpath
			self.inodepath = oldinodes
			self.dir = olddir
			'''
		except ShellException as e:
			raise ShellException("Error while mkdir: "+ e.value)
		

	def debug_see_dir(self):
		print "dir:       ", json.dumps(self.dir)
		print "path:      ", json.dumps(self.path)
		print "inodepath: ", json.dumps(self.inodepath)


	def __del__(self):
		# this saves persistent state onto disk
		try:
			if self.privatefile_loaded:
				with open(self.privatefile,'wb') as f:
					json.dump(self.user_credential,f)
		except:
			raise ShellException("failed to save credential file")




