import json, pickle
import dummyfileserver
# this module define behavior of the client program

# http://stackoverflow.com/questions/279237/import-a-module-from-a-relative-path
import os, sys, inspect, base64
from ..common import metadata, crypto, packing

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


def confirm(msg):
    ans = raw_input(msg + " (y/n)")
    if ans == 'y':
        return True
    else:
        return False


def debug(msg):
    print msg
    pass


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
    def verifyDir(self, d):
        # check if name exist
        if "name" not in d:
            return "directory name missing"
        if "content" not in d:
            return "directory content missing"
        return "pass"

    def authenticate(self, name, privatekey):
        return ("pass", 'token')

    def directory_prototype(self, name):
        return {"name": name, "content": {}}

    def __init__(self, name, privatefile, fileserver, keyrepo):
        # need to download root dir from the server
        self.name = name
        self.privatefile = privatefile
        self.privatefile_loaded = False
        # get credential

        with open(privatefile, 'r') as f:
            self.user_credential = json.loads(f.read())
            self.user_credential["MEK"] = crypto.import_key(base64.b64decode(self.user_credential["MEK"]))
            self.user_credential["MSK"] = crypto.import_key(base64.b64decode(self.user_credential["MSK"]))
        self.privatefile_loaded = True


        # authenticate
        (msg, token) = self.authenticate(name, self.user_credential["MEK"])
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
                self.createFile(src=rootfile, isdir=True, inode=0)
            except ShellException as e:
                raise ShellException("Error while trying to create root directory for the first time: " + e.value)

        print "fetching root directory"
        meta, data = self.getData(0)
        print "done"
        # check if data
        if data is None: # no root directory
            raise ShellException("root directory does not exist!")

        dirfile = data
        # need to do some check on metadata

        self.dir = json.loads(dirfile)
        self.inodepath = [(0, self.name)]
        self.path = ['root']
        # create temporary folder

        msg = self.verifyDir(self.dir)
        if msg != "pass":
            raise DirectoryFormatException(msg)

    def setToken(self, token):
        self.token = token

    def cdOneStep(self, path):
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
            if path not in self.dir["content"] or self.dir["content"][path][0] != "dir":
                raise ShellException("The given directory in the path does not exist: " + path)
            else:
                pathinode = self.dir["content"][path][1:3]
            # get metadata from the server
        (meta, dirfile) = self.getData(inode=pathinode[0], owner=pathinode[1])
        # need to check permission
        self.dir = json.loads(dirfile)
        # update internal state
        if path == "..":
            self.path.pop()
            self.inodepath.pop()
        else:
            self.path.append(path)
            self.inodepath.append(pathinode)


    def getData(self, inode, owner=None):

        if owner is None:
            owner = self.name
            # need to download then check integrity

        alldata = self.fileserver.read_file(self.name, owner, inode, self.token)
        if alldata is None:
            raise ShellException("The server returns nothing")
        meta = alldata[0]
        data = alldata[1]
        # need to check integrity of meta data
        owner = metadata.extract_owner_from_metadata(meta)
        # get the verification key
        verification_key = crypto.import_key(base64.b64decode(self.keyrepo.get_verification_key(owner)))
        try:
            meta = metadata.metadata_decode(meta, verification_key, self.name, self.user_credential["MEK"])
        except metadata.MetadataFormatException as e:
            raise ShellException("Metadata Malformed: " + e.value)
            # check if metadata points to the correct file
        if not self.checkFileID(meta[0], owner, inode):
            raise ShellException(
                "FileID mismatch - expected: %s, received: %s" % (self.encodeFileID(owner, inode), meta[0]))
        file_encryption_key = meta[3]
        file_verifying_key = meta[2]
        # need to check file id
        if meta[0] != owner + '_' + str(inode):
            raise ShellException(
                "The server returned the wrong file (expected: %s, received %s)" % (owner + '_' + str(inode), meta[0]))
        if file_encryption_key is None:
            raise ShellException("Cannot decrypt requested file: you don't have read permission")

        # verify file
        (data_sig, src) = packing.unpack_data(data, 2)
        if not crypto.asymmetric_verify(file_verifying_key, src, data_sig):
            raise ShellException("File Signature Verification Failed")
        data = crypto.symmetric_decrypt(src, file_encryption_key)
        return (meta, data)

    def getMetadata(self, inode, owner=None):
        if owner is None:
            owner = self.name
            # need to download then check integrity
        meta = self.fileserver.read_metadata(self.name, owner, inode, self.token)
        if meta is None:
            return None
        owner = metadata.extract_owner_from_metadata(meta)
        # get the verification key
        verification_key = crypto.import_key(base64.b64decode(self.keyrepo.get_verification_key(owner)))
        try:
            meta = metadata.metadata_decode(meta, verification_key, self.name, self.user_credential["MEK"])
        except metadata.MetadataFormatException as e:
            raise ShellException("Metadata Malformed: " + e.value)
        if meta[0] != owner + '_' + str(inode):
            raise ShellException("The server returned the wrong metadata (expected: %s, received %s)" % (
                owner + '_' + str(inode), meta[0]))

        return meta

    def getPath(self):
        return self.path[-1]

    def encodeFileID(self, owner, inodenumber):
        return str(owner) + "_" + str(inodenumber)

    def decodeFileID(self, fileid):
        try:
            idx = fileid.rfind('_')
            return (int(fileid[(idx + 1):]), fileid[:idx])
        except:
            raise ShellException("error while decoding file id")

    def checkFileID(self, fileid, owner, inode):
        try:
            inumber, own = self.decodeFileID(fileid)
            if int(inode) == inumber and own == str(owner):
                return True
        except:
            pass
        return False

    def createMetadata(self, inode, isdir, users=[]):
        file_id = self.encodeFileID(self.name, inode)
        is_folder = isdir
        file_key = crypto.generate_symmetric_key()
        file_sig_key = crypto.generate_file_signature_keypair()
        owner_sig_key = self.user_credential["MSK"]
        owner_pub_ekey = self.user_credential["MEK"][0:2]
        owner = (self.name, owner_pub_ekey)
        metadata_with_sig = metadata.metadata_encode(file_id, is_folder, file_key, file_sig_key, owner_sig_key, owner,
                                                     users)
        return metadata_with_sig, file_key, file_sig_key

    def getNewInode(self):
        inode = self.user_credential["max_inode"]
        self.user_credential["max_inode"] = self.user_credential["max_inode"] + 1
        return inode

    # need to return inode created
    # specify inode only if you're sure it's available, otherwise the file will be over written!
    def createFile(self, src, isdir, inode=None, users=[]):
        if inode is None:
            inode = self.getNewInode()
        if type(src) is str:
            # need to create metadata
            meta, file_encryption_key, file_sig_key = self.createMetadata(inode, isdir, users)
            src = crypto.symmetric_encrypt(src, file_encryption_key)
            data_sig = crypto.asymmetric_sign(file_sig_key, src)

            data_with_sig = packing.pack_data(data_sig, src)
            # need to handle error if file transmission fail

            result = self.fileserver.upload_file(self.name, inode, meta, data_with_sig, self.token)

            if result != "success":
                raise ShellException("Error creating file: " + result)
        else: # it's a file, need to find a way to handle this
            pass
        if isdir:
            isdir = "dir"
        else:
            isdir = "file"
        return (isdir, inode, self.name)

    def updateFile(self, src, inode, owner=None):
        if owner is None:
            owner = self.name
            # download metadata for the file encryption key
        # I need to know who the owner of the file is, otherwise cannot verify the file
        # how to access file from different user, if the inode is an integer?
        meta = self.getMetadata(inode, owner)
        file_encryption_key = meta[3]
        file_signing_key = meta[4]
        if file_signing_key is None: # don't have write access
            raise ShellException("You don't have write permission to this file")
        src = crypto.symmetric_encrypt(src, file_encryption_key)
        data_sig = crypto.asymmetric_sign(file_signing_key, src)
        data_with_sig = packing.pack_data(data_sig, src)
        # need to handle error if file transmission fail
        result = self.fileserver.modify_file(self.name, owner, inode, data_with_sig, self.token)
        if result != "success":
            raise ShellException("Error modifying file: " + result)

    def updateMetadata(self, meta, inode):
        # assume meta is the same as the one returned by getMetadata
        # might need to do conversion from list to cell
        file_id = meta[0]
        is_folder = meta[1]
        file_key = meta[3]
        file_sig_key = meta[4]
        owner_sig_key = self.user_credential["MSK"]
        owner = (meta[5], self.user_credential["MEK"][0:2])
        users = meta[6]
        meta_withsig = metadata.metadata_encode(file_id, is_folder, file_key, file_sig_key, owner_sig_key, owner, users)
        result = self.fileserver.modify_metadata(self.name, inode, meta_withsig, self.token)
        if result != "success":
            raise ShellException("Error modifying metadata: " + result)

    # functions for checking file names
    def checkDirName(self, name):
        if name.find('/') != -1 or name == "." or name == "..":
            return False
        return True

    def checkFileName(self, name):
        if name.find('/') != -1 or name == "." or name == "..":
            return False
        return True

    # return directory state in a tuple
    def saveState(self):
        oldpath = self.path
        oldinodes = self.inodepath
        olddir = self.dir
        self.oldstate = [oldpath, oldinodes, olddir, True]

    def restoreState(self):
        if self.oldstate[3]:
            self.path = self.oldstate[0]
            self.inodepath = self.oldstate[1]
            self.dir = self.oldstate[2]
            self.oldstate[3] = False
        else:
            raise ShellException("Internal Error: trying to restore stale state")

    def updateCurrentDirEntry(self):
        self.updateFile(json.dumps(self.dir), self.inodepath[-1][0], self.inodepath[-1][1])

    ############# shell command function ##################
    def ls(self, path='.'):
        oldpath = self.path
        oldinodes = self.inodepath
        olddir = self.dir
        self.cd(path)
        for key in self.dir["content"]:
            if self.dir["content"][key][0] == "dir":
                print "d:" + key
            else:
                print "f:" + key
        self.path = oldpath
        self.inodepath = oldinodes
        self.dir = olddir

    # need to support uploading the entire directory later
    def upload(self, arg):
        if len(arg) < 2:
            dst = ""
        else:
            dst = arg[1]
        src = arg[0]
        try:
            f = open(src, 'rb')
            file_content = f.read()
            f.close()
        except:
            raise ShellException("ul: error reading local file")
            # sanitize remote path
        filename = dst
        if len(filename) == 0:
            filename = os.path.basename(src)
        if not self.checkFileName(filename):
            raise ShellException("ul: invalid filename given: " + filename)
        try:
            # check if file exist
            if filename in self.dir["content"]:
                # check if the name is a directory
                if self.dir["content"][filename][0] == "dir":
                    print "directory %s already exists at path %s" % (filename, '/'.join(self.path))
                    print "Please specified a new file name, operation cancelled"
                    return
                    # check against malformed directory entry
                if self.dir["content"][filename][0] != "file":
                    raise ShellException(
                        "ul: current directory (%s) malformed, specified file (%s) exists but is not file or dir" % (
                            '/'.join(self.path), filename))

                print "warning: file %s already exists at path %s" % (filename, '/'.join(self.path))
                if not confirm("Overwrite? This will not change permission to the file"):
                    print "Operation cancelled"
                    return
                inode = self.dir["content"][filename]
                self.updateFile(file_content, inode[1], inode[2])
            else: # file does not exist
                meta = self.getMetadata(inode=self.inodepath[-1][0], owner=self.inodepath[-1][1])
                if meta[4] is None:
                    raise ShellException("cannot create file: you don't have write permission to the folder")
                inode = self.createFile(file_content, False)
                self.dir["content"][filename] = inode
                # update the directory
                self.updateCurrentDirEntry()
		except ShellException as e:
			raise ShellException("ul: error while uploading file: %s" % e.value)

	# need to support downloading the whole directory
	def download(self,arg):
		src = arg[0]
		if len(arg) < 2:
			dst = os.path.join('.',src)
		else:
			dst = arg[1]
		filename = src
		if not self.checkFileName(filename):
			raise ShellException("dl: invalid filename given: "+filename)

		try:

			if filename in self.dir["content"]:
				# check if the name is a directory
				if self.dir["content"][filename][0] == "dir":
					print "dl: given file %s  is a directory at path %s" % (filename,'/'.join(self.path))
					print "operation cancelled"
					return
				# check against malformed directory entry
				if self.dir["content"][filename][0] != "file":
					raise ShellException("dl: current directory (%s) malformed, specified file (%s) exists but is not file or dir" %('/'.join(self.path),filename) )
				inode = self.dir["content"][filename]
				(meta,data) = self.getData(inode=inode[1],owner=inode[2])
				if data is None:
					raise ShellException("server returned null data")
				try:
					with open(dst,'wb') as f:
						f.write(data)
						f.close()
				except ShellException as e:
					raise ShellException("dl: error while writing file to local disk")
			else: # file does not exist
				raise ShellException("remote file not found")
		except ShellException as e:
			raise ShellException("dl: error while downloading file: %s" % e.value)

	def rename(self,src,dst):
		meta = self.getMetadata(inode=self.inodepath[-1][0],owner=self.inodepath[-1][1])
		if meta[4] is None:
			raise ShellException("rename: write permission to the current directory needed")
		try:
			if not self.checkFileName(dst):
				raise ShellException("rename: illegal name: "+ dst)
			if src not in self.dir["content"]:
				# need to check if the directory exists
				raise ShellException("rename: source name doesn't exist: " + src)
			if dst in self.dir["content"]:
				# need to check if the directory exists
				raise ShellException("rename: destination name doesn't exist: " + dst)
			inode_info = self.dir["content"][src]
			self.dir["content"].pop(src,None)
			self.dir["content"][dst] = inode_info
			self.updateCurrentDirEntry()
		except ShellException as e:
			raise ShellException(e.value)

	# this delete everything in the current directory
	# return true for success, false if some file/directory cannot be removed
	def delete_all(self):
		meta = self.getMetadata(inode=self.inodepath[-1][0],owner=self.inodepath[-1][1])
		if meta[4] is None and len(self.dir["content"]) > 0:
			return False # no write permission to current directory, cannot remove any file
		success = True
		allfile = []
		for src in self.dir["content"]:
			allfile.append(src)
		for i in range(len(allfile)):
			src = allfile[i]
			inode = self.dir["content"][src]
			if inode[0] == "file": # this case is easy
				success = success and self.delete_file(src)
			elif inode[0] == "dir": # need to recurse into sub directory
				try:
					self.cd(src)
					good_to_go = True
				except:
					success = False
					good_to_go = False
				if good_to_go:
					success = self.delete_all()
					self.cd('..')
					success = success and self.delete_file(src)
			else:
				return False
		return success

	def delete_file(self,src):
		success = True
		inode = self.dir["content"][src]
		olddir = self.dir
		try:
			self.dir["content"].pop(src,None)
			self.updateCurrentDirEntry()
			if inode[2] == self.name: # if own the file, remove it from server
				status = self.fileserver.remove_file(self.name,self.name,inode[1],self.token)
			if status != "success":
				raise ShellException("failed to remove file from the server")
		except:
			self.dir = olddir
			self.updateCurrentDirEntry() # do this in case it fails after updating the current directory
			success = False
		return success

	def delete(self,src):
		meta = self.getMetadata(inode=self.inodepath[-1][0],owner=self.inodepath[-1][1])
		if meta[4] is None:
			raise ShellException("rm: write permission to the current directory needed")
		if src not in self.dir["content"]:
			raise ShellException("rm: file not found")
		inode = self.dir["content"][src]
		if inode[0] == "file": # this case is easy
			success = self.delete_file(src)
		elif inode[0] == "dir": # need to recurse into sub directory
			try:
				self.cd(src)
				good_to_go = True
			except:
				success = False
				good_to_go = False
			if good_to_go:
				success = self.delete_all()
				self.cd('..')
				success = success and self.delete_file(src)
		else:
			raise ShellException("rm: the given file is malformed")
		if not success:
			print "rm: some file were not removed successfully, they may belong to other user"		

	def share(self,src,users,access = 0):
		# get the inode
		if src not in self.dir["content"]:
			raise ShellException("share: file not found") 
		inode = self.dir["content"][src]
		meta = self.getMetadata(inode=inode[1],owner=inode[2])
		if inode[2] != self.name or meta[5] != self.name:
			raise ShellException("share: only the owner (%s) of the file can change permission" % meta[5])
		current_users = meta[6]
		new_users = []
		for usr in current_users:
			new_users.append(usr)
		# list of users that doesn't need to change permission
		new_users = [usr for usr in new_users if usr not in users]
		meta_users = []
		for usr in new_users:
			public_key = crypto.import_key(base64.b64decode(self.keyrepo.get_public_key(usr)))
			meta_users.append((usr,current_users[usr],public_key))
		if access > 0:
			for usr in users:
				public_key = crypto.import_key(base64.b64decode(self.keyrepo.get_public_key(usr)))
				meta_users.append((usr,access == 2,public_key))
		new_meta = (meta[0],meta[1],meta[2],meta[3],meta[4],meta[5],meta_users)
		self.updateMetadata(new_meta,inode[1])

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
		# check permission
		meta = self.getMetadata(inode=self.inodepath[-1][0],owner=self.inodepath[-1][1])
		if meta[4] is None:
			raise ShellException("mkdir: write permission to the current directory needed")
		try:
			if not self.checkDirName(name):
				raise ShellException("mkdir: illegal name: "+ name)
			if name in self.dir["content"]:
				# need to check if the directory exists
				raise ShellException("mkdir: name already exists: " + name)
			newdirfile = self.directory_prototype(name);
			newdirfile = json.dumps(newdirfile);
			inode = self.createFile(newdirfile,True)
			self.dir["content"][name] = inode
			self.updateCurrentDirEntry()
		except ShellException as e:
			raise ShellException(e.value)
		

	def debug_see_dir(self):
		print "dir:       ", json.dumps(self.dir)
		print "path:      ", json.dumps(self.path)
		print "inodepath: ", json.dumps(self.inodepath)
		#print "credential:", json.dumps(self.user_credential)
	def debug_see_credential(self):
		print "credential:", json.dumps(self.user_credential)

	def __del__(self):
		# this saves persistent state onto disk
		try:
			if self.privatefile_loaded:
				with open(self.privatefile,'wb') as f:
					self.user_credential["MEK"] = base64.b64encode(crypto.export_key(self.user_credential["MEK"]))
					self.user_credential["MSK"] = base64.b64encode(crypto.export_key(self.user_credential["MSK"]))
		
					json.dump(self.user_credential,f)
		except:
			raise ShellException("failed to save credential file")




