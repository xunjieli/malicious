import json
import os
import copy
import shutil
from ..common.metadata import *
from ..common.crypto import *

DEBUG = True


def confirm(msg):
    ans = None
    while ans != 'y' and ans != 'n':
        ans = raw_input(msg + '(y/n)')
    return ans == 'y'


def confirmAlways(msg):
    ans = None
    while ans != 'y' and ans != 'n' and ans != 'a':
        ans = raw_input(msg + '(y/n/a)')
    return ans == 'y' or ans == 'a', ans == 'a'


def debug(msg):
    if True:
        print msg

class ShellException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

    __repr__ = __str__


class ClientException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

    __repr__ = __str__


class SecurityException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

    __repr__ = __str__


class DirectoryFile:
    def __init__(self, files=None):
        self.files = {} if files is None else files

    def pack(self):
        return pack_object(self.files.items())

    def getFileHandle(self, name):
        return None if name not in self.files else self.files[name]

    def contains(self, name):
        return name in self.files

    def link(self, name, handle):
        self.files[name] = handle

    def unlink(self, name):
        del self.files[name]

    def ls(self):
        return self.files.keys()

    @staticmethod
    def unpack(data):
        file_handle_format = TupleFormat(StrFormat(), IntFormat())
        dict_format = ListFormat(TupleFormat(StrFormat(), file_handle_format))
        return DirectoryFile(dict(unpack_object(data, dict_format)))


class MaliciousClient:
    def __init__(self, name, storage, fileserver, keyrepo):
        self.name = name
        self.storage = storage
        self.private_key = storage.get_private_key()
        self.sign_key = storage.get_sign_key()

        self.fileserver = fileserver
        self.fileserver.set_user(self.name, self.private_key, self.sign_key)
        self.keyrepo = keyrepo

    def initialize(self):
        if self.storage.get_last_file_id() == -1:
            root_id = self.storage.new_file_id()
            root_file = DirectoryFile()
            debug("This is your first time. Setting up root directory.")
            self.createFile(contents=root_file.pack(), isdir=True, file_id=0)

    def getDir(self, handle):
        return DirectoryFile.unpack(self.getData(handle)[1])

    def changePath(self, names, relative_to_path=None):
        relative_to_path = [] if relative_to_path is None else relative_to_path
        path = copy.copy(relative_to_path)
        for name in names:
            if not self.push_dir(path, name):
                raise ClientException("Could not access directory " + name)
        return path

    def push_dir(self, path, name):
        if name == '..':
            if len(path) > 1:
                path.pop()
            return True
        if name == '.':
            return True
        dir = self.getDir(path[-1][0])
        if dir.contains(name):
            path.append((dir.getFileHandle(name), name))
            return True
        return False

    def encodeFileHandle(self, handle):
        return handle[0] + '-' + str(handle[1])

    def getData(self, handle):
        alldata = self.fileserver.read_file(handle[0], handle[1])
        if alldata is None:
            return None
        meta = alldata[0]
        data = alldata[1]

        file_owner = extract_owner_from_metadata(meta)
        verification_key = self.keyrepo.get_verify_key(file_owner)
        try:
            meta = metadata_decode(meta, verification_key, self.name, self.private_key)
            file_handle, is_folder, fvk, fek, fsk, file_owner, file_users = meta
        except MetadataFormatException as e:
            raise SecurityException("Metadata malformed: " + e.value)
            # check if metadata points to the correct file
        if self.encodeFileHandle(handle) != file_handle:
            raise SecurityException("Server returned metadata of incorrect file handle. "
                                    "Expected %s, received %s" %
                                    (self.encodeFileHandle(handle), file_handle))
        if fek is None:
            raise ClientException("Cannot decrypt requested file: you do not have read permission.")

        data_sig, contents = unpack_data(data, 2)
        if not asymmetric_verify(fvk, contents, data_sig):
            raise SecurityException("Server returned invalid file: File signature verification failed.")
        decrypted_contents = symmetric_decrypt(contents, fek)
        return meta, decrypted_contents

    def getMetadata(self, handle):
        meta = self.fileserver.read_metadata(handle[0], handle[1])
        if meta is None:
            return None
        file_owner = extract_owner_from_metadata(meta)
        verification_key = self.keyrepo.get_verify_key(file_owner)
        try:
            meta = metadata_decode(meta, verification_key, self.name, self.private_key)
            file_handle, is_folder, fvk, fek, fsk, file_owner, file_users = meta
        except MetadataFormatException as e:
            raise ClientException("Metadata Malformed: " + e.value)
        if self.encodeFileHandle(handle) != file_handle:
            raise SecurityException("Server returned metadata of incorrect file handle. "
                                    "Expected %s, received %s" %
                                    (self.encodeFileHandle(handle), file_handle))
        return meta

    def createMetadata(self, file_id, isdir, users=None):
        users = [] if None else users
        file_id = self.encodeFileHandle((self.name, file_id))
        is_folder = isdir
        file_key = generate_symmetric_key()
        file_sig_key = generate_file_signature_keypair()
        owner_sig_key = self.sign_key
        owner_public_key = self.private_key[:2]
        owner = self.name, owner_public_key
        metadata_with_sig = metadata_encode(file_id, is_folder, file_key, file_sig_key, owner_sig_key, owner,
                                            users)
        return metadata_with_sig, file_key, file_sig_key

    def createFile(self, contents, isdir, file_id=None, users=None):
        users = [] if users is None else users
        if file_id is None:
            file_id = self.storage.new_file_id()
        meta, fek, fsk = self.createMetadata(file_id, isdir, users)
        enc_contents = symmetric_encrypt(contents, fek)
        data_sig = asymmetric_sign(fsk, enc_contents)
        data_with_sig = pack_data(data_sig, enc_contents)

        self.fileserver.upload_file(file_id, meta, data_with_sig)
        return file_id

    def updateFile(self, contents, handle):
        meta = self.getMetadata(handle)
        fek = meta[3]
        fsk = meta[4]
        if fsk is None:
            raise ClientException("You do not have write permission to this file.")
        enc_contents = symmetric_encrypt(contents, fek)
        data_sig = asymmetric_sign(fsk, enc_contents)
        data_with_sig = pack_data(data_sig, enc_contents)

        self.fileserver.modify_file(handle[0], handle[1], data_with_sig)

    def updateMetadata(self, meta, file_id):
        file_handle, is_folder, fvk, fek, fsk, file_owner, users = meta
        owner_sig_key = self.sign_key
        owner = (file_owner, self.private_key[:2])
        meta_with_sig = metadata_encode(file_id, is_folder, fek, fsk, owner_sig_key, owner, users)
        result = self.fileserver.modify_metadata(file_id, meta_with_sig)

    # link the file into the directory with the given name
    def link(self, dir_handle, file_name, file_handle):
        dir_meta, dir_data = self.getData(dir_handle)
        dir = DirectoryFile.unpack(dir_data)
        dir.link(file_name, file_handle)
        self.updateFile(dir.pack(), dir_handle)

    def unlink(self, dir_handle, file_name):
        dir_meta, dir_data = self.getData(dir_handle)
        dir = DirectoryFile.unpack(dir_data)
        dir.unlink(file_name)
        self.updateFile(dir.pack(), dir_handle)

    def removeFile(self, file_id):
        self.fileserver.remove_file(file_id)

    def fileExists(self, dir_handle, name):
        dir = self.getDir(dir_handle)
        return dir.contains(name)

    def validateNewLink(self, dir_handle, name):
        if not self.isLinkNameValid(name):
            raise ClientException("Illegal name: " + name)
        if not self.hasWriteAccess(dir_handle):
            raise ClientException("No write permission to directory")
        if self.fileExists(dir_handle, name):
            raise ClientException("Cannot create directory: file/directory already exists: " + name)

    def createDirectory(self):
        dir = DirectoryFile()
        dirfile = dir.pack()
        return self.createFile(dirfile, True)

    def grant_permission(self, file_id, user, writeable):
        file_handle, is_folder, fvk, fek, fsk, owner, users = self.getMetadata((self.name, file_id))
        if owner != self.name:
            raise ClientException("Only the owner (%s) can share a file." % owner)
        if user in users and (users[user] == writeable or users[user] == True) :
            return  # already has this permission
        users[user] = writeable
        new_users = []
        for user in users:
            new_users.append((user, users[user], self.keyrepo.get_public_key(user)))
        new_meta = metadata_encode(file_handle, is_folder, fek, fsk, self.sign_key, owner, new_users)
        self.updateMetadata(new_meta, file_id)

    def hasWriteAccess(self, handle):
        return self.getMetadata(handle)[4] != None

    def isDirectory(self, handle):
        return self.getMetadata(handle)[1]

    def isLinkNameValid(self, name):
        return name.find('/') == -1 and name not in ['.', '..'] and name[0] not in ['~', '!']


class MaliciousShell:
    def __init__(self, name, storage, fileserver, keyrepo):
        self.client = MaliciousClient(name, storage, fileserver, keyrepo)
        self.name = name
        self.path = [((self.name, 0), '~')]

    def splitPath(self, path):
        return path.split('/')

    def ls(self, path='.'):
        new_path = self.client.changePath(self.splitPath(path), self.path)
        dir = self.client.getDir(new_path[-1][0])
        return dir.ls()

    def cd(self, path):
        self.path = self.walk_path(path)

    def pwd(self, path=None):
        path = self.path if path is None else path
        return '/'.join(e[1] for e in self.path)

    def createDirectory(self, dir_handle, name):
        self.client.validateNewLink(dir_handle, name)
        dir_id = self.client.createDirectory()
        self.client.link(dir_handle, name, (self.name, dir_id))
        return dir_id

    def mkdir(self, name):
        self.createDirectory(self.path[-1][0], name)

    def uploadFile(self, local_file, dir_handle, name=None):
        if name is None:
            name = os.path.basename(local_file)
        if self.client.fileExists(dir_handle, name):
            create = False
            dir = self.client.getDir(dir_handle)
        else:
            create = True
            self.client.validateNewLink(dir_handle, name)

        try:
            f = open(local_file, 'rb')
            file_content = f.read()
            f.close()
        except IOError:
            raise ShellException("Cannot read local file: " + local_file)

        if create:
            file_id = self.client.createFile(file_content, False)
            self.client.link(dir_handle, name, (self.name, file_id))
        else:
            self.client.updateFile(file_content, dir.getFileHandle(name))

    def deleteEntry(self, dir_handle, name):
        def deleteHelper(dir, rdir, link):
            meta = self.client.getMetadata(rdir)
            if not meta[1]:
                self.client.unlink(rdir, link)
                # TODO: unlink all from shared folders
                self.client.removeFile(dir.getFileHandle(link))
            else:
                child_dir_handle = dir.getFileHandle(link)
                child_dir = self.client.getDir(child_dir_handle)
                for entry in child_dir.ls():
                    deleteHelper(child_dir, child_dir_handle, entry)
                self.client.unlink(rdir, link)
                # TODO: unlink all from shared folders
                self.client.removeFile(child_dir_handle)

        deleteHelper(self.client.getDir(dir_handle), dir_handle, name)

    def upload(self, local_path, remote_path, name):
        while local_path[-1] == '/': local_path = local_path[:-1]
        replace_all = False

        def uploadHelper(lpath, rpath, rdir, link):
            global replace_all
            new_rpath = rpath + '/' + link
            merge_dir = False
            if self.client.fileExists(rdir, link):
                if self.client.isDirectory(self.client.getDir(rdir).getFileHandle(link)) and os.path.isdir(lpath):
                    merge_dir = True
                else:
                    if replace_all:
                        replace = True
                    else:
                        replace_all, replace = confirmAlways(
                            'File/directory ' + new_rpath + ' already exists. Replace?')
                    if not replace:
                        return
                    self.deleteEntry(rdir, link)

            if os.path.isfile(lpath):
                self.uploadFile(lpath, rdir, link)
            else:
                if not merge_dir:
                    new_dir_id = self.createDirectory(rdir, link)
                    new_dir_handle = (self.name, new_dir_id)
                else:
                    new_dir_handle = self.client.getDir(rdir).getFileHandle(link)
                for f in os.listdir(lpath):
                    uploadHelper(lpath + '/' + f, new_rpath, new_dir_handle, f)

        uploadHelper(local_path, self.pwd(remote_path), remote_path[-1][0], name)

    def download(self, remote_path, local_path):
        def downloadHelper(rpath, lpath):
            global replace_all
            merge_dir = False
            meta, data = self.client.getData(rpath[-1][0])
            if os.path.exists(lpath):
                if meta[1] and os.path.isdir(lpath):
                    merge_dir = True
                else:
                    if replace_all:
                        replace = True
                    else:
                        replace_all, replace = confirmAlways(
                            'File/directory' + lpath + ' already exists. Replace?')
                    if not replace:
                        return
                    shutil.rmtree(lpath, False)
            if not meta[1]:
                f = open(lpath, 'wb')
                with f:
                    f.write(data)
            else:
                if not merge_dir:
                    os.mkdir(lpath)
                dir = DirectoryFile.unpack(data)
                for f in dir.ls():
                    downloadHelper(self.client.changePath([f], rpath), lpath + '/' + f)
        downloadHelper(remote_path, local_path)


    def walk_path(self, path):
        base_path, path_names = self.convert_to_relative_path(self.path, self.splitPath(path))
        return self.client.changePath(base_path, path_names)

    def walk_path_uncertain_last(self, path):
        base_path, path_names = self.convert_to_relative_path(self.path, self.splitPath(path))
        if len(path_names) > 0:
            one_above_leaf = self.client.changePath(path_names[:-1], self.path)
            remote_path = one_above_leaf
            file_name = path_names[-1]
            if self.client.fileExists(one_above_leaf[-1][0], path_names[-1]):
                leaf = self.client.changePath(path_names[-1:], one_above_leaf)
                if self.client.isDirectory(leaf[-1][0]):
                    remote_path = leaf
                    file_name = None
        else:
            remote_path = base_path
            file_name = None
        return remote_path, file_name

    def convert_to_relative_path(self, base, names):
        if len(names) == 0: return base, names
        if names[0][0] in ['~', '!']:
            owner = self.name if names[0][1:] == '' else names[0][1:]
            file_id = ['~', '!'].index(names[0][0])
            return [((owner, file_id), names[0])], names[1:]
        return base, names

    def rm(self, remote):
        remote_path = self.walk_path(remote)
        if len(remote_path) == 1:
            raise ShellException("Cannot delete this file.")

        self.deleteEntry(remote_path[-2][0], remote_path[-1][1])

    def ul(self, local, remote=''):
        remote_path, file_name = self.walk_path_uncertain_last(remote)
        if file_name is None:
            file_name = os.path.basename(local)

        self.upload(local, remote_path, file_name)

    def dl(self, remote, local=None):
        if local is None:
            local = '.'
        remote_path = self.walk_path(remote)

        while local[-1] == '/':
            local = local[:-1]
        if os.path.isdir(local) and len(remote_path) > 1:
            local += '/' + remote_path[-1][1]
        self.download(remote_path, local)

    def mv(self, src, dst):
        src_path = self.walk_path(src)
        if len(src_path) == 1:
            raise ShellException("Directory is not movable.")
        dst_path, dst_file = self.walk_path_uncertain_last(dst)
        if dst_file is None:
            dst_file = src_path[-1][1]
        self.client.link(dst_path[-1][0], dst_file, self.client.storage.new_file_id())
        self.client.unlink(src_path[-2][0], src_path[-1][1])

    def grant(self, src, user, writeable, name=None):
        src_path = self.walk_path(src)
        if len(src_path) == 1 and name is None:
            raise ShellException("When sharing a root directory, a name under which it is shared must be specified.")
        if name is None:
            name = src_path[-1][1]
        self.client.grant_permission(src_path[-1][0], user, writeable)
        dst_path = self.client.changePath([((user, 1), '!'+user)], self.name)
        self.client.link(dst_path[-1][0], name,src_path[-1][0])