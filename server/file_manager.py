# this module manages file creation
import os
import sys
import common.metadata

class PermissionDeniedException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value_
    __repr__ = __str__

def metafile_name(fileID, userid):
    return userid +"_%d.meta" % fileID

def datafile_name(fileID, userid):
    return userid +"_%d.data" % fileID

def create_file(fileID, userid, metadata, datafile):
    if is_owner(userid, metadata) and not file_exist(fileID, userid):
        with open(metafile_name(fileID, userid), 'w+') as f:
            f.write(metadata)
        with open(datafile_name(fileID, userid), 'w+') as f:
            f.write(datafile)
            return True
    raise PermissionDeniedException()

def modify_metadata(fileID, userid, metadata):
    if is_owner(userid, metadata):
        with open(metafile_name(fileID, userid), 'w+') as f:
            f.write(metadata)
            return True
    raise PermissionDeniedException()

def modify_datafile(fileId, userid, datafile):
    if can_write_datafile(userid, metadata):
        with open(datafile_name(fileID, userid), 'w+') as f:
            f.write(datafile)
            return True
    raise PermissionDeniedException()

def delete_file(fileID, userid):
    ## remove both metadata and datafile
    os.remove(metafile_name(fileID, userid))
    os.remove(datafile_name(fileID, userid))
    return True

def read_metadata(fileID, userid):
    fname = userid +"_%d.meta" % fileID
    if not os.path.isfile(fname):
        raise PermissionDeniedException('trying to read metadata file that does not exist')
    else:
        with open(fname, 'r+') as metafile:
            fid, is_folder, fvk, fek, fsk, users = metadata_decode(metafile, None, None, None)
            if users.has_key(userid):
                return metafile.read()
    raise PermissionDeniedException('no read permission to metadata file requested')

def read_datafile(fileID, userid):
    fname = userid +"_%d.data" % fileID
    if not os.path.isfile(fname):
        raise PermissionDeniedException('trying to read data file that does not exist')
    else:
        if can_read_datafile(userid, fileID):
            with open(fname, 'r+') as datafile:
                return datafile.read()
    raise PermissionDeniedException('no read permission to data file requested')

def can_write_datafile(fileID, userid):
    fname = userid +"_%d.meta" % fileID
    if not os.path.isfile(fname):
        return False
    else:
        with open(fname, 'r+') as metafile:
            fid, is_folder, fvk, fek, fsk, users = metadata_decode(metafile, None, None, None)
            if users.has_key(userid):
                return users[userid]
    return False

def can_read_datafile(fileID, userid):
    fname = userid +"_%d.meta" % fileID
    if not os.path.isfile(fname):
        return False
    else:
        with open(fname, 'r+') as metafile:
            fid, is_folder, fvk, fek, fsk, users = metadata_decode(metafile, None, None, None)
            return users.has_key(userid)
    return False

# returns whether a file with id fileID exists
def file_exist(fileID, userid):
    meta = userid +"_%d.meta" % fileID
    data = userid +"_%d.data" % fileID
    return os.path.isfile(meta) && os.path.isfile(data):

def is_owner(userid, metadata):
    # TODO: confirm with Robin on how metadata exposes this info.
    return True
