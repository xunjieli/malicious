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

def create_file(fileID, userid, metadata, datafile):
    pass

def modify_metadata(fileID, userid, metadata):
    pass

def modify_datafile(fileId, userid, datafile):
    pass

def delete_file(fileID, userid):
    ## remove both metadata and datafile
    pass

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
        if can_read(userid, fileID):
            with open(fname, 'r+') as datafile:
                return datafile.read()
    raise PermissionDeniedException('no read permission to data file requested')

def can_write(userid, fileID):
    fname = userid +"_%d.meta" % fileID
    if not os.path.isfile(fname):
        return False
    else:
        with open(fname, 'r+') as metafile:
            fid, is_folder, fvk, fek, fsk, users = metadata_decode(metafile, None, None, None)
            if users.has_key(userid):
                return users[userid]
    return False

def can_read(userid, fileID):
    fname = userid +"_%d.meta" % fileID
    if not os.path.isfile(fname):
        return False
    else:
        with open(fname, 'r+') as metafile:
            fid, is_folder, fvk, fek, fsk, users = metadata_decode(metafile, None, None, None)
            return users.has_key(userid)
    return False

def can_create(userid, fileID):
    meta = userid +"_%d.meta" % fileID
    data = userid +"_%d.data" % fileID
    return not os.path.isfile(meta) || os.path.isfile(data):

