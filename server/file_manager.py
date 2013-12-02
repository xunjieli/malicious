# this module manages file creation
import os
import sys
from ..common import metadata

class PermissionDeniedException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)
    __repr__ = __str__

def metafile_name(fileID, owner_id):
    return owner_id +"_%d.meta" % fileID

def datafile_name(fileID, owner_id):
    return owner_id +"_%d.data" % fileID

def create_file(fileID, owner_id, metadata, datafile):
    # owner_id should be the same as client_id
    if is_owner(owner_id, metadata) and not file_exist(fileID, owner_id):
        with open(metafile_name(fileID, owner_id), 'w+') as f:
            f.write(metadata)
        with open(datafile_name(fileID, owner_id), 'w+') as f:
            f.write(datafile)
            return True
    raise PermissionDeniedException()

def modify_metadata(fileID, client_id, metadata):
    # owner_id = client_id
    if is_owner(client_id, metadata):
        with open(metafile_name(fileID, client_id), 'w+') as f:
            f.write(metadata)
            return True
    raise PermissionDeniedException()

def modify_datafile(fileId, client_id, owner_id, datafile):
    if can_write_datafile(owner_id, metadata):
        with open(datafile_name(fileID, owner_id), 'w+') as f:
            f.write(datafile)
            return True
    raise PermissionDeniedException()

def delete_file(fileID, client_id, owner_id):
    ## remove both metadata and datafile
    if client_id != owner_id:
        return False
    os.remove(metafile_name(fileID, owner_id))
    os.remove(datafile_name(fileID, owner_id))
    return True

def read_metadata(fileID, client_id, owner_id):
    fname = owner_id +"_%d.meta" % fileID
    if not os.path.isfile(fname):
        raise PermissionDeniedException('trying to read metadata file that does not exist')
    else:
        with open(fname, 'r+') as metafile:
            fid, is_folder, fvk, fek, fsk, users = metadata_decode(metafile, None, None, None)
            if users.has_key(owner_id):
                return metafile.read()
    raise PermissionDeniedException('no read permission to metadata file requested')

def read_datafile(fileID, client_id, owner_id):
    fname = owner_id +"_%d.data" % fileID
    if not os.path.isfile(fname):
        raise PermissionDeniedException('trying to read data file that does not exist')
    else:
        if can_read_datafile(owner_id, fileID):
            with open(fname, 'r+') as datafile:
                return datafile.read()
    raise PermissionDeniedException('no read permission to data file requested')

def can_write_datafile(fileID, client_id, owner_id):
    fname = owner_id +"_%d.meta" % fileID
    if not os.path.isfile(fname):
        return False
    else:
        with open(fname, 'r+') as metafile:
            fid, is_folder, fvk, fek, fsk, users = metadata_decode(metafile, None, None, None)
            if users.has_key(owner_id):
                return users[owner_id]
    return False

def can_read_datafile(fileID, client_id, owner_id):
    fname = metafile_name(fileID, owner_id)
    if not os.path.isfile(fname):
        return False
    else:
        with open(fname, 'r+') as metafile:
            fid, is_folder, fvk, fek, fsk, owner_id, users = metadata_decode(metafile, None, None, None)
            return users.has_key(owner_id)
    return False

# returns whether a file with id fileID exists
def file_exist(fileID, owner_id):
    meta = metafile_name(fileID, owner_id)
    data = datafile_name(fileID, owner_id)
    return os.path.isfile(meta) and os.path.isfile(data)

def is_owner(client_id, metadata):
    # TODO: confirm with Robin on how metadata exposes this info.
    return True
