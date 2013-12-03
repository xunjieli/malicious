# this module manages file creation
import os
import sys
from ..common import metadata

class PermissionDeniedException(Exception):
    def __init__(self, value=None):
        self.value = value
    def __str__(self):
        return repr(self.value)
    __repr__ = __str__

def metafile_name(fileID, owner_id):
    return owner_id +"_%d.meta" % fileID

def datafile_name(fileID, owner_id):
    return owner_id +"_%d.data" % fileID

def create_file(fileID, client_id, metafile, datafile):
    try:
        if is_owner(client_id, metafile) and not file_exist(fileID, client_id):
            with open(metafile_name(fileID, client_id), 'w+') as f:
                f.write(metafile)
            with open(datafile_name(fileID, client_id), 'w+') as f:
                f.write(datafile)
            return True
    except:
        raise PermissionDeniedException()

def modify_metadata(fileID, client_id, metafile):
    # owner_id = client_id
    if is_owner(client_id, metafile):
        with open(metafile_name(fileID, client_id), 'w+') as f:
            f.write(metafile)
            return True
    raise PermissionDeniedException()

def modify_datafile(fileID, client_id, owner_id, datafile):
    if can_write_datafile(fileID, client_id, owner_id):
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
            if client_id == owner_id:
                return metafile.read()
            content = metafile.read()
            users = metadata.extract_users_from_metadata(content)
            if users.has_key(client_id):
                return content
    raise PermissionDeniedException('no read permission to metadata file requested')

def read_datafile(fileID, client_id, owner_id):
    fname = owner_id +"_%d.data" % fileID
    if not os.path.isfile(fname):
        raise PermissionDeniedException('trying to read data file that does not exist')
    else:
        if can_read_datafile(fileID, client_id, owner_id):
            with open(fname, 'r+') as datafile:
                return datafile.read()
    raise PermissionDeniedException('no read permission to data file requested')

def can_write_datafile(fileID, client_id, owner_id):
    if client_id == owner_id:
        return True

    fname = owner_id +"_%d.meta" % fileID
    if not os.path.isfile(fname):
        return False
    else:
        with open(fname, 'r+') as metafile:
            metafile = metafile.read()
            users = metadata.extract_users_from_metadata(metafile)
            if users.has_key(client_id):
                return users[client_id]
    return False

def can_read_datafile(fileID, client_id, owner_id):
    if client_id == owner_id:
        return True
    ## otherwise check access control list
    fname = metafile_name(fileID, owner_id)
    if not os.path.isfile(fname):
        return False
    else:
        with open(fname, 'r+') as metafile:
            users = metadata.extract_users_from_metadata(metafile.read())
            return users.has_key(client_id)
    return False

# returns whether a file with id fileID exists
def file_exist(fileID, owner_id):
    meta = metafile_name(fileID, owner_id)
    data = datafile_name(fileID, owner_id)
    return os.path.isfile(meta) and os.path.isfile(data)

def is_owner(client_id, metafile):
    owner_id = metadata.extract_owner_from_metadata(metafile)
    return client_id == owner_id
