class ServerFuncs:
    def begin_authenticate(self, client_id):
        # TODO: generate token and persist in local storage
        token = 0 
        return token
    def end_authenticate(self, client_id, token):
        # TODO:
        return true

    def read_file(self, client_id, owner_id, fileID, token):
        '''
            return (metadata file, data file)
        '''
        # TODO: check token
        try:
            meta = file_manager.read_metadata(fileID, client_id, owner_id)
            data = file_manager.read_datafile(fileID, client_id, owner_id)
            return meta, data
        except:
            print "Unexpected error read_file"
            return (None, None) 

    def read_metadata(self, client_id, owner_id, fileID, token):
        '''
            return metafile
        '''
         # TODO: check token
        try:
            return file_manager.read_metadata(fileID, client_id, owner_id)
        except:
            print "Unexpected error read_metafile"
            return None

    def upload_file(self, client_id, fileID, metadata_file, data_file, token):
        '''
            return "Success" or "Fail"
        '''
         # TODO: check token
        try:
            file_manager.create_file(fileID, client_id, metadata_file,
datafile)
            return "Success"
        except:
            print "Unexpected error read_metafile"
            return "Fail"

    def modify_metadata(self, client_id, owner_id, fileID, metadata_file, token):
        '''
            return "Success" or "Fail"
        '''
         # TODO: check token
        try:
            file_manager.modify_metadata(fileID, client_id, metadata_file)
            return "Success"
        except:
            print "Unexpected error read_metafile"
            return "Fail"


    def modify_file(self, client_id, owner_id, fileID, data_file, token):
        '''
            return "Success" or "Fail"
        '''
         # TODO: check token
        try:
            file_manager.modify_datafile(fileID, client_id, data_file)
            return "Success"
        except:
            print "Unexpected error read_metafile"
            return "Fail"

    def remove_file(self, client_id, owner_id, fileID, token):
        # TODO: check token
        if file_manager.modify_datafile(fileID, client_id, data_file):
            return "Success"
        return "Fail"

