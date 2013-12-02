class ServerFuncs:
    def begin_authenticate(self, client_id):
        # TODO: generate token and persist in local storage
        token = 0 
        return token
    def end_authenticate(self, client_id, token):
        # TODO:
        return true

    def read_file(self, client_id, owner_id, fileID, token):
        if 

    def read_metadata(self, client_id, owner_id, fileID, token):
        pass

    def upload_file(self, client_id, owner_id, fileID, metadata_file, data_file, token):
        pass

    def modify_metadata(self, client_id, owner_id, fileID, metadata_file, token):
        pass

    def modify_file(self, client_id, owner_id, fileID, data_file, token):
        pass

    def remove_file(self, client_id, owner_id, fileID, token):
        pass

