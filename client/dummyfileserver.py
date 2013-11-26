import os
# use for testing purposes only
root = "~/Dropbox/6.858/project_dummyserver"
def read_file(client_id, fileID, token):
	if not os.path.isdir(client_id):
		os.mkdir(client_id)
	try:
		with open(fileID+".md",'r') as f:
			meta = f.read()
			f.close()
		with open(fileID+".dat",'r') as f:
			data = f.read()
			f.close()

		return (meta,data)
	except:
		return None

def read_metadata(client_id, fileID, token):
	if not os.path.isdir(client_id):
		os.mkdir(client_id)
	try:
		with open(fileID+".md",'r') as f:
			meta = f.read()
			f.close()
		return meta
	except:
		return None

def upload_file(client_id, fileID,  metadata_file, data_file, token):
	if not os.path.isdir(client_id):
		os.mkdir(client_id)
	try:
		with open(fileID+".md",'w') as f:
			f.write(metadata_file)
			f.close()
		with open(fileID+".dat",'w') as f:
			f.write(data_file)
			f.close()

		return True
	except:
		return False

def modify_metadata(client_id, fileID,  metadata_file, token):
	if not os.path.isdir(client_id):
		os.mkdir(client_id)
	try:
		with open(fileID+".md",'w') as f:
			f.write(metadata_file)
			f.close()
		
		return True
	except:
		return False

def modify_file(client_id, fileID, data_file, token):
	if not os.path.isdir(client_id):
		os.mkdir(client_id)
	try:
		with open(fileID+".dat",'w') as f:
			f.write(data_file)
			f.close()
		return True
	except:
		return False

def remove_file(client_id, fileID, token):
	if not os.path.isdir(client_id):
		os.mkdir(client_id)
	try:
		os.remove(fileID+".md")
		os.remove(fileID+".dat")
		return True
	except:
		return False


