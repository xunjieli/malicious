import os,sys
# use for testing purposes only
root = "/Users/tiam/Dropbox/6.858/project_dummyserver"
def read_file(client_id, owner,fileID, token):
	fullpath = os.path.join(root,owner)
	if not os.path.isdir(fullpath):
		os.mkdir(fullpath)
	fileID = str(fileID)
	try:
		with open(os.path.join(fullpath,fileID+".md"),'r') as f:
			meta = f.read()
			f.close()
		with open(os.path.join(fullpath,fileID+".dat"),'r') as f:
			data = f.read()
			f.close()

		return (meta,data)
	except:
		print "Unexpected error:", sys.exc_info()[0]
		return (None,None)


def read_metadata(client_id, owner,fileID, token):
	fullpath = os.path.join(root,owner)
	if not os.path.isdir(fullpath):
		os.mkdir(fullpath)
	fileID = str(fileID)
	try:
		with open(os.path.join(fullpath,fileID+".md"),'r') as f:
			meta = f.read()
			f.close()
		return meta
	except:
		return None

def upload_file(client_id, fileID,  metadata_file, data_file, token):
	fullpath = os.path.join(root,client_id)
	if not os.path.isdir(fullpath):
		os.mkdir(fullpath)
	fileID = str(fileID)
	try:
		with open(os.path.join(fullpath,str(fileID)+".md"),'w') as f:
			f.write(metadata_file)
			f.close()
		with open(os.path.join(fullpath,str(fileID)+".dat"),'w') as f:
			f.write(data_file)
			f.close()
		return "success"
	except:
		return "something failed"

def modify_metadata(client_id, fileID,  metadata_file, token):
	fullpath = os.path.join(root,client_id)
	if not os.path.isdir(fullpath):
		os.mkdir(fullpath)
	fileID = str(fileID)
	try:
		with open(os.path.join(fullpath,fileID+".md"),'w') as f:
			f.write(metadata_file)
			f.close()
		
		return "success"
	except:
		return "something failed"

def modify_file(client_id,owner, fileID, data_file, token):
	fullpath = os.path.join(root,owner)
	if not os.path.isdir(fullpath):
		os.mkdir(fullpath)
	fileID = str(fileID)
	try:
		with open(os.path.join(fullpath,fileID+".dat"),'w') as f:
			f.write(data_file)
			f.close()
		return "success"
	except:
		return "something failed"

def remove_file(client_id,owner, fileID, token):
	fullpath = os.path.join(root,owner)
	fileID = str(fileID)
	if not os.path.isdir(fullpath):
		os.mkdir(fullpath)
	try:
		os.remove(os.path.join(fullpath,fileID+".md"))
		os.remove(os.path.join(fullpath,fileID+".dat"))
		return "success"
	except:
		return "something failed"


