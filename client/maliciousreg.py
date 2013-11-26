import sys
import dummykeydist
import json
if __name__ == "__main__":
	if len(sys.argv) < 3:
		print "Usage: "+sys.argv[0]+" [username] [privatefile location]"
		sys.exit(1)
	keydist = dummykeydist.dummykeydist()
	credential = {"max_inode":0L,"key":None}
	print "creating encryption key"
	key = keydist.register(sys.argv[1])
	if key is None:
		print "Error registering the user, nothing has been done"
		sys.exit(1)
	credential['key'] = key
	json.dump(credential,open(sys.argv[2],'wb'))
	print "registration succesful"
