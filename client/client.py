import xmlrpclib

s = xmlrpclib.ServerProxy('http://localhost:8000')
userid = raw_input("Enter your username: ")
print s.beginAuthenticate(userid)
#print s.system.listMethods()
