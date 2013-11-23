import xmlrpclib

s = xmlrpclib.ServerProxy('http://localhost:8000')
input_var = raw_input("Enter your username: ")
print s.helloworld(input_var)  # Returns 5
#print s.system.listMethods()
