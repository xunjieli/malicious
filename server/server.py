from SimpleXMLRPCServer import SimpleXMLRPCServer
from SimpleXMLRPCServer import SimpleXMLRPCRequestHandler
from server_func import ServerFuncs

# Restrict to a particular path.
class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)

# Create server
server = SimpleXMLRPCServer(("localhost", 8000),
                            requestHandler=RequestHandler)
server.register_introspection_functions()

#def helloworld(username):
#    return 'hello %s' % username
#server.register_function(helloworld, 'helloworld')

# Register an instance; all the methods of the instance are
# published as XML-RPC methods (in this case, just 'div').

server.register_instance(MyFuncs())

# Run the server's main loop
server.serve_forever()
