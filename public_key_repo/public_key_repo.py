from SimpleXMLRPCServer import SimpleXMLRPCServer
from SimpleXMLRPCServer import SimpleXMLRPCRequestHandler
from public_key_repo_func import RepoFuncs

"""
A trusted public key distribution server.
"""
# Restrict to a particular path.
class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)

# Create server
public_key_repo_server = SimpleXMLRPCServer(("localhost", 8008),
                            requestHandler=RequestHandler)
public_key_repo_server.register_introspection_functions()

public_key_repo_server.register_instance(RepoFuncs())

# Run the server's main loop
public_key_repo_server.serve_forever()
