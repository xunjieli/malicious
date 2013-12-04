import os
import sys
import socket
import stat
import traceback
import errno
import json
from packing import *

def parse_req(req):
    method, arg_str = unpack_data(req, 2)
    args = unpack_object(arg_str)
    return method, args

def format_req(method, args):
    arg_str = pack_object(args)
    return pack_data(method, arg_str)

def format_resp(resp):
    return pack_object(resp)

def parse_resp(resp):
    return unpack_object(resp)

def recv_block(socket, size):
    buffer = ''
    while len(buffer) < size:
        new_data = socket.recv(size - len(buffer))
        if new_data == '':
            return None
        buffer += new_data
    return buffer

def buffered_readstrings(sock):
    while True:
        try:
            size = recv_block(sock, 4)
            if size is None:
                break
            size = unpack('<I', size)[0]
            data = recv_block(sock, size)
            if data is None:
                break
            yield data
        except IOError as e:
            traceback.print_exc()
            if e.errno == errno.ECONNRESET:
                break

class RpcServer(object):
    def run_sock(self, sock, module):
        lines = buffered_readstrings(sock)
        for req in lines:

            #friendlyify = lambda x: x if len(x)<10 else x[:10]+'...'
            #friendly_args = [friendlyify(str(x)) for x in args]
            #print "Received RPC: %s(%s)" %(method, ', '.join(friendly_args))

            try:
                (method, args) = parse_req(req)
                m = module.__getattribute__('rpc_' + method)
                ret = m(*args)
            except Exception as e:
                traceback.print_exc()
                ret = 2, str(e)

            #print "Sending Response: " + repr(ret)
            data = format_resp(ret)
            sock.sendall(pack('<I', len(data)))
            sock.sendall(data)

    def run_sockpath_fork(self, port, module):

        server = socket.socket()
        server.bind(('0.0.0.0', port))

        server.listen(1)
        while True:
            conn, addr = server.accept()
            pid = os.fork()
            if pid == 0:
                # fork again to avoid zombies
                if os.fork() <= 0:
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    self.run_sock(conn, module)
                    sys.exit(0)
                else:
                    sys.exit(0)
            conn.close()
            os.waitpid(pid, 0)

class RpcClient(object):
    def __init__(self, sock):
        self.sock = sock
        self.lines = buffered_readstrings(sock)

    def call(self, method, *args):

        #friendlyify = lambda x: x if len(x)<10 else x[:10]+'...'
        #friendly_args = [friendlyify(str(x)) for x in args]
        #print "RPC: %s(%s)" %(method, ', '.join(friendly_args))

        data = format_req(method, args)
        self.sock.sendall(pack('<I', len(data)))
        self.sock.sendall(data)
        resp = parse_resp(self.lines.next())
        #print "Response: " + repr(resp)
        return resp

    def close(self):
        self.sock.close()

    ## __enter__ and __exit__ make it possible to use RpcClient()
    ## in a "with" statement, so that it's automatically closed.
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

def client_connect(server, port):
    sock = socket.socket()
    sock.connect((server, port))
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return RpcClient(sock)

