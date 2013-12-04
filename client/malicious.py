import sys
import shell2 as shell
import dummykeydist
import dummyfileserver

import fileserver_rpc
import client_db
from ..common import global_configs
from ..public_key_repo.public_key_repo_client import *

from ..common import crypto

client = None
#key_repo = xmlrpclib.ServerProxy('http://localhost:8008')
# fileserver = xmlrpclib.ServerProxy('http://localhost:8000')
# keep the test local now so I don't have to run separate process to test this
#key_repo = dummykeydist.dummykeydist()
#fileserver = dummyfileserver
key_repo = PublicKeyRepoStub('localhost', global_configs.KEYREPO_PORT)
fileserver = fileserver_rpc.FileServerRpcStub(fileserver_rpc.FileServerConnector('localhost', global_configs.RELAY_PORT))
db = client_db.ClientDB('client.db')

def register(name, db):
    print "creating encryption keys..."
    MEK = crypto.generate_user_encryption_keypair()
    MSK = crypto.generate_user_signature_keypair()
    print "keys generation successful"

    db.new_user(name, MEK, MSK)
    # upload key to repo
    key_repo.set_public_key(name, MEK[0:2])
    key_repo.set_verify_key(name, MSK[0:2])
    print "registration successful"

    return 0


def getcmd():
    global client
    cmd = raw_input(client.pwd() + ">>")
    return cmd.split(' ')


def execcmd(cmd):
    try:
        if cmd[0] == 'cd':
            if len(cmd) < 2:
                print "usage: cd [remote directory]"
                return
            client.cd(cmd[1])
        elif cmd[0] == 'pwd':
            print client.pwd()
        elif cmd[0] == 'mkdir':
            if len(cmd) < 2:
                print "usage: mkdir [directory name]"
                return
            client.mkdir(cmd[1])
        elif cmd[0] == 'ls':
            for line in client.ls():
                print line
        elif cmd[0] == "ul":
            if len(cmd) < 2:
                print "usage: ul [local source] [optional:remote name]"
                return
            client.ul(*cmd[1:])
        elif cmd[0] == "dl":
            if len(cmd) < 2:
                print "usage: dl [remote name] [optional:local]"
                return
            client.dl(*cmd[1:])
        elif cmd[0] == "mv":
            if len(cmd) < 2:
                print "usage: rename [remote source] [new name]"
                return
            client.mv(cmd[1], cmd[2])
        elif cmd[0] == "shr": # share read access
            if len(cmd) < 3:
                print "usage: shr [remote file] [user] [optional: shared name]"
                return
            client.grant(cmd[1], cmd[2], False, *cmd[3:])
        elif cmd[0] == "shw":
            if len(cmd) < 3:
                print "usage: shw [remote file] [user] [optional: shared name]"
                return
            client.grant(cmd[1], cmd[2], False, *cmd[3:])
        elif cmd[0] == "unshare":
            if len(cmd) < 3:
                print "usage: unshare [remote file] [user1] [user2] [user3] ..."
                return
            #client.share(cmd[1], cmd[2:], 0)
        elif cmd[0] == "rm":
            if len(cmd) < 2:
                print "usage: rm [remote file]"
                return
            client.rm(cmd[1])
        elif cmd[0] == 'debug_see_dir' or cmd[0] == "dsd":
            client.debug_see_dir()
        elif cmd[0] == 'debug_see_credential' or cmd[0] == "dsc":
            client.debug_see_credential()
        else:
            print 'Command not found'
    except shell.ShellException as e:
        print e.value


def run():
    print "Welcome to malicious file sharing system"
    if len(sys.argv) > 2:
        name = sys.argv[1]
        print "Name and password file supplied from command line:"
        print name
    else:
        print "please log in:"
        name = raw_input("username:")
    db.select_user(name)
    while not db.user_exists():
        print "cannot find the user, do you want to register for a new account (y/n)?"
        ans = raw_input()
        if ans == 'y':
            stat = register(name, db)
            if stat:
                print "error while registering for an account, please restart the program"
                sys.exit(1)
        else:
            sys.exit(0)
    global client
    client = shell.MaliciousShell(name, db, fileserver, key_repo)
    client.client.initialize()

    if len(sys.argv) > 3:
        print "Entering script mode"
        scriptfile = open(sys.argv[3], 'r').read()
        cmd = scriptfile.split('\n')
        for i in range(len(cmd)):
            execcmd(cmd[i])
    else:
        cmd = getcmd()
        while cmd[0] != "quit" and cmd[0] != "exit":
            execcmd(cmd)
            cmd = getcmd()

if __name__ == 'main':
    run()