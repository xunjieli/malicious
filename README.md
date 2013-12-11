run test like 

set up the server
<pre>sh launch.sh</pre>

run the client
<pre>python -m malicious.client.malicious</pre>

Functionalities supported are

<pre>
cd <dir>: Change the current directory
ls: List the contents of the current directory
ul <local> <remote>: Recursively upload from local path to remote path
dl <remote> <local>: Recursively download from remote path to local path
rm <remote>: Recursively delete remote path
mv <from> <to>: Move/rename in NeFS
shr <path> <user> <shared name>: Share read permission to a file or directory to a user under a certain name
shw <path> <user> <shared name>: Same as above, except also granting write permission (read permission implied)
unshare <path> <user>: Unshare the file/directory from the user
friend <user>: Set up a shared folder for the user so that the user can now share files with you

</pre>


run tests like:
<pre>python -m malicious.server.file_manager_test</pre>

<pre>python -m malicious.common.metadata_test</pre>
