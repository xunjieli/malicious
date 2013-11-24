from public_key_repo_func import MyFuncs
import os

key = 'hhjdfhsjlssflkk'
userid = 'test1'

fun = MyFuncs()
fun.set_public_key(userid, key)
actual_key = fun.get_public_key(userid)
if actual_key != key:
    print "actual key is: %s" % actual_key
    print "expected key is: %s" % key
    print "test failed"
    raise
# clean up

os.remove(userid+'.pkey')
print "test passed"
