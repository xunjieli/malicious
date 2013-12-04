cd ..
python -m malicious.public_key_repo.public_key_repo &
echo "Public key repo running at PID: $!"
python -m malicious.server.server &
echo "Server running at PID: $!"
sleep 3
node malicious/rpc_relay/relay.js `python -c 'from malicious.common.global_configs import *; print KEYREPO_RELAY_PORT'` `python -c 'from malicious.common.global_configs import *; print KEYREPO_PORT'` &
echo "Public key repo relay running at PID: $!"
node malicious/rpc_relay/relay.js `python -c 'from malicious.common.global_configs import *; print FILESERVER_RELAY_PORT'` `python -c 'from malicious.common.global_configs import *; print FILESERVER_PORT'` &
echo "Server relay running at PID: $!"