import wallycore as wally
import os

rho = os.urandom(32)
priv_key = os.urandom(32)
message_hash = os.urandom(32)
pub_key = wally.ec_public_key_from_private_key(priv_key)

# start-step-1
host_commitment = wally.ak_host_commit_from_bytes(rho, wally.EC_FLAG_ECDSA)
# end-step-1

# start-step-2
signer_commitment = wally.ak_signer_commit_from_bytes(priv_key, message_hash, host_commitment, wally.EC_FLAG_ECDSA)
# end-step-2

# start-step-4
signature = wally.ak_sig_from_bytes(priv_key, message_hash, rho, wally.EC_FLAG_ECDSA)
# end-step-4

# start-step-5
wally.ak_verify(pub_key, message_hash, rho, signer_commitment, wally.EC_FLAG_ECDSA, signature)
# end-step-5
