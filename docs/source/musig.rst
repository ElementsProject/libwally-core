Musig Functions
===============

.. c:function:: int wally_musig_keyagg_cache_free(struct wally_musig_keyagg_cache *cache)

   
   Free a keyagg_cache.
   
   :param cache: The keyagg_cache to free.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_keyagg_cache_serialize(const struct wally_musig_keyagg_cache *cache, unsigned char *bytes_out, size_t len)

   
   Serialize a keyagg_cache to its raw 197-byte form.
   
   :param cache: The keyagg_cache to serialize.
   :param bytes_out: 197-byte output buffer.
   :param len: Size of ``bytes_out``. Must be `WALLY_MUSIG_KEYAGG_CACHE_LEN`.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_keyagg_cache_parse(const unsigned char *bytes, size_t bytes_len, struct wally_musig_keyagg_cache **output)

   
   Restore a keyagg_cache from its raw 197-byte form.
   
   :param bytes: The 197-byte serialized keyagg_cache.
   :param bytes_len: Length of bytes. Must be WALLY_MUSIG_KEYAGG_CACHE_LEN.
   :param output: Destination for the allocated keyagg_cache.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_secnonce_free(struct wally_musig_secnonce *nonce)

   
   Free a secnonce, securely zeroing it first.
   
   :param nonce: The secnonce to free.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_pubnonce_parse(const unsigned char *bytes, size_t bytes_len, struct wally_musig_pubnonce **output)

   
   Parse a public nonce from its 66-byte serialized form.
   
   :param bytes: The 66-byte serialized pubnonce.
   :param bytes_len: Length of bytes. Must be WALLY_MUSIG_PUBNONCE_LEN.
   :param output: Destination for the allocated pubnonce.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_pubnonce_serialize(const struct wally_musig_pubnonce *nonce, unsigned char *bytes_out, size_t len)

   
   Serialize a public nonce to its 66-byte form.
   
   :param nonce: The pubnonce to serialize.
   :param bytes_out: 66-byte output buffer.
   :param len: Size of ``bytes_out``. Must be `WALLY_MUSIG_PUBNONCE_LEN`.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_pubnonce_free(struct wally_musig_pubnonce *nonce)

   
   Free a pubnonce.
   
   :param nonce: The pubnonce to free.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_aggnonce_parse(const unsigned char *bytes, size_t bytes_len, struct wally_musig_aggnonce **output)

   
   Parse an aggregate nonce from its 66-byte serialized form.
   
   :param bytes: The 66-byte serialized aggnonce.
   :param bytes_len: Length of bytes. Must be WALLY_MUSIG_AGGNONCE_LEN.
   :param output: Destination for the allocated aggnonce.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_aggnonce_serialize(const struct wally_musig_aggnonce *nonce, unsigned char *bytes_out, size_t len)

   
   Serialize an aggregate nonce to its 66-byte form.
   
   :param nonce: The aggnonce to serialize.
   :param bytes_out: 66-byte output buffer.
   :param len: Size of ``bytes_out``. Must be `WALLY_MUSIG_AGGNONCE_LEN`.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_aggnonce_free(struct wally_musig_aggnonce *nonce)

   
   Free an aggnonce.
   
   :param nonce: The aggnonce to free.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_session_free(struct wally_musig_session *session)

   
   Free a session.
   
   :param session: The session to free.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_session_serialize(const struct wally_musig_session *session, unsigned char *bytes_out, size_t len)

   
   Serialize a session to its raw 133-byte form.
   
   :param session: The session to serialize.
   :param bytes_out: 133-byte output buffer.
   :param len: Size of ``bytes_out``. Must be `WALLY_MUSIG_SESSION_LEN`.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_session_parse(const unsigned char *bytes, size_t bytes_len, struct wally_musig_session **output)

   
   Restore a session from its raw 133-byte form.
   
   :param bytes: The 133-byte serialized session.
   :param bytes_len: Length of bytes. Must be WALLY_MUSIG_SESSION_LEN.
   :param output: Destination for the allocated session.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_partial_sig_parse(const unsigned char *bytes, size_t bytes_len, struct wally_musig_partial_sig **output)

   
   Parse a partial signature from its 32-byte serialized form.
   
   :param bytes: The 32-byte serialized partial signature.
   :param bytes_len: Length of bytes. Must be WALLY_MUSIG_PARTIAL_SIG_LEN.
   :param output: Destination for the allocated partial_sig.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_partial_sig_serialize(const struct wally_musig_partial_sig *sig, unsigned char *bytes_out, size_t len)

   
   Serialize a partial signature to its 32-byte form.
   
   :param sig: The partial_sig to serialize.
   :param bytes_out: 32-byte output buffer.
   :param len: Size of ``bytes_out``. Must be `WALLY_MUSIG_PARTIAL_SIG_LEN`.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_partial_sig_free(struct wally_musig_partial_sig *sig)

   
   Free a partial signature.
   
   :param sig: The partial_sig to free.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_pubkey_agg(const unsigned char *pub_keys, size_t pub_keys_len, unsigned char *agg_pk_out, size_t agg_pk_out_len, struct wally_musig_keyagg_cache **cache_out)

   
   Compute the MuSig2 aggregate public key from N individual public keys.
   
   :param pub_keys: Concatenated array of compressed public keys (each EC_PUBLIC_KEY_LEN bytes).
   :param pub_keys_len: Length of pub_keys. Must be a non-zero multiple of EC_PUBLIC_KEY_LEN.
   :param agg_pk_out: 32-byte buffer to receive the x-only aggregate public key. May be NULL.
   :param agg_pk_out_len: Size of ``agg_pk_out``. Must be `EC_XONLY_PUBLIC_KEY_LEN`.
   :param cache_out: Destination for the allocated keyagg_cache (required for signing). May be NULL.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_pubkey_get(const struct wally_musig_keyagg_cache *cache, unsigned char *pub_key_out, size_t pub_key_out_len)

   
   Extract the non-xonly (compressed) aggregate public key from a keyagg_cache.
   
   :param cache: The keyagg_cache produced by wally_musig_pubkey_agg.
   :param pub_key_out: 33-byte buffer to receive the compressed aggregate public key.
   :param pub_key_out_len: Size of ``pub_key_out``. Must be `EC_PUBLIC_KEY_LEN`.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_pubkey_ec_tweak_add(struct wally_musig_keyagg_cache *cache, const unsigned char *tweak, size_t tweak_len, unsigned char *pub_key_out, size_t pub_key_out_len)

   
   Apply BIP-32 plain EC tweaking to an aggregate key via the keyagg_cache.
   
   :param cache: The keyagg_cache to tweak (modified in place).
   :param tweak: 32-byte tweak value.
   :param tweak_len: Length of tweak. Must be 32.
   :param pub_key_out: 33-byte buffer for the tweaked compressed public key. May be NULL.
   :param pub_key_out_len: Size of ``pub_key_out``. Must be `EC_PUBLIC_KEY_LEN`.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_pubkey_xonly_tweak_add(struct wally_musig_keyagg_cache *cache, const unsigned char *tweak, size_t tweak_len, unsigned char *pub_key_out, size_t pub_key_out_len)

   
   Apply BIP-341 x-only tweaking to an aggregate key via the keyagg_cache.
   
   :param cache: The keyagg_cache to tweak (modified in place).
   :param tweak: 32-byte tweak value.
   :param tweak_len: Length of tweak. Must be 32.
   :param pub_key_out: 33-byte buffer for the tweaked compressed public key. May be NULL.
   :param pub_key_out_len: Size of ``pub_key_out``. Must be `EC_PUBLIC_KEY_LEN`.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_pubkey_to_xpub(const unsigned char *agg_pk, size_t agg_pk_len, uint32_t version, struct ext_key **output)

   
   Construct a BIP-32 synthetic extended public key from a MuSig2 aggregate
   x-only public key, as specified by BIP-328.
   
   The chain code is the fixed constant SHA256("MuSig2MuSig2MuSig2"). The
   resulting ext_key has depth=0, child_num=0, and no parent fingerprint.
   Unhardened BIP-32 derivation (bip32_key_from_parent with
   BIP32_FLAG_KEY_PUBLIC) is supported on the output key. Hardened derivation
   is not possible (no private key).
   
   :param agg_pk: 32-byte x-only aggregate public key from wally_musig_pubkey_agg.
   :param agg_pk_len: Must be EC_XONLY_PUBLIC_KEY_LEN (32).
   :param version: BIP-32 version code. Use BIP32_VER_MAIN_PUBLIC or
   BIP32_VER_TEST_PUBLIC.
   :param output: Destination for the allocated ext_key.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_pubkeys_derive_then_agg(const unsigned char *xpubs, size_t xpubs_len, uint32_t child_num, unsigned char *agg_pk_out, size_t agg_pk_out_len, struct wally_musig_keyagg_cache **cache_out)

   
   Derive child key from each xpub at child_num, sort derived pubkeys
   lexicographically (BIP-390), then aggregate.
   
   :param xpubs: Concatenated 78-byte serialized BIP-32 extended public keys.
   :param xpubs_len: Length of xpubs in bytes. Must be a multiple of BIP32_SERIALIZED_LEN and at least 2 * BIP32_SERIALIZED_LEN.
   :param child_num: Unhardened child index to derive (< BIP32_INITIAL_HARDENED_CHILD).
   :param agg_pk_out: Destination for the 32-byte x-only aggregate pubkey, or NULL.
   :param agg_pk_out_len: Size of ``agg_pk_out``. Must be `EC_XONLY_PUBLIC_KEY_LEN`.
   :param cache_out: Destination for the allocated keyagg_cache, or NULL.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_pubkeys_agg_then_derive(const unsigned char *pub_keys, size_t pub_keys_len, uint32_t version, uint32_t child_num, unsigned char *pub_key_out, size_t pub_key_out_len, struct ext_key **child_out)

   
   Aggregate N pubkeys, construct BIP-328 synthetic xpub, then derive child_num.
   
   :param pub_keys: Concatenated 33-byte compressed public keys.
   :param pub_keys_len: Length of pub_keys. Must be a multiple of EC_PUBLIC_KEY_LEN and at least 2 * EC_PUBLIC_KEY_LEN.
   :param version: BIP32_VER_MAIN_PUBLIC or BIP32_VER_TEST_PUBLIC.
   :param child_num: Unhardened child index to derive.
   :param pub_key_out: Destination for the 33-byte compressed child pubkey, or NULL.
   :param pub_key_out_len: Size of ``pub_key_out``. Must be `EC_PUBLIC_KEY_LEN`.
   :param child_out: Destination for the allocated child ext_key, or NULL.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_nonce_gen(const unsigned char *session_secrand32, size_t session_secrand_len, const unsigned char *seckey, size_t seckey_len, const unsigned char *pubkey33, size_t pubkey_len, const struct wally_musig_keyagg_cache *keyagg_cache, const unsigned char *msg32, size_t msg_len, const unsigned char *extra_input32, size_t extra_len, struct wally_musig_secnonce **secnonce_out, struct wally_musig_pubnonce **pubnonce_out)

   
   Generate a MuSig2 secret/public nonce pair.
   
   :param session_secrand32: 32-byte unique random session ID. MUST NOT be reused.
   :param session_secrand_len: Must be 32.
   :param seckey: 32-byte secret key of the signer (optional, can be NULL).
   :param seckey_len: Must be 32 if seckey is non-NULL, 0 otherwise.
   :param pubkey33: 33-byte compressed public key of this signer (required).
   :param pubkey_len: Must be EC_PUBLIC_KEY_LEN (33).
   :param keyagg_cache: keyagg_cache from wally_musig_pubkey_agg (optional, can be NULL).
   :param msg32: 32-byte message to be signed, if known (optional, can be NULL).
   :param msg_len: Must be 32 if msg32 is non-NULL, 0 otherwise.
   :param extra_input32: 32-byte extra entropy input (optional, can be NULL).
   :param extra_len: Must be 32 if extra_input32 is non-NULL, 0 otherwise.
   :param secnonce_out: Destination for the allocated secret nonce. Must be kept secret.
   :param pubnonce_out: Destination for the allocated public nonce to send to cosigners.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_nonce_gen_counter(uint64_t counter, const unsigned char *seckey, size_t seckey_len, const unsigned char *pubkey33, size_t pubkey_len, const struct wally_musig_keyagg_cache *keyagg_cache, const unsigned char *msg32, size_t msg_len, const unsigned char *extra_input32, size_t extra_len, struct wally_musig_secnonce **secnonce_out, struct wally_musig_pubnonce **pubnonce_out)

   
   Generate a MuSig2 secret/public nonce pair using a counter-based session ID.
   
   This variant is intended for hardware wallets or deterministic signers that
   cannot generate random session IDs. The uint64_t counter is serialized as an
   8-byte little-endian value, zero-padded to 32 bytes, and used as the
   session_id32. Per BIP-327, seckey MUST be provided when using a counter.
   
   :param counter: Monotonically increasing counter. MUST NOT be reused with the same seckey.
   :param seckey: 32-byte secret key of the signer (REQUIRED for counter mode).
   :param seckey_len: Must be 32.
   :param pubkey33: 33-byte compressed public key of this signer (required).
   :param pubkey_len: Must be EC_PUBLIC_KEY_LEN (33).
   :param keyagg_cache: keyagg_cache from wally_musig_pubkey_agg (optional, can be NULL).
   :param msg32: 32-byte message to be signed, if known (optional, can be NULL).
   :param msg_len: Must be 32 if msg32 is non-NULL, 0 otherwise.
   :param extra_input32: 32-byte extra entropy input (optional, can be NULL).
   :param extra_len: Must be 32 if extra_input32 is non-NULL, 0 otherwise.
   :param secnonce_out: Destination for the allocated secret nonce. Must be kept secret.
   :param pubnonce_out: Destination for the allocated public nonce to send to cosigners.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_nonce_agg(const unsigned char *pubnonces, size_t pubnonces_len, size_t n_pubnonces, struct wally_musig_aggnonce **aggnonce_out)

   
   Aggregate N serialized public nonces into a single aggregate nonce.
   
   :param pubnonces: Flat array of serialized pubnonces (each WALLY_MUSIG_PUBNONCE_LEN bytes).
   :param pubnonces_len: Total byte length. Must equal n_pubnonces * WALLY_MUSIG_PUBNONCE_LEN.
   :param n_pubnonces: Number of pubnonces. Must be >= 2.
   :param aggnonce_out: Destination for the allocated aggregate nonce.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_nonce_process(const struct wally_musig_aggnonce *aggnonce, const unsigned char *msg32, size_t msg32_len, const struct wally_musig_keyagg_cache *cache, const unsigned char *adaptor, size_t adaptor_len, struct wally_musig_session **session_out)

   
   Process the aggregate nonce and message to create a signing session.
   
   Must be called by every participant after nonce aggregation and before signing.
   
   :param aggnonce: The aggregate nonce from wally_musig_nonce_agg.
   :param msg32: The 32-byte message to sign.
   :param msg32_len: Must be 32.
   :param cache: The keyagg_cache from wally_musig_pubkey_agg (and optional tweaks).
   :param adaptor: Optional 33-byte compressed adaptor public key (can be NULL).
   :param adaptor_len: Must be EC_PUBLIC_KEY_LEN if adaptor is non-NULL, 0 otherwise.
   :param session_out: Destination for the allocated session.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_partial_sign(struct wally_musig_secnonce *secnonce, const unsigned char *seckey, size_t seckey_len, const struct wally_musig_keyagg_cache *cache, const struct wally_musig_session *session, struct wally_musig_partial_sig **partial_sig_out)

   
   Produce a partial signature for this participant.
   
   WARNING: The secnonce is irrevocably zeroed whenever secp256k1_musig_partial_sign
   is reached (i.e., when WALLY_OK or WALLY_ERROR is returned). Input validation
   failures (WALLY_EINVAL) do not consume the secnonce. Never attempt to sign
   twice with the same secnonce.
   
   :param secnonce: The secret nonce from wally_musig_nonce_gen (zeroed after use).
   :param seckey: The 32-byte secret key of this signer.
   :param seckey_len: Must be 32.
   :param cache: The keyagg_cache from wally_musig_pubkey_agg.
   :param session: The session from wally_musig_nonce_process.
   :param partial_sig_out: Destination for the allocated partial signature.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_partial_sig_verify(const struct wally_musig_partial_sig *sig, const struct wally_musig_pubnonce *pubnonce, const unsigned char *pubkey, size_t pubkey_len, const struct wally_musig_keyagg_cache *cache, const struct wally_musig_session *session)

   
   Verify a partial signature from one participant.
   
   Returns WALLY_OK if valid, WALLY_ERROR if the signature is invalid,
   WALLY_EINVAL for bad arguments.
   
   :param sig: The partial signature to verify.
   :param pubnonce: The signer's public nonce (from round 1).
   :param pubkey: The signer's 33-byte compressed public key.
   :param pubkey_len: Must be EC_PUBLIC_KEY_LEN (33).
   :param cache: The keyagg_cache from wally_musig_pubkey_agg.
   :param session: The session from wally_musig_nonce_process.

   :return: See :ref:`error-codes`


.. c:function:: int wally_musig_partial_sig_agg(const unsigned char *partial_sigs, size_t partial_sigs_len, size_t n_sigs, const struct wally_musig_session *session, unsigned char *sig64_out, size_t sig64_out_len)

   
   Aggregate N partial signatures into a final 64-byte BIP-340 Schnorr signature.
   
   :param partial_sigs: Flat array of serialized partial signatures
   (each WALLY_MUSIG_PARTIAL_SIG_LEN bytes).
   :param partial_sigs_len: Total byte length. Must equal n_sigs * WALLY_MUSIG_PARTIAL_SIG_LEN.
   :param n_sigs: Number of partial signatures. Must be >= 2.
   :param session: The session from wally_musig_nonce_process.
   :param sig64_out: 64-byte buffer to receive the final Schnorr signature.
   :param sig64_out_len: Size of ``sig64_out``. Must be `EC_SIGNATURE_LEN`.

   :return: See :ref:`error-codes`


 
Musig Constants
---------------

.. c:macro:: WALLY_MUSIG_PUBNONCE_LEN
 
    Sizes of serialized MuSig2 objects

.. c:macro:: WALLY_MUSIG_AGGNONCE_LEN
 
    

.. c:macro:: WALLY_MUSIG_PARTIAL_SIG_LEN
 
    

.. c:macro:: WALLY_MUSIG_KEYAGG_CACHE_LEN
 
    Sizes of opaque MuSig2 objects (for buffer allocation)

.. c:macro:: WALLY_MUSIG_SESSION_LEN
 
    

.. c:macro:: WALLY_MUSIG_SECNONCE_LEN
 
    

.. c:macro:: WALLY_MUSIG2_CHAINCODE_LEN
 
    Length of the BIP-328 synthetic chain code (same as BIP-32 chain code)
