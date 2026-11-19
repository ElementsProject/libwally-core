Miniscript Satisfier
====================

These functions produce non-malleable (or optionally malleable) witness
stacks for a parsed miniscript expression, such as one decoded from a
script by ``ms_descriptor_from_script``.

The satisfier mirrors `rust-miniscript <https://github.com/rust-bitcoin/rust-miniscript>`__'s
``Satisfaction::sat_dissat`` at commit ``1834bc06``.

Satisfier Context
-----------------

.. c:type:: ms_satisfier

   Asset provider passed to :c:func:`ms_satisfy_node`. All function
   pointers may be ``NULL`` if the corresponding asset type is not
   available.

   .. c:member:: bool (*lookup_sig)(...)

      Look up a signature for a public key. Called for ``pk_k``,
      ``pk_h``, ``multi``, and ``multi_a`` fragments. The output buffer
      holds ``EC_SIGNATURE_DER_MAX_LEN`` + 1 bytes (max-DER signature plus
      sighash byte); callbacks must not write more.

   .. c:member:: bool (*lookup_preimage)(...)

      Look up a 32-byte hash preimage. ``hash_type`` is one of
      ``MS_HASH_SHA256``, ``MS_HASH_HASH256``, ``MS_HASH_RIPEMD160``,
      ``MS_HASH_HASH160``.

   .. c:member:: bool (*check_older)(...)

      Return ``true`` if the relative locktime ``lock`` is currently
      satisfied (i.e. the UTXO is old enough).

   .. c:member:: bool (*check_after)(...)

      Return ``true`` if the absolute locktime ``lock`` is currently
      satisfied.

   .. c:member:: void *user_data

      Opaque pointer passed back to each callback.

Functions
---------

.. c:function:: void ms_satisfy_node(const ms_node *node, const ms_satisfier *stfr, bool malleable, ms_satisfaction *sat_out, ms_satisfaction *dissat_out)

   Compute both satisfaction and dissatisfaction for the miniscript
   expression *node*. The keys of the expression must be public keys:
   keys of other kinds are treated as having no signature available.

   The traversal is iterative (post-order), mirroring
   ``rust-miniscript::Satisfaction::sat_dissat``.

   When *malleable* is ``false`` the returned satisfaction is
   non-malleable: a third party cannot replace it with a strictly
   lighter witness. When *malleable* is ``true`` the cheapest witness
   is returned regardless of malleability.

   If an allocation fails, every result computed from the failed
   allocation (including either output) is set to ``MS_WITNESS_OOM``,
   rather than treating the affected sub-expression as impossible and
   returning a different satisfaction.
