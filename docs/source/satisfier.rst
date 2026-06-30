Miniscript Satisfier
====================

These functions produce non-malleable (or optionally malleable) witness
stacks for a miniscript expression encoded as an ``ms_node`` AST.

The satisfier mirrors `rust-miniscript <https://github.com/rust-bitcoin/rust-miniscript>`__'s
``Satisfaction::sat_dissat`` at commit ``1834bc06``.

Satisfier Context
-----------------

.. c:type:: ms_satisfier

   Asset provider passed to :c:func:`satisfy_node`. All function
   pointers may be ``NULL`` if the corresponding asset type is not
   available.

   .. c:member:: bool (*lookup_sig)(...)

      Look up a signature for a public key. Called for ``pk_k``,
      ``pk_h``, ``multi``, and ``multi_a`` fragments.

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

   .. c:member:: const unsigned char *leaf_hash

      32-byte taproot leaf hash used for Schnorr signatures. Set to
      ``NULL`` for segwit v0 scripts.

   .. c:member:: void *user_data

      Opaque pointer passed back to each callback.

Functions
---------

.. c:function:: void satisfy_node(const ms_node *node, const ms_satisfier *stfr, bool malleable, ms_satisfaction *sat_out, ms_satisfaction *dissat_out)

   Compute both satisfaction and dissatisfaction for the miniscript
   subtree rooted at *node*.

   The traversal is iterative (post-order), mirroring
   ``rust-miniscript::Satisfaction::sat_dissat``.

   When *malleable* is ``false`` (the default for PSBT finalization)
   the returned satisfaction is non-malleable: a third party cannot
   replace it with a strictly lighter witness. When *malleable* is
   ``true`` the cheapest witness is returned regardless of
   malleability.

   On allocation failure, both outputs are set to
   ``MS_WITNESS_IMPOSSIBLE``.

   Individual leaf terminals (``pk_k``, ``pk_h``, hash fragments,
   timelocks, ``multi``, ``multi_a``) return ``MS_WITNESS_UNAVAILABLE``
   until the corresponding handler phase lands.
