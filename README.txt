### TODO

  * NIF part.
  * Verify constraints -- add/remove leading zeros as appropriate.
  * Impose message size limit of something like 4-16KB.

### Data types.

  XXX document variables below

### Public-key cryptography.

  crypto_box_keypair() -> {Public_key, Secret_key}.

  crypto_box(Plain_text, Nonce, Public_key, Secret_key) -> Cipher_text.

  crypto_box_open(Cipher_text, Nonce, Public_key, Secret_key) -> {ok, Plain_text} | forged_or_garbled.

  crypto_box_beforenm(Public_key, Secret_key) -> Context.

  crypto_box_afternm(Plain_text, Nonce, Context) -> Cipher_text.

  crypto_box_open_afternm(Cipher_text, Nonce, Context) -> {ok, Plain_text} | forged_or_garbled.

## Scalar multiplication.

  crypto_scalarmult(Integer, Group_p) -> Group_q.

  crypto_scalarmult_base(Integer) -> Group_q.

## Signatures.

  crypto_sign_keypair() -> {Public_key, Secret_key}.

  crypto_sign(Message, Secret_key) -> Signed_msg.

  crypto_sign_open(Signed_msg, Public_key) -> {ok, Verified_msg} | forged_or_garbled.

### Secret-key cryptography.

## Authenticated encryption.

  crypto_secretbox(Plain_text, Nonce, Secret_key) -> Cipher_text.

  crypto_secretbox_open(Cipher_text, Nonce, Secret_key) -> {ok, Plain_text} | forged_or_garbled.

## Encryption.

  crypto_stream(Byte_cnt, Nonce, Secret_key) -> Byte_stream.

  crypto_stream_xor(In_text, Nonce, Secret_key) -> Out_text.

## Message authentication.

  crypto_auth(Message, Secret_key) -> Authenticator.

  crypto_auth_verify(Authenticator, Message, Secret_key) -> authenticated | forged_or_garbled.

## Single-message authentication.

  crypto_onetimeauth(Message, Secret_key) -> Authenticator.

  crypto_onetimeauth_verify(Authenticator, Message, Secret_key) -> authenticated | forged_or_garbled.

### Low-level functions.

## Hashing.

  crypto_hash(Message) -> Hash_bin.

## String comparison.

  crypto_verify_16(Bin_x, Bin_y) -> equal | not_equal.

  crypto_verify_32(Bin_x, Bin_y) -> equal | not_equal.

## Random number generator.

  crypto_random_bytes(Cnt) -> Bytes.
