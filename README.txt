### About.

  This package provides Erlang bindings for 'libsodium', a portable packaging of NaCl
  cryptography library. The bindings are pretty complete, covering all public APIs of
  all chosen primitives through NIF code in 'c_src/salt_nif.c' and supporting Erlang
  modules.

  NaCl provides high-speed cryptographic primitives whose implementations are resilient
  to side-channel attacks by design. The API exposes high-level operations with clear
  security contracts and minimal space for user to introduce undue risks accidentally.

  Most of the crypto is performed directly on scheduler threads without visible side
  effects (aside from allocation of result terms) and without performing any system
  calls. Upper bound on execution latency is imposed indirectly by limiting input
  block sizes throughout.

  This is not considered to be a problematic decision as it is likely that networking
  applications will likewise prefer to limit maximum PDU size, and storage applications
  are likely to operate on blocks of constant size. Fine tuning of the limit may be
  desirable looking forward, current value of 16KB is chosen arbitrarily. Future changes
  should be supported by measurements on relevant CPUs with the target of one reduction
  per operation, or cca 1ms. The author defines "relevant CPUs" as "enteprise class
  amd64 chips".

  Key generation and RNG routines are blocking, or at least potentially blocking, and
  are therefore perfomed on a worker thread via call too 'salt_server'. This means all
  these calls get serialized and incur somewhat higher latency. It is reasonable to
  expect key generation to only be performed at relatively low frequencies. The same
  hopefully applies to random bytes generation.

### References.

  Websites

    * Home of NaCl project: 	http://nacl.cr.yp.to
    * Home of libsodium: 	https://github.com/jedisct1/libsodium
    * Home of Salt: 		https://github.com/freza/salt

  Papers

    "The security impact of a new cryptographic library"
    Daniel J. Bernstein, Tanja Lange, Peter Schwabe
    http://cr.yp.to/highspeed/coolnacl-20120725.pdf

    "Cryptography in NaCl"
    Daniel J. Bernstein
    http://cr.yp.to/highspeed/naclcrypto-20090310.pdf

### Credits and Licensing.

  The original NaCl code was released by Daniel J. Bernstein, Tanja Lange, Peter
  Schwabe and contributors into the public domain.

  Libsodium, by Frank Denis and contributors, is subject to a MIT-style license.

  Salt, by Jachym Holecek, is subject to a 2-clause BSD license.

### Compiling.

  * Install 'libsodium':

    $ git clone git@github.com:jedisct1/libsodium.git
    $ ( cd libsodium && \
	./configure --prefix="/usr/local" --disable-ssp --disable-pie \
                    --disable-silent-rules && \
	make && make check && sudo make install && make clean )

  * Build 'salt', you'll need 'rebar' utility:

    $ git clone git@github.com:freza/salt.git
    $ ( cd salt && rebar clean && rebar compile )

  * To run a simple self-test have a look at '_run' script.

  * The 'salt_test' module is also a good source of simple usage examples.

### TODO

  * Verify current message/block size limit of 16KB corresponds to reasonable latency.
  * Also export BLAKE2b hash function, despite not having "chosen" status.
  * Perform 'libsodium' initialization from worker thread before app startup completes.

### Data types.

  XXX document variables below, pretty obvious what they are, also see include/salt.hrl

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
