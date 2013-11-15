/*
 * Copyright (c) 2013 Jachym Holecek <freza@circlewave.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define DEBUG 0
#if DEBUG == 1
#include <sys/uio.h>
#include <unistd.h>
#endif

#include <crypto_box.h>
#include <crypto_scalarmult_curve25519.h> 	/* XXXjh crypto_scalarmult.h missing */
#include <crypto_sign.h>
#include <crypto_secretbox.h>
#include <crypto_stream.h>
#include <crypto_auth.h>
#include <crypto_onetimeauth.h>
#include <crypto_hash.h>
#include <crypto_verify_16.h>
#include <crypto_verify_32.h>
#include <randombytes.h>

/* XXXjh crypto_scalarmult.h missing */
#define crypto_scalarmult_SCALARBYTES 	crypto_scalarmult_curve25519_SCALARBYTES
#define crypto_scalarmult_BYTES 	crypto_scalarmult_curve25519_BYTES
#define crypto_scalarmult_base		crypto_scalarmult_curve25519_base
#define crypto_scalarmult		crypto_scalarmult_curve25519

#include <erl_nif.h>

/*
 * Type name normalization, utility macros.
 */

typedef unsigned int 		uint_t;
typedef unsigned long 		ulong_t;
typedef ErlNifEnv 		nif_heap_t;
typedef ERL_NIF_TERM 		nif_term_t;
typedef ErlNifFunc 		nif_func_t;
typedef ErlNifMutex 		nif_lock_t;
typedef ErlNifCond 		nif_cond_t;
typedef ErlNifResourceType 	nif_type_t;
typedef ErlNifBinary 		nif_bin_t;
typedef ErlNifTid 		nif_tid_t;
typedef ErlNifPid 		nif_pid_t;

/* Version tag on all internal data structures. */
#define SALT_VSN(maj, min, rev) 	(((maj) << 16) | ((min) << 8) | (rev))

/* Restrict processing latency by imposing payload size limit. */
#define SALT_MAX_MESSAGE_SIZE 		(16*1024)
/* XXX Measure how long crypto_[secret]box[_open] take for this size, roughly? */
/* XXX We want these calls to be equivalent to the default 1 reduction charged per NIF call */

/*
 * Internal data structures.
 */

struct salt_pcb {
	uint32_t 		sc_vsn; 		/* Version tag for code upgrades. Must be first. */
	nif_tid_t 		sc_thread; 		/* Thread for blocking operations. */

	nif_lock_t 		*sc_lock; 		/* Protect the following fields. */
	nif_cond_t 		*sc_cond; 		/* Worker thread turnstile. */
	struct salt_msg 	*sc_req_first; 		/* Blocking request queue head. */
	struct salt_msg 	**sc_req_lastp; 	/* Blocking request queue tail, last req_next. */
	uint_t 			sc_req_npend; 		/* Blocking request queue length. */

	volatile bool 		sc_exit_flag; 		/* Termination request from GC callback. */
};

struct salt_msg {
	struct salt_msg 	*msg_next;
	nif_heap_t 		*msg_heap;
	uint_t 			msg_type; 		/* SALT_DESC_${Type} */
	nif_pid_t 		msg_from;
	nif_term_t 		msg_mref;
	nif_term_t 		msg_reply; 		/* Response tuple. */
	uint_t 			msg_aux; 		/* Auxiliary data, used by RANDOMBYTES_REQ. */
};

#define SALT_MSG_BOXKEYPAIR_REQ		1
#define SALT_MSG_SIGNKEYPAIR_REQ 	2
#define SALT_MSG_RANDOMBYTES_REQ 	3

/*
 * Globals.
 */

static nif_type_t 		*salt_pcb_type = NULL;

static const uint8_t 		salt_secretbox_zerobytes[crypto_secretbox_ZEROBYTES] = {0,}; 		/* C99 */
static const uint8_t 		salt_secretbox_boxzerobytes[crypto_secretbox_BOXZEROBYTES] = {0,}; 	/* C99 */
static const uint8_t 		salt_box_boxzerobytes[crypto_box_BOXZEROBYTES] = {0,}; 			/* C99 */
static const uint8_t 		salt_box_zerobytes[crypto_box_ZEROBYTES] = {0,}; 			/* C99 */

/* Slightly more readable this way. Variable 'hp' always calling process' heap. */
#define BADARG 			enif_make_badarg(hp)

/*
 * Forward decls.
 */

static nif_term_t salt_enqueue_req(nif_heap_t *, struct salt_pcb *, nif_pid_t, nif_term_t, uint_t, uint_t);
static void *salt_worker_loop(void *);
static void salt_handle_req(struct salt_pcb *, struct salt_msg *);
static void salt_reply_keypair(struct salt_msg *, nif_bin_t *, nif_bin_t *);
static void salt_reply_bytes(struct salt_msg *, nif_bin_t *);
static void salt_reply_error(struct salt_msg *, const char *);

/*
 * Exported functions.
 */

static nif_term_t
start(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	struct salt_pcb 	*sc;
	nif_cond_t 		*cv;
	nif_lock_t 		*lk;
	nif_term_t 		pcb;

	if (argc != 0)
		return (BADARG);

	/* Create thread control block, pass ownership to Erlang. */
	assert(salt_pcb_type != NULL);
	sc = enif_alloc_resource(salt_pcb_type, sizeof(*sc));
	if (sc == NULL)
		goto fail_0;

	cv = enif_cond_create("lots_pcb_cv");
	if (cv == NULL)
		goto fail_1;

	lk = enif_mutex_create("lots_pcb_lock");
	if (lk == NULL)
		goto fail_2;

	sc->sc_vsn = SALT_VSN(1, 0, 0);
	sc->sc_lock = lk;
	sc->sc_cond = cv;
	sc->sc_req_first = NULL;
	sc->sc_req_lastp = &sc->sc_req_first;
	sc->sc_req_npend = 0;
	sc->sc_exit_flag = false;

	if (enif_thread_create("salt_thread", &sc->sc_thread, salt_worker_loop, sc, NULL) != 0)
		goto fail_3;

	pcb = enif_make_resource(hp, sc);
	enif_release_resource(sc);

	return (pcb);

	/* Failure handling. */
 fail_3:
	enif_mutex_destroy(lk);
 fail_2:
	enif_cond_destroy(cv);
 fail_1:
	enif_release_resource(sc);
 fail_0:
	return (BADARG);
}

static nif_term_t
salt_box_keypair(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_box_keypair(Pcb, From_pid, From_ref) -> enqueued | congested | exiting. */
	struct salt_pcb 	*sc;
	nif_pid_t 		pid;
	nif_term_t 		ref;

	if (argc != 3)
		return (BADARG);

	/* Unpack arguments, check types. */
	if (! enif_get_resource(hp, argv[0], salt_pcb_type, (void **)&sc))
		return (BADARG);

	if (! enif_get_local_pid(hp, argv[1], &pid))
		return (BADARG);

	if (! enif_is_ref(hp, argv[2]))
		return (BADARG);
	ref = argv[2];

	return (salt_enqueue_req(hp, sc, pid, ref, SALT_MSG_BOXKEYPAIR_REQ, 0));
}

static nif_term_t
salt_box(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_box(Plain_text, Nonce, Public_key, Secret_key) -> Cipher_text. */
	nif_bin_t 		pt;
	nif_bin_t 		nc;
	nif_bin_t 		pk;
	nif_bin_t 		sk;
	nif_bin_t 		ct;
	nif_term_t 		raw;
	nif_term_t 		sub;

	if (argc != 4)
		return (BADARG);

	/* Unpack arguments ensuring they're suitably typed. */
	if (! enif_inspect_iolist_as_binary(hp, argv[0], &pt))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[1], &nc))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[2], &pk))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[3], &sk))
		return (BADARG);

	/* Check constraints on size and zero prefixing. */
	if (pt.size < crypto_box_ZEROBYTES || pt.size > SALT_MAX_MESSAGE_SIZE)
		return (BADARG);
	if (memcmp((const void *)pt.data, &salt_box_zerobytes[0], crypto_box_ZEROBYTES) != 0)
		return (BADARG);

	if (nc.size != crypto_box_NONCEBYTES)
		return (BADARG);

	if (pk.size != crypto_box_PUBLICKEYBYTES)
		return (BADARG);

	if (sk.size != crypto_box_SECRETKEYBYTES)
		return (BADARG);

	/* Allocate space for cipher text. NB: Passing ENOMEM as BADARG. */
	if (! enif_alloc_binary(pt.size, &ct))
		return (BADARG);

	/* Perform the crypto, strip leading zeros. */
	(void)crypto_box(ct.data, pt.data, pt.size, nc.data, pk.data, sk.data);

	raw = enif_make_binary(hp, &ct);
	sub = enif_make_sub_binary(hp, raw, crypto_box_BOXZEROBYTES, ct.size - crypto_box_BOXZEROBYTES);

	return (sub);
}

static nif_term_t
salt_box_open(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_box_open(Cipher_text, Nonce, Public_key, Secret_key) -> {ok, Plain_text} | forged_or_garbled. */
	nif_bin_t 		pt;
	nif_bin_t 		nc;
	nif_bin_t 		pk;
	nif_bin_t 		sk;
	nif_bin_t 		ct;
	nif_term_t 		raw;
	nif_term_t 		sub;
	nif_term_t 		tag;

	if (argc != 4)
		return (BADARG);

	/* Unpack arguments ensuring they're suitably typed. */
	if (! enif_inspect_iolist_as_binary(hp, argv[0], &ct))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[1], &nc))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[2], &pk))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[3], &sk))
		return (BADARG);

	/* Check constraints on size and zero prefixing. */
	if (ct.size < crypto_box_BOXZEROBYTES || ct.size > SALT_MAX_MESSAGE_SIZE)
		return (BADARG);
	if (memcmp((const void *)ct.data, &salt_box_boxzerobytes[0], crypto_box_BOXZEROBYTES) != 0)
		return (BADARG);

	if (nc.size != crypto_box_NONCEBYTES)
		return (BADARG);

	if (pk.size != crypto_box_PUBLICKEYBYTES)
		return (BADARG);

	if (sk.size != crypto_box_SECRETKEYBYTES)
		return (BADARG);

	/* Allocate space for plain text. NB: Passing ENOMEM as BADARG. */
	if (! enif_alloc_binary(ct.size, &pt))
		return (BADARG);

	/* Perform the crypto, strip leading zeros and return rest if authentic. */
	if (crypto_box_open(pt.data, ct.data, ct.size, nc.data, pk.data, sk.data) != 0) {
		enif_release_binary(&pt);

		return (enif_make_atom(hp, "forged_or_garbled"));
	}

	raw = enif_make_binary(hp, &pt);
	sub = enif_make_sub_binary(hp, raw, crypto_box_ZEROBYTES, pt.size - crypto_box_ZEROBYTES);
	tag = enif_make_atom(hp, "ok");

	return (enif_make_tuple2(hp, tag, sub));
}

static nif_term_t
salt_box_beforenm(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_box_beforenm(Public_key, Secret_key) -> Context. */
	nif_bin_t 		pk;
	nif_bin_t 		sk;
	nif_bin_t 		bn;

	if (argc != 2)
		return (BADARG);

	/* Unpack arguments ensuring they're suitably typed. */
	if (! enif_inspect_binary(hp, argv[0], &pk))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[1], &sk))
		return (BADARG);

	/* Check size constraints. */
	if (pk.size != crypto_box_PUBLICKEYBYTES)
		return (BADARG);

	if (sk.size != crypto_box_SECRETKEYBYTES)
		return (BADARG);

	/* Allocate space for precomputed context. NB: Passing ENOMEM as BADARG. */
	if (! enif_alloc_binary(crypto_box_BEFORENMBYTES, &bn))
		return (BADARG);

	(void)crypto_box_beforenm(bn.data, pk.data, sk.data);
	return (enif_make_binary(hp, &bn));
}

static nif_term_t
salt_box_afternm(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_box_afternm(Plain_text, Nonce, Context) -> Cipher_text. */
	nif_bin_t 		pt;
	nif_bin_t 		nc;
	nif_bin_t 		bn;
	nif_bin_t 		ct;
	nif_term_t 		raw;
	nif_term_t 		sub;

	if (argc != 3)
		return (BADARG);

	/* Unpack arguments ensuring they're suitably typed. */
	if (! enif_inspect_iolist_as_binary(hp, argv[0], &pt))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[1], &nc))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[2], &bn))
		return (BADARG);

	/* Check constraints on size and zero prefixing. */
	if (pt.size < crypto_box_ZEROBYTES || pt.size > SALT_MAX_MESSAGE_SIZE)
		return (BADARG);
	if (memcmp((const void *)pt.data, &salt_box_zerobytes[0], crypto_box_ZEROBYTES) != 0)
		return (BADARG);

	if (nc.size != crypto_box_NONCEBYTES)
		return (BADARG);

	if (bn.size != crypto_box_BEFORENMBYTES)
		return (BADARG);

	/* Allocate space for precomputed context. NB: Passing ENOMEM as BADARG. */
	if (! enif_alloc_binary(pt.size, &ct))
		return (BADARG);

	/* Perform the crypto, strip leading zeros. */
	(void)crypto_box_afternm(ct.data, pt.data, pt.size, nc.data, bn.data);

	raw = enif_make_binary(hp, &ct);
	sub = enif_make_sub_binary(hp, raw, crypto_box_BOXZEROBYTES, ct.size - crypto_box_BOXZEROBYTES);

	return (sub);
}

static nif_term_t
salt_box_open_afternm(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_box_open_afternm(Cipher_text, Nonce, Context) -> {ok, Plain_text} | forged_or_garbled. */
	nif_bin_t 		ct;
	nif_bin_t 		nc;
	nif_bin_t 		bn;
	nif_bin_t 		pt;
	nif_term_t 		raw;
	nif_term_t 		sub;
	nif_term_t 		tag;

	if (argc != 3)
		return (BADARG);

	/* Unpack arguments ensuring they're suitably typed. */
	if (! enif_inspect_iolist_as_binary(hp, argv[0], &ct))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[1], &nc))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[2], &bn))
		return (BADARG);

	/* Check constraints on size and zero prefixing. */
	if (ct.size < crypto_box_BOXZEROBYTES || ct.size > SALT_MAX_MESSAGE_SIZE)
		return (BADARG);
	if (memcmp((const void *)ct.data, &salt_box_boxzerobytes[0], crypto_box_BOXZEROBYTES) != 0)
		return (BADARG);

	if (nc.size != crypto_box_NONCEBYTES)
		return (BADARG);

	if (bn.size != crypto_box_BEFORENMBYTES)
		return (BADARG);

	/* Allocate space for plain text. NB: Passing ENOMEM as BADARG. */
	if (! enif_alloc_binary(ct.size, &pt))
		return (BADARG);

	/* Perform the crypto, strip leading zeros and return rest if authentic. */
	if (crypto_box_open_afternm(pt.data, ct.data, ct.size, nc.data, bn.data) != 0) {
		enif_release_binary(&pt);

		return (enif_make_atom(hp, "forged_or_garbled"));
	}

	raw = enif_make_binary(hp, &pt);
	sub = enif_make_sub_binary(hp, raw, crypto_box_ZEROBYTES, pt.size - crypto_box_ZEROBYTES);
	tag = enif_make_atom(hp, "ok");

	return (enif_make_tuple2(hp, tag, sub));
}

static nif_term_t
salt_scalarmult(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_scalarmult(Integer, Group_p) -> Group_q. */
	nif_bin_t 		n;
	nif_bin_t 		p;
	nif_bin_t 		q;

	if (argc != 2)
		return (BADARG);

	/* Unpack arguments ensuring they're suitably typed. */
	if (! enif_inspect_binary(hp, argv[0], &n))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[1], &p))
		return (BADARG);

	/* Check constraints on size. */
	if (n.size != crypto_scalarmult_SCALARBYTES)
		return (BADARG);

	if (p.size != crypto_scalarmult_BYTES)
		return (BADARG);

	/* Allocate space for plain text. NB: Passing ENOMEM as BADARG. */
	if (! enif_alloc_binary(crypto_scalarmult_BYTES, &q))
		return (BADARG);
	
	crypto_scalarmult(q.data, n.data, p.data);
	return (enif_make_binary(hp, &q));
}

static nif_term_t
salt_scalarmult_base(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_scalarmult(Integer) -> Group_q. */
	nif_bin_t 		n;
	nif_bin_t 		q;

	if (argc != 1)
		return (BADARG);

	/* Unpack arguments ensuring they're suitably typed. */
	if (! enif_inspect_binary(hp, argv[0], &n))
		return (BADARG);

	/* Check constraints on size. */
	if (n.size != crypto_scalarmult_SCALARBYTES)
		return (BADARG);

	/* Allocate space for plain text. NB: Passing ENOMEM as BADARG. */
	if (! enif_alloc_binary(crypto_scalarmult_BYTES, &q))
		return (BADARG);
	
	crypto_scalarmult_base(q.data, n.data);
	return (enif_make_binary(hp, &q));
}

static nif_term_t
salt_sign_keypair(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_sign_keypair(Pcb, From_pid, From_ref) -> enqueued | congested | exiting. */
	struct salt_pcb 	*sc;
	nif_pid_t 		pid;
	nif_term_t 		ref;

	if (argc != 3)
		return (BADARG);

	/* Unpack arguments, check types. */
	if (! enif_get_resource(hp, argv[0], salt_pcb_type, (void **)&sc))
		return (BADARG);

	if (! enif_get_local_pid(hp, argv[1], &pid))
		return (BADARG);

	if (! enif_is_ref(hp, argv[2]))
		return (BADARG);
	ref = argv[2];

	return (salt_enqueue_req(hp, sc, pid, ref, SALT_MSG_SIGNKEYPAIR_REQ, 0));
}

static nif_term_t
salt_sign(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_sign(Message, Secret_key) -> Signed_msg. */
	unsigned long long 	len;
	nif_bin_t 		pm;
	nif_bin_t 		sk;
	nif_bin_t 		sm;
	nif_term_t 		raw;

	if (argc != 2)
		return (BADARG);

	/* Unpack arguments ensuring they're suitably typed. */
	if (! enif_inspect_iolist_as_binary(hp, argv[0], &pm))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[1], &sk))
		return (BADARG);

	/* Check constraints on size. */
	if (pm.size < 1 || pm.size > SALT_MAX_MESSAGE_SIZE)
		return (BADARG);

	if (sk.size != crypto_sign_SECRETKEYBYTES)
		return (BADARG);

	/* Perform the crypto, potentially adjust signed message size. */
	if (! enif_alloc_binary(pm.size + crypto_sign_BYTES, &sm))
		return (BADARG);

	(void)crypto_sign(sm.data, &len, pm.data, pm.size, sk.data);
	raw = enif_make_binary(hp, &sm);

	if (len != sm.size)
		return (enif_make_sub_binary(hp, raw, 0, len));
	else
		return (raw);
}

static nif_term_t
salt_sign_open(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_sign_open(Signed_msg, Public_key) -> {ok, Verified_msg} | forged_or_garbled. */
	unsigned long long 	len;
	nif_bin_t 		sm;
	nif_bin_t 		pk;
	nif_bin_t 		pm;
	nif_term_t 		raw;
	nif_term_t 		sub;
	nif_term_t 		tag;

	if (argc != 2)
		return (BADARG);

	/* Unpack arguments ensuring they're suitably typed. */
	if (! enif_inspect_iolist_as_binary(hp, argv[0], &sm))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[1], &pk))
		return (BADARG);

	/* Check constraints on size. */
	if (sm.size < 1 || sm.size > SALT_MAX_MESSAGE_SIZE)
		return (BADARG);

	if (pk.size != crypto_sign_PUBLICKEYBYTES)
		return (BADARG);

	/* Perform the crypto, potentially adjust signed message size. */
	if (! enif_alloc_binary(sm.size + crypto_sign_BYTES, &pm))
		return (BADARG);

	if (crypto_sign_open(pm.data, &len, sm.data, sm.size, pk.data) != 0) {
		enif_release_binary(&pm);

		return (enif_make_atom(hp, "forged_or_garbled"));
	}
	raw = enif_make_binary(hp, &pm);
	tag = enif_make_atom(hp, "ok");

	if (len != sm.size)
		sub = enif_make_sub_binary(hp, raw, 0, len);
	else
		sub = raw;
	return (enif_make_tuple2(hp, tag, sub));
}

static nif_term_t
salt_secretbox(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_secretbox(Plain_text, Nonce, Secret_key) -> Cipher_text. */
	nif_bin_t 		pt;
	nif_bin_t 		nc;
	nif_bin_t 		sk;
	nif_bin_t 		ct;
	nif_term_t 		raw;
	nif_term_t 		sub;

	if (argc != 3)
		return (BADARG);

	/* Unpack arguments ensuring they're suitably typed. */
	if (! enif_inspect_iolist_as_binary(hp, argv[0], &pt))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[1], &nc))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[2], &sk))
		return (BADARG);

	/* Check constraints on size and zero prefixing. */
	if (pt.size < crypto_secretbox_ZEROBYTES || pt.size > SALT_MAX_MESSAGE_SIZE)
		return (BADARG);
	if (memcmp((const void *)pt.data, &salt_secretbox_zerobytes[0], crypto_secretbox_ZEROBYTES) != 0)
		return (BADARG);

	if (nc.size != crypto_secretbox_NONCEBYTES)
		return (BADARG);

	if (sk.size != crypto_secretbox_KEYBYTES)
		return (BADARG);

	/* Allocate space for cipher text. NB: Passing ENOMEM as BADARG. */
	if (! enif_alloc_binary(pt.size, &ct))
		return (BADARG);

	/* Perform the crypto, strip leading zeros. */
	(void)crypto_secretbox(ct.data, pt.data, pt.size, nc.data, sk.data);

	raw = enif_make_binary(hp, &ct);
	sub = enif_make_sub_binary(hp, raw, crypto_secretbox_BOXZEROBYTES, ct.size - crypto_secretbox_BOXZEROBYTES);

	return (sub);
}

static nif_term_t
salt_secretbox_open(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_secretbox_open(Cipher_text, Nonce, Secret_key) -> {ok, Plain_text} | forged_or_garbled. */
	nif_bin_t 		ct;
	nif_bin_t 		nc;
	nif_bin_t 		sk;
	nif_bin_t 		pt;
	nif_term_t 		raw;
	nif_term_t 		sub;
	nif_term_t 		tag;

	if (argc != 3)
		return (BADARG);

	/* Unpack arguments ensuring they're suitably typed. */
	if (! enif_inspect_iolist_as_binary(hp, argv[0], &ct))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[1], &nc))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[2], &sk))
		return (BADARG);

	/* Check constraints on size and zero prefixing. */
	if (ct.size < crypto_secretbox_BOXZEROBYTES || ct.size > SALT_MAX_MESSAGE_SIZE)
		return (BADARG);
	if (memcmp((const void *)ct.data, &salt_secretbox_boxzerobytes[0], crypto_secretbox_BOXZEROBYTES) != 0)
		return (BADARG);

	if (nc.size != crypto_secretbox_NONCEBYTES)
		return (BADARG);

	if (sk.size != crypto_secretbox_KEYBYTES)
		return (BADARG);

	/* Allocate space for plain text. NB: Passing ENOMEM as BADARG. */
	if (! enif_alloc_binary(ct.size, &pt))
		return (BADARG);

	/* Perform the crypto, strip leading zeros. */
	if (crypto_secretbox_open(pt.data, ct.data, ct.size, nc.data, sk.data) != 0) {
		enif_release_binary(&pt);

		return (enif_make_atom(hp, "forged_or_garbled"));
	}

	raw = enif_make_binary(hp, &pt);
	sub = enif_make_sub_binary(hp, raw, crypto_secretbox_ZEROBYTES, ct.size - crypto_secretbox_ZEROBYTES);
	tag = enif_make_atom(hp, "ok");

	return (enif_make_tuple2(hp, tag, sub));
}

static nif_term_t
salt_stream(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_stream(Byte_cnt, Nonce, Secret_key) -> Byte_stream. */
	nif_bin_t 		nc;
	nif_bin_t 		sk;
	nif_bin_t 		bs;
	uint_t 			cnt;

	if (argc != 3)
		return (BADARG);

	/* Unpack arguments ensuring they're suitably typed. */
	if (! enif_get_uint(hp, argv[0], &cnt))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[1], &nc))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[2], &sk))
		return (BADARG);

	/* Check constraints on size. */
	if (cnt < 1 || cnt > SALT_MAX_MESSAGE_SIZE)
		return (BADARG);

	if (nc.size != crypto_secretbox_NONCEBYTES)
		return (BADARG);

	if (sk.size != crypto_secretbox_KEYBYTES)
		return (BADARG);

	/* Allocate space for byte stream. NB: Passing ENOMEM as BADARG. */
	if (! enif_alloc_binary(cnt, &bs))
		return (BADARG);

	(void)crypto_stream(bs.data, bs.size, nc.data, sk.data);
	return (enif_make_binary(hp, &bs));
}

static nif_term_t
salt_stream_xor(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_stream_xor(In_text, Nonce, Secret_key) -> Out_text. */
	nif_bin_t 		it;
	nif_bin_t 		nc;
	nif_bin_t 		sk;
	nif_bin_t 		ot;

	if (argc != 3)
		return (BADARG);

	/* Unpack arguments ensuring they're suitably typed. */
	if (! enif_inspect_binary(hp, argv[0], &it))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[1], &nc))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[2], &sk))
		return (BADARG);

	/* Check constraints on size. */
	if (it.size < 1 || it.size > SALT_MAX_MESSAGE_SIZE)
		return (BADARG);

	if (nc.size != crypto_stream_NONCEBYTES)
		return (BADARG);

	if (sk.size != crypto_stream_KEYBYTES)
		return (BADARG);

	/* Allocate space for output byte stream. NB: Passing ENOMEM as BADARG. */
	if (! enif_alloc_binary(it.size, &ot))
		return (BADARG);

	(void)crypto_stream_xor(ot.data, it.data, it.size, nc.data, sk.data);
	return (enif_make_binary(hp, &ot));
}

static nif_term_t
salt_auth(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_auth(Message, Secret_key) -> Authenticator. */
	nif_bin_t 		ms;
	nif_bin_t 		sk;
	nif_bin_t 		au;

	if (argc != 2)
		return (BADARG);

	/* Unpack arguments ensuring they're suitably typed. */
	if (! enif_inspect_iolist_as_binary(hp, argv[0], &ms))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[1], &sk))
		return (BADARG);

	/* Check constraints on size. */
	if (ms.size < 1 || ms.size > SALT_MAX_MESSAGE_SIZE)
		return (BADARG);

	if (sk.size != crypto_auth_KEYBYTES)
		return (BADARG);

	/* Allocate space for authenticator. NB: Passing ENOMEM as BADARG. */
	if (! enif_alloc_binary(crypto_auth_BYTES, &au))
		return (BADARG);

	(void)crypto_auth(au.data, ms.data, ms.size, sk.data);
	return (enif_make_binary(hp, &au));
}

static nif_term_t
salt_auth_verify(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_auth_verify(Authenticator, Message, Secret_key) -> authenticated | forged_or_garbled. */
	nif_bin_t 		au;
	nif_bin_t 		ms;
	nif_bin_t 		sk;

	if (argc != 3)
		return (BADARG);

	/* Unpack arguments ensuring they're suitably typed. */
	if (! enif_inspect_binary(hp, argv[0], &au))
		return (BADARG);

	if (! enif_inspect_iolist_as_binary(hp, argv[1], &ms))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[2], &sk))
		return (BADARG);

	/* Check constraints on size. */
	if (au.size != crypto_auth_BYTES)
		return (BADARG);

	if (ms.size < 1 || ms.size > SALT_MAX_MESSAGE_SIZE)
		return (BADARG);

	if (sk.size != crypto_auth_KEYBYTES)
		return (BADARG);

	/* Perform the crypto. */
	if (crypto_auth_verify(au.data, ms.data, ms.size, sk.data) != 0)
		return (enif_make_atom(hp, "forged_or_garbled"));

	return (enif_make_atom(hp, "authenticated"));
}

static nif_term_t
salt_onetimeauth(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_onetimeauth(Message, Secret_key) -> Authenticator. */
	nif_bin_t 		ms;
	nif_bin_t 		sk;
	nif_bin_t 		au;

	if (argc != 2)
		return (BADARG);

	/* Unpack arguments ensuring they're suitably typed. */
	if (! enif_inspect_iolist_as_binary(hp, argv[0], &ms))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[1], &sk))
		return (BADARG);

	/* Check constraints on size. */
	if (ms.size < 1 || ms.size > SALT_MAX_MESSAGE_SIZE)
		return (BADARG);

	if (sk.size != crypto_onetimeauth_KEYBYTES)
		return (BADARG);

	/* Allocate space for authenticator. NB: Passing ENOMEM as BADARG. */
	if (! enif_alloc_binary(crypto_onetimeauth_BYTES, &au))
		return (BADARG);

	(void)crypto_onetimeauth(au.data, ms.data, ms.size, sk.data);
	return (enif_make_binary(hp, &au));
}

static nif_term_t
salt_onetimeauth_verify(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_onetimeauth_verify(Authenticator, Message, Secret_key) -> authenticated | forged_or_garbled. */
	nif_bin_t 		au;
	nif_bin_t 		ms;
	nif_bin_t 		sk;

	if (argc != 3)
		return (BADARG);

	/* Unpack arguments ensuring they're suitably typed. */
	if (! enif_inspect_binary(hp, argv[0], &au))
		return (BADARG);

	if (! enif_inspect_iolist_as_binary(hp, argv[1], &ms))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[2], &sk))
		return (BADARG);

	/* Check constraints on size. */
	if (au.size != crypto_onetimeauth_BYTES)
		return (BADARG);

	if (ms.size < 1 || ms.size > SALT_MAX_MESSAGE_SIZE)
		return (BADARG);

	if (sk.size != crypto_onetimeauth_KEYBYTES)
		return (BADARG);

	/* Perform the crypto. */
	if (crypto_onetimeauth_verify(au.data, ms.data, ms.size, sk.data) != 0)
		return (enif_make_atom(hp, "forged_or_garbled"));

	return (enif_make_atom(hp, "authenticated"));
}

static nif_term_t
salt_hash(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_hash(Message) -> Hash_bin. */
	nif_bin_t 		ms;
	nif_bin_t 		hs;

	if (argc != 1)
		return (BADARG);

	if (! enif_inspect_iolist_as_binary(hp, argv[0], &ms))
		return (BADARG);

	if (ms.size < 1 || ms.size > SALT_MAX_MESSAGE_SIZE)
		return (BADARG);

	if (! enif_alloc_binary(crypto_hash_BYTES, &hs))
		return (BADARG);

	(void)crypto_hash(hs.data, ms.data, ms.size);
	return (enif_make_binary(hp, &hs));
}

static nif_term_t
salt_verify_16(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_verify_16(Bin_x, Bin_y) -> equal | not_equal. */
	nif_bin_t 		bx;
	nif_bin_t 		by;

	if (argc != 2)
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[0], &bx))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[1], &by))
		return (BADARG);

	if (bx.size != 16 || by.size != 16)
		return (BADARG);

	if (crypto_verify_16(bx.data, by.data) != 0)
		return (enif_make_atom(hp, "not_equal"));

	return (enif_make_atom(hp, "equal"));
}

static nif_term_t
salt_verify_32(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_verify_32(Bin_x, Bin_y) -> equal | not_equal. */
	nif_bin_t 		bx;
	nif_bin_t 		by;

	if (argc != 2)
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[0], &bx))
		return (BADARG);

	if (! enif_inspect_binary(hp, argv[1], &by))
		return (BADARG);

	if (bx.size != 32 || by.size != 32)
		return (BADARG);

	if (crypto_verify_32(bx.data, by.data) != 0)
		return (enif_make_atom(hp, "not_equal"));

	return (enif_make_atom(hp, "equal"));
}

static nif_term_t
salt_random_bytes(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* salt_random_bytes(Pcb, From_pid, From_ref, Cnt) -> enqueued | congested | exiting. */
	struct salt_pcb 	*sc;
	nif_pid_t 		pid;
	nif_term_t 		ref;
	uint_t 			cnt;

	if (argc != 4)
		return (BADARG);

	/* Unpack arguments, check types. */
	if (! enif_get_resource(hp, argv[0], salt_pcb_type, (void **)&sc))
		return (BADARG);

	if (! enif_get_local_pid(hp, argv[1], &pid))
		return (BADARG);

	if (! enif_is_ref(hp, argv[2]))
		return (BADARG);
	ref = argv[2];

	/* Get requested size, make sure it's in bounds. */
	if (! enif_get_uint(hp, argv[3], &cnt))
		return (BADARG);
	if (cnt < 1 || cnt > SALT_MAX_MESSAGE_SIZE)
		return (BADARG);

	return (salt_enqueue_req(hp, sc, pid, ref, SALT_MSG_RANDOMBYTES_REQ, cnt));
}


/*
 * Implementation.
 */

static nif_term_t
salt_enqueue_req(nif_heap_t *hp, struct salt_pcb *sc, nif_pid_t pid, nif_term_t ref, uint_t type, uint_t aux)
{
	struct salt_msg 	*sm;
	const char 		*err;

	/* Prepare async request for worker thread. */
	sm = enif_alloc(sizeof(*sm));
	if (sm == NULL)
		return (BADARG);

	sm->msg_heap = enif_alloc_env();
	assert(sm->msg_heap != NULL);

	sm->msg_next = NULL;
	sm->msg_from = pid; /* struct copy */
	sm->msg_mref = enif_make_copy(sm->msg_heap, ref);
	sm->msg_type = type;
	sm->msg_aux = aux;

	/* Enqueue request checking for failure scenarios. */
	enif_mutex_lock(sc->sc_lock);

	if (sc->sc_req_npend >= 128) {
		err = "congested";
		goto fail;
	}
	if (sc->sc_exit_flag) {
		/* XXX This should not even be possible, no? */
		err = "exiting";
		goto fail;
	}
	*sc->sc_req_lastp = sm;
	sc->sc_req_lastp = &sm->msg_next;
	sc->sc_req_npend += 1;

	enif_cond_signal(sc->sc_cond);
	enif_mutex_unlock(sc->sc_lock);

	return (enif_make_atom(hp, "enqueued"));

	/* Failure treatment. */
 fail:
	enif_mutex_unlock(sc->sc_lock);
	enif_free_env(sm->msg_heap);
	enif_free(sm);

	return (enif_make_atom(hp, err));
}

static void *
salt_worker_loop(void *arg)
{
	struct salt_pcb 	*sc = arg;
	struct salt_msg 	*sm;
	struct salt_msg 	*tmp;

	/* XXX initialization of libsodium */
	/* XXX send readiness indication to owner */

	/* Pick up next batch of work, react promptly to termination requests. */
 loop:
	enif_mutex_lock(sc->sc_lock);
 wait:
	if (sc->sc_exit_flag) {
		enif_mutex_unlock(sc->sc_lock);
		return (NULL);
	}
	if (sc->sc_req_first == NULL) {
		enif_cond_wait(sc->sc_cond, sc->sc_lock);
		goto wait;
	}

	sm = sc->sc_req_first;
	sc->sc_req_first = NULL;
	sc->sc_req_lastp = &sc->sc_req_first;
	sc->sc_req_npend = 0;
	
	enif_mutex_unlock(sc->sc_lock);

	/* Handle all requests, release when done. */
 next:
	salt_handle_req(sc, sm);
	tmp = sm->msg_next;
	
	enif_free_env(sm->msg_heap);
	enif_free(sm);

	if (tmp == NULL)
		goto loop;

	sm = tmp;
	goto next;
}

static void
salt_handle_req(struct salt_pcb *sc, struct salt_msg *sm)
{
	const char 		*err;
	nif_bin_t 		pk;
	nif_bin_t 		sk;
	nif_bin_t 		rb;

	/* Preemptive termination check via dirty read. */
	if (sc->sc_exit_flag) {
		err = "exiting";
		goto fail_0;
	}

	/* Perform know request or reject unknown (forwards compatibility). */
	switch (sm->msg_type) {
	case SALT_MSG_BOXKEYPAIR_REQ:
		if (! enif_alloc_binary(crypto_box_PUBLICKEYBYTES, &pk)) {
			err = "enomem";
			goto fail_0;
		}
		if (! enif_alloc_binary(crypto_box_SECRETKEYBYTES, &sk)) {
			err = "enomem";
			goto fail_1;
		}
		
		crypto_box_keypair(pk.data, sk.data);
		salt_reply_keypair(sm, &pk, &sk);
		break;

	case SALT_MSG_SIGNKEYPAIR_REQ:
		if (! enif_alloc_binary(crypto_sign_PUBLICKEYBYTES, &pk)) {
			err = "enomem";
			goto fail_0;
		}
		if (! enif_alloc_binary(crypto_sign_SECRETKEYBYTES, &sk)) {
			err = "enomem";
			goto fail_1;
		}
		
		crypto_sign_keypair(pk.data, sk.data);
		salt_reply_keypair(sm, &pk, &sk);
		break;

	case SALT_MSG_RANDOMBYTES_REQ:
		if (! enif_alloc_binary(sm->msg_aux, &rb)) {
			err = "enomem";
			goto fail_0;
		}

		/* XXX not sure I want to rely on native RNG, but not sure either if salsa20 randombytes is kosher */
		/* XXX probably best to write one that uses dev random but also encrypts output with stream cipher? */
		randombytes_buf(rb.data, rb.size);
		salt_reply_bytes(sm, &rb);
		break;

	default:
		err = "unsupported";
		goto fail_0;
	}

	return ;

	/* Failure treatment. */
 fail_1:
	enif_release_binary(&pk);
 fail_0:
	salt_reply_error(sm, err);
	return ;
}

static void
salt_reply_keypair(struct salt_msg *sm, nif_bin_t *pk, nif_bin_t *sk)
{
	nif_heap_t 		*hp = sm->msg_heap;
	nif_term_t 		tag;
	nif_term_t 		val;
	nif_term_t 		res;
	nif_term_t 		msg;
	nif_term_t 		pb;
	nif_term_t 		sb;

	/* From_pid ! {Mref, {ok, {Pk, Sk}}} */
	pb = enif_make_binary(hp, pk);
	sb = enif_make_binary(hp, sk);

	tag = enif_make_atom(hp, "ok");
	val = enif_make_tuple2(hp, pb, sb);
	res = enif_make_tuple2(hp, tag, val);
	msg = enif_make_tuple2(hp, sm->msg_mref, res);

	(void)enif_send(NULL, &sm->msg_from, hp, msg);
}

static void
salt_reply_bytes(struct salt_msg *sm, nif_bin_t *bs)
{
	nif_heap_t 		*hp = sm->msg_heap;
	nif_term_t 		tag;
	nif_term_t 		res;
	nif_term_t 		msg;
	nif_term_t 		bb;

	/* From_pid ! {Mref, {ok, Bytes}} */
	bb = enif_make_binary(hp, bs);

	tag = enif_make_atom(hp, "ok");
	res = enif_make_tuple2(hp, tag, bb);
	msg = enif_make_tuple2(hp, sm->msg_mref, res);

	(void)enif_send(NULL, &sm->msg_from, hp, msg);
}

static void
salt_reply_error(struct salt_msg *sm, const char *why)
{
	nif_heap_t 		*hp = sm->msg_heap;
	nif_term_t 		tag;
	nif_term_t 		rsn;
	nif_term_t 		res;
	nif_term_t 		msg;

	/* From_pid ! {Mref, {error, Rsn}} */
	tag = enif_make_atom(hp, "error");
	rsn = enif_make_atom(hp, why);
	res = enif_make_tuple2(hp, tag, rsn);
	msg = enif_make_tuple2(hp, sm->msg_mref, res);

	(void)enif_send(NULL, &sm->msg_from, hp, msg);
}

#if DEBUG == 1
static void
print_bytes(const char *tag, nif_bin_t *buf)
{
	static const char 	*alphabet = "0123456789ABCDEF";
	uint_t 			cnt = (3 + 2*buf->size);
	uint8_t 		str[cnt];
	struct iovec  		iov[2];
	int 			i;

	/* XXX inlined UNCONST and ARRAYCOUNT... */
	iov[0].iov_base = (void *)((ulong_t)(const void *)tag);
	iov[0].iov_len = strlen(tag);
	iov[1].iov_base = str;
	iov[1].iov_len = cnt;
	
	str[0] = ' ';
	str[1] = '0';
	str[2] = 'x';

	for (i = 0; i <= buf->size; i++) {
		str[2*i + 3] = alphabet[buf->data[i] >> 4];
		str[2*i + 4] = alphabet[buf->data[i] % 16];
	}

	(void)writev(STDERR_FILENO, (const void *)&iov[0], (sizeof(iov)/sizeof(iov[0])));
}
#endif /* DEBUG */

/*
 * ERTS interface.
 */

static void
salt_pcb_free(nif_heap_t *hp, void *obj)
{
	struct salt_pcb 	*sc = obj;
	struct salt_msg 	*sm;
	struct salt_msg 	*tmp;

	/* Signal termination request, join worker thread, release all resources. */
	enif_mutex_lock(sc->sc_lock);
	sc->sc_exit_flag = true;
	enif_cond_signal(sc->sc_cond);
	enif_mutex_unlock(sc->sc_lock);

	(void)enif_thread_join(sc->sc_thread, NULL);

	sm = sc->sc_req_first;
 loop:
	if (sm == NULL)
		goto done;
	tmp = sm->msg_next;

	enif_free_env(sm->msg_heap);
	enif_free(sm);

	sm = tmp;
	goto loop;
 done:
	enif_mutex_destroy(sc->sc_lock);
	enif_cond_destroy(sc->sc_cond);

	/* Done, PCB itself released by ERTS. */
	return ;
}

static int
salt_load(nif_heap_t *hp, void **priv_data, nif_term_t load_info)
{
	int 			flags;

	/* Commit to takeover existing values on code upgrade. */
	flags = (ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER);

	/* Create or inherit PCB type. */
	salt_pcb_type = enif_open_resource_type(hp, NULL, "salt_pcb", salt_pcb_free, flags, NULL);
	if (salt_pcb_type == NULL)
		return (EIO);

	return (0);
}

static nif_func_t salt_exports[] = {
	{"start", 0, start},
	{"salt_box_keypair", 3, salt_box_keypair},
	{"salt_box", 4, salt_box},
	{"salt_box_open", 4, salt_box_open},
	{"salt_box_beforenm", 2, salt_box_beforenm},
	{"salt_box_afternm", 3, salt_box_afternm},
	{"salt_box_open_afternm", 3, salt_box_open_afternm},
	{"salt_scalarmult", 2, salt_scalarmult},
	{"salt_scalarmult_base", 1, salt_scalarmult_base},
	{"salt_sign_keypair", 3, salt_sign_keypair},
	{"salt_sign", 2, salt_sign},
	{"salt_sign_open", 2, salt_sign_open},
	{"salt_secretbox", 3, salt_secretbox},
	{"salt_secretbox_open", 3, salt_secretbox_open},
	{"salt_stream", 3, salt_stream},
	{"salt_stream_xor", 3, salt_stream_xor},
	{"salt_auth", 2, salt_auth},
	{"salt_auth_verify", 3, salt_auth_verify},
	{"salt_onetimeauth", 2, salt_onetimeauth},
	{"salt_onetimeauth_verify", 3, salt_onetimeauth_verify},
	{"salt_hash", 1, salt_hash},
	{"salt_verify_16", 2, salt_verify_16},
	{"salt_verify_32", 2, salt_verify_32},
	{"salt_random_bytes", 4, salt_random_bytes},
};

ERL_NIF_INIT(salt_nif, salt_exports, salt_load, NULL, NULL, NULL)
