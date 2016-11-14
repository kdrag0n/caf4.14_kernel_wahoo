/*
 * HEH: Hash Encrypt Hash mode
 *
 * Copyright (c) 2016 Google Inc.
 *
 * Authors:
 *	Alex Cope <alexcope@xxxxxxxxxx>
 *	Eric Biggers <ebiggers@xxxxxxxxxx>
 */

/*
 * Hash Encrypt Hash (HEH) is a proposed block cipher mode of operation which
 * extends the strong pseudo-random permutation (SPRP) property of block ciphers
 * (e.g. AES) to arbitrary length input strings.  It uses two keyed invertible
 * hash functions with a layer of ECB encryption applied in-between.  The
 * algorithm is specified by the following Internet Draft:
 *
 *	https://tools.ietf.org/html/draft-cope-heh-00
 *
 * Although HEH can be used as either a regular symmetric cipher or as an AEAD,
 * currently this module only provides it as a symmetric cipher (skcipher).
 * Additionally, only 48-byte keys and 16-byte nonces are supported.
 */

#include <crypto/gf128mul.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/skcipher.h>
#include <crypto/scatterwalk.h>
#include <crypto/skcipher.h>
#include "internal.h"

/*
 * The block size is the size of GF(2^128) elements and also the required block
 * size of the underlying block cipher.
 */
#define HEH_BLOCK_SIZE		16

/* Required key size in bytes */
#define HEH_KEY_SIZE		48
#define HEH_PRF_KEY_OFFSET	16
#define HEH_BLK_KEY_OFFSET	32

/*
 * Macro to get the offset in bytes to the last full block
 * (or equivalently the length of all full blocks excluding the last)
 */
#define HEH_TAIL_OFFSET(len) (((len) - HEH_BLOCK_SIZE) & ~(HEH_BLOCK_SIZE - 1))

struct heh_instance_ctx {
	struct crypto_shash_spawn cmac;
	struct crypto_skcipher_spawn ecb;
};

struct heh_tfm_ctx {
	struct crypto_shash *cmac;
	struct crypto_skcipher *ecb;
	struct gf128mul_4k *tau_key;
};

struct heh_cmac_data {
	u8 nonce[HEH_BLOCK_SIZE];
	__le32 nonce_length;
	__le32 aad_length;
	__le32 message_length;
	__le32 padding;
};

struct heh_req_ctx { /* aligned to alignmask */
	be128 beta1_key;
	be128 beta2_key;
	union {
		struct {
			struct heh_cmac_data data;
			struct shash_desc desc;
			/* + crypto_shash_descsize(cmac) */
		} cmac;
		struct {
			u8 tail[2 * HEH_BLOCK_SIZE];
			int (*crypt)(struct skcipher_request *);
			struct scatterlist tmp_sgl[2];
			struct skcipher_request req;
			/* + crypto_skcipher_reqsize(ecb) */
		} ecb;
	} u;
};

static inline struct heh_req_ctx *heh_req_ctx(struct skcipher_request *req)
{
	unsigned int alignmask = crypto_skcipher_alignmask(
						crypto_skcipher_reqtfm(req));

	return (void *)PTR_ALIGN((u8 *)skcipher_request_ctx(req),
				 alignmask + 1);
}

static inline void async_done(struct crypto_async_request *areq, int err,
			      int (*next_step)(struct skcipher_request *, u32))
{
	struct skcipher_request *req = areq->data;

	if (err)
		goto out;

	err = next_step(req, req->base.flags & ~CRYPTO_TFM_REQ_MAY_SLEEP);
	if (err == -EINPROGRESS ||
	    (err == -EBUSY && (req->base.flags & CRYPTO_TFM_REQ_MAY_BACKLOG)))
		return;
out:
	skcipher_request_complete(req, err);
}

/*
 * Generate the per-message "beta" keys used by the hashing layers of HEH.  The
 * first beta key is the CMAC of the nonce, the additional authenticated data
 * (AAD), and the lengths in bytes of the nonce, AAD, and message.  The nonce
 * and AAD are each zero-padded to the next 16-byte block boundary, and the
 * lengths are serialized as 4-byte little endian integers and zero-padded to
 * the next 16-byte block boundary.  The second beta key is the first one
 * interpreted as an element in GF(2^128) and multiplied by x.
 *
 * Note that because the nonce and AAD may, in general, be variable-length, the
 * key generation must be done by a pseudo-random function (PRF) on
 * variable-length inputs.  CBC-MAC does not satisfy this, as it is only a PRF
 * on fixed-length inputs.  CMAC remedies this flaw.  Including the lengths of
 * the nonce, AAD, and message is also critical to avoid collisions.
 *
 * That being said, this implementation does not yet operate as an AEAD and
 * therefore there is never any AAD, nor are variable-length nonces supported.
 */
static int generate_betas(struct skcipher_request *req,
			  be128 *beta1_key, be128 *beta2_key)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct heh_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct heh_req_ctx *rctx = heh_req_ctx(req);
	struct heh_cmac_data *data = &rctx->u.cmac.data;
	struct shash_desc *desc = &rctx->u.cmac.desc;
	int err;

	BUILD_BUG_ON(sizeof(*data) != HEH_BLOCK_SIZE + 16);
	memcpy(data->nonce, req->iv, HEH_BLOCK_SIZE);
	data->nonce_length = cpu_to_le32(HEH_BLOCK_SIZE);
	data->aad_length = cpu_to_le32(0);
	data->message_length = cpu_to_le32(req->cryptlen);
	data->padding = cpu_to_le32(0);

	desc->tfm = ctx->cmac;
	desc->flags = req->base.flags;

	err = crypto_shash_digest(desc, (const u8 *)data, sizeof(*data),
				  (u8 *)beta1_key);
	if (err)
		return err;

	gf128mul_x_ble(beta2_key, beta1_key);
	return 0;
}

/*
 * Evaluation of a polynomial over GF(2^128) using Horner's rule.  The
 * polynomial is evaluated at 'point'.  The polynomial's coefficients are taken
 * from 'coeffs_sgl' and are for terms with consecutive descending degree ending
 * at degree 1.  'bytes_of_coeffs' is 16 times the number of terms.
 */
static be128 evaluate_polynomial(struct gf128mul_4k *point,
				 struct scatterlist *coeffs_sgl,
				 unsigned int bytes_of_coeffs)
{
	be128 value = {0};
	struct sg_mapping_iter miter;
	unsigned int remaining = bytes_of_coeffs;
	unsigned int needed = 0;

	sg_miter_start(&miter, coeffs_sgl, sg_nents(coeffs_sgl),
		       SG_MITER_FROM_SG | SG_MITER_ATOMIC);
	while (remaining) {
		be128 coeff;
		const u8 *src;
		unsigned int srclen;
		u8 *dst = (u8 *)&value;

		/*
		 * Note: scatterlist elements are not necessarily evenly
		 * divisible into blocks, nor are they necessarily aligned to
		 * __alignof__(be128).
		 */
		sg_miter_next(&miter);

		src = miter.addr;
		srclen = min_t(unsigned int, miter.length, remaining);
		remaining -= srclen;

		if (needed) {
			unsigned int n = min(srclen, needed);
			u8 *pos = dst + (HEH_BLOCK_SIZE - needed);

			needed -= n;
			srclen -= n;

			while (n--)
				*pos++ ^= *src++;

			if (!needed)
				gf128mul_4k_ble(&value, point);
		}

		while (srclen >= HEH_BLOCK_SIZE) {
			memcpy(&coeff, src, HEH_BLOCK_SIZE);
			be128_xor(&value, &value, &coeff);
			gf128mul_4k_ble(&value, point);
			src += HEH_BLOCK_SIZE;
			srclen -= HEH_BLOCK_SIZE;
		}

		if (srclen) {
			needed = HEH_BLOCK_SIZE - srclen;
			do {
				*dst++ ^= *src++;
			} while (--srclen);
		}
	}
	sg_miter_stop(&miter);
	return value;
}

/*
 * Split the message into 16 byte blocks, padding out the last block, and use
 * the blocks as coefficients in the evaluation of a polynomial over GF(2^128)
 * at the secret point 'tau_key'.  For ease of implementing the higher-level
 * heh_hash_inv() function, the constant and degree-1 coefficients are swapped.
 *
 * Mathematically, compute:
 *	t^N * m_0 + ... + t^2 * m_{N-2} + t * m_N + m_{N-1}
 *
 * where:
 *	t is tau_key
 *	N is the number of full blocks in the message
 *	m_i is the i-th full block in the message for i = 0 to N-1 inclusive
 *	m_N is the (possibly empty) partial block of the message padded up to 16
 *		bytes with a 0x01 byte followed by 0x00 bytes
 *
 * Note that when the message length is a multiple of 16, m_N is composed
 * entirely of padding, i.e. 0x0100...00.
 */
static be128 poly_hash(struct crypto_skcipher *tfm, struct scatterlist *sgl,
		       unsigned int len)
{
	struct heh_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);
	unsigned int tail_offset = HEH_TAIL_OFFSET(len);
	unsigned int tail_len = len - tail_offset;
	be128 hash;
	be128 tail[2];

	/* Handle all full blocks except the last */
	hash = evaluate_polynomial(ctx->tau_key, sgl, tail_offset);

	/* Handle the last full block and the partial block */

	scatterwalk_map_and_copy(tail, sgl, tail_offset, tail_len, 0);
	*((u8 *)tail + tail_len) = 0x01;
	memset((u8 *)tail + tail_len + 1, 0, sizeof(tail) - 1 - tail_len);

	be128_xor(&hash, &hash, &tail[1]);
	gf128mul_4k_ble(&hash, ctx->tau_key);
	be128_xor(&hash, &hash, &tail[0]);
	return hash;
}

/*
 * Transform all full blocks except the last.
 * This is used by both the hash and inverse hash phases.
 */
static int heh_tfm_blocks(struct skcipher_request *req,
			  struct scatterlist *src_sgl,
			  struct scatterlist *dst_sgl, unsigned int len,
			  const be128 *hash, const be128 *beta_key)
{
	struct skcipher_walk walk;
	be128 e = *beta_key;
	int err;
	unsigned int nbytes;

	err = skcipher_walk_virt_init(&walk, req, false, src_sgl, dst_sgl, len);
	while ((nbytes = walk.nbytes)) {
		const be128 *src = (be128 *)walk.src.virt.addr;
		be128 *dst = (be128 *)walk.dst.virt.addr;

		do {
			gf128mul_x_ble(&e, &e);
			be128_xor(dst, src, hash);
			be128_xor(dst, dst, &e);
			src++;
			dst++;
		} while ((nbytes -= HEH_BLOCK_SIZE) >= HEH_BLOCK_SIZE);
		err = skcipher_walk_done(&walk, nbytes);
	}
	return err;
}

/*
 * The hash phase of HEH.  Given a message, compute:
 *
 *     (m_0 + H, ..., m_{N-2} + H, H, m_N) + (xb, x^2b, ..., x^{N-1}b, b, 0)
 *
 * where:
 *	N is the number of full blocks in the message
 *	m_i is the i-th full block in the message for i = 0 to N-1 inclusive
 *	m_N is the unpadded partial block, possibly empty
 *	H is the poly_hash() of the message, keyed by tau_key
 *	b is beta_key
 *	x is the element x in our representation of GF(2^128)
 *
 * Note that the partial block remains unchanged, but it does affect the result
 * of poly_hash() and therefore the transformation of all the full blocks.
 */
static int heh_hash(struct skcipher_request *req, const be128 *beta_key)
{
	be128 hash;
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	unsigned int tail_offset = HEH_TAIL_OFFSET(req->cryptlen);
	unsigned int partial_len = req->cryptlen % HEH_BLOCK_SIZE;
	int err;

	/* poly_hash() the full message including the partial block */
	hash = poly_hash(tfm, req->src, req->cryptlen);

	/* Transform all full blocks except the last */
	err = heh_tfm_blocks(req, req->src, req->dst, tail_offset, &hash,
			     beta_key);
	if (err)
		return err;

	/* Set the last full block to hash XOR beta_key */
	be128_xor(&hash, &hash, beta_key);
	scatterwalk_map_and_copy(&hash, req->dst, tail_offset, HEH_BLOCK_SIZE,
				 1);

	/* Copy the partial block if needed */
	if (partial_len != 0 && req->src != req->dst) {
		unsigned int offs = tail_offset + HEH_BLOCK_SIZE;

		scatterwalk_map_and_copy(&hash, req->src, offs, partial_len, 0);
		scatterwalk_map_and_copy(&hash, req->dst, offs, partial_len, 1);
	}
	return 0;
}

/*
 * The inverse hash phase of HEH.  This undoes the result of heh_hash().
 */
static int heh_hash_inv(struct skcipher_request *req, const be128 *beta_key)
{
	be128 hash;
	be128 tmp;
	struct scatterlist tmp_sgl[2];
	struct scatterlist *tail_sgl;
	unsigned int len = req->cryptlen;
	unsigned int tail_offset = HEH_TAIL_OFFSET(len);
	struct scatterlist *sgl = req->dst;
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	int err;

	/*
	 * The last full block was computed as hash XOR beta_key, so XOR it with
	 * beta_key to recover hash.
	 */
	tail_sgl = scatterwalk_ffwd(tmp_sgl, sgl, tail_offset);
	scatterwalk_map_and_copy(&hash, tail_sgl, 0, HEH_BLOCK_SIZE, 0);
	be128_xor(&hash, &hash, beta_key);

	/* Transform all full blocks except the last */
	err = heh_tfm_blocks(req, sgl, sgl, tail_offset, &hash, beta_key);
	if (err)
		return err;

	/*
	 * Recover the last full block.  We know 'hash', i.e. the poly_hash() of
	 * the the original message.  The last full block was the constant term
	 * of the polynomial.  To recover the last full block, temporarily zero
	 * it, compute the poly_hash(), and take the difference from 'hash'.
	 */
	memset(&tmp, 0, sizeof(tmp));
	scatterwalk_map_and_copy(&tmp, tail_sgl, 0, HEH_BLOCK_SIZE, 1);
	tmp = poly_hash(tfm, sgl, len);
	be128_xor(&tmp, &tmp, &hash);
	scatterwalk_map_and_copy(&tmp, tail_sgl, 0, HEH_BLOCK_SIZE, 1);
	return 0;
}

static int heh_hash_inv_step(struct skcipher_request *req, u32 flags)
{
	struct heh_req_ctx *rctx = heh_req_ctx(req);

	return heh_hash_inv(req, &rctx->beta2_key);
}

static void heh_ecb_tail_done(struct crypto_async_request *areq, int err)
{
	return async_done(areq, err, heh_hash_inv_step);
}

static int heh_ecb_tail(struct skcipher_request *req, u32 flags)
{
	struct heh_req_ctx *rctx = heh_req_ctx(req);
	unsigned int partial_len = req->cryptlen % HEH_BLOCK_SIZE;
	struct scatterlist *tail_sgl;
	int err;

	if (partial_len == 0) /* no partial block? */
		goto next_step;

	/*
	 * Extract the already encrypted/decrypted last full block and the not
	 * yet encrypted/decrypted partial block.  The former will be used as a
	 * pad to encrypt/decrypt the partial block.
	 */
	tail_sgl = scatterwalk_ffwd(rctx->u.ecb.tmp_sgl, req->dst,
				    HEH_TAIL_OFFSET(req->cryptlen));
	scatterwalk_map_and_copy(rctx->u.ecb.tail, tail_sgl, 0,
				 HEH_BLOCK_SIZE + partial_len, 0);

	/* Encrypt/decrypt the partial block using the pad */
	crypto_xor(&rctx->u.ecb.tail[HEH_BLOCK_SIZE], rctx->u.ecb.tail,
		   partial_len);
	scatterwalk_map_and_copy(&rctx->u.ecb.tail[HEH_BLOCK_SIZE], tail_sgl,
				 HEH_BLOCK_SIZE, partial_len, 1);

	/* Encrypt/decrypt the last full block again */
	skcipher_request_set_callback(&rctx->u.ecb.req, flags,
				      heh_ecb_tail_done, req);
	skcipher_request_set_crypt(&rctx->u.ecb.req, tail_sgl, tail_sgl,
				   HEH_BLOCK_SIZE, NULL);
	err = rctx->u.ecb.crypt(&rctx->u.ecb.req);
	if (err)
		return err;
next_step:
	return heh_hash_inv_step(req, flags);
}

static void heh_ecb_full_done(struct crypto_async_request *areq, int err)
{
	return async_done(areq, err, heh_ecb_tail);
}

/*
 * The encrypt phase of HEH.  This uses ECB encryption, with special handling
 * for the partial block at the end if any.  The source data is already in
 * req->dst, so the encryption happens in-place.
 *
 * After the encrypt phase we continue on to the inverse hash phase.  The
 * functions calls are chained to support asynchronous ECB algorithms.
 */
static int heh_ecb(struct skcipher_request *req, bool decrypt)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct heh_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct heh_req_ctx *rctx = heh_req_ctx(req);
	struct skcipher_request *ecb_req = &rctx->u.ecb.req;
	unsigned int full_len = HEH_TAIL_OFFSET(req->cryptlen) + HEH_BLOCK_SIZE;

	rctx->u.ecb.crypt = decrypt ? crypto_skcipher_decrypt :
				      crypto_skcipher_encrypt;

	/* Encrypt/decrypt all full blocks */
	skcipher_request_set_tfm(ecb_req, ctx->ecb);
	skcipher_request_set_callback(ecb_req, req->base.flags,
				      heh_ecb_full_done, req);
	skcipher_request_set_crypt(ecb_req, req->dst, req->dst, full_len, NULL);
	return rctx->u.ecb.crypt(ecb_req) ?: heh_ecb_tail(req, req->base.flags);
}

static int heh_crypt(struct skcipher_request *req, bool decrypt)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct heh_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct heh_req_ctx *rctx = heh_req_ctx(req);
	int err;

	/* Inputs must be at least one full block */
	if (req->cryptlen < HEH_BLOCK_SIZE)
		return -EINVAL;

	/* Key must have been set */
	if (!ctx->tau_key)
		return -ENOKEY;

	err = generate_betas(req, &rctx->beta1_key, &rctx->beta2_key);
	if (err)
		return err;

	if (decrypt)
		swap(rctx->beta1_key, rctx->beta2_key);

	err = heh_hash(req, &rctx->beta1_key);
	if (err)
		return err;

	return heh_ecb(req, decrypt);
}

static int heh_encrypt(struct skcipher_request *req)
{
	return heh_crypt(req, false);
}

static int heh_decrypt(struct skcipher_request *req)
{
	return heh_crypt(req, true);
}

static int heh_setkey(struct crypto_skcipher *parent, const u8 *key,
		      unsigned int keylen)
{
	struct heh_tfm_ctx *ctx = crypto_skcipher_ctx(parent);
	struct crypto_shash *cmac = ctx->cmac;
	struct crypto_skcipher *ecb = ctx->ecb;
	const u8 *prf_key, *blk_key;
	int err;

	if (keylen != HEH_KEY_SIZE) {
		crypto_skcipher_set_flags(parent, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}

	prf_key = key + HEH_PRF_KEY_OFFSET;
	blk_key = key + HEH_BLK_KEY_OFFSET;

	/* tau_key */
	if (ctx->tau_key)
		gf128mul_free_4k(ctx->tau_key);
	ctx->tau_key = gf128mul_init_4k_ble((const be128 *)key);
	if (!ctx->tau_key)
		return -ENOMEM;

	/* prf_key */
	crypto_shash_clear_flags(cmac, CRYPTO_TFM_REQ_MASK);
	crypto_shash_set_flags(cmac, crypto_skcipher_get_flags(parent) &
				     CRYPTO_TFM_REQ_MASK);
	err = crypto_shash_setkey(cmac, prf_key, 16);
	crypto_skcipher_set_flags(parent, crypto_shash_get_flags(cmac) &
					  CRYPTO_TFM_RES_MASK);
	if (err)
		return err;

	/* blk_key */
	crypto_skcipher_clear_flags(ecb, CRYPTO_TFM_REQ_MASK);
	crypto_skcipher_set_flags(ecb, crypto_skcipher_get_flags(parent) &
				       CRYPTO_TFM_REQ_MASK);
	err = crypto_skcipher_setkey(ecb, blk_key, 16);
	crypto_skcipher_set_flags(parent, crypto_skcipher_get_flags(ecb) &
					  CRYPTO_TFM_RES_MASK);
	return err;
}

static int heh_init_tfm(struct crypto_skcipher *tfm)
{
	struct skcipher_instance *inst = skcipher_alg_instance(tfm);
	struct heh_instance_ctx *ictx = skcipher_instance_ctx(inst);
	struct heh_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct crypto_shash *cmac;
	struct crypto_skcipher *ecb;
	unsigned int reqsize;
	int err;

	cmac = crypto_spawn_shash(&ictx->cmac);
	if (IS_ERR(cmac))
		return PTR_ERR(cmac);

	ecb = crypto_spawn_skcipher(&ictx->ecb);
	err = PTR_ERR(ecb);
	if (IS_ERR(ecb))
		goto err_free_cmac;

	ctx->cmac = cmac;
	ctx->ecb = ecb;

	reqsize = crypto_skcipher_alignmask(tfm) &
		  ~(crypto_tfm_ctx_alignment() - 1);
	reqsize += max(offsetof(struct heh_req_ctx, u.cmac.desc) +
			sizeof(struct shash_desc) +
			crypto_shash_descsize(cmac),
		       offsetof(struct heh_req_ctx, u.ecb.req) +
			sizeof(struct skcipher_request) +
			crypto_skcipher_reqsize(ecb));
	crypto_skcipher_set_reqsize(tfm, reqsize);
	return 0;

err_free_cmac:
	crypto_free_shash(cmac);
	return err;
}

static void heh_exit_tfm(struct crypto_skcipher *tfm)
{
	struct heh_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);

	gf128mul_free_4k(ctx->tau_key);
	crypto_free_shash(ctx->cmac);
	crypto_free_skcipher(ctx->ecb);
}

static void heh_free_instance(struct skcipher_instance *inst)
{
	struct heh_instance_ctx *ctx = skcipher_instance_ctx(inst);

	crypto_drop_shash(&ctx->cmac);
	crypto_drop_skcipher(&ctx->ecb);
	kfree(inst);
}

/*
 * Create an instance of HEH as a skcipher.
 *
 * This relies on underlying CMAC and ECB algorithms, usually cmac(aes) and
 * ecb(aes).  For performance reasons we support asynchronous ECB algorithms.
 * However, we do not yet support asynchronous CMAC algorithms because CMAC is
 * only used on a small fixed amount of data per request, independent of the
 * request length.  This would change if AEAD or variable-length nonce support
 * were to be exposed.
 */
static int heh_create_common(struct crypto_template *tmpl, struct rtattr **tb,
			     const char *full_name, const char *cmac_name,
			     const char *ecb_name)
{
	struct crypto_attr_type *algt;
	struct skcipher_instance *inst;
	struct heh_instance_ctx *ctx;
	struct shash_alg *cmac;
	struct skcipher_alg *ecb;
	int err;

	algt = crypto_get_attr_type(tb);
	if (IS_ERR(algt))
		return PTR_ERR(algt);

	/* User must be asking for something compatible with skcipher */
	if ((algt->type ^ CRYPTO_ALG_TYPE_SKCIPHER) & algt->mask)
		return -EINVAL;

	/* Allocate the skcipher instance */
	inst = kzalloc(sizeof(*inst) + sizeof(*ctx), GFP_KERNEL);
	if (!inst)
		return -ENOMEM;

	ctx = skcipher_instance_ctx(inst);

	/* Set up the cmac and ecb spawns */

	ctx->cmac.base.inst = skcipher_crypto_instance(inst);
	err = crypto_grab_shash(&ctx->cmac, cmac_name, 0, CRYPTO_ALG_ASYNC);
	if (err)
		goto err_free_inst;
	cmac = crypto_spawn_shash_alg(&ctx->cmac);

	ctx->ecb.base.inst = skcipher_crypto_instance(inst);
	err = crypto_grab_skcipher(&ctx->ecb, ecb_name, 0,
				   crypto_requires_sync(algt->type,
							algt->mask));
	if (err)
		goto err_drop_cmac;
	ecb = crypto_spawn_skcipher_alg(&ctx->ecb);

	/* HEH only supports block ciphers with 16 byte block size */
	err = -EINVAL;
	if (ecb->base.cra_blocksize != HEH_BLOCK_SIZE)
		goto err_drop_ecb;

	/* The underlying "ECB" algorithm must not require an IV */
	err = -EINVAL;
	if (crypto_skcipher_alg_ivsize(ecb) != 0)
		goto err_drop_ecb;

	/* Set the instance names */

	err = -ENAMETOOLONG;
	if (snprintf(inst->alg.base.cra_driver_name, CRYPTO_MAX_ALG_NAME,
		     "heh_base(%s,%s)", cmac->base.cra_driver_name,
		     ecb->base.cra_driver_name) >= CRYPTO_MAX_ALG_NAME)
		goto err_drop_ecb;

	strcpy(inst->alg.base.cra_name, full_name); /* guaranteed to fit */

	/* Finish initializing the instance */

	inst->alg.base.cra_flags = (cmac->base.cra_flags |
				    ecb->base.cra_flags) & CRYPTO_ALG_ASYNC;
	inst->alg.base.cra_blocksize = HEH_BLOCK_SIZE;
	inst->alg.base.cra_ctxsize = sizeof(struct heh_tfm_ctx);
	inst->alg.base.cra_alignmask = ecb->base.cra_alignmask |
					(__alignof__(be128) - 1);
	inst->alg.base.cra_priority = ecb->base.cra_priority;

	inst->alg.ivsize = HEH_BLOCK_SIZE;
	inst->alg.min_keysize = HEH_KEY_SIZE;
	inst->alg.max_keysize = HEH_KEY_SIZE;

	inst->alg.init = heh_init_tfm;
	inst->alg.exit = heh_exit_tfm;
	inst->alg.setkey = heh_setkey;
	inst->alg.encrypt = heh_encrypt;
	inst->alg.decrypt = heh_decrypt;
	inst->free = heh_free_instance;

	/* Register the instance */
	err = skcipher_register_instance(tmpl, inst);
	if (err)
		goto err_drop_ecb;
	return 0;

err_drop_ecb:
	crypto_drop_skcipher(&ctx->ecb);
err_drop_cmac:
	crypto_drop_shash(&ctx->cmac);
err_free_inst:
	kfree(inst);
	return err;
}

static int heh_create(struct crypto_template *tmpl, struct rtattr **tb)
{
	const char *cipher_name;
	char full_name[CRYPTO_MAX_ALG_NAME];
	char cmac_name[CRYPTO_MAX_ALG_NAME];
	char ecb_name[CRYPTO_MAX_ALG_NAME];

	/* Get the name of the requested block cipher (e.g. aes) */
	cipher_name = crypto_attr_alg_name(tb[1]);
	if (IS_ERR(cipher_name))
		return PTR_ERR(cipher_name);

	if (snprintf(full_name, CRYPTO_MAX_ALG_NAME, "heh(%s)", cipher_name) >=
	    CRYPTO_MAX_ALG_NAME)
		return -ENAMETOOLONG;

	if (snprintf(cmac_name, CRYPTO_MAX_ALG_NAME, "cmac(%s)", cipher_name) >=
	    CRYPTO_MAX_ALG_NAME)
		return -ENAMETOOLONG;

	if (snprintf(ecb_name, CRYPTO_MAX_ALG_NAME, "ecb(%s)", cipher_name) >=
	    CRYPTO_MAX_ALG_NAME)
		return -ENAMETOOLONG;

	return heh_create_common(tmpl, tb, full_name, cmac_name, ecb_name);
}

static struct crypto_template heh_tmpl = {
	.name = "heh",
	.create = heh_create,
	.module = THIS_MODULE,
};

static int heh_base_create(struct crypto_template *tmpl, struct rtattr **tb)
{
	char full_name[CRYPTO_MAX_ALG_NAME];
	const char *cmac_name;
	const char *ecb_name;

	cmac_name = crypto_attr_alg_name(tb[1]);
	if (IS_ERR(cmac_name))
		return PTR_ERR(cmac_name);

	ecb_name = crypto_attr_alg_name(tb[2]);
	if (IS_ERR(ecb_name))
		return PTR_ERR(ecb_name);

	if (snprintf(full_name, CRYPTO_MAX_ALG_NAME, "heh_base(%s,%s)",
		     cmac_name, ecb_name) >= CRYPTO_MAX_ALG_NAME)
		return -ENAMETOOLONG;

	return heh_create_common(tmpl, tb, full_name, cmac_name, ecb_name);
}

/*
 * If HEH is instantiated as "heh_base" instead of "heh", then specific
 * implementations of cmac and ecb can be specified instead of just the cipher
 */
static struct crypto_template heh_base_tmpl = {
	.name = "heh_base",
	.create = heh_base_create,
	.module = THIS_MODULE,
};

static int __init heh_module_init(void)
{
	int err;

	err = crypto_register_template(&heh_tmpl);
	if (err)
		return err;

	err = crypto_register_template(&heh_base_tmpl);
	if (err)
		goto out_undo_heh;

	return 0;

out_undo_heh:
	crypto_unregister_template(&heh_tmpl);
	return err;
}

static void __exit heh_module_exit(void)
{
	crypto_unregister_template(&heh_tmpl);
	crypto_unregister_template(&heh_base_tmpl);
}

module_init(heh_module_init);
module_exit(heh_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hash-Encrypt-Hash block cipher mode");
MODULE_ALIAS_CRYPTO("heh");
MODULE_ALIAS_CRYPTO("heh_base");
