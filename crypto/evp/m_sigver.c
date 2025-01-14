/*
 * Copyright 2006-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/ossl_typ.h>

#include "internal/evp_int.h"
#include "internal/eng_int.h"
#include "evp_locl.h"

static int update(EVP_MD_CTX *ctx, const void *data, size_t datalen)
{
    EVPerr(EVP_F_UPDATE, EVP_R_ONLY_ONESHOT_SUPPORTED);
    return 0;
}

static int do_sigver_init(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                          const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey,
                          int ver)
{
    if (ctx->pctx == NULL)
        ctx->pctx = EVP_PKEY_CTX_new(pkey, e);
    if (ctx->pctx == NULL)
        return 0;

    if (!(ctx->pctx->pmeth->flags & EVP_PKEY_FLAG_SIGCTX_CUSTOM)) {

        if (type == NULL) {
            int def_nid;
            if (EVP_PKEY_get_default_digest_nid(pkey, &def_nid) > 0)
                type = EVP_get_digestbynid(def_nid);
        }

        if (type == NULL) {
            EVPerr(EVP_F_DO_SIGVER_INIT, EVP_R_NO_DEFAULT_DIGEST);
            return 0;
        }
    }

    if (ver) {
        if (ctx->pctx->pmeth->verifyctx_init) {
            if (ctx->pctx->pmeth->verifyctx_init(ctx->pctx, ctx) <= 0)
                return 0;
            ctx->pctx->operation = EVP_PKEY_OP_VERIFYCTX;
        } else if (ctx->pctx->pmeth->digestverify != 0) {
            ctx->pctx->operation = EVP_PKEY_OP_VERIFY;
            ctx->update = update;
        } else if (EVP_PKEY_verify_init(ctx->pctx) <= 0) {
            return 0;
        }
    } else {
        if (ctx->pctx->pmeth->signctx_init) {
            if (ctx->pctx->pmeth->signctx_init(ctx->pctx, ctx) <= 0)
                return 0;
            ctx->pctx->operation = EVP_PKEY_OP_SIGNCTX;
        } else if (ctx->pctx->pmeth->digestsign != 0) {
            ctx->pctx->operation = EVP_PKEY_OP_SIGN;
            ctx->update = update;
        } else if (EVP_PKEY_sign_init(ctx->pctx) <= 0) {
            return 0;
        }
    }
    if (EVP_PKEY_CTX_set_signature_md(ctx->pctx, type) <= 0)
        return 0;
    if (pctx)
        *pctx = ctx->pctx;
    if (ctx->pctx->pmeth->flags & EVP_PKEY_FLAG_SIGCTX_CUSTOM)
        return 1;
    if (!EVP_DigestInit_ex(ctx, type, e))
        return 0;
        
#ifndef OPENSSL_NO_CNSM
    if (ctx->pctx->pkey->type == EVP_PKEY_EC)
    {
    	if(ctx->engine != NULL) {
	    	if(strcmp(ctx->engine->id,"skf")) {  //yangliqiang add for skf engine,have compute Z in skf engine lib,20190718.
		        if (EC_GROUP_get_curve_name(EC_KEY_get0_group(ctx->pctx->pkey->pkey.ec)) == NID_sm2)
		        {
		            /*Need Set SM2 Sign And Verify Extra Data: Add Message Z*/
		            unsigned char ex_dgst[EVP_MAX_MD_SIZE];
		            if (!sm2_compute_z_digest(ex_dgst, EVP_sm3(), "1234567812345678", strlen("1234567812345678"), ctx->pctx->pkey->pkey.ec))
		                return 0;
		            if (!EVP_DigestUpdate(ctx, ex_dgst, 32))
		                return 0;
		        }
	    	}
    	}
		else {
			if (EC_GROUP_get_curve_name(EC_KEY_get0_group(ctx->pctx->pkey->pkey.ec)) == NID_sm2)
	        {
	            /*Need Set SM2 Sign And Verify Extra Data: Add Message Z*/
	            unsigned char ex_dgst[EVP_MAX_MD_SIZE];
	            if (!sm2_compute_z_digest(ex_dgst, EVP_sm3(), "1234567812345678", strlen("1234567812345678"), ctx->pctx->pkey->pkey.ec))
	                return 0;
	            if (!EVP_DigestUpdate(ctx, ex_dgst, 32))
	                return 0;
	        }
		}
    }
#endif
    /*
     * This indicates the current algorithm requires
     * special treatment before hashing the tbs-message.
     */
    if (ctx->pctx->pmeth->digest_custom != NULL)
        return ctx->pctx->pmeth->digest_custom(ctx->pctx, ctx);

    return 1;
}

int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                       const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey)
{
    return do_sigver_init(ctx, pctx, type, e, pkey, 0);
}

int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                         const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey)
{
    return do_sigver_init(ctx, pctx, type, e, pkey, 1);
}

int EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
                        size_t *siglen)
{
    int sctx = 0, r = 0;
    EVP_PKEY_CTX *pctx = ctx->pctx;
    if (pctx->pmeth->flags & EVP_PKEY_FLAG_SIGCTX_CUSTOM) {
        if (!sigret)
            return pctx->pmeth->signctx(pctx, sigret, siglen, ctx);
        if (ctx->flags & EVP_MD_CTX_FLAG_FINALISE)
            r = pctx->pmeth->signctx(pctx, sigret, siglen, ctx);
        else {
            EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_dup(ctx->pctx);
            if (!dctx)
                return 0;
            r = dctx->pmeth->signctx(dctx, sigret, siglen, ctx);
            EVP_PKEY_CTX_free(dctx);
        }
        return r;
    }
    if (pctx->pmeth->signctx)
        sctx = 1;
    else
        sctx = 0;
    if (sigret) {
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int mdlen = 0;
        if (ctx->flags & EVP_MD_CTX_FLAG_FINALISE) {
            if (sctx)
                r = ctx->pctx->pmeth->signctx(ctx->pctx, sigret, siglen, ctx);
            else
                r = EVP_DigestFinal_ex(ctx, md, &mdlen);
        } else {
            EVP_MD_CTX *tmp_ctx = EVP_MD_CTX_new();
            if (tmp_ctx == NULL)
                return 0;
            if (!EVP_MD_CTX_copy_ex(tmp_ctx, ctx)) {
                EVP_MD_CTX_free(tmp_ctx);
                return 0;
            }
            if (sctx)
                r = tmp_ctx->pctx->pmeth->signctx(tmp_ctx->pctx,
                                                  sigret, siglen, tmp_ctx);
            else
                r = EVP_DigestFinal_ex(tmp_ctx, md, &mdlen);
            EVP_MD_CTX_free(tmp_ctx);
        }
        if (sctx || !r)
            return r;
        if (EVP_PKEY_sign(ctx->pctx, sigret, siglen, md, mdlen) <= 0)
            return 0;
    } else {
        if (sctx) {
            if (pctx->pmeth->signctx(pctx, sigret, siglen, ctx) <= 0)
                return 0;
        } else {
            int s = EVP_MD_size(ctx->digest);
            if (s < 0 || EVP_PKEY_sign(pctx, sigret, siglen, NULL, s) <= 0)
                return 0;
        }
    }
    return 1;
}

int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen,
                   const unsigned char *tbs, size_t tbslen)
{
    if (ctx->pctx->pmeth->digestsign != NULL)
        return ctx->pctx->pmeth->digestsign(ctx, sigret, siglen, tbs, tbslen);
    if (sigret != NULL && EVP_DigestSignUpdate(ctx, tbs, tbslen) <= 0)
        return 0;
    return EVP_DigestSignFinal(ctx, sigret, siglen);
}

int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig,
                          size_t siglen)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    int r = 0;
    unsigned int mdlen = 0;
    int vctx = 0;

    if (ctx->pctx->pmeth->verifyctx)
        vctx = 1;
    else
        vctx = 0;
    if (ctx->flags & EVP_MD_CTX_FLAG_FINALISE) {
        if (vctx)
            r = ctx->pctx->pmeth->verifyctx(ctx->pctx, sig, siglen, ctx);
        else
            r = EVP_DigestFinal_ex(ctx, md, &mdlen);
    } else {
        EVP_MD_CTX *tmp_ctx = EVP_MD_CTX_new();
        if (tmp_ctx == NULL)
            return -1;
        if (!EVP_MD_CTX_copy_ex(tmp_ctx, ctx)) {
            EVP_MD_CTX_free(tmp_ctx);
            return -1;
        }
        if (vctx)
            r = tmp_ctx->pctx->pmeth->verifyctx(tmp_ctx->pctx,
                                                sig, siglen, tmp_ctx);
        else
            r = EVP_DigestFinal_ex(tmp_ctx, md, &mdlen);
        EVP_MD_CTX_free(tmp_ctx);
    }
    if (vctx || !r)
        return r;
    return EVP_PKEY_verify(ctx->pctx, sig, siglen, md, mdlen);
}

int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret,
                     size_t siglen, const unsigned char *tbs, size_t tbslen)
{
    if (ctx->pctx->pmeth->digestverify != NULL)
        return ctx->pctx->pmeth->digestverify(ctx, sigret, siglen, tbs, tbslen);
    if (EVP_DigestVerifyUpdate(ctx, tbs, tbslen) <= 0)
        return -1;

	if(ctx->engine != NULL){
		if(!strcmp(ctx->engine->id,"skf"))
			ctx->flags = EVP_MD_CTX_FLAG_FINALISE;  //add by yangliqiang
	}
	return EVP_DigestVerifyFinal(ctx, sigret, siglen);
}
