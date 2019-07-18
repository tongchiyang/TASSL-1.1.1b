#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/objects.h>
#include <openssl/ossl_typ.h>
#include <openssl/sm3.h>
#include <openssl/ec.h>
#include <openssl/skf.h>
#include <openssl/gmskf.h>
#include <openssl/gmapi.h>

#include "internal/skf_int.h"
#include "internal/evp_int.h"
#include "internal/evp_locl.h"
#include "internal/rsa_locl.h"
#include "internal/ec_lcl.h"

#include "e_skf_err.c"
#ifndef ENGINE_CMD_BASE
#error did not get engine.h
#endif

#define MAX_PIN_LENGTH   32

static const char *engine_skf_id = "skf";
static const char *engine_skf_name = "skf FEITIAN ePass3000GM Engine V1.0.0";
static const char *skf_conf_section="skf_section";
static int   g_skf_idx = -1;

static DEVHANDLE*     gh_dev = NULL;
static HAPPLICATION*  gh_app = NULL;
static HCONTAINER*    gh_container    = NULL;
static int*           gp_dev_authd    = NULL;
static int*           gp_pin_verified = NULL;

#define SKF_CMD_SO_PATH			   ENGINE_CMD_BASE
#define SKF_CMD_MODULE_PATH 	   (ENGINE_CMD_BASE+1)
#define SKF_CMD_PIN		           (ENGINE_CMD_BASE+2)
#define SKF_CMD_VERBOSE		       (ENGINE_CMD_BASE+3)
#define SKF_CMD_QUIET		       (ENGINE_CMD_BASE+4)
#define SKF_CMD_LOAD_CERT_CTRL	   (ENGINE_CMD_BASE+5)
#define SKF_CMD_INIT_ARGS	       (ENGINE_CMD_BASE+6)
#define SKF_CMD_SET_USER_INTERFACE (ENGINE_CMD_BASE+7)
#define SKF_CMD_SET_CALLBACK_DATA  (ENGINE_CMD_BASE+8)
#define SKF_CMD_FORCE_LOGIN	       (ENGINE_CMD_BASE+9)
#define SKF_CMD_OPEN_DEV		   (ENGINE_CMD_BASE+10)
#define SKF_CMD_DEV_AUTH		   (ENGINE_CMD_BASE+11)
#define SKF_CMD_OPEN_APP		   (ENGINE_CMD_BASE+12)
#define SKF_CMD_VERIFY_PIN		   (ENGINE_CMD_BASE+13)
#define SKF_CMD_OPEN_CONTAINER	   (ENGINE_CMD_BASE+14)

struct st_engine_ctx{
	long   verbose;
	char*  module;
	char*  dev_name;
	char*  app_name;
	char*  pin;
	size_t pin_length;
	char*  auth_key;
	char*  init_args;
	UI_METHOD *ui_method;
	void *callback_data;
	int   force_login;
	int   is_dev_authd;
	int   is_pin_verified;
	DEVINFO        devInfo;
	DEVHANDLE      h_dev;
	HAPPLICATION   h_app;
	HCONTAINER     h_container;
	/* Engine initialization mutex */
#if OPENSSL_VERSION_NUMBER >= 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)
	CRYPTO_RWLOCK *rwlock;
#else
	int rwlock;
#endif
};
typedef struct st_engine_ctx ENGINE_CTX;


static int EC_KEY_set_ECCPUBLICKEYBLOB(EC_KEY *ec_key, const ECCPUBLICKEYBLOB *blob) {
	int ret = 0;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;

	if (blob->BitLen != EC_GROUP_get_degree(EC_KEY_get0_group(ec_key))) {
		GMAPIerr(GMAPI_F_EC_KEY_SET_ECCPUBLICKEYBLOB, GMAPI_R_INVALID_KEY_LENGTH);
		return 0;
	}

	if (!(x = BN_bin2bn(blob->XCoordinate, sizeof(blob->XCoordinate), NULL))) {
		GMAPIerr(GMAPI_F_EC_KEY_SET_ECCPUBLICKEYBLOB, ERR_R_BN_LIB);
		goto end;
	}
	if (!(y = BN_bin2bn(blob->YCoordinate, sizeof(blob->YCoordinate), NULL))) {
		GMAPIerr(GMAPI_F_EC_KEY_SET_ECCPUBLICKEYBLOB, ERR_R_BN_LIB);
		goto end;
	}
	if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
		GMAPIerr(GMAPI_F_EC_KEY_SET_ECCPUBLICKEYBLOB, GMAPI_R_INVALID_PUBLIC_KEY);
		goto end;
	}

	ret = 1;
end:
	BN_free(x);
	BN_free(y);
	return ret;
}

static EC_KEY *EC_KEY_new_from_ECCPUBLICKEYBLOB(const ECCPUBLICKEYBLOB *blob) {
	EC_KEY *ret;

	if (!(ret = EC_KEY_new_by_curve_name(NID_sm2))) {
		GMAPIerr(GMAPI_F_EC_KEY_NEW_FROM_ECCPUBLICKEYBLOB, ERR_R_EC_LIB);
		return NULL;
	}

	if (!EC_KEY_set_ECCPUBLICKEYBLOB(ret, blob)) {
		GMAPIerr(GMAPI_F_EC_KEY_NEW_FROM_ECCPUBLICKEYBLOB,
			GMAPI_R_DECODE_EC_PUBLIC_KEY_FAILED);
		EC_KEY_free(ret);
		return NULL;
	}

	return ret;
}

static int RSA_set_RSAPUBLICKEYBLOB(RSA *rsa, const RSAPUBLICKEYBLOB *blob) {
	int ret = 0;
	BIGNUM *n = NULL;
	BIGNUM *e = NULL;

	if (!rsa || !blob) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAPUBLICKEYBLOB,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if ((blob->BitLen < OPENSSL_RSA_FIPS_MIN_MODULUS_BITS)
		|| (blob->BitLen > sizeof(blob->Modulus) * 8)
		|| (blob->BitLen % 8 != 0)) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAPUBLICKEYBLOB,
			GMAPI_R_INVALID_RSA_KEY_LENGTH);
		return 0;
	}

	if (!(n = BN_bin2bn(blob->Modulus, sizeof(blob->Modulus), NULL))) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAPUBLICKEYBLOB,
			GMAPI_R_INVALID_RSA_PUBLIC_KEY);
		goto end;
	}

	if (!(e = BN_bin2bn(blob->PublicExponent,
		sizeof(blob->PublicExponent), NULL))) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAPUBLICKEYBLOB,
			GMAPI_R_INVALID_RSA_PUBLIC_KEY);
		goto end;
	}

	if (!RSA_set0_key(rsa, n, e, NULL)) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAPUBLICKEYBLOB,
			GMAPI_R_INVALID_RSA_PUBLIC_KEY);
		goto end;
	}
	n = NULL;
	e = NULL;

	ret = 1;

end:
	BN_free(n);
	BN_free(e);
	return ret;
}

static RSA *RSA_new_from_RSAPUBLICKEYBLOB(const RSAPUBLICKEYBLOB *blob) {
	RSA *ret = NULL;
	RSA *rsa = NULL;

	if (!blob) {
		GMAPIerr(GMAPI_F_RSA_NEW_FROM_RSAPUBLICKEYBLOB,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	if (!(rsa = RSA_new())) {
		GMAPIerr(GMAPI_F_RSA_NEW_FROM_RSAPUBLICKEYBLOB,
			ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	if (!RSA_set_RSAPUBLICKEYBLOB(rsa, blob)) {
		GMAPIerr(GMAPI_F_RSA_NEW_FROM_RSAPUBLICKEYBLOB,
			GMAPI_R_INVALID_RSA_PUBLIC_KEY);
		goto end;
	}

	ret = rsa;
	rsa = NULL;

end:
	RSA_free(rsa);
	return ret;
}



//ctx functions begin.
void ctx_log(ENGINE_CTX *ctx, int level, const char *format, ...) {
	va_list ap;
	if (level > ctx->verbose)
		return;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}

static ENGINE_CTX* ctx_new(){
	long eline;
	char *p;
	CONF *conf;
	ENGINE_CTX *ctx;

	ctx = OPENSSL_malloc(sizeof(ENGINE_CTX));
	if (ctx == NULL)
		return NULL;
	memset(ctx, 0, sizeof(ENGINE_CTX));

	conf=NCONF_new(NULL);
	if(!NCONF_load(conf,CONF_get1_default_config_file(),&eline)){
		ESKFerr(ESKF_F_SKF_INIT, ESKF_R_SKF_LOAD_CONF_FAILED);
		goto end;
	}
	p=NCONF_get_string(conf,skf_conf_section,"SO_PATH");
	ctx->module=OPENSSL_strdup(p);
	
	p=NCONF_get_string(conf,skf_conf_section,"AUTHKEY");
	ctx->auth_key=OPENSSL_strdup(p);
	
	p=NCONF_get_string(conf,skf_conf_section,"USER_PIN");
	ctx->pin=OPENSSL_strdup(p);
	
	p=NCONF_get_string(conf,skf_conf_section,"DEV_NAME");
	ctx->dev_name=OPENSSL_strdup(p);
	
	p=NCONF_get_string(conf,skf_conf_section,"APP_NAME");
	ctx->app_name=OPENSSL_strdup(p);
	
	NCONF_get_number(conf,skf_conf_section,"VERBOSE",&ctx->verbose);

	ctx->h_dev = NULL;
	ctx->h_app = NULL;
	ctx->h_container = NULL;

	gh_dev = &ctx->h_dev;
	gh_app = &ctx->h_app;
	gh_container = &ctx->h_container;
	
#if OPENSSL_VERSION_NUMBER >= 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)
	ctx->rwlock = CRYPTO_THREAD_lock_new();
#else
	ctx->rwlock = CRYPTO_get_dynlock_create_callback() ? CRYPTO_get_new_dynlockid() : 0;
#endif
end:
	if(conf != NULL){
		NCONF_free(conf);
	}
	return ctx;
}

static ENGINE_CTX *get_ctx(ENGINE *engine) {
	ENGINE_CTX *ctx;

	if (g_skf_idx < 0) {
		g_skf_idx = ENGINE_get_ex_new_index(0, "skf", NULL, NULL, 0);
		if (g_skf_idx < 0)
			return NULL;
		ctx = NULL;
	} else {
		ctx = ENGINE_get_ex_data(engine, g_skf_idx);
	}
	
	if (ctx == NULL) {
		ctx = ctx_new();
		ENGINE_set_ex_data(engine, g_skf_idx, ctx);
	}
	return ctx;
}

static int ctx_finish(ENGINE_CTX *ctx) {
	ULONG rv;
	if (ctx) {
		if (ctx->h_dev) {
            if ((rv = SKF_DisConnectDev(ctx->h_dev)) != SAR_OK) {
                ESKFerr(ESKF_F_SKF_FINISH, ESKF_R_SKF_DIS_CONNNECT_DEV_FAILED);
                return 0;
            }
        }
	}
	SKF_UnloadLibrary();
	return 1;
}

static int ctx_destroy(ENGINE_CTX *ctx) {
	if(ctx){
		OPENSSL_free(ctx->module);
		OPENSSL_free(ctx->auth_key);
		OPENSSL_free(ctx->pin);
		OPENSSL_free(ctx->dev_name);
		OPENSSL_free(ctx->app_name);
		OPENSSL_free(ctx->h_dev);
		OPENSSL_free(ctx->h_app);
		OPENSSL_free(ctx->h_container);
		
#if OPENSSL_VERSION_NUMBER >= 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)
		CRYPTO_THREAD_lock_free(ctx->rwlock);
#else
		if (ctx->rwlock)
			CRYPTO_destroy_dynlockid(ctx->rwlock);
#endif
		OPENSSL_free(ctx);
	}
	return 1;
}


static int ctx_ctrl_set_module(ENGINE_CTX *ctx, const char *modulename) {
	OPENSSL_free(ctx->module);
	ctx->module = modulename ? OPENSSL_strdup(modulename) : NULL;
	return 1;
}

/* Free PIN storage in secure way. */
static void ctx_destroy_pin(ENGINE_CTX *ctx) {
	if (ctx->pin != NULL) {
		OPENSSL_cleanse(ctx->pin, ctx->pin_length);
		OPENSSL_free(ctx->pin);
		ctx->pin = NULL;
		ctx->pin_length = 0;
	}
}

static int ctx_get_pin(ENGINE_CTX *ctx, const char* token_label, UI_METHOD *ui_method, void *callback_data) {
	UI *ui;
	char* prompt;

	/* call ui to ask for a pin */
	ui = UI_new_method(ui_method);
	if (ui == NULL) {
		ctx_log(ctx, 0, "UI_new failed\n");
		return 0;
	}
	if (callback_data != NULL)
		UI_add_user_data(ui, callback_data);

	ctx_destroy_pin(ctx);
	ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH+1);
	if (ctx->pin == NULL)
		return 0;
	
	memset(ctx->pin, 0, MAX_PIN_LENGTH+1);
	ctx->pin_length = MAX_PIN_LENGTH;
	prompt = UI_construct_prompt(ui, "skf device usrpin", token_label);
	if (!prompt) {
		return 0;
	}
	if (!UI_dup_input_string(ui, prompt,UI_INPUT_FLAG_DEFAULT_PWD, ctx->pin, 4, MAX_PIN_LENGTH)) {
		ctx_log(ctx, 0, "UI_dup_input_string failed\n");
		UI_free(ui);
		OPENSSL_free(prompt);
		return 0;
	}
	OPENSSL_free(prompt);

	if (UI_process(ui)) {
		ctx_log(ctx, 0, "UI_process failed\n");
		UI_free(ui);
		return 0;
	}
	UI_free(ui);
	return 1;
}

/* Set the PIN used for login. A copy of the PIN shall be made.
 *
 * If the PIN cannot be assigned, the value 0 shall be returned
 * and errno shall be set as follows:
 *
 *   EINVAL - a NULL PIN was supplied
 *   ENOMEM - insufficient memory to copy the PIN
 *
 * @param pin the pin to use for login. Must not be NULL.
 *
 * @return 1 on success, 0 on failure.
 */
static int ctx_ctrl_set_pin(ENGINE_CTX *ctx, const char *pin) {
	/* Pre-condition check */
	if (pin == NULL) {
		ESKFerr(ESKF_F_SET_USERPIN, ERR_R_PASSED_NULL_PARAMETER);
		errno = EINVAL;
		return 0;
	}

	/* Copy the PIN. If the string cannot be copied, NULL
	 * shall be returned and errno shall be set. */
	ctx_destroy_pin(ctx);
	ctx->pin = OPENSSL_strdup(pin);
	if (ctx->pin == NULL) {
		ESKFerr(ESKF_F_SET_USERPIN, ERR_R_MALLOC_FAILURE);
		errno = ENOMEM;
		return 0;
	}
	ctx->pin_length = strlen(ctx->pin);
	return 1;
}

static int ctx_ctrl_inc_verbose(ENGINE_CTX *ctx) {
	ctx->verbose++;
	return 1;
}

static int ctx_ctrl_set_quiet(ENGINE_CTX *ctx) {
	ctx->verbose = -1;
	return 1;
}

static int ctx_ctrl_load_cert(ENGINE_CTX *ctx, void *p) {
	return 1;
}

static int ctx_ctrl_set_init_args(ENGINE_CTX *ctx, const char *init_args_orig) {
	OPENSSL_free(ctx->init_args);
	ctx->init_args = init_args_orig ? OPENSSL_strdup(init_args_orig) : NULL;
	return 1;
}

static int ctx_ctrl_set_user_interface(ENGINE_CTX *ctx, UI_METHOD *ui_method) {
	ctx->ui_method = ui_method;
	return 1;
}

static int ctx_ctrl_set_callback_data(ENGINE_CTX *ctx, void *callback_data) {
	ctx->callback_data = callback_data;
	return 1;
}

static int ctx_ctrl_force_login(ENGINE_CTX *ctx) {
	ctx->force_login = 1;
	return 1;
}

static int ctx_open_dev(ENGINE_CTX *ctx,const char *devname) {
	ULONG rv;
	
	if (ctx->h_dev) {
		ESKFerr(ESKF_F_OPEN_DEV, ESKF_R_DEV_ALREADY_CONNECTED);
		return 0;
	}
	if ((rv = SKF_ConnectDev((LPSTR)devname, &ctx->h_dev)) != SAR_OK) {
		ESKFerr(ESKF_F_OPEN_DEV, ESKF_R_SKF_CONNECT_DEV_FAILED);
		return 0;
	}
	if ((rv = SKF_GetDevInfo(ctx->h_dev, &ctx->devInfo)) != SAR_OK) {
		ESKFerr(ESKF_F_OPEN_DEV, ESKF_R_SKF_GET_DEV_INFO_FAILED);
		return 0;
	}
	return 1;
}

static int ctx_dev_auth(ENGINE_CTX *ctx,const char *hexauthkey) {
	int ret = 0;
	ULONG rv;
	const EVP_CIPHER *cipher = EVP_sm4_ecb();
	EVP_CIPHER_CTX *evp_ctx = NULL;
	unsigned char authkey[EVP_MAX_KEY_LENGTH];
	unsigned char authrand[16];
	unsigned char authdata[16];
	ULONG  len;
	HANDLE hSessionKey;

	if (!ctx->h_dev) {
		ESKFerr(ESKF_F_DEV_AUTH, ESKF_R_DEV_IS_NOT_CONNECTED);
		return 0;
	}

	len = 8;
	memset(authrand, 0, sizeof(authrand));
	if ((rv = SKF_GenRandom(ctx->h_dev, authrand, len)) != SAR_OK) {
		ESKFerr(ESKF_F_DEV_AUTH, ESKF_R_SKF_GEN_RANDOM_FAILED);
		goto end;
	}

	if((rv = SKF_GetDevInfo(ctx->h_dev, &ctx->devInfo)) != SAR_OK){
		ESKFerr(ESKF_F_DEV_INFO, ESKF_R_SKF_DEV_INFO);
		goto end;
	}

	if((rv = SKF_SetSymmKey(ctx->h_dev, hexauthkey,ctx->devInfo.DevAuthAlgId, &hSessionKey)) != SAR_OK){
		ESKFerr(ESKF_F_SET_AUTHKEY, ESKF_R_SKF_SET_SYMMKEY_FAILED);
		goto end;
	}
		
	/*
	if (!(evp_ctx = EVP_CIPHER_CTX_new())) {
		ESKFerr(ESKF_F_DEV_AUTH, ERR_R_EVP_LIB);
		goto end;
	}

	if (!EVP_EncryptInit(evp_ctx, cipher, authkey, NULL)) {
		ESKFerr(ESKF_F_DEV_AUTH, ERR_R_EVP_LIB);
		goto end;
	}

	if (!EVP_Cipher(evp_ctx, authdata, authrand, sizeof(authrand))) {
		ESKFerr(ESKF_F_DEV_AUTH, ERR_R_EVP_LIB);
		goto end;
	}
	*/
	
	BLOCKCIPHERPARAM param = {0};
	if((rv = SKF_EncryptInit(hSessionKey, param)) !=SAR_OK){
		ESKFerr(ESKF_F_DEV_AUTH, ERR_R_EVP_LIB);
		goto end;
	}
	
	len = sizeof(authdata);
	if((rv = SKF_Encrypt(hSessionKey, authrand, 16, authdata, &len)) !=SAR_OK){
		ESKFerr(ESKF_F_DEV_AUTH, ERR_R_EVP_LIB);
		goto end;
	}

	if ((rv = SKF_DevAuth(ctx->h_dev, authdata, sizeof(authdata))) != SAR_OK) {
		ESKFerr(ESKF_F_DEV_AUTH, ESKF_R_SKF_DEV_AUTH_FAILED);
		goto end;
	}

	ctx->is_dev_authd = 1;
	ret = 1;
end:
	EVP_CIPHER_CTX_free(evp_ctx);
	return ret;
}

static int ctx_open_app(ENGINE_CTX *ctx,const char *appname) {
	ULONG rv;
	
	if (!ctx->h_dev) {
		ESKFerr(ESKF_F_OPEN_APP, ESKF_R_DEV_NOT_CONNECTED);
		return 0;
	}

	/*
	if (!ctx->is_dev_authd) {
		ESKFerr(ESKF_F_OPEN_APP, ESKF_R_DEV_NOT_AUTHENTICATED);
		return 0;
	}
	*/
	if (ctx->h_app) {
		ESKFerr(ESKF_F_OPEN_APP, ESKF_R_APP_ALREADY_OPENED);
		return 0;
	}

	if ((rv = SKF_OpenApplication(ctx->h_dev, (LPSTR)appname, &ctx->h_app)) != SAR_OK) {
		ESKFerr(ESKF_F_OPEN_APP, ESKF_R_SKF_OPEN_APPLICATION_FAILED);
		return 0;
	}

	return 1;
}

static int ctx_verify_pin(ENGINE_CTX *ctx,const char *userpin) {
	ULONG rv;
	ULONG retryCount;
	
	if (!ctx->h_dev) {
		ESKFerr(ESKF_F_VERIFY_PIN, ESKF_R_DEV_NOT_CONNECTED);
		return 0;
	}
	/*
	if (!ctx->is_dev_authd) {
		ESKFerr(ESKF_F_VERIFY_PIN, ESKF_R_DEV_NOT_AUTHENCATED);
		return 0;
	}
	*/
	if (!ctx->h_app) {
		ESKFerr(ESKF_F_VERIFY_PIN, ESKF_R_APP_NOT_OPENED);
		return 0;
	}

	if ((rv = SKF_VerifyPIN(ctx->h_app, USER_TYPE, (LPSTR)userpin, &retryCount)) != SAR_OK) {
		ESKFerr(ESKF_F_VERIFY_PIN, ESKF_R_SKF_VERIFY_PIN_FAILED);
		return 0;
	}
	printf("SKF_VerifyPIN success,retryCount=%d\n",retryCount);
	ctx->is_pin_verified = 1;
	return 1;
}

static int ctx_open_container(ENGINE_CTX *ctx,const char *containername)
{
	ULONG rv;
	
	if (!ctx->h_dev) {
		ESKFerr(ESKF_F_OPEN_CONTAINER, ESKF_R_DEV_NOT_CONNECTED);
		return 0;
	}
	/*
	if (!ctx->is_dev_authd) {
		ESKFerr(ESKF_F_OPEN_CONTAINER, ESKF_R_DEV_NOT_AUTHENTICATED);
		return 0;
	}
	*/
	if (!ctx->h_app) {
		ESKFerr(ESKF_F_OPEN_CONTAINER, ESKF_R_APP_NOT_OPENED);
		return 0;
	}

	if (!ctx->is_pin_verified) {
		ESKFerr(ESKF_F_OPEN_CONTAINER, ESKF_R_PIN_NOT_VERIFIED);
		return 0;
	}

	if (ctx->h_container) {
		ESKFerr(ESKF_F_OPEN_CONTAINER, ESKF_R_CONTAINER_ALREADY_OPENED);
		return 0;
	}

	if ((rv = SKF_OpenContainer(ctx->h_app, (LPSTR)containername, &ctx->h_container)) != SAR_OK) {
		ESKFerr(ESKF_F_OPEN_CONTAINER, ESKF_R_SKF_OPEN_CONTAINER_FAILED);
		return 0;
	}

	return 1;
}

int ctx_engine_ctrl(ENGINE_CTX *ctx, int cmd, long i, void *p, void (*f)()) {
	(void)i;
	(void)f;	

	switch (cmd) {
	case SKF_CMD_MODULE_PATH:
		return ctx_ctrl_set_module(ctx, (const char *)p);
	case SKF_CMD_PIN:
		return ctx_ctrl_set_pin(ctx, (const char *)p);
	case SKF_CMD_VERBOSE:
		return ctx_ctrl_inc_verbose(ctx);
	case SKF_CMD_QUIET:
		return ctx_ctrl_set_quiet(ctx);
	case SKF_CMD_LOAD_CERT_CTRL:
		return ctx_ctrl_load_cert(ctx, p);
	case SKF_CMD_INIT_ARGS:
		return ctx_ctrl_set_init_args(ctx, (const char *)p);
	case ENGINE_CTRL_SET_USER_INTERFACE:
	case SKF_CMD_SET_USER_INTERFACE:
		return ctx_ctrl_set_user_interface(ctx, (UI_METHOD *)p);
	case ENGINE_CTRL_SET_CALLBACK_DATA:
	case SKF_CMD_SET_CALLBACK_DATA:
		return ctx_ctrl_set_callback_data(ctx, p);
	case SKF_CMD_FORCE_LOGIN:
		return ctx_ctrl_force_login(ctx);
	case SKF_CMD_OPEN_DEV:
		return ctx_open_dev(ctx,p);
	case SKF_CMD_DEV_AUTH:
		return ctx_dev_auth(ctx,(const char *)p);
	case SKF_CMD_OPEN_APP:
		return ctx_open_app(ctx,p);
	case SKF_CMD_VERIFY_PIN:
		return ctx_verify_pin(ctx,p);
	case SKF_CMD_OPEN_CONTAINER:
		return ctx_open_container(ctx,p);
	default:
		ESKFerr(ESKF_F_SKF_ENGINE_CTRL, ESKF_R_INVALID_CTRL_CMD);
		break;
	}
	return 0;
	
}

static EVP_PKEY *ctx_load_key(ENGINE_CTX *ctx, const char *s_slot_key_id,
		UI_METHOD *ui_method, void *callback_data,
		const int isPrivate, const int login) {
	ULONG rv, len;
	ECCPUBLICKEYBLOB eccblob;
	RSAPUBLICKEYBLOB rsablob;
	EVP_PKEY *pk = NULL;
	EC_KEY *ec_key = NULL;
	RSA *rsa = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	int nbytes;
	ULONG containerType;

	if(!ctx->h_container) {
		ESKFerr(ESKF_F_SKF_LOAD_PUBKEY, ESKF_R_CONTAINER_NOT_OPENED);
		goto end;
	}

	if ((rv = SKF_GetContainerType(ctx->h_container, &containerType)) != SAR_OK) {
		ESKFerr(ESKF_F_GET_CONTAINER_TYPE, ESKF_R_SKF_GET_CONTAINER_TYPE_FAILED);
		goto end;
	}

	if(isPrivate){//TODO,private
		
	}
	else{
		if (containerType == SKF_CONTAINER_TYPE_ECC) {
			len = sizeof(eccblob);
			if ((rv = SKF_ExportPublicKey(ctx->h_container, TRUE, &eccblob, &len)) != SAR_OK) {
				ESKFerr(ESKF_F_SKF_LOAD_PUBKEY, ESKF_R_SKF_EXPORT_PUBLIC_KEY_FAILED);
				goto end;
			}
			if (!(ec_key = EC_KEY_new_from_ECCPUBLICKEYBLOB(&eccblob))) {
				return 0;
			}
			EVP_PKEY_set1_EC_KEY(pk, ec_key);
			ec_key = NULL;
		}
		else if(containerType == SKF_CONTAINER_TYPE_RSA) {
			len = sizeof(rsablob);
			if ((rv = SKF_ExportPublicKey(ctx->h_container, TRUE, (BYTE *)&rsablob, &len)) != SAR_OK) {
				ESKFerr(ESKF_F_SKF_LOAD_PUBKEY, ESKF_R_SKF_EXPORT_PUBLIC_KEY_FAILED);
				return 0;
			}
			if (!(rsa = RSA_new_from_RSAPUBLICKEYBLOB(&rsablob))) {
				return 0;
			}
			EVP_PKEY_set1_RSA(pk, rsa);
			rsa = NULL;
		}
		else{//TODO RSA
			ESKFerr(ESKF_F_SKF_LOAD_PUBKEY, ESKF_R_INVALID_CONTAINER_TYPE);
		}
	}
	
end:
	if(ec_key)
		EC_KEY_free(ec_key);
	/*
	if(rsa)
	*/
	if(x)
		BN_free(x);
	if(y)
		BN_free(y);
	return pk;
}

static EVP_PKEY *ctx_load_pubkey(ENGINE_CTX *ctx, const char *s_key_id,UI_METHOD *ui_method, void *callback_data) {
	EVP_PKEY *pk = NULL;

	ERR_clear_error();
	if (!ctx->force_login)
		pk = ctx_load_key(ctx, s_key_id, ui_method, callback_data, 0, 0);
	
	if (pk == NULL) { /* Try again with login */
		ERR_clear_error();
		pk = ctx_load_key(ctx, s_key_id, ui_method, callback_data, 0, 1);
	}
	
	if (pk == NULL) {
		ctx_log(ctx, 0, "ctx_load_pubkey returned NULL\n");
		if (!ERR_peek_last_error())
			ESKFerr(ESKF_F_SKF_LOAD_PUBKEY, ESKF_R_SKF_OBJECT_NOT_FOUND);
		return NULL;
	}
	return pk;
}

static EVP_PKEY *ctx_load_privkey(ENGINE_CTX *ctx, const char *s_key_id,	UI_METHOD *ui_method, void *callback_data) {
	EVP_PKEY *pk = NULL;

	ERR_clear_error();
	return pk;
}
//ctx functions end.

//skf engine functions begin.
static const ENGINE_CMD_DEFN skf_cmd_defns[] = {
	{SKF_CMD_SO_PATH,
	 	"SO_PATH",
	 	"Specifies the path to the 'skf' engine shared library",
	 	ENGINE_CMD_FLAG_STRING},
	{SKF_CMD_MODULE_PATH,
		"MODULE_PATH",
		"Specifies the path to the vendor skf module shared library",
		ENGINE_CMD_FLAG_STRING},
	{SKF_CMD_PIN,
		"PIN",
		"Specifies the pin code",
		ENGINE_CMD_FLAG_STRING},
	{SKF_CMD_VERBOSE,
		"VERBOSE",
		"Print additional details",
		ENGINE_CMD_FLAG_NO_INPUT},
	{SKF_CMD_QUIET,
		"QUIET",
		"Remove additional details",
		ENGINE_CMD_FLAG_NO_INPUT},
	{SKF_CMD_LOAD_CERT_CTRL,
		"LOAD_CERT_CTRL",
		"Get the certificate from card",
		ENGINE_CMD_FLAG_INTERNAL},
	{SKF_CMD_INIT_ARGS,
		"INIT_ARGS",
		"Specifies additional initialization arguments to the skf module",
		ENGINE_CMD_FLAG_STRING},
	{SKF_CMD_SET_USER_INTERFACE,
		"SET_USER_INTERFACE",
		"Set the global user interface (internal)",
		ENGINE_CMD_FLAG_INTERNAL},
	{SKF_CMD_SET_CALLBACK_DATA,
		"SET_CALLBACK_DATA",
		"Set the global user interface extra data (internal)",
		ENGINE_CMD_FLAG_INTERNAL},
	{SKF_CMD_FORCE_LOGIN,
		"FORCE_LOGIN",
		"Force login to the skf module",
		ENGINE_CMD_FLAG_NO_INPUT},
	{SKF_CMD_OPEN_DEV,
		 "OPEN_DEVICE",
		 "Connect skf device with device name",
		 ENGINE_CMD_FLAG_STRING},
	{SKF_CMD_DEV_AUTH,
		 "DEV_AUTH",
		 "Authenticate to device with authentication key",
		 ENGINE_CMD_FLAG_STRING},
	{SKF_CMD_OPEN_APP,
		 "OPEN_APP",
		 "Open application with specified application name",
		 ENGINE_CMD_FLAG_STRING},
	{SKF_CMD_VERIFY_PIN,
		 "VERIFY_PIN",
		 "Authenticate to application with USER PIN",
		 ENGINE_CMD_FLAG_STRING},
	{SKF_CMD_OPEN_CONTAINER,
		 "OPEN_CONTAINER",
		 "Open container with specified container name",
		 ENGINE_CMD_FLAG_STRING},
	{0, NULL, NULL, 0},
};

static int skf_destroy(ENGINE *engine) {
	ENGINE_CTX *ctx;
	int rv = 1;

	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;
	
	rv = ctx_destroy(ctx);
	ENGINE_set_ex_data(engine, g_skf_idx, NULL);
	ERR_unload_ESKF_strings();
	return rv;
}

static int skf_init(ENGINE *engine) {
	ENGINE_CTX *ctx;
	
	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;
	
	SKF_LoadLibrary((LPSTR)(ctx->module), NULL);
	return 1;
}

static int skf_finish(ENGINE *engine) {
	ENGINE_CTX *ctx;
	ULONG rv;
	
	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;
	
#if OPENSSL_VERSION_NUMBER >= 0x10100005L && !defined(LIBRESSL_VERSION_NUMBER)
	rv &= ctx_finish(ctx);
#endif
	return 1;
}

static int skf_ctrl(ENGINE *engine, int cmd, long i, void *p, void (*f)()) {
	ENGINE_CTX *ctx = NULL;
	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;

	return ctx_engine_ctrl(ctx, cmd, i, p, f);
}

static EVP_PKEY *skf_load_pubkey(ENGINE *engine, const char *s_key_id,	UI_METHOD *ui_method, void *callback_data) {
	ENGINE_CTX *ctx;
	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;
	
	return ctx_load_pubkey(ctx, s_key_id, ui_method, callback_data);
}

static EVP_PKEY *skf_load_privkey(ENGINE *engine, const char *s_key_id,	UI_METHOD *ui_method, void *callback_data) {
	ENGINE_CTX *ctx;
	EVP_PKEY *pkey;

	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;
	
	pkey = ctx_load_privkey(ctx, s_key_id, ui_method, callback_data);
#ifdef EVP_F_EVP_PKEY_SET1_ENGINE
	/* EVP_PKEY_set1_engine() is required for OpenSSL 1.1.x,
	 * but otherwise setting pkey->engine breaks OpenSSL 1.0.2 */
	if (pkey && !EVP_PKEY_set1_engine(pkey, engine)) {
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
#endif /* EVP_F_EVP_PKEY_SET1_ENGINE */
	return pkey;
}


//skf rand bgein.
int skf_rand_bytes(unsigned char *buf, int num) {
	ULONG rv;
	
	if ((rv = SKF_GenRandom(*gh_dev, buf, (ULONG)num)) != SAR_OK) {
		ESKFerr(ESKF_F_SKF_RAND_BYTES, ESKF_R_GEN_RANDOM_FAILED);
		return 0;
	}
	
	return 1;
}

static RAND_METHOD skf_rand = {
	NULL,
	skf_rand_bytes,
	NULL,
	NULL,
	skf_rand_bytes,
	NULL,
};
//skf rand end.

//skf sm3 begin.
static int skf_sm3_init(EVP_MD_CTX *ctx) {
	ULONG rv;
	ULONG ulIdLen = 0;
	unsigned char *pPubKey = NULL;
	ULONG    ulPubKeyLen =0;
	ECCPUBLICKEYBLOB  EccPubKey;
	unsigned char pucId[32] ={0};
	
#ifndef OPENSSL_NO_SM2
	ctx->flags = EVP_MD_CTX_FLAG_SKFENG;
#endif
	
	if((rv = SKF_ExportPublicKey(*gh_container,TRUE,pPubKey,&ulPubKeyLen)) != SAR_OK) {
		ESKFerr(ESKF_F_SKF_SM3_INIT, ESKF_R_SKF_EXPORT_PUBLIC_KEY_FAILED);
		return 0;
	}
	
	pPubKey = (unsigned char *)malloc(ulPubKeyLen);
	if(pPubKey == NULL)
	{
		ESKFerr(ESKF_F_SKF_SM3_INIT, ESKF_R_SKF_EXPORT_PUBLIC_KEY_FAILED);
		return 0;
	}
	
	if(ulPubKeyLen != sizeof(ECCPUBLICKEYBLOB))
	{
		ESKFerr(ESKF_F_SKF_SM3_INIT, ESKF_R_SKF_EXPORT_PUBLIC_KEY_FAILED);
		return 0;
	}
	
	if((rv = SKF_ExportPublicKey(*gh_container,TRUE,pPubKey,&ulPubKeyLen)) != SAR_OK) {
		ESKFerr(ESKF_F_SKF_SM3_INIT, ESKF_R_SKF_EXPORT_PUBLIC_KEY_FAILED);
		return 0;
	}
	memcpy(&EccPubKey,pPubKey,ulPubKeyLen);
	memcpy(pucId,"1234567812345678",16);
	ulIdLen = 16;
	if ((rv = SKF_DigestInit(*gh_dev, SGD_SM3, &EccPubKey, pucId, ulIdLen, &(ctx->md_data))) != SAR_OK) {
		ESKFerr(ESKF_F_SKF_SM3_INIT, ESKF_R_SKF_DIGEST_INIT_FAILED);
		return 0;
	}

	//TODO free
	if(pPubKey != NULL){
		free(pPubKey);
	}
	return 1;
}

static int skf_sm3_update(EVP_MD_CTX *ctx, const void *data, size_t count) {
	ULONG rv;
	BYTE *pbData = (BYTE *)data;
	ULONG ulDataLen = (ULONG)count;

	if ((rv = SKF_DigestUpdate(ctx->md_data, pbData, ulDataLen)) != SAR_OK) {
		ESKFerr(ESKF_F_SKF_SM3_UPDATE, ESKF_R_SKF_DIGEST_UPDATE_FAILED);
		return 0;
	}

	return 1;
}



static int skf_sm3_final(EVP_MD_CTX *ctx, unsigned char *md) {
	ULONG rv;
	BYTE *pHashData = (BYTE *)md;
	ULONG ulHashLen = SM3_DIGEST_LENGTH;
	
	if ((rv = SKF_DigestFinal(ctx->md_data, pHashData, &ulHashLen)) != SAR_OK) {
		ESKFerr(ESKF_F_SKF_SM3_FINAL, ESKF_R_SKF_DIGEST_FINAL_FAILED);
		return 0;
	}
	if ((rv = SKF_CloseHandle(ctx->md_data)) != SAR_OK) {
		ESKFerr(ESKF_F_SKF_SM3_FINAL, ESKF_R_SKF_CLOSE_HANDLE_FAILED);
		return 0;
	}

	ctx->md_data = NULL;
	return 1;
}

static const EVP_MD skf_sm3 = {
	NID_sm3,
	NID_sm3WithRSAEncryption,
	SM3_DIGEST_LENGTH,
	0,
	skf_sm3_init,
	skf_sm3_update,
	skf_sm3_final,
	NULL,
	NULL,
	SM3_CBLOCK,
	sizeof(EVP_MD *) + sizeof(HANDLE),
};

static int skf_digest_nids[] = {NID_sm3, 0};
static int skf_num_digests = sizeof(skf_digest_nids-1)/sizeof(skf_digest_nids[0]);

static int skf_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid) {
	if (!digest) {
		*nids = skf_digest_nids;
		return skf_num_digests;
	}

	switch (nid) {
	case NID_sm3:
		*digest = &skf_sm3;
		break;
	default:
		*digest = NULL;
		return 0;
	}

	return 1;
}
//skf sm3 end.

static int ECDSA_SIG_set_ECCSIGNATUREBLOB(ECDSA_SIG *sig, const ECCSIGNATUREBLOB *blob) {
	if (!(sig->r = BN_bin2bn(blob->r, sizeof(blob->r), sig->r))) {
		GMAPIerr(GMAPI_F_ECDSA_SIG_SET_ECCSIGNATUREBLOB, ERR_R_BN_LIB);
		return 0;
	}

	if (!(sig->s = BN_bin2bn(blob->s, sizeof(blob->s), sig->s))) {
		GMAPIerr(GMAPI_F_ECDSA_SIG_SET_ECCSIGNATUREBLOB, ERR_R_BN_LIB);
		return 0;
	}

	return 1;
}

//skf rsa sign begin.
static int skf_rsa_sign(int type, const unsigned char *m, unsigned int mlen,
	unsigned char *sig, unsigned int *siglen, const RSA *rsa)
{
	ULONG rv;
	BYTE *data = (BYTE *)m;
	ULONG dataLen = (ULONG)mlen;
	BYTE signature[1024];
	ULONG sigLen;

	/* we need to check if container type is RSA */

	sigLen = (ULONG)sizeof(signature);
	if ((rv = SKF_RSASignData(*gh_container, data, dataLen, signature, &sigLen)) != SAR_OK) {
		ESKFerr(ESKF_F_SKF_RSA_SIGN, ESKF_R_SIGN_FAILED);
		return 0;
	}

	/* do we need to convert signature format? */
	memcpy(sig, signature, sigLen);
	*siglen = (unsigned int)sigLen;
	return 1;
}

static RSA_METHOD skf_rsa = {
	"SKF RSA method",     //name
	NULL,                 //rsa_pub_enc
	NULL,                 //rsa_pub_dec
	NULL,                 //rsa_priv_enc
	NULL,                 //rsa_priv_dec
	NULL,                 //rsa_mod_exp
	NULL,                 //bn_mod_exp
	NULL,                 //init
	NULL,                 //finish
	NULL,                 //flags
	NULL,                 //app_data
	skf_rsa_sign,         //rsa_sign
	NULL,                 //rsa_verify
	NULL,                 //rsa_keygen
};

static void printHex(unsigned char* _buf,int _lenth){
        int i=0;
        printf("\n------------hex begin-----------\n");
        for(i=0;i<_lenth;i++){
                printf("%02x",_buf[i]);
        }
        printf("\n------------hex end------------\n");
}

static ECDSA_SIG *skf_sm2sign_sig(const unsigned char *dgst, int dgstlen,
	const BIGNUM *in_kinv, const BIGNUM *in_r, EC_KEY *ec_key)
{
	ECDSA_SIG *ret = NULL;
	BYTE *pbDigest = (BYTE *)dgst;
	ULONG ulDigestLen = (ULONG)dgstlen;
	ECCSIGNATUREBLOB sigBlob;
	ULONG rv;
	int ok = 0;
	int i = 0;

	if (in_kinv || in_r) {
		
	}
	if ((rv = SKF_ECCSignData(*gh_container,pbDigest, ulDigestLen, &sigBlob)) != SAR_OK) {
		goto end;
	}
	//test print begin.
	printf("sm2 sign r\n");
	printHex(sigBlob.r,64);
	printf("sm2 sign s\n");
	printHex(sigBlob.s,64);
	//test print end.

	/*
	rv = SKF_ECCVerify(*gh_dev,&EccPubKey,pHashData,ulHashLen,&sigBlob);
	printf("rv = %x \n");
	*/
	
	if (!(ret = ECDSA_SIG_new())) {
		goto end;
	}
	if (!ECDSA_SIG_set_ECCSIGNATUREBLOB(ret, &sigBlob)) {
		goto end;
	}

	ok = 1;
end:
	if (!ok && ret) {
		ECDSA_SIG_free(ret);
		ret = NULL;
	}

	return ret;
}

static EC_KEY_METHOD skf_sm2sign = {
	"SKF-SM2 signature)",            //name
	0,                               //flags
	NULL,                            //init
	NULL,                            //finish
	NULL,                            //copy
	NULL,                            //set_group
	NULL,                            //set_private
	NULL,                            //set_public
	NULL,                            //keygen
	NULL,                            //compute_key
	NULL,                            //sign
	NULL,                            //sign_setup
	skf_sm2sign_sig,                 //sign_sig
	NULL,                            //verify
	NULL,                            //verify_sig
#ifndef OPENSSL_NO_SM2
	NULL,                            //encrypt
	NULL,                            //do_encrypt
	NULL,                            //decrypt
	NULL                             //do_decrypt
#endif
};
	
//skf rsa sign end.

//skf cipher begin.
static int skf_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,	const unsigned char *iv, int enc) {
	ULONG rv;
	ULONG ulAlgID;
	BLOCKCIPHERPARAM param;
	
	switch (EVP_CIPHER_CTX_nid(ctx)) {
	/*
	case NID_ssf33_ecb:
		ulAlgID = SGD_SSF33_ECB;
		break;
	case NID_ssf33_cbc:	
		ulAlgID = SGD_SSF33_CBC;
		break;
	case NID_ssf33_cfb128:
		ulAlgID = SGD_SSF33_CFB;
		break;
	case NID_ssf33_ofb128:
		ulAlgID = SGD_SSF33_OFB;
		break;
	*/

	case NID_sm1_ecb:
		ulAlgID = SGD_SM1_ECB;
		break;
	case NID_sm1_cbc:
		ulAlgID = SGD_SM1_CBC;
		break;
	/*
	case NID_sm1_cfb128:
		ulAlgID = SGD_SM1_CFB;
		break;
	case NID_sm1_ofb128:
		ulAlgID = SGD_SM1_OFB;
		break;
	*/

	case NID_sms4_ecb:
		ulAlgID = SGD_SM4_ECB;
		break;
	case NID_sms4_cbc:
		ulAlgID = SGD_SM4_CBC;
		break;
	/*
	case NID_sms4_cfb128:
		ulAlgID = SGD_SM4_CFB;
		break;
	case NID_sms4_ofb128:
		ulAlgID = SGD_SM4_OFB;
		break;
	*/

	default:
		OPENSSL_assert(0);
		return 0;
	}
	
	if ((rv = SKF_SetSymmKey(*gh_dev, (BYTE *)key, ulAlgID, &(ctx->cipher_data))) != SAR_OK) {
		ESKFerr(ESKF_F_SKF_INIT_KEY, ESKF_R_SKF_SET_SYMMKEY_FAILED);
		return 0;
	}
	
	memcpy(&(param.IV), ctx->iv, ctx->cipher->block_size);
	param.IVLen = ctx->cipher->block_size;
	param.PaddingType = SKF_NO_PADDING;
	param.FeedBitLen = 0;

	if (ctx->encrypt) {
		if ((rv = SKF_EncryptInit(ctx->cipher_data, param)) != SAR_OK) {
			ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_ENCINIT_FAILED);
			return 0;
		}
	} else {
		if ((rv = SKF_DecryptInit(ctx->cipher_data, param)) != SAR_OK) {
			ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_DECINIT_FAILED);
			return 0;
		}
	}
	return 1;
}


static int skf_cipher_cleanup(EVP_CIPHER_CTX *ctx) {
	return 1;
}

static int _cipher_mode(EVP_CIPHER_CTX *ctx, unsigned char *out,	const unsigned char *in, size_t len) {
	ULONG rv;
	BLOCKCIPHERPARAM param;
	ULONG ulDataLen = 0;
	ULONG ulEncryptedLen =0;
	ULONG ulTempCipherLen= 0;
	ULONG ulLeftLen =0;
	BYTE block[MAX_IV_LEN] = {0};
	int  n = 0;
	int  b = 0;
	int  bl= 0;
	int  i = 0;
	
	ulDataLen = len - len % ctx->cipher->block_size;
	ulLeftLen = len - ulDataLen;
	if (ctx->encrypt) {
		if(ulLeftLen){ //如果数据长度不是block_size的整数倍
			if(ulDataLen){
				if ((rv = SKF_EncryptUpdate(ctx->cipher_data, (BYTE *)in, ulDataLen,NULL, &ulTempCipherLen)) != SAR_OK) {
					ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_ENC_FAILED);
					return 0;
				}
				if ((rv = SKF_EncryptUpdate(ctx->cipher_data, (BYTE *)in, ulDataLen,(BYTE *)out, &ulTempCipherLen)) != SAR_OK) {
					ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_ENC_FAILED);
					return 0;
				}
				
				b  = ctx->cipher->block_size;
				bl = ctx->cipher->block_size - ulLeftLen;
				n = bl;
				
			    for (i = ulLeftLen; i < b; i++)
			        block[i] = n;
				
				memcpy(block, in+ulDataLen, ulLeftLen);
				if ((rv = SKF_EncryptUpdate(ctx->cipher_data, (BYTE *)block, ctx->cipher->block_size,NULL, &ulEncryptedLen)) != SAR_OK) {
					ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_ENC_FAILED);
					return 0;
				}
				if ((rv = SKF_EncryptUpdate(ctx->cipher_data, (BYTE *)block, ctx->cipher->block_size,(BYTE *)(out+ulTempCipherLen), &ulEncryptedLen)) != SAR_OK) {
					ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_ENC_FAILED);
					return 0;
				}
				ulTempCipherLen += ulEncryptedLen;
				if ((rv = SKF_EncryptFinal(ctx->cipher_data,(BYTE *)(out+ulTempCipherLen), &ulEncryptedLen)) != SAR_OK) {
					ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_ENC_FAILED);
					return 0;
				}
				ulEncryptedLen += ulTempCipherLen;
			}
			else {
				b  = ctx->cipher->block_size;
				bl = ctx->cipher->block_size - len;
				n = bl;
				
			    for (i = len; i < b; i++)
			        block[i] = n;
				
				memcpy(block, in, len);
				if ((rv = SKF_Encrypt(ctx->cipher_data, (BYTE *)block, ctx->cipher->block_size,NULL, &ulEncryptedLen)) != SAR_OK) {
					ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_ENC_FAILED);
					return 0;
				}
				if ((rv = SKF_Encrypt(ctx->cipher_data, (BYTE *)in, ctx->cipher->block_size,(BYTE *)out, &ulEncryptedLen)) != SAR_OK) {
					ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_ENC_FAILED);
					return 0;
				}
			}
		}
		else{
			if ((rv = SKF_Encrypt(ctx->cipher_data, (BYTE *)in, ulDataLen,NULL, &ulEncryptedLen)) != SAR_OK) {
				ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_ENC_FAILED);
				return 0;
			}
			if ((rv = SKF_Encrypt(ctx->cipher_data, (BYTE *)in, ulDataLen,(BYTE *)out, &ulEncryptedLen)) != SAR_OK) {
				ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_ENC_FAILED);
				return 0;
			}
		}
	} 
	else {
		if(ulLeftLen){ //判断解密数据长度是否为block_size的整数倍，如果不是整数倍则认为解密数据长度错误
			ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_DEC_DATALEN_ERROR);
			return 0;
		}
		else {
			if ((rv = SKF_Decrypt(ctx->cipher_data, (BYTE *)in, ulDataLen,NULL, &ulEncryptedLen)) != SAR_OK) {
				ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_DEC_FAILED);
				return 0;
			}
			if ((rv = SKF_Decrypt(ctx->cipher_data, (BYTE *)in, ulDataLen,(BYTE *)out, &ulEncryptedLen)) != SAR_OK) {
				ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_DEC_FAILED);
				return 0;
			}
		}
	}
	return ulEncryptedLen;
}

static int _update_mode(EVP_CIPHER_CTX *ctx, unsigned char *out,	const unsigned char *in, size_t len){
	ULONG rv;
	ULONG ulDataLen = len;
	ULONG ulTempCipherLen = len;

	if(ctx->encrypt){
		if ((rv = SKF_EncryptUpdate(ctx->cipher_data, (BYTE *)in, ulDataLen,(BYTE *)out, &ulTempCipherLen)) != SAR_OK) {
			ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_ENC_FAILED);
			return 0;
		}
	}
	else {
		if ((rv = SKF_DecryptUpdate(ctx->cipher_data, (BYTE *)in, ulDataLen,(BYTE *)out, &ulTempCipherLen)) != SAR_OK) {
			ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_ENC_FAILED);
			return 0;
		}
	}
	return ulTempCipherLen;
	/*
	BLOCKCIPHERPARAM param;
	ULONG ulDataLen = 0;
	ULONG ulEncryptedLen =0;
	ULONG ulTempCipherLen= 0;
	ULONG ulLeftLen =0;
	ulDataLen = len - len % ctx->cipher->block_size;
	ulLeftLen = len - ulDataLen;
	if (ctx->encrypt) {
		if(ulLeftLen){ //如果数据长度不是block_size的整数倍
			if(ulDataLen){
				if ((rv = SKF_EncryptUpdate(ctx->cipher_data, (BYTE *)in, ulDataLen,NULL, &ulTempCipherLen)) != SAR_OK) {
					ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_ENC_FAILED);
					return 0;
				}
				if ((rv = SKF_EncryptUpdate(ctx->cipher_data, (BYTE *)in, ulDataLen,(BYTE *)out, &ulTempCipherLen)) != SAR_OK) {
					ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_ENC_FAILED);
					return 0;
				}

				memset(ctx->buf,0x00,sizeof(ctx->buf));
				ctx->buf_len = len - ulDataLen;
				memcpy(ctx->buf, in+ulDataLen, ctx->buf_len);
			}
			else {
				memset(ctx->buf,0x00,sizeof(ctx->buf));
				ctx->buf_len = len;
				memcpy(ctx->buf, in, ctx->buf_len);
				if ((rv = SKF_Encrypt(ctx->cipher_data, (BYTE *)ctx->buf, ctx->cipher->block_size,NULL, &ulEncryptedLen)) != SAR_OK) {
					ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_ENC_FAILED);
					return 0;
				}
				if ((rv = SKF_Encrypt(ctx->cipher_data, (BYTE *)in, ctx->cipher->block_size,(BYTE *)out, &ulEncryptedLen)) != SAR_OK) {
					ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_ENC_FAILED);
					return 0;
				}
				memset(ctx->buf,0x00,sizeof(ctx->buf));
				ctx->buf_len = 0;
			}
		}
		else{
			if ((rv = SKF_Encrypt(ctx->cipher_data, (BYTE *)in, ulDataLen,NULL, &ulEncryptedLen)) != SAR_OK) {
				ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_ENC_FAILED);
				return 0;
			}
			if ((rv = SKF_Encrypt(ctx->cipher_data, (BYTE *)in, ulDataLen,(BYTE *)out, &ulEncryptedLen)) != SAR_OK) {
				ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_ENC_FAILED);
				return 0;
			}
			memset(ctx->buf,0x00,sizeof(ctx->buf));
			ctx->buf_len = 0;
		}
	} 
	else {
		if(ulLeftLen){ //判断解密数据长度是否为block_size的整数倍，如果不是整数倍则认为解密数据长度错误
			ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_DEC_DATALEN_ERROR);
			return 0;
		}
		else {
			if ((rv = SKF_Decrypt(ctx->cipher_data, (BYTE *)in, ulDataLen,NULL, &ulEncryptedLen)) != SAR_OK) {
				ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_DEC_FAILED);
				return 0;
			}
			if ((rv = SKF_Decrypt(ctx->cipher_data, (BYTE *)in, ulDataLen,(BYTE *)out, &ulEncryptedLen)) != SAR_OK) {
				ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_DEC_FAILED);
				return 0;
			}
		}
	}
	return ulEncryptedLen;
	*/
}

static int _final_mode(EVP_CIPHER_CTX *ctx, unsigned char *out,	const unsigned char *in, size_t len){
	ULONG rv;
	ULONG ulDataLen = len;
	ULONG ulTempCipherLen = len;
	ULONG ulCipherLen2 = len;

	if(ctx->encrypt){
		if ((rv = SKF_EncryptUpdate(ctx->cipher_data, (BYTE *)in, ulDataLen,(BYTE *)out, &ulCipherLen2)) != SAR_OK) {
			ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_ENC_FAILED);
			return 0;
		}
		
		if ((rv = SKF_EncryptFinal(ctx->cipher_data, (BYTE *)out+ulCipherLen2, &ulTempCipherLen)) != SAR_OK) {
			ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_ENC_FAILED);
			return 0;
		}
	}
	else {
		if ((rv = SKF_DecryptFinal(ctx->cipher_data,(BYTE *)out, &ulTempCipherLen)) != SAR_OK) {
			ESKFerr(ESKF_F_SKF_CIPHER, ESKF_R_SKF_CIPHER_ENC_FAILED);
			return 0;
		}
	}
	return 1;
}

static int skf_cipher_do(EVP_CIPHER_CTX *ctx, unsigned char *out,	const unsigned char *in, size_t len) {
	switch(ctx->step){
		case 0:
			return _cipher_mode(ctx,out,in,len);
		case 1:
			return _update_mode(ctx,out,in,len);
		case 2:	
			return _final_mode(ctx,out,in,len);
	}
	return 0;
}

#define BLOCK_CIPHER_generic(cipher,mode,MODE)	\
static const EVP_CIPHER skf_##cipher##_##mode = { \
	NID_##cipher##_##mode,	\
	16,16,16,		\
	EVP_CIPH_##MODE##_MODE,	\
	skf_cipher_init,	\
	skf_cipher_do,		\
	skf_cipher_cleanup,	\
	sizeof(HANDLE),		\
	NULL,NULL,NULL,NULL };

/*
BLOCK_CIPHER_generic(ssf33,ecb,ECB)
BLOCK_CIPHER_generic(ssf33,cbc,CBC)
BLOCK_CIPHER_generic(ssf33,cfb1,CFB)
BLOCK_CIPHER_generic(ssf33,cfb8,CFB)
BLOCK_CIPHER_generic(ssf33,cfb128,CFB)
BLOCK_CIPHER_generic(ssf33,ofb128,OFB)
*/
BLOCK_CIPHER_generic(sm1,ecb,ECB)
BLOCK_CIPHER_generic(sm1,cbc,CBC)
/*
BLOCK_CIPHER_generic(sm1,cfb1,CFB)
BLOCK_CIPHER_generic(sm1,cfb8,CFB)
BLOCK_CIPHER_generic(sm1,cfb128,CFB)
BLOCK_CIPHER_generic(sm1,ofb128,OFB)
*/
BLOCK_CIPHER_generic(sms4,ecb,ECB)
BLOCK_CIPHER_generic(sms4,cbc,CBC)
/*
BLOCK_CIPHER_generic(sms4,cfb1,CFB)
BLOCK_CIPHER_generic(sms4,cfb8,CFB)
BLOCK_CIPHER_generic(sms4,cfb128,CFB)
BLOCK_CIPHER_generic(sms4,ofb128,OFB)
*/

static int skf_cipher_nids[] = {
	/*
	NID_ssf33_ecb,
	NID_ssf33_cbc,
	NID_ssf33_cfb1,
	NID_ssf33_cfb8,
	NID_ssf33_cfb128,
	NID_ssf33_ofb128,
	*/
	NID_sm1_ecb,
	NID_sm1_cbc,
	/*
	NID_sm1_cfb1,
	NID_sm1_cfb8,
	NID_sm1_cfb128,
	NID_sm1_ofb128,
	*/
	NID_sms4_ecb,
	NID_sms4_cbc,
	/*
	NID_sms4_cfb1,
	NID_sms4_cfb8,
	NID_sms4_cfb128,
	NID_sms4_ofb128,
	*/
};
	
static int skf_num_ciphers = sizeof(skf_cipher_nids)/sizeof(skf_cipher_nids[0]);

static int skf_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid) {
	if (!cipher) {
		*nids = skf_cipher_nids;
		return skf_num_ciphers;
	}

	switch (nid) {
	/*
	case NID_ssf33_ecb:
		*cipher = &skf_ssf33_ecb;
		break;
	case NID_ssf33_cbc:
		*cipher = &skf_ssf33_cbc;
		break;
	case NID_ssf33_cfb128:
		*cipher = &skf_ssf33_cfb128;
		break;
	case NID_ssf33_ofb128:
		*cipher = &skf_ssf33_ofb128;
		break;
	*/
	case NID_sm1_ecb:
		*cipher = &skf_sm1_ecb;
		break;
	case NID_sm1_cbc:
		*cipher = &skf_sm1_cbc;
		break;
	/*
	case NID_sm1_cfb128:
		*cipher = &skf_sm1_cfb128;
		break;
	case NID_sm1_ofb128:
		*cipher = &skf_sm1_ofb128;
		break;
	*/
	case NID_sms4_ecb:
		*cipher = &skf_sms4_ecb;
		break;
	case NID_sms4_cbc:
		*cipher = &skf_sms4_cbc;
		break;
	/*
	case NID_sms4_cfb128:
		*cipher = &skf_sms4_cfb128;
		break;
	case NID_sms4_ofb128:
		*cipher = &skf_sms4_ofb128;
		break;
	*/

	default:
		*cipher = NULL;
		return 0;
	}

	return 1;
}


//skf cipher end.

//skf engine functions end.


static int bind_helper(ENGINE *e) {
	if (!ENGINE_set_id(e, engine_skf_id) ||
			!ENGINE_set_destroy_function(e, skf_destroy) ||
			!ENGINE_set_init_function(e, skf_init) ||
			!ENGINE_set_finish_function(e, skf_finish) ||
			!ENGINE_set_ctrl_function(e, skf_ctrl) ||
			!ENGINE_set_cmd_defns(e, skf_cmd_defns) ||
			!ENGINE_set_name(e, engine_skf_name) ||
			!ENGINE_set_RAND(e, &skf_rand) ||
			!ENGINE_set_EC(e, &skf_sm2sign)||
			!ENGINE_set_RSA(e, &skf_rsa)   ||
			!ENGINE_set_digests(e, skf_digests) ||
			!ENGINE_set_ciphers(e, skf_ciphers) ||
			!ENGINE_set_load_pubkey_function(e, skf_load_pubkey) ||
			!ENGINE_set_load_privkey_function(e, skf_load_privkey)) {
	}else {
		ERR_load_ESKF_strings();
		return 1;
	}
}

static int bind_fn(ENGINE *e, const char *id) {
	if (id && strcmp(id, engine_skf_id)) {
		fprintf(stderr, "bad engine id\n");
		return 0;
	}
	if (!bind_helper(e)) {
		fprintf(stderr, "bind failed\n");
		return 0;
	}
	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN();
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn);

