#include <stdio.h>
#include <openssl/err.h>
#include "e_skf_err.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(0,func,0)
# define ERR_REASON(reason) ERR_PACK(0,0,reason)

static ERR_STRING_DATA ESKF_str_functs[] = {
    {ERR_FUNC(ESKF_F_DEV_AUTH), "DEV_AUTH"},
    {ERR_FUNC(ESKF_F_OPEN_APP), "OPEN_APP"},
    {ERR_FUNC(ESKF_F_OPEN_CONTAINER), "OPEN_CONTAINER"},
    {ERR_FUNC(ESKF_F_OPEN_DEV), "OPEN_DEV"},
    {ERR_FUNC(ESKF_F_SET_AUTHKEY), "SET_AUTHKEY"},
    {ERR_FUNC(ESKF_F_SET_USERPIN), "SET_USERPIN"},
    {ERR_FUNC(ESKF_F_SKF_CIPHER), "SKF_CIPHER"},
    {ERR_FUNC(ESKF_F_SKF_CIPHERS), "SKF_CIPHERS"},
    {ERR_FUNC(ESKF_F_SKF_DIGESTS), "SKF_DIGESTS"},
    {ERR_FUNC(ESKF_F_SKF_ENGINE_CTRL), "SKF_ENGINE_CTRL"},
    {ERR_FUNC(ESKF_F_SKF_FINISH), "SKF_FINISH"},
    {ERR_FUNC(ESKF_F_SKF_INIT), "SKF_INIT"},
    {ERR_FUNC(ESKF_F_SKF_INIT_KEY), "SKF_INIT_KEY"},
    {ERR_FUNC(ESKF_F_SKF_LOAD_PUBKEY), "SKF_LOAD_PUBKEY"},
    {ERR_FUNC(ESKF_F_SKF_RAND_BYTES), "SKF_RAND_BYTES"},
    {ERR_FUNC(ESKF_F_SKF_RSA_SIGN), "SKF_RSA_SIGN"},
    {ERR_FUNC(ESKF_F_SKF_SM2_DO_SIGN), "SKF_SM2_DO_SIGN"},
    {ERR_FUNC(ESKF_F_SKF_SM3_FINAL), "SKF_SM3_FINAL"},
    {ERR_FUNC(ESKF_F_SKF_SM3_INIT), "SKF_SM3_INIT"},
    {ERR_FUNC(ESKF_F_SKF_SM3_UPDATE), "SKF_SM3_UPDATE"},
    {ERR_FUNC(ESKF_F_VERIFY_PIN), "VERIFY_PIN"},
    {ERR_FUNC(ESKF_F_DEV_INFO), "DEV_INFO"},
    {ERR_FUNC(ESKF_F_GET_CONTAINER_TYPE), "CONTAINER_TYPE"},
    {0, NULL}
};

static ERR_STRING_DATA ESKF_str_reasons[] = {
    {ERR_REASON(ESKF_R_APP_ALREADY_OPENED), "app already opened"},
    {ERR_REASON(ESKF_R_APP_NOT_OPENED), "app not opened"},
    {ERR_REASON(ESKF_R_CONTAINER_ALREADY_OPENED), "container already opened"},
    {ERR_REASON(ESKF_R_CONTAINER_NOT_OPENED), "container not opened"},
    {ERR_REASON(ESKF_R_DEV_ALREADY_AUTHENTICATED),
     "dev already authenticated"},
    {ERR_REASON(ESKF_R_DEV_ALREADY_CONNECTED), "dev already connected"},
    {ERR_REASON(ESKF_R_DEV_IS_NOT_CONNECTED), "dev is not connected"},
    {ERR_REASON(ESKF_R_DEV_NOT_AUTHENCATED), "dev not authencated"},
    {ERR_REASON(ESKF_R_DEV_NOT_AUTHENTICATED), "dev not authenticated"},
    {ERR_REASON(ESKF_R_DEV_NOT_CONNECTED), "dev not connected"},
    {ERR_REASON(ESKF_R_GEN_RANDOM_FAILED), "gen random failed"},
    {ERR_REASON(ESKF_R_INVALID_CONTAINER_TYPE), "invalid container type"},
    {ERR_REASON(ESKF_R_INVALID_CTRL_CMD), "invalid ctrl cmd"},
    {ERR_REASON(ESKF_R_NOT_IMPLEMENTED), "not implemented"},
    {ERR_REASON(ESKF_R_PIN_NOT_VERIFIED), "pin not verified"},
    {ERR_REASON(ESKF_R_SIGN_FAILED), "sign failed"},
    {ERR_REASON(ESKF_R_SKF_CLOSE_HANDLE_FAILED), "skf close handle failed"},
    {ERR_REASON(ESKF_R_SKF_CONNECT_DEV_FAILED), "skf connect dev failed"},
    {ERR_REASON(ESKF_R_SKF_DEV_AUTH_FAILED), "skf dev auth failed"},
    {ERR_REASON(ESKF_R_SKF_DIGEST_FINAL_FAILED), "skf digest final failed"},
    {ERR_REASON(ESKF_R_SKF_DIGEST_INIT_FAILED), "skf digest init failed"},
    {ERR_REASON(ESKF_R_SKF_DIGEST_UPDATE_FAILED), "skf digest update failed"},
    {ERR_REASON(ESKF_R_SKF_DIS_CONNNECT_DEV_FAILED),
     "skf dis connnect dev failed"},
    {ERR_REASON(ESKF_R_SKF_EXPORT_PUBLIC_KEY_FAILED),
     "skf export public key failed"},
    {ERR_REASON(ESKF_R_SKF_GEN_RANDOM_FAILED), "skf gen random failed"},
    {ERR_REASON(ESKF_R_SKF_GET_CONTAINER_TYPE_FAILED),
     "skf get container type failed"},
    {ERR_REASON(ESKF_R_SKF_GET_DEV_INFO_FAILED), "skf get dev info failed"},
    {ERR_REASON(ESKF_R_SKF_OPEN_APPLICATION_FAILED),
     "skf open application failed"},
    {ERR_REASON(ESKF_R_SKF_OPEN_CONTAINER_FAILED),
     "skf open container failed"},
    {ERR_REASON(ESKF_R_SKF_SET_SYMMKEY_FAILED), "skf set symmkey failed"},
    {ERR_REASON(ESKF_R_SKF_VERIFY_PIN_FAILED), "skf verify pin failed"},
    {ERR_REASON(ESKF_R_SKF_LOAD_CONF_FAILED), "skf load openssl.cnf failed"},
    {ERR_REASON(ESKF_R_SKF_DEV_INFO), "skf get device info failed"},
    {ERR_REASON(ESKF_R_SKF_OBJECT_NOT_FOUND), "skf loadpubkey error"},
    {ERR_REASON(ESKF_R_SKF_CIPHER_DEC_FAILED), "skf cipher dec error"},
    {ERR_REASON(ESKF_R_SKF_CIPHER_ENC_FAILED), "skf cipher enc error"},
    {ERR_REASON(ESKF_R_SKF_CIPHER_DECINIT_FAILED), "skf cipher dec init error"},
    {ERR_REASON(ESKF_R_SKF_CIPHER_ENCINIT_FAILED), "skf cipher enc init error"},
    {ERR_REASON(ESKF_R_SKF_CIPHER_DEC_DATALEN_ERROR), "skf cipher dec datalen error"},
    {ERR_REASON(ESKF_R_SKF_CONTAINER_TYPE), "get container type error"},
    {0, NULL}
};

#endif

#ifdef ESKF_LIB_NAME
static ERR_STRING_DATA ESKF_lib_name[] = {
    {0, ESKF_LIB_NAME},
    {0, NULL}
};
#endif

static int ESKF_lib_error_code = 0;
static int ESKF_error_init = 1;

static void ERR_load_ESKF_strings(void)
{
    if (ESKF_lib_error_code == 0)
        ESKF_lib_error_code = ERR_get_next_error_library();

    if (ESKF_error_init) {
        ESKF_error_init = 0;
#ifndef OPENSSL_NO_ERR
        ERR_load_strings(ESKF_lib_error_code, ESKF_str_functs);
        ERR_load_strings(ESKF_lib_error_code, ESKF_str_reasons);
#endif

#ifdef ESKF_LIB_NAME
        ESKF_lib_name->error = ERR_PACK(ESKF_lib_error_code, 0, 0);
        ERR_load_strings(0, ESKF_lib_name);
#endif
    }
}

static void ERR_unload_ESKF_strings(void)
{
    if (ESKF_error_init == 0) {
#ifndef OPENSSL_NO_ERR
        ERR_unload_strings(ESKF_lib_error_code, ESKF_str_functs);
        ERR_unload_strings(ESKF_lib_error_code, ESKF_str_reasons);
#endif

#ifdef ESKF_LIB_NAME
        ERR_unload_strings(0, ESKF_lib_name);
#endif
        ESKF_error_init = 1;
    }
}

static void ERR_ESKF_error(int function, int reason, char *file, int line)
{
    if (ESKF_lib_error_code == 0)
        ESKF_lib_error_code = ERR_get_next_error_library();
    ERR_PUT_error(ESKF_lib_error_code, function, reason, file, line);
}
