#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ossl_typ.h>

#include "internal/evp_locl.h"
#include "internal/rsa_locl.h"
#include "internal/ec_lcl.h"

static void display_openssl_errors(int l) {
	const char *file;
	char buf[120];
	int e, line;

	if (ERR_peek_error() == 0)
		return;
	fprintf(stderr, "At main.c:%d:\n", l);

	while ((e = ERR_get_error_line(&file, &line))) {
		ERR_error_string(e, buf);
		fprintf(stderr, "- SSL %s: %s:%d\n", buf, file, line);
	}
}
void printHex(unsigned char* _buf,int _lenth) {
	int i=0;
	printf("\n------------hex begin-----------\n");
	for(i=0;i<_lenth;i++){
		printf("%02x",_buf[i]);
	}
	printf("\n------------hex end------------\n");
}

int main() {
	ENGINE	*engine;
	int	ret,num=20;
	char	buf[20],*name;
	OpenSSL_add_all_algorithms();
	EVP_MD_CTX* ctx = NULL;
	const EVP_MD *digest_algo;
	unsigned char digest[EVP_MAX_MD_SIZE];
	EC_KEY *ec_key = NULL;
	size_t len;
	char msg1[]="Hello Dig1";
	char msg2[]="Hello Dig2";

	//EVP_PKEY_CTX *pkey_ctx;
	/*
	const char* efile = "/home/gmssl/thirdparty/GmSSL-master-install/ssl/openssl.cnf";
	ret = CONF_modules_load_file(NULL, "engines", 0);
	if (ret <= 0) {
		fprintf(stderr, "cannot load %s\n", efile);
		display_openssl_errors(__LINE__);
		exit(1);
	}

	char *p;
	CONF *conf;
	long eline;
	conf=NCONF_new(NULL);
	if(!NCONF_load(conf,efile,&eline)){
		printf("load openssl.cnf error\n");
	}
	p=NCONF_get_string(conf,"skf_section","SO_PATH");
	printf("p=%s\n",p);
	
	ENGINE_add_conf_module();
	*/
#if OPENSSL_VERSION_NUMBER>=0x10100000
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
		| OPENSSL_INIT_ADD_ALL_DIGESTS \
		| OPENSSL_INIT_LOAD_CONFIG, NULL);
#else
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();
#endif
	ERR_clear_error();


	if((engine=ENGINE_by_id("skf")) != NULL){
		name = (char *)ENGINE_get_name(engine);
		printf("engine name :%s \n",name);
		
	}
	else{
		printf("ENGINE_by_id error!\n");
		return 0;
	}

	if (!ENGINE_init(engine)) {
		printf("Could not initialize engine\n");
		display_openssl_errors(__LINE__);
		ret = 1;
		goto end;
	}
	ENGINE_load_builtin_engines();

	
	if (!ENGINE_ctrl_cmd_string(engine, "OPEN_DEVICE", "ES3000GM VCR 1", 0)) {
		display_openssl_errors(__LINE__);
		goto end;
	}
	/*
	if (!ENGINE_ctrl_cmd_string(engine, "DEV_AUTH", "7kfcTgCLeYTwwLly", 0)) {
		display_openssl_errors(__LINE__);
		goto end;
	}
	*/

	if (!ENGINE_ctrl_cmd_string(engine, "OPEN_APP", "KOAL_ECC_APP", 0)) {
		display_openssl_errors(__LINE__);
		goto end;
	}
	
	if (!ENGINE_ctrl_cmd_string(engine, "VERIFY_PIN", "123456", 0)) {
		display_openssl_errors(__LINE__);
		goto end;
	}

	if (!ENGINE_ctrl_cmd_string(engine, "OPEN_CONTAINER", "KOAL_ECC", 0)) {
		display_openssl_errors(__LINE__);
		goto end;
	}

	memset(buf,0x00,sizeof(buf));
	num = 16;
	if(!RAND_bytes((unsigned char *)buf,num)){
		printf("skf rand_bytes error\n");
		goto end;
	}
	printHex(buf,num);

	len = sizeof(digest);
	memset(digest,"0x31",sizeof(digest));

	digest_algo = EVP_get_digestbyname("sm3");
	ctx = EVP_MD_CTX_create();
	if(ctx == NULL)
		printf("EVP_MD_CTX_new error\n");
	if (EVP_DigestInit(ctx, digest_algo) <= 0) {
		printf("EVP_DigestInit error\n");
	}

	EVP_DigestInit_ex(ctx, digest_algo,engine);
	EVP_DigestUpdate(ctx, msg1, strlen(msg1));
	len = EVP_MAX_MD_SIZE;
        EVP_DigestFinal_ex(ctx, digest, &len);
	printf("Digest:\n");
	printHex(digest,len);

	//begin sign
	if (!(ec_key = EC_KEY_new_method(engine))) {
		goto end;
	}

	unsigned char signature[256] = {0};
	unsigned int  ulSigLen = 256;
	ECDSA_SIG *sm2sinblob = ec_key->meth->sign_sig(digest,len,NULL,NULL,NULL);

	unsigned char key[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99";
	unsigned char iv[]  = "\x2B\x95\x99\x0A\x91\x51\x37\x4A\xBD\x8F\xF8\xC5\xA7\xA0\xFE\x08";
	unsigned char ciphertext[48+16] = {0};
	unsigned char plaintext[48] = {0};

	memset(plaintext,0x31,sizeof(plaintext));

	int cipher_len = 0;
	int plaintext_len = 0;

	//begin cipher.
	EVP_CIPHER_CTX* evp_cipher_ctx = EVP_CIPHER_CTX_new();
	//const EVP_CIPHER *evp_cipher = EVP_sms4_cbc();
	const EVP_CIPHER *evp_cipher = ENGINE_get_cipher(engine,NID_sm1_ecb);

	EVP_CipherInit_ex(evp_cipher_ctx,evp_cipher,engine,key,iv,1);
	cipher_len = EVP_Cipher(evp_cipher_ctx,ciphertext,plaintext,sizeof(plaintext));
	printf("EVP_Cipher encrypt:\n");
	printHex(ciphertext,cipher_len);

	memset(plaintext,0x00,sizeof(plaintext));
	EVP_CipherInit_ex(evp_cipher_ctx,evp_cipher,engine,key,iv,0);
	plaintext_len = EVP_Cipher(evp_cipher_ctx,plaintext,ciphertext,cipher_len);
	printf("EVP_Cipher dncrypt:\n");
	printHex(plaintext,plaintext_len);


	unsigned char tmp_buf[55];
	unsigned char tmp_buf2[64];
	unsigned char epms[48 + 16];
	int padl = 0;
       	int outl = sizeof(epms);

	memset(tmp_buf,0x31,sizeof(tmp_buf));

	EVP_EncryptInit_ex(evp_cipher_ctx, evp_cipher, engine, key,iv);
	EVP_EncryptUpdate(evp_cipher_ctx, epms, &outl, tmp_buf,sizeof(tmp_buf));
	EVP_EncryptFinal_ex(evp_cipher_ctx, &(epms[outl]), &padl);
	printf("outl=%d,padl=%d\n",outl,padl);
	outl += padl;

	printf("EVP_update encrypt:\n");
	printHex(epms,outl);

	memset(tmp_buf2,0x00,sizeof(tmp_buf2));
	padl = 0;

	EVP_DecryptInit_ex(evp_cipher_ctx, evp_cipher, engine, key,iv);
	EVP_DecryptUpdate(evp_cipher_ctx, tmp_buf2, &outl,epms,sizeof(epms));
	EVP_DecryptFinal_ex(evp_cipher_ctx, &(tmp_buf2[outl]), &padl);
	outl += padl;
	printf("DEC outl=%d,padl=%d\n",outl,padl);

	printf("EVP_update decrypt:\n");
	printHex(tmp_buf2,outl);


	//end cipher.

	/*
	pkey_ctx = EVP_PKEY_CTX_new(NULL, engine);
	if (pkey_ctx == NULL) {
		fprintf(stderr, "Could not create context\n");
		goto end;
	}

	if (EVP_PKEY_sign_init(pkey_ctx) <= 0) {
	fprintf(stderr, "Could not init signature\n");
	display_openssl_errors(__LINE__);
	exit(1);
	}

	if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
	fprintf(stderr, "Could not set padding\n");
	display_openssl_errors(__LINE__);
	exit(1);
	}

	if (EVP_PKEY_CTX_set_signature_md(pkey_ctx, digest_algo) <= 0) {
	fprintf(stderr, "Could not set message digest algorithm\n");
	display_openssl_errors(__LINE__);
	exit(1);
	}

	sig_len = sizeof(sig);
	if (EVP_PKEY_sign(pkey_ctx, sig, &sig_len, md,
	EVP_MD_size(digest_algo)) <= 0) {
	display_openssl_errors(__LINE__);
	exit(1);
	}
	EVP_PKEY_CTX_free(pkey_ctx);
	*/

end:
	EVP_MD_CTX_free(ctx);
	ENGINE_finish(engine);
	return 0;
}
