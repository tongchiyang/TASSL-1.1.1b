/*
 * ++
 * FACILITY:
 *
 *      Simplest SM2 TLSv1.1 Server
 *
 * ABSTRACT:
 *
 *   This is an example of a SSL server with minimum functionality.
 *    The socket APIs are used to handle TCP/IP operations. This SSL
 *    server loads its own certificate and key, but it does not verify
 *  the certificate of the SSL client.
 *
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "openssl/crypto.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/engine.h"

#define MAX_BUF_LEN 4096
#define SM2_SERVER_CERT     "../cert/certs/SS.pem"
#define SM2_SERVER_KEY      "../cert/certs/SS.pem"

#define SM2_SERVER_ENC_CERT     "../cert/certs/SE.pem"
#define SM2_SERVER_ENC_KEY      "../cert/certs/SE.pem"

#define SM2_SERVER_CA_CERT  "../cert/certs/CA.pem"

#define SM2_SERVER_CA_PATH  "."
#define SSL_ERROR_WANT_HSM_RESULT 10
#define ON   1
#define OFF  0

# define B_FORMAT_TEXT   0x8000
# define FORMAT_UNDEF    0
# define FORMAT_TEXT    (1 | B_FORMAT_TEXT)     /* Generic text */
# define FORMAT_BINARY   2                      /* Generic binary */
# define FORMAT_BASE64  (3 | B_FORMAT_TEXT)     /* Base64 */
# define FORMAT_ASN1     4                      /* ASN.1/DER */
# define FORMAT_PEM     (5 | B_FORMAT_TEXT)
# define FORMAT_PKCS12   6
# define FORMAT_SMIME   (7 | B_FORMAT_TEXT)
# define FORMAT_ENGINE   8                      /* Not really a file format */
# define FORMAT_PEMRSA  (9 | B_FORMAT_TEXT)     /* PEM RSAPubicKey format */
# define FORMAT_ASN1RSA  10                     /* DER RSAPubicKey format */
# define FORMAT_MSBLOB   11                     /* MS Key blob format */
# define FORMAT_PVK      12                     /* MS PVK file format */
# define FORMAT_HTTP     13                     /* Download using HTTP */
# define FORMAT_NSS      14                     /* NSS keylog format */

#define RETURN_NULL(x) if ((x)==NULL) exit(1)
#define RETURN_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define RETURN_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(1); }
int opt = 1;

static UI_METHOD *ui_method = NULL;
static const UI_METHOD *ui_fallback_method = NULL;

BIO *bio_in = NULL;
BIO *bio_out = NULL;
BIO *bio_err = NULL;

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

void ShowCerts(SSL * ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("数字证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("证书: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n", line);
        free(line);
        X509_free(cert);
    } else
        printf("无证书信息！\n");
}


int verify_callback(int ok, X509_STORE_CTX *ctx)
{
	if (!ok) {
		ok = 1;
	}

	return (ok);
}

#ifndef OPENSSL_NO_ENGINE
/* Try to load an engine in a shareable library */
static ENGINE *try_load_engine(const char *engine)
{
	ENGINE *e = ENGINE_by_id("dynamic");
	if (e) {
		if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engine, 0)
			|| !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
			ENGINE_free(e);
			e = NULL;
		}
	}
	return e;
}
#endif

ENGINE *setup_engine(const char *engine, int debug)
{
    ENGINE *e = NULL;
	char* name;
#ifndef OPENSSL_NO_ENGINE
    if (engine != NULL) {
        if (strcmp(engine, "auto") == 0) {
            fprintf(stderr, "enabling auto ENGINE support\n");
            ENGINE_register_all_complete();
            return NULL;
        }
        if ((e = ENGINE_by_id(engine)) == NULL
            && (e = try_load_engine(engine)) == NULL) {
            fprintf(stderr, "invalid engine \"%s\"\n", engine);
            return NULL;
        }
        if (debug) {
            ENGINE_ctrl(e, ENGINE_CTRL_SET_LOGSTREAM, 0, bio_err, 0);
        }
        ENGINE_ctrl_cmd(e, "SET_USER_INTERFACE", 0, ui_method, 0, 1);
        if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
            fprintf(stderr, "can't use that engine\n");
            ENGINE_free(e);
            return NULL;
        }
		name = (char *)ENGINE_get_name(engine);
		printf("engine name :%s \n",name);
        fprintf(stderr, "engine \"%s\" set.\n", ENGINE_get_id(e));
    }
#endif
    return e;
}

void release_engine(ENGINE *e)
{
#ifndef OPENSSL_NO_ENGINE
    if (e != NULL)
        /* Free our "structural" reference. */
        ENGINE_free(e);
#endif
}



int main(int argc, char **argv)
{
	int   ret = 0;
	int     err;
	int     verify_client = OFF; /* To verify a client certificate, set ON */

	int     listen_sock;
	int     sock;
	struct sockaddr_in sa_serv;
	struct sockaddr_in sa_cli;
	size_t client_len;
	char    *str;
	char    buf[MAX_BUF_LEN];

	SSL_CTX         *ctx = NULL;
	SSL             *ssl = NULL;
	const SSL_METHOD      *meth;
	ENGINE	*engine;
	char* name;
	
	short int       s_port = 4433;

	int hsm_tag = 0;
	int aio_tag = 0;
	
	/*----------------------------------------------------------------*/
	if (argc > 1)
	{
		for (err = 1; err < argc; err++)
		{
			if (!strcasecmp(argv[err], "-H"))
				hsm_tag = 1;
			else if (!strcasecmp(argv[err], "-A"))
				aio_tag = 1;
			else if (!strcasecmp(argv[err], "-P"))
			{
				if (argc >= (err + 2))
					s_port = atoi(argv[++err]);
				else
					s_port = 4433;
				
				if (s_port <= 0) s_port = 4433;
			}
		}
	}
	else
	{
		printf("Usage: %s [-h [-a]] [-p port]\n\t-h: Use HSM\n\t-a: Use HSM With Asynchronism Mode\n\t-p port: service port, default 4433\n", argv[0]);
	}

	printf("Service With HSM=%s AIO=%s Port=%d\n", (hsm_tag ? "YES" : "NO"), (aio_tag ? "YES" : "NO"), s_port);
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

	/*add by yangliqiang 20190717,begin*/
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
		goto err;
	}

	//engine = setup_engine("skf", 1);

	
	ENGINE_load_builtin_engines();

	
	if (!ENGINE_ctrl_cmd_string(engine, "OPEN_DEVICE", "ES3000GM VCR 1", 0)) {
		display_openssl_errors(__LINE__);
		goto err;
	}
	/*
	if (!ENGINE_ctrl_cmd_string(engine, "DEV_AUTH", "7kfcTgCLeYTwwLly", 0)) {
		display_openssl_errors(__LINE__);
		goto end;
	}
	*/

	if (!ENGINE_ctrl_cmd_string(engine, "OPEN_APP", "KOAL_ECC_APP", 0)) {
		display_openssl_errors(__LINE__);
		goto err;
	}
	
	if (!ENGINE_ctrl_cmd_string(engine, "VERIFY_PIN", "123456", 0)) {
		display_openssl_errors(__LINE__);
		goto err;
	}

	if (!ENGINE_ctrl_cmd_string(engine, "OPEN_CONTAINER", "KOAL_ECC", 0)) {
		display_openssl_errors(__LINE__);
		goto err;
	}
	/*add by yangliqiang 20190717,end*/
	
	/* Load encryption & hashing algorithms for the SSL program */
	SSL_library_init();

	/* Load the error strings for SSL & CRYPTO APIs */
	SSL_load_error_strings();

	/* Create a SSL_METHOD structure (choose a SSL/TLS protocol version) */
	meth = SSLv23_server_method();
//	set_sm2_group_id_custom(29);

	/* Create a SSL_CTX structure */
	ctx = SSL_CTX_new(meth);

	if (!ctx)
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	/* Load the server certificate into the SSL_CTX structure */
	if (SSL_CTX_use_certificate_file(ctx, SM2_SERVER_CERT, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	/* Load the private-key corresponding to the server certificate */
	if (SSL_CTX_use_PrivateKey_file(ctx, SM2_SERVER_KEY, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	/* Check if the server certificate and private-key matches */
	if (!SSL_CTX_check_private_key(ctx))
	{
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(1);
	}

	/* Load the server encrypt certificate into the SSL_CTX structure */
	if (SSL_CTX_use_certificate_file(ctx, SM2_SERVER_ENC_CERT, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	/* Load the private-key corresponding to the server encrypt certificate */
	if (SSL_CTX_use_enc_PrivateKey_file(ctx, SM2_SERVER_ENC_KEY, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	/* Check if the server encrypt certificate and private-key matches */
	if (!SSL_CTX_check_enc_private_key(ctx))
	{
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(1);
	}


	if (verify_client == ON)
	{
		/* Load the RSA CA certificate into the SSL_CTX structure */
		if (!SSL_CTX_load_verify_locations(ctx, SM2_SERVER_CA_CERT, NULL))
		{
			ERR_print_errors_fp(stderr);
			exit(1);
		}

		/* Set to require peer (client) certificate verification */
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
		//SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
		//SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

		/* Set the verification depth to 1 */
		SSL_CTX_set_verify_depth(ctx, 1);

	}
	/* ----------------------------------------------- */
	/* Set up a TCP socket */
	listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);   

	setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, ( void *)&opt, sizeof(opt));
	RETURN_ERR(listen_sock, "socket");
	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family      = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port        = htons(s_port);          /* Server Port number */
	err = bind(listen_sock, (struct sockaddr*)&sa_serv, sizeof(sa_serv));

	RETURN_ERR(err, "bind");

	/* Wait for an incoming TCP connection. */
	err = listen(listen_sock, 5);                    

	RETURN_ERR(err, "listen");
	client_len = sizeof(sa_cli);

	/* Socket for a TCP/IP connection is created */
	sock = accept(listen_sock, (struct sockaddr *)&sa_cli, (socklen_t *)&client_len);

	RETURN_ERR(sock, "accept");
	close(listen_sock);

	printf("Connection from %lx, port %x\n",
		sa_cli.sin_addr.s_addr, 
		sa_cli.sin_port);

	/* ----------------------------------------------- */
	/* TCP connection is ready. */
	/* A SSL structure is created */

	ssl = SSL_new(ctx);

	RETURN_NULL(ssl);

	/* Assign the socket into the SSL structure (SSL and socket without BIO) */
	SSL_set_fd(ssl, sock);

	/* Perform SSL Handshake on the SSL server */
	/*err = SSL_accept(ssl);*/
	SSL_set_accept_state(ssl);
	while (1)
	{
		err = SSL_do_handshake(ssl);
		if (err <= 0)
		{
			if (SSL_get_error(ssl, err) == SSL_ERROR_WANT_HSM_RESULT)
				continue;
			else
			{
				ERR_print_errors_fp(stderr);
				goto err;
			}
		}
		else
			break;
	}

	RETURN_SSL(err);

	/* Informational output (optional) */
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));
	ShowCerts(ssl);
	

	/*------- DATA EXCHANGE - Receive message and send reply. -------*/
	/* Receive data from the SSL client */
	while(1){
		memset(buf, 0x00, sizeof(buf));
		err = SSL_read(ssl, buf, sizeof(buf) - 1);
		if(err <= 0){
			printf("ssl_read fail!\n");
			break;
		}
		
		printf("the buf =[%s]\n", buf);
		break;
	}

	RETURN_SSL(err);

	buf[err] = '\0';

	printf("Received %d chars:'%s'\n", err, buf);

	/* Send data to the SSL client */
	err = SSL_write(ssl,
		"-----This message is from the SSL server-----\n", 
		strlen("-----This message is from the SSL server-----\n"));

	RETURN_SSL(err);

	/*--------------- SSL closure ---------------*/
	/* Shutdown this side (server) of the connection. */

	err = SSL_shutdown(ssl);

	RETURN_SSL(err);

	/* Terminate communication on a socket */
	close(sock);

err:

	/* Free the SSL structure */
	if (ssl) SSL_free(ssl);

	/* Free the SSL_CTX structure */
	if (ctx) SSL_CTX_free(ctx);

	EVP_MD_CTX_free(ctx);
	ENGINE_finish(engine);

	return 0;

	
}





