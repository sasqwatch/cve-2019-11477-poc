#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/logs.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#ifdef WIN32
#include <winsock.h>
#else
#include <resolv.h>
#include <netdb.h>
#endif

//#include "log_client.h"

#define FAIL          -1
#define BUF_SIZE      16384
#define DHFILE        "dh1024.pem"
#define MAX_HOST_LEN  256

#define DELIMITER     "\r\n"
#define DELIMITER_LEN 2

#define INDEX_FILE      "/index.html"
#define INDEX_FILE_LEN  12

#define MAX_FILE_NAME_LEN 256

struct rinfo
{
  FILE *fp;
  uint8_t *domain;
  uint32_t dlen;
  uint8_t *content;
  uint32_t clen;
  uint32_t size; // total size including header size
  uint32_t sent; // actual sent size
  uint32_t rlen; // header size
};

#ifdef TIME_LOG
log_t time_log[NUM_OF_LOGS];
#endif /* TIME_LOG */

int running = 1;

int open_listener(int port);
SSL_CTX* init_server_ctx(void);
void load_certificates(SSL_CTX* ctx);
void load_dh_params(SSL_CTX *ctx, char *file);
void load_ecdh_params(SSL_CTX *ctx);
int http_parse_request(uint8_t *msg, uint32_t mlen, struct rinfo *r);
size_t fetch_content(uint8_t *buf, struct rinfo *r);
int fetch_cert(SSL *ssl, int *ad, void *arg);

void int_handler(int dummy) {
	EDGE_LOG("End of experiment");
	running = 0;
	exit(0);
}

// Origin Server Implementation
int main(int count, char *strings[]) {
	SSL *ssl;
	SSL_CTX *ctx;
	int server, client, sent = -1, rcvd = -1, offset = 0, success = 1, mlen = 0, tmp = 0;
  unsigned long start, end, stime, etime;
	char *portnum, *prefix;

	if (count != 2) {
		printf("Usage: %s <portnum>\n", strings[0]);
		exit(0);
	}

	signal(SIGINT, int_handler);
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	portnum = strings[1];

	ctx = init_server_ctx();
	load_ecdh_params(ctx);
	load_certificates(ctx);

	server = open_listener(atoi(portnum)); /* create server socket */

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	while (running) {
		if ((client = accept(server, (struct sockaddr *) &addr, &len)) > 0) {
      struct rinfo r;
      char rbuf[BUF_SIZE] = {0};
      char wbuf[BUF_SIZE] = {0};
      int ret, sndbuf, rcvbuf, optlen;

      memset(&r, 0x0, sizeof(struct rinfo));
      EDGE_LOG("New Connection is accepted");

		  ssl = SSL_new(ctx);
		  SSL_set_fd(ssl, client);      
      SSL_set_time_log(ssl, NULL);

		  if (SSL_accept(ssl) == FAIL)
      {
			  ERR_print_errors_fp(stderr);
        success = 0;
      }

      if (success)
      {
        while (rcvd < 0)
        {
          rcvd = SSL_read(ssl, rbuf, BUF_SIZE);
        }

        RECORD_LOG(SSL_get_time_log(ssl), SERVER_SERVE_HTML_START);
        EDGE_LOG("rcvd: %d", rcvd);
        if (rcvd > 0)
        {
          EDGE_LOG("before http parse requeset");
          http_parse_request(rbuf, rcvd, &r);
          mlen = fetch_content(wbuf, &r);
          EDGE_LOG("content length: %d, content sent: %d", r.size, r.sent);
        }

        while (r.size > r.sent)
        {
          EDGE_LOG("Before Sending (mlen): %d bytes", mlen);
          tmp = 0;
          while (tmp < mlen)
          {
  		      sent = SSL_write(ssl, wbuf, mlen);
            if (sent > 0)
              tmp += sent;
            else
            {
              switch (SSL_get_error(ssl, sent))
              {
                case SSL_ERROR_NONE:
                  printf("SSL_ERROR_NONE\n");
                  break;
                case SSL_ERROR_ZERO_RETURN:
                  printf("SSL_ERROR_ZERO_RETURN\n");
                  break;
                case SSL_ERROR_WANT_READ:
                  printf("SSL_ERROR_WANT_READ\n");
                  break;
                case SSL_ERROR_WANT_WRITE:
                  printf("SSL_ERROR_WANT_WRITE\n");
                  break;
                case SSL_ERROR_WANT_X509_LOOKUP:
                  printf("SSL_ERROR_WANT_X509_LOOKUP\n");
                  break;
                case SSL_ERROR_SYSCALL:
                  printf("SSL_ERROR_SYSCALL\n");
                  printf("errno: %d\n", errno);
                  break;
                case SSL_ERROR_SSL:
                  printf("SSL_ERROR_SSL\n");
                  break;
                default:
                  printf("Unknown Error\n");
              }
            }
          }
          sent = 0;
          EDGE_LOG("After Sending (sent): %d bytes", tmp);
          if (tmp > 0)
          {
            r.sent += tmp;
          }
          mlen = fetch_content(wbuf, &r);
          EDGE_LOG("sent: %d, content length: %d, content sent: %d", 
              tmp, r.size, r.sent);
        }

        RECORD_LOG(SSL_get_time_log(ssl), SERVER_SERVE_HTML_END);
        INTERVAL(SSL_get_time_log(ssl), SERVER_SERVE_HTML_START, SERVER_SERVE_HTML_END);
        EDGE_LOG("HTTP Request Length: %d, HTTP Response Length: %d", rcvd, r.size);

		    printf("SERVER: Send the HTTP Test Page Success: %d\n", r.sent);
      
        mlen = 0;
        offset = 0;
        rcvd = -1;
        sent = -1;
      }
      close(client);
      SSL_free(ssl);
      ssl = NULL;
      success = 1;

      memset(rbuf, 0x0, BUF_SIZE);
      memset(wbuf, 0x0, BUF_SIZE);
    }
	}

	SSL_CTX_free(ctx); /* release context */
	close(server); /* close server socket */

	return 0;
}

int open_listener(int port)
{   
  int sd, ret;
	struct sockaddr_in addr;
	int enable;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	enable = 1;
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		perror("setsockopt(SO_REUSEADDR) failed");
		abort();
	}

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

	if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		perror("can't bind port");
		abort();
	}
	if (listen(sd, 10) != 0) {
		perror("Can't configure listening port");
		abort();
	}

  fcntl(sd, F_SETFL, O_NONBLOCK);

	return sd;
}

SSL_CTX* init_server_ctx(void) {
	SSL_METHOD *method;
	SSL_CTX *ctx;

	SSL_load_error_strings(); /* load all error messages */
	method = (SSL_METHOD *) TLS_server_method(); /* create new server-method instance */
	ctx = SSL_CTX_new(method); /* create new context from method */
	if (ctx == NULL) {
		EDGE_LOG("SSL_CTX init failed!");
		abort();
	}

#ifdef TLS13
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
#else
	SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
#endif /* TLS13 */

#ifdef SESSION_RESUMPTION
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
#else
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
#endif /* SESSION_RESUMPTION */

  SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256");
  SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
  SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	return ctx;
}

void load_certificates(SSL_CTX* ctx) {
	/* Load certificates for verification purpose*/
	if (SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs") != 1) {
		ERR_print_errors_fp(stderr);
		abort();
	}

	/* Set default paths for certificate verifications */
	if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
		ERR_print_errors_fp(stderr);
		abort();
	}

	SSL_CTX_set_tlsext_servername_callback(ctx, fetch_cert);
}

void load_dh_params(SSL_CTX *ctx, char *file) {
	DH *ret = 0;
	BIO *bio;

	if ((bio = BIO_new_file(file, "r")) == NULL) {
		perror("Couldn't open DH file");
	}

	BIO_free(bio);

	if (SSL_CTX_set_tmp_dh(ctx, ret) < 0) {
		perror("Couldn't set DH parameters");
	}
}

void load_ecdh_params(SSL_CTX *ctx) {
	EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

	if (!ecdh)
		perror("Couldn't load the ec key");

	if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
		perror("Couldn't set the ECDH parameter (NID_X9_62_prime256v1)");
}

int fetch_cert(SSL *ssl, int *ad, void *arg) {
	EDGE_LOG("Start: fetch_cert: ssl: %p, ad: %p, arg: %p", ssl, ad, arg);
	(void) ad;
	(void) arg;

	int ret;
	uint8_t crt_path[MAX_HOST_LEN];
	uint8_t priv_path[MAX_HOST_LEN];
	uint8_t *p;
	uint32_t len;

	if (!ssl)
		return SSL_TLSEXT_ERR_NOACK;

	const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	EDGE_LOG("Received name: %s", name);

	if (!name || name[0] == '\0')
		return SSL_TLSEXT_ERR_NOACK;

	memset(crt_path, 0x0, MAX_HOST_LEN);
	memset(priv_path, 0x0, MAX_HOST_LEN);

	p = crt_path;
	len = strlen(name);
	memcpy(p, name, len);

	ret = mkdir(p, 0775);
	if (ret < 0) {
		if (errno == EEXIST) {
			EDGE_MSG("The directory exists");
		} else {
			EDGE_MSG("Other error");
		}
	}

	p += len;
	memcpy(p, "/cert.der", 9);

	p = priv_path;
	len = strlen(name);
	memcpy(p, name, len);

	p += len;
	memcpy(p, "/priv.der", 9);

	EDGE_LOG("crt_path: %s", crt_path); EDGE_LOG("priv_path: %s", priv_path);

	if (SSL_use_certificate_file(ssl, crt_path, SSL_FILETYPE_ASN1) != 1) {
		EDGE_LOG("Loading the certificate error");
		return SSL_TLSEXT_ERR_NOACK;
	}

	EDGE_MSG("Loading the certificate success");

	if (SSL_use_PrivateKey_file(ssl, priv_path, SSL_FILETYPE_ASN1) != 1) {
		EDGE_LOG("Loading the private key error");
		return SSL_TLSEXT_ERR_NOACK;
	}

	EDGE_MSG("Loading the private key success");

	if (SSL_check_private_key(ssl) != 1) {
		EDGE_LOG("Checking the private key error");
		return SSL_TLSEXT_ERR_NOACK;
	}

	EDGE_MSG("Checking the private key success");

#ifdef TLS_DC
	if (SSL_is_delegated_credential_enabled(ssl)) {

		// replace the cert's private key with dc's private key
		uint8_t dc_path[MAX_HOST_LEN];
		memset(dc_path, 0x0, MAX_HOST_LEN);
		memset(priv_path, 0x0, MAX_HOST_LEN);

		p = dc_path;
		len = strlen(name);
		memcpy(p, name, len);

		p += len;
		memcpy(p, "/dc.bin", 7);

		EDGE_LOG("dc_path: %s", dc_path);

		p = priv_path;
		len = strlen(name);
		memcpy(p, name, len);

		p += len;
		memcpy(p, "/dc_priv.key", 12);

		EDGE_LOG("dc_priv_path: %s", priv_path);

		if (access(dc_path, F_OK) == -1)
			EDGE_LOG("[TLS_DC] Delegated credential not found");
		else if (access(priv_path, F_OK) == -1)
			EDGE_LOG("[TLS_DC] Delegated credential private key not found");
		else {
			if (SSL_use_delegated_credential_file(ssl, dc_path) != 1) {
				EDGE_LOG("[TLS_DC] Loading the delegated credential error");
				return SSL_TLSEXT_ERR_NOACK;
			}

			EDGE_MSG("[TLS_DC] Loading the delegated credential success");

			if (SSL_use_PrivateKey_dc_file(ssl, priv_path, SSL_FILETYPE_ASN1) != 1) {
				EDGE_LOG("[TLS_DC] Loading the delegated credential private key error");
				return SSL_TLSEXT_ERR_NOACK;
			}

			EDGE_MSG("[TLS_DC] Loading the delegated credential private key success");
		}
	}
#endif /* TLS_DC */

	EDGE_MSG("Finished: fetch_cert");
	return SSL_TLSEXT_ERR_OK;
}

size_t fetch_content(uint8_t *buf, struct rinfo *r)
{
  EDGE_LOG("Start: fetch_content: buf: %p, r: %p", buf, r);

	const char *resp = 	
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html\r\n"
		"Content-Length: %ld\r\n"
		"\r\n";

  size_t total, sz;
  uint8_t path[MAX_HOST_LEN];
  uint8_t *p;
  int rlen, mlen;
  rlen = 0;

  if (r->fp && r->size != 0 && r->size <= r->sent)
  {
    fclose(r->fp);
    goto ret;
  }

  if (!(r->fp))
  {
    memset(path, 0x0, MAX_HOST_LEN);
    p = path;

    memcpy(p, r->domain, r->dlen);
    p += r->dlen;
  
    memcpy(p, r->content, r->clen);
    EDGE_LOG("path: %s", path);

    r->fp = fopen(path, "rb");

    if (!(r->fp))
    {
      EDGE_LOG("Error in opening the file");
      r->size = -1;
      goto ret;
    }
  }

  if (r->size == 0)
  {
    fseek(r->fp, 0L, SEEK_END);
    r->size = total = ftell(r->fp);
    sz = total - r->sent;
    EDGE_LOG("sz: %ld, r->sent: %u", sz, r->sent);
  }

  EDGE_LOG("r->size: %u, r->sent: %u", r->size, r->sent);

  memset(buf, 0x0, BUF_SIZE);
  p = buf;
  
  if (r->sent == 0)
  {
    snprintf(p, BUF_SIZE, resp, sz);
    rlen = strlen(buf);
    r->rlen = rlen;
    r->size += rlen;
    p += rlen;
  }

  if (r->sent > 0)
    fseek(r->fp, r->sent - r->rlen, SEEK_SET);
  else
    fseek(r->fp, 0, SEEK_SET);

  if (r->size - r->sent > BUF_SIZE)
  {
    if (r->sent != 0)
      sz = BUF_SIZE;
    else
      sz = BUF_SIZE - rlen;
  }
  else
  {
    sz = r->size - r->sent;
  }
  mlen = fread(p, 1, sz, r->fp);

  EDGE_LOG("sz: %ld, rlen: %d", sz, rlen);
  EDGE_MSG("Finished: fetch_content");
ret:
  return mlen + rlen;
}

int http_parse_request(uint8_t *msg, uint32_t mlen, struct rinfo *r) {
	EDGE_LOG("Start: http_parse_request: msg: %p, mlen: %d, rinfo: %p", msg, mlen, r);
	(void) mlen;
	int l;
	uint8_t *cptr, *nptr, *p, *q;
	struct rinfo *info;

#ifdef DEBUG
  uint8_t buf[MAX_HOST_LEN] = {0};
#endif /* DEBUG */

	info = r;
	cptr = msg;

	while ((nptr = strstr(cptr, DELIMITER))) {
		l = nptr - cptr;

#ifdef DEBUG
    memcpy(buf, cptr, l);
    buf[l+1] = 0;
    EDGE_LOG("Token (%d bytes): %s", l, buf);
#endif /* DEBUG */

		p = cptr;

		while (*p == ' ')
			p++;

		if ((l > 0) && (strncmp((const char *) p, "GET", 3) == 0)) {
			p += 3;

			while (*p != '/')
				p++;

			q = p;

			while (*q != ' ' && *q != '\r')
				q++;

			if (q - p == 1) {
				info->content = (uint8_t *) malloc(INDEX_FILE_LEN + 1);
				memset(info->content, 0x0, INDEX_FILE_LEN + 1);
				memcpy(info->content, INDEX_FILE, INDEX_FILE_LEN);
				info->clen = INDEX_FILE_LEN;
			} else {
				info->content = (uint8_t *) malloc(q - p + 1);
				memset(info->content, 0x0, q - p + 1);
				memcpy(info->content, p, q - p);
				info->clen = q - p;
			}
		}

		if ((l > 0) && (strncmp((const char *) p, "Host:", 5) == 0)) {
			p += 5;

			while (*p == ' ')
				p++;

			info->domain = (uint8_t *) malloc(nptr - p + 1);
			memset(info->domain, 0x0, nptr - p + 1);
			memcpy(info->domain, p, nptr - p);
			info->dlen = nptr - p;
		}

		cptr = nptr + DELIMITER_LEN;

#ifdef DEBUG
    memset(buf, 0x0, MAX_HOST_LEN);
#endif /* DEBUG */
	}

	EDGE_LOG("Domain name in parser (%d bytes): %s", info->dlen, info->domain); EDGE_LOG("Content name in parser (%d bytes): %s", info->clen, info->content); EDGE_LOG("Finished: http_parse_request");

	return 1;
}

