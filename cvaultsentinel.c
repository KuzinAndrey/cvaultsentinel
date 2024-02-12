/*
 * CVaultSentinel HTTP API daemon (for encrypt/decrypt data)
 *
 * Author: Kuzin Andrey <kuzinandrey@yandex.ru>
 *
 * 2023-10-02 - Initial release
 * 2024-02-11 - Add support of Shamir Shared Secrets
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <event.h>
#include <event2/thread.h>
#include <evhttp.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#ifndef SHAMIR_MODE
#include "gen_table.h"
#else
#include <ctype.h>
#include <openssl/sha.h>
#include "shamir.h"
#include "gen_table_shamir.h"
int save_shamir_key(const char *);
int open_shamir();
void destroy_shamir();
pthread_mutex_t shamir_mutex;
#endif

#ifdef PRODUCTION_MODE
#define TRACEFUNC
#define TRACE
#define DEBUG(...) {}
#else
#define TRACEFUNC fprintf(stderr,"TRACEFUNC %s:%d - %s()\n", __FILE__, __LINE__, __func__);
#define TRACE fprintf(stderr,"TRACE %s:%d - %s()\n", __FILE__, __LINE__, __func__);
#define DEBUG(...) fprintf(stderr, __VA_ARGS__);
#endif

// working threads for web handlers
#ifndef HTTP_THREADS_CAP
#define HTTP_THREADS_CAP 2
#endif

#define HTTP_LISTEN_PORT 6969
#define HTTP_MAX_CONNECTIONS 1024

#define W(...) evbuffer_add_printf(buf, __VA_ARGS__)

#define PROJECT_TITLE "CVaultSentinel"
#define PROJECT_VERSION "v0.2"

#define HTTP_UNAUTHORIZED 401

static time_t global_start_time = 0;
static int global_need_refresh = 0;

#define XOR_BLOCK_NUM 4
struct xor_block_st {
	int num;
	pthread_t thread;
	pthread_mutex_t mutex;
	uint32_t key;
}; 
static struct xor_block_st xor_data[XOR_BLOCK_NUM] = {0};

static const char base64[]=
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

static char base64dec[256] = {0};

// Multithreaded HTTP server
struct http_worker {
	int id;
	pthread_t thread;
	struct event_base *base;
	struct evhttp *http;

	size_t request_count;
	size_t encrypt_count;
	size_t decrypt_count;
	size_t send_bytes;
}; // struct http_worker

static struct http_worker workers[HTTP_THREADS_CAP];
static int http_server_socket = -1;
static int http_server_running = 0;

// HTTP server based on event2 library
int http_bind_socket() {
	TRACEFUNC

	int r;
	int sockfd;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		fprintf(stderr, "Error: can't create socket\n");
		return -1;
	}

	int one = 1;
	r = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(int));

	struct sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(HTTP_LISTEN_PORT);

#ifdef PRODUCTION_MODE
	// listen only locally for production (we don't use HTTPS)
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#else
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
#endif

	r = bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
	if (r < 0) {
		fprintf(stderr, "Error: can't bind socket\n");
		return -1;
	}
	r = listen(sockfd, HTTP_MAX_CONNECTIONS);
	if (r < 0) {
		fprintf(stderr, "Error: can't listen socket\n");
		return -1;
	}

	int flags;
	if ((flags = fcntl(sockfd, F_GETFL, 0)) < 0
		|| fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
		fprintf(stderr, "Error: can't fcntl socket\n");
		return -1;
	}

	return sockfd;
} // http_bind_socket()

void *http_dispatch(void *arg) {
	TRACEFUNC

	struct http_worker *w = (struct http_worker *) arg;
	event_base_dispatch(w->base);

	pthread_exit(NULL);
} // http_dispatch()

// HTTP callbacks definitions
typedef int (*function_url_handler_t)(struct evhttp_request *, struct evbuffer *);
int www_root_handler(struct evhttp_request *, struct evbuffer *);
int www_info_handler(struct evhttp_request *, struct evbuffer *);
int www_status_handler(struct evhttp_request *, struct evbuffer *);
int www_encrypt_handler(struct evhttp_request *, struct evbuffer *);
int www_decrypt_handler(struct evhttp_request *, struct evbuffer *);
#ifndef PRODUCTION_MODE
int www_blockinfo_handler(struct evhttp_request *, struct evbuffer *);
#endif
#ifdef SHAMIR_MODE
int www_shamir_handler(struct evhttp_request *, struct evbuffer *);
#endif

// Array of URL's served by HTTP
struct http_uri {
	char *uri;
	char *content_type; // if NULL - "text/html;charset=utf-8"
	function_url_handler_t handler;
} http_uri_list[] = {
	{ "/", NULL, &www_root_handler}
	,{ "/info", NULL, &www_info_handler}
	,{ "/status", "text/plain", &www_status_handler}
	,{ "/encrypt", NULL, &www_encrypt_handler}
	,{ "/decrypt", NULL, &www_decrypt_handler}
#ifndef PRODUCTION_MODE
	,{ "/blockinfo", NULL, &www_blockinfo_handler}
#endif
#ifdef SHAMIR_MODE
	,{ "/shamir", NULL, &www_shamir_handler}
#endif
	,{ NULL, NULL, NULL} // end of list
}; // http_uri_list

void http_process_request(struct evhttp_request *req, void *arg) {
	TRACEFUNC

	struct http_worker *w = (struct http_worker *)arg;
	if (!w) return;

	w->request_count++;

	int http_code = HTTP_NOTFOUND; // default "Page not found"
	const char *http_message = "Page not found";
	const char *conttype = "text/html;charset=utf-8";
	struct evhttp_uri *uri_parsed = NULL;

	uri_parsed = evhttp_uri_parse(req->uri);
	if (!uri_parsed) {
		evhttp_send_error(req, HTTP_BADREQUEST, 0);
		return;
	}

	struct evbuffer *buf = evbuffer_new();
	if (!buf) {
		evhttp_send_error(req, HTTP_INTERNAL, "Can't allocate memory for reply");
		if (uri_parsed) evhttp_uri_free(uri_parsed);
		return;
	}

	char *path = evhttp_decode_uri(evhttp_uri_get_path(uri_parsed));
	if (path) {
		struct http_uri *u = http_uri_list;
		while (u->uri) {
			if (0 == strcmp(path, u->uri)) {
				if (u->content_type) conttype = u->content_type;
				http_code = u->handler(req, buf);
				if (http_code == HTTP_OK) {
					if (*(path+1) == 'e') w->encrypt_count++;
					else if (*(path+1) == 'd') w->decrypt_count++;
				}
				break;
			}
			u++;
		} // while
		free(path);
	} else http_code = HTTP_INTERNAL;

	switch (http_code) {
	case HTTP_OK:
		evhttp_add_header(req->output_headers, "Expires", "Mon, 01 Jan 1995 00:00:00 GMT");
		evhttp_add_header(req->output_headers, "Cache-Control", "no-cache, must-revalidate");
		evhttp_add_header(req->output_headers, "Pragma", "no-cache");
		if (strlen(conttype) > 0) {
			evhttp_add_header(req->output_headers, "Content-type", conttype);
		};
		w->send_bytes += evbuffer_get_length(buf);
		http_message = "OK";
		break;
	case HTTP_UNAUTHORIZED: http_message = "Unauthorized"; break;
	case HTTP_BADREQUEST: http_message = "Wrong request"; break;
	case HTTP_NOTFOUND: http_message = "Not found"; break;
	case HTTP_MOVEPERM: http_message = "Moved Permanently"; break;
	case HTTP_BADMETHOD: http_message = "Bad method"; break;
	default:
		http_code = HTTP_INTERNAL;
		http_message = "Internal server error";
	} // switch
	evhttp_send_reply(req, http_code, http_message, buf);

	if (buf) evbuffer_free(buf);
	if (uri_parsed) evhttp_uri_free(uri_parsed);
} // http_process_request()

// Main signal handler
void signal_handler(int sig) {
	TRACEFUNC
	int i;
	switch (sig) {
	case SIGTERM: case SIGINT: case SIGQUIT:
		for (i = 0; i < HTTP_THREADS_CAP; i++)
			if (workers[i].base)
				event_base_loopbreak(workers[i].base);
		http_server_running = 0;
		break;
	case SIGHUP:
		global_need_refresh = 1;
		break;
	} // swtich
} // signal_handler

//  modify password data with xor (protection from Meltdown, Spectre type of attack)
void *xor_block(void *data) {
	TRACEFUNC

	struct xor_block_st *me = data;
	DEBUG("block = %d\n",me->num);
	while (http_server_running != 1) {};

#ifdef SHAMIR_MODE
	while (!shamir_open && http_server_running) sleep(1);
	if (!http_server_running) {
		pthread_exit(NULL);
		return NULL;
	}
#endif

	size_t myblock_len = gen_crypt_size / sizeof(uint32_t) / XOR_BLOCK_NUM;
	uint32_t *myblock = (uint32_t *)&gen_crypt[me->num * (gen_crypt_size / XOR_BLOCK_NUM)];

	while (http_server_running) {
		uint32_t new_xor_code = rand();
		pthread_mutex_lock(&me->mutex);
		for (size_t i = 0; i < myblock_len; ++i) {
			myblock[i] = myblock[i] ^ me->key ^ new_xor_code;
		}
		me->key = new_xor_code;
		pthread_mutex_unlock(&me->mutex);
		sleep(1);
	} // while
	pthread_exit(NULL);
} // xor_block()

char *get_gen_crypt_part(size_t start, void *buf, size_t buf_size) {
	size_t xor_block_size = gen_crypt_size / XOR_BLOCK_NUM;
	start %= gen_crypt_size;
	size_t block_start = (start % gen_crypt_size) / xor_block_size;
	size_t block_end = ((start + buf_size) % gen_crypt_size) / xor_block_size;

	uint32_t k[16]; // this is enought for AES key and iv arrays (don't use heap)
	// uint32_t *k = calloc(buf_size / sizeof(uint32_t) + 2, sizeof(uint32_t));
	// if (!k) return NULL;

	size_t si = start / sizeof(uint32_t) % (xor_block_size / sizeof(uint32_t));
	size_t se = ((start + buf_size) / sizeof(uint32_t) + 1) % (xor_block_size / sizeof(uint32_t));
	uint32_t *block = (uint32_t *)&gen_crypt[block_start * xor_block_size];

	size_t e = xor_block_size / sizeof(uint32_t) - si; // вышли за пределы блока
	if (se >= si) e = se - si; // в пределах одного блока
	uint32_t *p = k;
	pthread_mutex_lock(&xor_data[block_start].mutex);
		for (size_t i = 0; i <= e; ++i)
			*p++ = block[si + i] ^ xor_data[block_start].key;
	pthread_mutex_unlock(&xor_data[block_start].mutex);

	if (se < si) {
		block = (uint32_t *)&gen_crypt[block_end * xor_block_size];
		pthread_mutex_lock(&xor_data[block_end].mutex);
		for (size_t i = 0; i <= se; ++i)
			*p++ = block[i + 1] ^ xor_data[block_end].key;
		pthread_mutex_unlock(&xor_data[block_end].mutex);
	}

	memcpy(buf, (char *)k + start % sizeof(uint32_t), buf_size);
	// free(k);
	return buf;
}


/*
 * MAIN
 */
int main(int argc, char **argv) {
	const int sig_array[] = { SIGTERM, SIGHUP, SIGINT, SIGQUIT };

	tzset();
	global_start_time = time(NULL);
	srand(global_start_time);

	memset(base64dec, 0x80, sizeof(base64dec));
	for (int i = 0; i < sizeof(base64) - 1; i++)
		base64dec[(int)base64[i]] = (unsigned char) i;
	base64dec['='] = 0;

	evthread_use_pthreads();

	http_server_socket = http_bind_socket();
	if (http_server_socket < 0) {
		fprintf(stderr, "Error: can't call http_bind_socket()\n");
		return 1;
	};

#ifdef PRODUCTION_MODE
	if (daemon(0, 0) != 0) {
		fprintf(stderr,"Can't daemonize process!\n");
		return 7;
	};
#endif

	for (int i = 0; i < HTTP_THREADS_CAP; i++) {
		workers[i].id = i;

		workers[i].base = event_init();
		if (!workers[i].base) {
			fprintf(stderr, "Error: can't init event_base() for worker #%d\n",i);
			return 2;
		}

		workers[i].http = evhttp_new(workers[i].base);
		if (!workers[i].http) {
			fprintf(stderr, "Error: can't init event_base() for worker #%d\n",i);
			return 3;
		}

		if (0 != evhttp_accept_socket(workers[i].http, http_server_socket)) {
			fprintf(stderr, "Error: can't run evhttp_accept_socket()\n");
			return 4;
		}

		evhttp_set_gencb(workers[i].http, http_process_request, (void *)&workers[i]);
		if (0 != pthread_create(&workers[i].thread, NULL, http_dispatch, (void *)&workers[i])) {
			fprintf(stderr, "Error: can't create pthread with %s()\n","http_dispatch");
			return 5;
		};
	} // for accept

#ifdef SHAMIR_MODE
	pthread_mutex_init(&shamir_mutex, NULL);
#endif

	for (int i = 0; i < XOR_BLOCK_NUM; i++) {
		xor_data[i].num = i;
		xor_data[i].key = 0;
		pthread_mutex_init(&xor_data[i].mutex, NULL);
		if (0 != pthread_create(&xor_data[i].thread, NULL, xor_block, (void *)&xor_data[i])) {
			fprintf(stderr, "Error: can't create pthread with %s()\n","xor_block");
			return 6;
		}
		DEBUG("Thread #%d = %p (num = %d)\n", i, (void *)xor_data[i].thread, xor_data[i].num);
	}
	http_server_running = 1;

	for (int i = 0; i < sizeof(sig_array) / sizeof(sig_array[0]); i++)
		signal(sig_array[i], signal_handler);
		
	while (http_server_running) {
		// receive HUP signal to reload data
		if (global_need_refresh == 1) {
			// TODO here refresh config or any
			global_need_refresh = 0;
		}

		// TODO something every second

		sleep(1);
	} // while

	for (int i = 0; i < HTTP_THREADS_CAP; i++) {
		pthread_join(workers[i].thread, NULL);
	} // for join

	for (int i = 0; i < XOR_BLOCK_NUM; i++) {
		pthread_join(xor_data[i].thread, NULL);
	} // for join

	return 0;
} // main()


/*
 * HTTP URL: /
 * Main page of HTTP server
 */
int www_root_handler(struct evhttp_request *req, struct evbuffer *buf) {
	TRACEFUNC
	if (!req || !buf) return HTTP_INTERNAL;

	W("<html>");
	W("<head>");
	W("<title>%s (%s)</title>", PROJECT_TITLE, PROJECT_VERSION);
	W("</head>");
	W("<body bgcolor=white link=blue>");
	W("<h1>%s (%s)</h1>", PROJECT_TITLE, PROJECT_VERSION);

#ifdef SHAMIR_MODE
	struct evkeyvalq urls;
	struct evkeyval *url;
	const char *uri;
	int open_message = 0;
	uri = evhttp_request_get_uri(req);
	if (uri && evhttp_parse_query(uri, &urls) == 0) {
		for (url = (&urls)->tqh_first; url; url = url->next.tqe_next) {
			if (strcmp("open", url->key) == 0) { open_message = 1; continue; }
		}
	} else return HTTP_BADREQUEST;
	evhttp_clear_headers(&urls);

	if (open_message && shamir_open)
		W("<p><font color=green><b>SHAMIR SECRET OPEN SUCCESS</b></font></p>");

	if (!shamir_open) W("<font color=red>SHAMIR SECRET UNKNOWN - ALL WORK IS BLOCKED</font>");
#endif

	W("<ul>"
	"<li><a href=/info>Information page</a></li>"
	"<li><a href=/status>Status for monitoring</a></li>"
	);
#ifdef SHAMIR_MODE
	if (!shamir_open)
		W("<li><a href=/shamir>Enter Shamir secret</a></li>");
#endif
#ifndef PRODUCTION_MODE
	for (int i = 0; i < XOR_BLOCK_NUM; i++) {
		W("<li><a href=/blockinfo?block=%d>XOR block #%d</a></li>", i, i);
	}
#endif
	W(
	"</ul>"
	);
	W("<p>By kuzinandrey@yandex.ru 2024-02-11</p>");
	W("</body>");
	W("</html>");

	return HTTP_OK;
} // www_root_handler()


/*
 * HTTP URL: /info
 * Information page for HTTP server
 */
int www_info_handler(struct evhttp_request *req, struct evbuffer *buf) {
	TRACEFUNC

	if (!req || !buf) return HTTP_INTERNAL;
	size_t total_req = 0, total_bytes = 0;
	char tm_buff[100];
	struct tm tm_st;

	W("<html>");
	W("<head>");
	W("<title>%s: %s</title>",PROJECT_TITLE,"Information page");
	W("</head>");
	W("<body bgcolor=white link=blue>");
	W("<h1>%s (%s): %s</h1>", PROJECT_TITLE, PROJECT_VERSION, "Information page");

#ifdef SHAMIR_MODE
	if (!shamir_open) W("<h3><font color=red>SHAMIR SECRET UNKNOWN - ALL WORK IS BLOCKED</font></h3>");
#endif

	time_t now_time = time(NULL);
	localtime_r(&global_start_time, &tm_st);
	sprintf(tm_buff, "%04d-%02d-%02d %02d:%02d:%02d", tm_st.tm_year + 1900, tm_st.tm_mon + 1, tm_st.tm_mday,
		tm_st.tm_hour, tm_st.tm_min, tm_st.tm_sec);

	W("<p>Start time: %s", tm_buff);
	W("<br>Uptime: %lu secs", (long)(now_time - global_start_time));
	W("<br>Remote host: %s", req->remote_host);
	W("<br>Size of crypto table: %lu", gen_crypt_size);
	W("<br>XOR protection threads: %d", XOR_BLOCK_NUM);
	W("<br>Web threads: %d", HTTP_THREADS_CAP);
	W("</p>");
	W("<p>Web threads statistics:<br><table border=1>");
	W("<tr>");
	char *head[] = {"Web thread","Requests","Send bytes","Encrypt","Decrypt",NULL};
	char **p = head; while(*p) { W("<th>%s</th>", *p); p++; }
	W("</tr>");
	for (int i = 0; i < HTTP_THREADS_CAP; i++) {
		W("<tr>");
		W("<td>#%d - %p</td>", workers[i].id, (void *)workers[i].thread);
		W("<td>%lu</td>", workers[i].request_count);
		W("<td>%lu</td>", workers[i].send_bytes);
		W("<td>%lu</td>", workers[i].encrypt_count);
		W("<td>%lu</td>", workers[i].decrypt_count);
		W("</tr>");
		total_req += workers[i].request_count;
		total_bytes += workers[i].send_bytes;
	};
	W("</table></p>");
	W("<p>Total requests: %lu"
	"<br>Total send bytes %lu"
	"</p>",
	total_req, total_bytes);
	W("<p><a href=/>[back]</a></p>");

	return HTTP_OK;
} // www_info_handler()

/*
 * HTTP URL: /status
 * Status page for HTTP server (for monitoring purposes)
 */
int www_status_handler(struct evhttp_request *req, struct evbuffer *buf) {
	TRACEFUNC
	if (!req || !buf) return HTTP_INTERNAL;
#ifdef SHAMIR_MODE
	if (!shamir_open) W("status=CLOSED\n");
	else
#endif
	W("status=OK\n");
	W("build=%s\n", build_id);

	return HTTP_OK;
} // www_status_handler()


#ifndef PRODUCTION_MODE
/*
 * HTTP URL: /blockinfo
 * Info page for N block of gen_crypt
 */
int www_blockinfo_handler(struct evhttp_request *req, struct evbuffer *buf) {
	TRACEFUNC

	if (!req || !buf) return HTTP_INTERNAL;

#ifdef SHAMIR_MODE
	if (!shamir_open) {
		DEBUG("Error: shamir is closed\n");
		return HTTP_INTERNAL;
	}
#endif

	struct evkeyvalq urls;
	struct evkeyval *url;
	const char *uri;

	char *block = NULL;

	uri = evhttp_request_get_uri(req);
	if (uri && evhttp_parse_query(uri, &urls) == 0) {
		for (url = (&urls)->tqh_first; url; url = url->next.tqe_next) {
			if (strcmp("block", url->key) == 0) { block = url->value; continue; }
		}
	} else return HTTP_BADREQUEST;

	if (!block) {
		evhttp_clear_headers(&urls);
		return HTTP_BADREQUEST; // HTTP 400
	}

	int num = atoi(block);
	evhttp_clear_headers(&urls);

	W("<html>");
	W("<head>");
	W("<title>%s: %s</title>",PROJECT_TITLE,"Block info");
	W("</head>");
	W("<body bgcolor=white link=blue>");
	W("<h1>%s (%s): %s</h1>", PROJECT_TITLE, PROJECT_VERSION, "Block info");

#ifdef SHAMIR_MODE
	if (!shamir_open) W("<font color=red>SHAMIR SECRET UNKNOWN - ALL WORK IS BLOCKED</font>");
#endif

	if (num >= 0 && num < XOR_BLOCK_NUM) {
		W("<pre>");
		W("Block #: %d\n", num);
		pthread_mutex_lock(&xor_data[num].mutex);
			W("Temp XOR key: %" PRIu32 "\n", xor_data[num].key);
			W("Data (first 256 bytes):\n");
			size_t start_addr = gen_crypt_size / XOR_BLOCK_NUM * num;
			for (int i = 0; i <= 0xFF; i++) {
				if (i % 16 == 0 && i > 0) W("\n");
				W("%02X ", gen_crypt[start_addr + i]);
			}
		pthread_mutex_unlock(&xor_data[num].mutex);
		W("</pre>");
		W("<p><a href=/>[back]</a></p>");
	} else {
		W("<p><font color=red>Wrong block number: %d</font></p>",num);
	}
	W("</body>");
	W("</html>");

	return HTTP_OK;
} // www_status_handler()
#endif


/*
 * HTTP URL: /encrypt
 * Encrypt data block
 */
int www_encrypt_handler(struct evhttp_request *req, struct evbuffer *buf) {
	TRACEFUNC
	if (!req || !buf) return HTTP_INTERNAL;

#ifdef SHAMIR_MODE
	if (!shamir_open) {
		DEBUG("Error: shamir is closed\n");
		return HTTP_INTERNAL;
	}
#endif

	struct evbuffer *reqinbuf;
	int http_ret = HTTP_OK;

	unsigned char *input_buf = NULL;
	size_t input_len = 0;
	size_t input_size = 0;

	unsigned char *crypto_buf = NULL;
	size_t crypto_len = 0;
	size_t crypto_size = 0;

	int key_pos = rand();
	int iv_pos = rand();
	unsigned char key[32];
	unsigned char iv[16];

	if (evhttp_request_get_command(req) != EVHTTP_REQ_POST) {
		return HTTP_BADMETHOD;
	}

	if (get_gen_crypt_part(key_pos, key, sizeof(key)) == NULL
		|| get_gen_crypt_part(iv_pos, iv, sizeof(iv)) == NULL) {
		return HTTP_INTERNAL;
	};

	input_size = 1024;
	input_buf = malloc(input_size);
	if (!input_buf) {
		DEBUG("Can't allocate memory %ld\n", input_size);
		return HTTP_INTERNAL;
	}

	reqinbuf = evhttp_request_get_input_buffer(req);

	while (evbuffer_get_length(reqinbuf)) {
		unsigned char buf[256];
		int n;
		n = evbuffer_remove(reqinbuf, buf, sizeof(buf));
		if (n > 0) {
			if (input_len + n >= input_size) {
				unsigned char *r;
				r = realloc(input_buf, input_size * 2);
				if (!r) {
					http_ret = HTTP_INTERNAL;
					goto _exit;
				}
				input_buf = r;
				input_size *= 2;
			}
			memcpy(input_buf + input_len, buf, n);
			input_len += n;
		}
	};

	crypto_size = input_len + 128; // extra space for encryption padding & any addon data
	crypto_buf = malloc(crypto_size);
	if (!crypto_buf) {
		// ERR_print_errors_fp(stderr);
		http_ret = HTTP_INTERNAL;
		goto _exit;
	}

	memcpy(crypto_buf, &key_pos, sizeof(int));
	crypto_len += sizeof(int);
	
	memcpy(crypto_buf + crypto_len, &iv_pos, sizeof(int));
	crypto_len += sizeof(int);
	

/////// MAKE AES 256 CBC ////////
	EVP_CIPHER_CTX *ctx = NULL;

	if(!(ctx = EVP_CIPHER_CTX_new())) {
		// ERR_print_errors_fp(stderr);
		http_ret = HTTP_INTERNAL;
		goto _exit;
	}

	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		// ERR_print_errors_fp(stderr);
		http_ret = HTTP_INTERNAL;
		goto _exit;
	}

	int len;
	if(1 != EVP_EncryptUpdate(ctx, crypto_buf + crypto_len, &len, input_buf, input_len)) {
		// ERR_print_errors_fp(stderr);
		http_ret = HTTP_INTERNAL;
		goto _exit;
	}
	crypto_len += len;

	if(1 != EVP_EncryptFinal_ex(ctx, crypto_buf + crypto_len, &len)) {
		// ERR_print_errors_fp(stderr);
		http_ret = HTTP_INTERNAL;
		goto _exit;
	}
	crypto_len += len;
		
	EVP_CIPHER_CTX_free(ctx);
	ctx = NULL;
///////////////
	// W("<pre>");
	// W("key = %d\n", key_pos);
	// W("iv = %d\n", iv_pos);
	// W("length = %ld\n", input_len);
	// W("size = %ld\n", input_size);
	// W("crypto_length = %ld\n", crypto_len);
	// W("crypto_size = %ld\n", crypto_size);

	// W("Original:\n");
	// for (size_t i = 0; i < input_len; i++) {
	// 	if (i % 16 == 0 && i > 0) W("\n");
	// 	W("%02X ", (char)input_buf[i] & 0xFF);
	// }

	// W("\n\nCrypto:\n");
	unsigned char b64line[75];
	size_t b64line_len = 0;
	size_t remain = crypto_len;
	unsigned char *p = crypto_buf, *o = b64line;
	while (remain >= 3) {
		*o++ = base64[p[0] >> 2];
		*o++ = base64[((p[0] & 0x03) << 4) | (p[1] >> 4)];
		*o++ = base64[((p[1] & 0x0F) << 2) | (p[2] >> 6)];
		*o++ = base64[p[2] & 0x3F];
		remain -= 3;
		p+=3;
		b64line_len += 4;
		if (b64line_len >= 72) {
			*o++ = '\0';
			W("%s\n",b64line);
			o = b64line;
			b64line_len = 0;
		}
	}
	if (remain > 0) {
		*o++ = base64[p[0] >> 2];
		if (remain == 1) {
			*o++ = base64[(p[0] & 0x03) << 4];
			*o++ = '=';
		} else {
			*o++ = base64[((p[0] & 0x03) << 4) | (p[1] >> 4)];
			*o++ = base64[(p[1] & 0x0F) << 2];
		}
		*o++ = '=';
		b64line_len += 4;
	}
	*o++ = '\0';
	if (b64line_len > 0) W("%s",b64line);

	// for (size_t i = 0; i < crypto_len; i++) {
	// 	if (i % 16 == 0 && i > 0) W("\n");
	// 	W("%02X ", (char)crypto_buf[i] & 0xFF);
	// }

	// W("</pre>");

_exit:
	if (input_buf) free(input_buf);
	if (crypto_buf) free(crypto_buf);
	if (ctx) EVP_CIPHER_CTX_free(ctx);
	return http_ret;
} // www_encrypt_handler()


/*
 * HTTP URL: /www_decrypt_handler
 * Decrypt data block
 */
int www_decrypt_handler(struct evhttp_request *req, struct evbuffer *buf) {
	TRACEFUNC
	if (!req || !buf) {
		DEBUG("Error: empty input parameters\n");
		return HTTP_INTERNAL;
	}

#ifdef SHAMIR_MODE
	if (!shamir_open) {
		DEBUG("Error: shamir is closed\n");
		return HTTP_INTERNAL;
	}
#endif

	struct evbuffer *reqinbuf;
	int http_ret = HTTP_OK;
	int key_pos = 0;
	int iv_pos = 0;
	unsigned char key[32];
	unsigned char iv[16];

	if (evhttp_request_get_command(req) != EVHTTP_REQ_POST) {
		return HTTP_BADMETHOD;
	}

	unsigned char *input_buf = NULL;
	size_t input_len = 0;
	size_t input_size = 0;

	unsigned char *crypto_buf = NULL;
	size_t crypto_size = 0;

	input_size = 1024;
	input_buf = malloc(input_size);
	if (!input_buf) {
		DEBUG("Can't allocate memory %ld\n", input_size);
		return HTTP_INTERNAL;
	}

	reqinbuf = evhttp_request_get_input_buffer(req);
	while (evbuffer_get_length(reqinbuf)) {
		unsigned char buf[256];
		int n;
		n = evbuffer_remove(reqinbuf, buf, sizeof(buf));
		if (n > 0) {
			if (input_len + n >= input_size) {
				unsigned char *r;
				r = realloc(input_buf, input_size * 2);
				if (!r) {
					DEBUG("Can't realloc memory %ld\n", input_size * 2);
					http_ret = HTTP_INTERNAL;
					goto _exit;
				}
				input_buf = r;
				input_size *= 2;
			}
			memcpy(input_buf + input_len, buf, n);
			input_len += n;
		}
	};

	// base64dec
	size_t out_len = 0;
	unsigned char block[4];
	unsigned char ch;
	int pos = 0;
	unsigned char *out = input_buf;
	int pad = 0;
	for (size_t i = 0; i < input_len; i++) {
		ch = base64dec[input_buf[i]];
		if (ch == 0x80) continue; // skip unknown chars
		if (input_buf[i] == '=') pad++;
		block[pos++] = ch;
		if (pos == 4) {
			*out++ = (block[0] << 2) | (block[1] >> 4);
			*out++ = (block[1] << 4) | (block[2] >> 2);
			*out++ = (block[2] << 6) | block[3];
			pos = 0;
			if (pad) {
				if (pad == 1) out--;
				else if (pad == 2) out -= 2;
				break;
			}
		}
	}
	out_len = out - input_buf;

	memcpy(&key_pos, input_buf, sizeof(int));
	out_len -= sizeof(int);
	memcpy(&iv_pos, input_buf + sizeof(int), sizeof(int));
	out_len -= sizeof(int);

	crypto_size = out_len;
	crypto_buf = malloc(crypto_size);
	if (!crypto_buf) {
		DEBUG("Can't allocate memory %ld\n", crypto_size);
		http_ret = HTTP_INTERNAL;
		goto _exit;
	}

	if (get_gen_crypt_part(key_pos, key, sizeof(key)) == NULL
		|| get_gen_crypt_part(iv_pos, iv, sizeof(iv)) == NULL) {
		DEBUG("Can't get keys key_pos=%d, iv_pos=%d\n", key_pos, iv_pos);
		http_ret = HTTP_INTERNAL;
		goto _exit;
	} else {
		DEBUG("Get keys key_pos=%d, iv_pos=%d\n", key_pos, iv_pos);
	};

/// AES 256 DEC ///
	EVP_CIPHER_CTX *ctx = NULL;

	if(!(ctx = EVP_CIPHER_CTX_new())) {
		DEBUG("OpenSSL error on line %d\n",__LINE__);
		// ERR_print_errors_fp(stderr);
		http_ret = HTTP_INTERNAL;
		goto _exit;
	}

	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		DEBUG("OpenSSL error on line %d\n",__LINE__);
		// ERR_print_errors_fp(stderr);
		http_ret = HTTP_INTERNAL;
		goto _exit;
	}

	int len;
	if(1 != EVP_DecryptUpdate(ctx, crypto_buf, &len, input_buf + 2 * sizeof(int), out_len)) {
		DEBUG("OpenSSL error on line %d\n",__LINE__);
		// ERR_print_errors_fp(stderr);
		http_ret = HTTP_INTERNAL;
		goto _exit;
	}
	out_len = len;

	if(1 != EVP_DecryptFinal_ex(ctx, crypto_buf + len, &len)) {
		DEBUG("OpenSSL error on line %d\n",__LINE__);
		// ERR_print_errors_fp(stderr);
		http_ret = HTTP_INTERNAL;
		goto _exit;
	}
	out_len += len;

	EVP_CIPHER_CTX_free(ctx);
	ctx = NULL;
///////////////////

	evbuffer_add(buf,crypto_buf,out_len);

_exit:
	if (input_buf) free(input_buf);
	if (crypto_buf) free(crypto_buf);
	if (ctx) EVP_CIPHER_CTX_free(ctx);
	return http_ret;
} // www_decrypt_handler()

#ifdef SHAMIR_MODE
int save_shamir_key(const char *k) {
	int key_num = 0;
	if (!k || strlen(k) < (SHAMIR_SECRET_SIZE * 8 / 6 + 1)) return -1; // Wrong size of key
	if (!isdigit(*k)) return -2; // No key number
	key_num = *k - '0';
	if (key_num < 1 || key_num > 5) return -3; // Wrong key number
	key_num -= 1;
	DEBUG("key %d = %s\n", key_num + 1, k + 1);

	// base64dec
	char block[4];
	char ch;
	int pos = 0;
	char *out = shamir_key[key_num];
	int pad = 0;
	for (size_t i = 1; i < strlen(k); i++) {
		ch = base64dec[(unsigned char)k[i]];
		if (ch == 0x80) continue; // skip unknown chars
		if (k[i] == '=') pad++;
		block[pos++] = ch;
		if (pos == 4) {
			*out++ = (block[0] << 2) | (block[1] >> 4);
			*out++ = (block[1] << 4) | (block[2] >> 2);
			*out++ = (block[2] << 6) | block[3];
			pos = 0;
			if (pad) {
				if (pad == 1) out--;
				else if (pad == 2) out -= 2;
				break;
			}
		}
	}
	shamir_key_present[key_num] = 1;
	return 0;
} // save_shamir_key()

int open_shamir() {
	char restore[SHAMIR_SECRET_SIZE];
	int found = 0;

	// We need at least 3 keys to open shamir secret
	size_t count = 0;
	for (int i = 0; i < 5; i++) {
		if (shamir_key_present[i] == 1) count++;
	};
	if (count < 3) return -1;

	// Brute force key combination
	for (int i = 0; i < 5; i++) {
	for (int j = 0; j < 5; j++) {
	for (int k = 0; k < 5; k++)
	{
		if (!shamir_key_present[i] || !shamir_key_present[j] || !shamir_key_present[k]) continue;
		if (0 == restore_shamir_secret(restore, SHAMIR_SECRET_SIZE,
			i + 1, shamir_key[i],
			j + 1, shamir_key[j],
			k + 1, shamir_key[k])
		) {
			unsigned char sha256test_secret[SHA256_DIGEST_LENGTH];
			SHA256((unsigned char *)restore, SHAMIR_SECRET_SIZE, sha256test_secret);

			DEBUG("Shamir secret SHA256 compare: ");
			if (memcmp(shamir_secret_sha256, sha256test_secret, SHA256_DIGEST_LENGTH) == 0) {
				DEBUG("OK\n");
				found = 1;
				break;
			} else {
				DEBUG("FAILED (%d,%d,%d)\n",i,j,k);
			}
		} else continue;
	} if (found) break; } if (found) break;}

	if (found != 1) return -2;

	// DECRYPT MAIN GEN_CRYPT SPACE
	char decrypto_by[SHAMIR_SECRET_SIZE * 2]; // 32 + 16 = 48 = 24 * 2 !!!
	unsigned char aes_key[32];
	unsigned char aes_iv[16];
	/*
	 *                 24 bytes          24 bytes
	 * decrypto_by |    *****       |      *****      |
	 *                    ^secret            ^secret xor sha256
	 *
	 *                 32 bytes             16 bytes
	 * aes keys   |       *key*          |    *iv*   |
	 */

	memcpy(decrypto_by, restore, SHAMIR_SECRET_SIZE);
	char *p = decrypto_by + SHAMIR_SECRET_SIZE;
	memcpy(p, restore, SHAMIR_SECRET_SIZE);
	for (int i = 0; i < SHAMIR_SECRET_SIZE; i++) {
		*(p + i) ^= gen_crypt_sha256[i];
	};

	memcpy(aes_key, decrypto_by, sizeof(aes_key));
	memcpy(aes_iv, decrypto_by + sizeof(aes_key), sizeof(aes_iv));

	// clean memory from passwords
	for (int i = 0; i < sizeof(restore); i++) restore[i] = rand() & 0xFF;
	for (int i = 0; i < sizeof(decrypto_by); i++) decrypto_by[i] = rand() & 0xFF;

	gen_crypt = malloc(gen_crypt_shamir_size);
	if (!gen_crypt) return -3; // No memory for decryption buffer

	EVP_CIPHER_CTX *ctx = NULL;

	if(!(ctx = EVP_CIPHER_CTX_new())) {
		DEBUG("OpenSSL error on line %d\n",__LINE__);
		goto _exit;
	}

	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv)) {
		DEBUG("OpenSSL error on line %d\n",__LINE__);
		goto _exit;
	}

	int len = 0;
	if(1 != EVP_DecryptUpdate(ctx, gen_crypt, &len, gen_crypt_shamir, gen_crypt_shamir_size)) {
		DEBUG("OpenSSL error on line %d\n",__LINE__);
		goto _exit;
	}
	gen_crypt_size = len;

	if(1 != EVP_DecryptFinal_ex(ctx, gen_crypt + gen_crypt_size, &len)) {
		DEBUG("OpenSSL error on line %d\n",__LINE__);
		goto _exit;
	}
	gen_crypt_size += len;

	EVP_CIPHER_CTX_free(ctx);
	ctx = NULL;
	///////////////////

	unsigned char sha256test_secret[SHA256_DIGEST_LENGTH];
	SHA256(gen_crypt, gen_crypt_size, sha256test_secret);

	DEBUG("Password space SHA256 compare: ");
	if (memcmp(gen_crypt_sha256, sha256test_secret, SHA256_DIGEST_LENGTH) == 0) {
		DEBUG("OK\n");
		unsigned char *t = realloc(gen_crypt, gen_crypt_size);
		if (t) gen_crypt = t; else {
			DEBUG("Realloc failed %d\n",__LINE__);
			goto _exit;
		}
	} else {
		DEBUG("FAILED\n");
		goto _exit;
	}

	return 0;

_exit:
	// clean memory from passwords
	for (int i = 0; i < sizeof(aes_key); i++) aes_key[i] = rand() & 0xFF;
	for (int i = 0; i < sizeof(aes_iv); i++) aes_iv[i] = rand() & 0xFF;

	if (ctx) EVP_CIPHER_CTX_free(ctx);
	if (gen_crypt) { free(gen_crypt); gen_crypt = NULL; gen_crypt_size = 0; }

	return -4;
} // open_shamir()

// clear memory from sensitive shamir data
void destroy_shamir() {
	if (!shamir_open) return;
	for (int i = 0; i < 5; i++) {
		for (int j = 0; j < SHAMIR_SECRET_SIZE; j++) {
			shamir_key[i][j] = rand() & 0xFF;
			shamir_secret[j] = rand() & 0xFF;
		}
	}
	DEBUG("Destroy shamir\n");
} // destroy_shamir()


/*
 * HTTP URL: /shamir
 * Info page for N block of gen_crypt
 */
int www_shamir_handler(struct evhttp_request *req, struct evbuffer *buf) {
	TRACEFUNC

	if (!req || !buf) return HTTP_INTERNAL;
	int ret = HTTP_INTERNAL;

	pthread_mutex_lock(&shamir_mutex);
	if (shamir_open) {
		pthread_mutex_unlock(&shamir_mutex);
		return HTTP_NOTFOUND;
	}

	struct evkeyvalq urls;
	struct evkeyval *url;
	const char *uri;

	char *shamir_key = NULL;
	int saved = 0;

	uri = evhttp_request_get_uri(req);
	if (uri && evhttp_parse_query(uri, &urls) == 0) {
		for (url = (&urls)->tqh_first; url; url = url->next.tqe_next) {
			if (strcmp("key", url->key) == 0) { shamir_key = url->value; continue; }
			if (strcmp("saved", url->key) == 0) { saved = 1; continue; }
		}
	} else {
		ret = HTTP_BADREQUEST;
		goto _exit;
	}

	if (shamir_key) {
		if (0 == save_shamir_key(shamir_key)) {
			if (open_shamir() == 0) {
				shamir_open = 1;
				destroy_shamir();
				evhttp_add_header(req->output_headers, "Location", "/?open=1");
			} else {
				evhttp_add_header(req->output_headers, "Location", "/shamir?saved=1");
			}
			ret = HTTP_MOVEPERM;
		} else ret = HTTP_INTERNAL;
		goto _exit;
	} else {
		W("<html>");
		W("<head>");
		W("<title>%s: %s</title>",PROJECT_TITLE,"Shamir keys");
		W("</head>");
		W("<body bgcolor=white link=blue>");

		W("<h1>%s: is closed</h1>",PROJECT_TITLE);

		W("<p><font color=red>No any data can be encrypted or decrypted in closed mode !!!</font></p>");
		W("<p>For open <b>%s</b> to work you must enter at least <b>3 shared keys</b>.</p>",PROJECT_TITLE);

		if (saved) {
			W("<p><font color=green>Save key successfully</font></p>");
		}

		W("<form action=/shamir method=get>");
		W("<p>Enter your shared key here: <input type=text name=key> ");
		W("<input type=submit value=Send>");
		W("</form>");

		W("<p>Data about entered shamir keys:<ul>");
		for (int i = 0; i < 5; i++) {
			W("<li>Key %d: %s</li>", i + 1, shamir_key_present[i] == 1 ?
				"<font color=green>enterred</font>"
				: "<font color=red>not enterred</font>");
		}
		W("</ul></p>");

		W("<p><a href=/>[back]</a></p>");

		W("</body>");
		W("</html>");
	}

	ret = HTTP_OK;
_exit:
	evhttp_clear_headers(&urls);
	pthread_mutex_unlock(&shamir_mutex);
	return ret;
} // www_shamir_handler()

#endif /* SHAMIR_MODE */
