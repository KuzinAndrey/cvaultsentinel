/*
 * CVaultSentinel HTTP API daemon (for encrypt/decrypt data)
 *
 * Author: Kuzin Andrey, 2023-10-02
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <event.h>
#include <event2/thread.h>
#include <evhttp.h>
#include "gen_table.h"

#ifdef PRODUCTION_MODE
#define TRACEFUNC
#define TRACE
#define DEBUG(...) {}
#else
#define TRACEFUNC fprintf(stderr,"TRACEFUNC %s:%d - %s()\n", __FILE__, __LINE__, __func__);
#define TRACE fprintf(stderr,"TRACE %s:%d - %s()\n", __FILE__, __LINE__, __func__);
#define DEBUG(...) fprintf(stderr, __VA_ARGS__);
#endif

#define HTTP_THREADS_CAP 2
#define HTTP_LISTEN_PORT 6969
#define HTTP_MAX_CONNECTIONS 1024

#define W(...) evbuffer_add_printf(buf, __VA_ARGS__)

#define PROJECT_TITLE "CVaultSentinel"

#define HTTP_UNAUTHORIZED 401

static time_t global_start_time = 0;
static int global_need_refresh = 0;

// Multithreaded HTTP server
struct http_worker {
	int id;
	pthread_t thread;
	struct event_base *base;
	struct evhttp *http;

	size_t request_count;
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
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // INADDR_ANY;
	addr.sin_port = htons(HTTP_LISTEN_PORT);

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
int www_status_handler(struct evhttp_request *, struct evbuffer *);

// Array of URL's served by HTTP
struct http_uri {
	char *uri;
	char *content_type; // if NULL - "text/html;charset=utf-8"
	function_url_handler_t handler;
} http_uri_list[] = {
	{ "/", NULL, &www_root_handler}
	,{ "/status", NULL, &www_status_handler}
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

	struct http_uri *u = http_uri_list;
	while (u->uri) {
		if (0 == strcmp(path, u->uri)) {
			if (u->content_type) conttype = u->content_type;
			http_code = u->handler(req, buf);
			break;
		}
		u++;
	} // while

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


/*
 * MAIN
 */
int main(int argc, char **argv) {
	const int sig_array[] = { SIGTERM, SIGHUP, SIGINT, SIGQUIT };

	tzset();
	global_start_time = time(NULL);

	evthread_use_pthreads();

	http_server_socket = http_bind_socket();
	if (http_server_socket < 0) {
		fprintf(stderr, "Error: can't call http_bind_socket()\n");
		return 1;
	};
	
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
		pthread_create(&workers[i].thread, NULL, http_dispatch, (void *)&workers[i]);
	} // for accept
	http_server_running = 1;

#ifdef PRODUCTION_MODE
	if (daemon(0, 0) != 0) {
		fprintf(stderr,"Can't daemonize process!\n");
		return 5;
	};
#endif

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
	W("<title>%s</title>",PROJECT_TITLE);
	W("</head>");
	W("<body bgcolor=white link=blue>");
	W("<h1>%s</h1>",PROJECT_TITLE);

	W("<p>%s</p>","TODO");
	W("</body>");
	W("</html>");

	return HTTP_OK;
} // www_root_handler()


/*
 * HTTP URL: /status
 * Statistics page for HTTP server
 */
int www_status_handler(struct evhttp_request *req, struct evbuffer *buf) {
	TRACEFUNC

	if (!req || !buf) return HTTP_INTERNAL;
	size_t total_req = 0, total_bytes = 0;
	char tm_buff[100];
	struct tm tm_st;

	W("<html>");
	W("<head>");
	W("<title>%s: %s</title>",PROJECT_TITLE,"Status page");
	W("</head>");
	W("<body bgcolor=white link=blue>");
	W("<h1>%s: %s</h1>",PROJECT_TITLE,"Status page");
	W("<pre>");
	time_t now_time = time(NULL);
	localtime_r(&global_start_time, &tm_st);
	sprintf(tm_buff, "%04d-%02d-%02d %02d:%02d:%02d", tm_st.tm_year + 1900, tm_st.tm_mon + 1, tm_st.tm_mday,
		tm_st.tm_hour, tm_st.tm_min, tm_st.tm_sec);

	W("Start time: %s\n", tm_buff);
	W("Uptime: %lu secs\n", (long)(now_time - global_start_time));
	W("Remote host: %s\n", req->remote_host);
	W("Size of crypto table: %lu\n", gen_crypt_size);
	W("===================\n");
	for (int i = 0; i < HTTP_THREADS_CAP; i++) {
		W("Thread #%d - requests %lu, send bytes %lu\n",
			workers[i].id, workers[i].request_count, workers[i].send_bytes);
		total_req += workers[i].request_count;
		total_bytes += workers[i].send_bytes;
	};
	W("===================\n"
	"Total requests: %lu\n"
	"Total send bytes %lu\n",
	total_req, total_bytes);
	W("</pre>");
	W("<p><a href=/>[back]</a></p>");

	return HTTP_OK;
} // www_status_handler()