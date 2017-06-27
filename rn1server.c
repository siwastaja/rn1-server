#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include "libwebsockets.h"
#endif

#if UV_VERSION_MAJOR == 0
#error "UV version too old."
#endif

#define DUMB_PERIOD 50

uv_loop_t *loop;

struct per_vhost_data__rn1 {
	uv_timer_t timeout_watcher;
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;
};

struct per_session_data__rn1 {
	int number;
};

uint8_t buf[2048];

static void alloc_cb(uv_handle_t* handle, size_t suggest_size, uv_buf_t* buf)
{
	buf->base = malloc(suggest_size);
	buf->len = suggest_size;
}

void tcphandler_read(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf)
{
	if(nread >= 0)
	{
		lwsl_notice("Got %d bytes!\n", (int)nread);
	}
	else // EOF
	{
		lwsl_notice("Got EOF!\n");
//		uv_close((uv_handle_t*)tcp, on_close);
	}

	if(buf->base)
		free(buf->base);
}

static void tcphandler_established(uv_connect_t *conn, int status)
{
	lwsl_notice("Connection to the robot established!\n");
	uv_stream_t* stream = conn->handle;
	uv_read_start(stream, alloc_cb, tcphandler_read);
}


static void uv_timeout_cb_rn1(uv_timer_t *w)
{
	struct per_vhost_data__rn1 *vhd = lws_container_of(w,
			struct per_vhost_data__rn1, timeout_watcher);
	lws_callback_on_writable_all_protocol_vhost(vhd->vhost, vhd->protocol);
}

static int callback_rn1(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	struct per_session_data__rn1 *pss =
			(struct per_session_data__rn1 *)user;
	struct per_vhost_data__rn1 *vhd =
			(struct per_vhost_data__rn1 *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	unsigned char buf[LWS_PRE + 20];
	unsigned char *p = &buf[LWS_PRE];
	int n, m;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__rn1));
		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);


		uv_tcp_t* client = malloc(sizeof(uv_tcp_t));
		uv_tcp_init(lws_uv_getloop(vhd->context, 0), client);

		uv_connect_t* conn = malloc(sizeof(uv_connect_t));

		struct sockaddr_in dest;
		uv_ip4_addr("192.168.88.118", 22222, &dest);

		uv_tcp_connect(conn, client, (const struct sockaddr*)&dest, tcphandler_established);

		lwsl_notice("TCP connection requested...\n");


//		uv_timer_init(lws_uv_getloop(vhd->context, 0),
//			      &vhd->timeout_watcher);
//		uv_timer_start(&vhd->timeout_watcher,
//			       uv_timeout_cb_rn1, DUMB_PERIOD, DUMB_PERIOD);

		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (!vhd)
			break;
	//	lwsl_notice("di: LWS_CALLBACK_PROTOCOL_DESTROY: v=%p, ctx=%p\n", vhd, vhd->context);
	//	uv_timer_stop(&vhd->timeout_watcher);
	//	uv_close((uv_handle_t *)&vhd->timeout_watcher, NULL);
		break;

	case LWS_CALLBACK_ESTABLISHED:
		pss->number = 0;
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		n = lws_snprintf((char *)p, sizeof(buf) - LWS_PRE, "%d", pss->number++);
		m = lws_write(wsi, p, n, LWS_WRITE_TEXT);
		if (m < n) {
			lwsl_err("ERROR %d writing to di socket\n", n);
			return -1;
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		if (len < 6)
			break;
		if (strcmp((const char *)in, "reset\n") == 0)
			pss->number = 0;
		if (strcmp((const char *)in, "closeme\n") == 0) {
			lwsl_notice("dumb_inc: closing as requested\n");
			lws_close_reason(wsi, LWS_CLOSE_STATUS_GOINGAWAY,
					 (unsigned char *)"seeya", 5);
			return -1;
		}
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_RN1 \
	{ \
		"rn1-protocol", \
		callback_rn1, \
		sizeof(struct per_session_data__rn1), \
		10, /* rx buf size must be >= permessage-deflate rx size */ \
	}

#if !defined (LWS_PLUGIN_STATIC)
		
static const struct lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_RN1
};

LWS_EXTERN LWS_VISIBLE int
init_protocol_rn1(struct lws_context *context,
			     struct lws_plugin_capability *c)
{
	if (c->api_magic != LWS_PLUGIN_API_MAGIC) {
		lwsl_err("Plugin API %d, library API %d", LWS_PLUGIN_API_MAGIC,
			 c->api_magic);
		return 1;
	}

	c->protocols = protocols;
	c->count_protocols = ARRAY_SIZE(protocols);
	c->extensions = NULL;
	c->count_extensions = 0;

	return 0;
}

LWS_EXTERN LWS_VISIBLE int
destroy_protocol_rn1(struct lws_context *context)
{
	return 0;
}

#endif
