#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include "libwebsockets.h"
#endif

#if UV_VERSION_MAJOR == 0
#error "UV version too old."
#endif

struct per_vhost_data__rn1 {
	uv_tcp_t client;
	uv_connect_t conn;
	uv_stream_t* stream;
	uv_timer_t timeout_watcher;
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;
};

struct per_vhost_data__rn1 *common_vhd;

struct per_session_data__rn1 {
	int number;
};

pid_t my_pid;
static void run_map_sync()
{
	if((my_pid = fork()) == 0)
	{
		static char *argv[] = {"/home/hrst/rn1-server/map_sync.sh", NULL};
		if((execve(argv[0], (char **)argv , NULL)) == -1)
		{
			lwsl_err("run_map_rsync(): execve failed\n");
		}
	}
	else
	{
		lwsl_err("run_map_rsync(): fork failed\n");
	}
}

static int poll_map_rsync()
{
	int status = 0;
	if(waitpid(my_pid , &status , WNOHANG) == 0)
		return -999999;

	return status;
}

static void alloc_cb(uv_handle_t* handle, size_t suggest_size, uv_buf_t* buf)
{
	buf->base = malloc(suggest_size);
	buf->len = suggest_size;
}

typedef struct __attribute__((packed))
{
	uint8_t msgid;
	uint8_t len_msb;
	uint8_t len_lsb;
	uint8_t pay[2048];
} tcpbuf_struct_t;

typedef union
{
	tcpbuf_struct_t b;
	uint8_t a[2048+3];
} tcpbuf_t;

static tcpbuf_t tcpbuf;
static int tcpbufloc;

static int send_png = 0;

void request_write_callback()
{
//	lwsl_notice("          request_write_callback()\n");
	lws_callback_on_writable_all_protocol_vhost(common_vhd->vhost, common_vhd->protocol);
}

#define MSG_RINGBUF_LEN 16

int latest_msg_lens[MSG_RINGBUF_LEN];
uint8_t internal_latest_msgs[MSG_RINGBUF_LEN][LWS_PRE+2048];
uint8_t* latest_msgs[MSG_RINGBUF_LEN];

int msg_ringbuf_wr, msg_ringbuf_rd;

void parse_message()
{
	int len = ((tcpbuf.b.len_msb<<8) | tcpbuf.b.len_lsb)+3;
	if(len < 0 || len > 2000)
	{
		lwsl_err("parse_message(): illegal len=%d!\n", len);
		return;
	}

	request_write_callback();

	int next = msg_ringbuf_wr+1; if(next >= MSG_RINGBUF_LEN) next = 0;

	if(next == msg_ringbuf_rd)
	{
		lwsl_notice("ignoring message(%d) due to ringbuf overrun\n", tcpbuf.b.msgid);
		return;
	}

	memcpy(latest_msgs[msg_ringbuf_wr], tcpbuf.a, len);
	latest_msg_lens[msg_ringbuf_wr] = len;

	msg_ringbuf_wr = next;
}

void tcphandler_read(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf)
{
	if(nread >= 0)
	{
		int uvbufloc = 0;

//		lwsl_notice("Got %d bytes!\n", (int)nread);

		while(1)
		{
			if(tcpbufloc < 3)
			{
				int amount = ((nread-uvbufloc)<3) ? (nread-uvbufloc) : 3;
				if(amount == 0)
				{
//					lwsl_notice("uv_buf fully processed\n");
					break;
				}
//				lwsl_notice("tcpbufloc(%d) < 3, uvbufloc=%d, writing %d bytes to tcpbuf\n", (int)tcpbufloc, uvbufloc, amount);
				memcpy(&tcpbuf.a[tcpbufloc], &buf->base[uvbufloc], amount);
				tcpbufloc += amount;
				uvbufloc += amount;
			}

			if(tcpbufloc >= 3)
			{
				int msglen = (tcpbuf.b.len_msb<<8) | tcpbuf.b.len_lsb;
				int in_uv_buf = nread - uvbufloc;
				if(in_uv_buf == 0)
				{
//					lwsl_notice("uv_buf fully processed\n");
					break;
				}

				int amount = (in_uv_buf>msglen) ? msglen : in_uv_buf;
				if(tcpbufloc + amount > 2000)
				{
					lwsl_err("tcpbufloc(%d) + amount(%d) > %d!\n", (int)tcpbufloc, amount, 2000);
					tcpbufloc = 0;
					break;

				}
//				lwsl_notice("tcpbufloc(%d) >= 3, uvbufloc=%d, writing %d bytes to tcpbuf\n", (int)tcpbufloc, uvbufloc, amount);
				memcpy(&tcpbuf.a[tcpbufloc], &buf->base[uvbufloc], amount);
				tcpbufloc += amount;
				uvbufloc += amount;

				if(tcpbufloc >= msglen+3)
				{
//					lwsl_notice("tcpbufloc(%d) >= msglen+3(%d), parsing(%d)\n", (int)tcpbufloc, msglen+3, tcpbuf.b.msgid);
					parse_message();
					tcpbufloc = 0;
				}
			}
		}

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
	struct per_vhost_data__rn1 *vhd = lws_container_of(conn,
			struct per_vhost_data__rn1, conn);
	vhd->stream = conn->handle;
	uv_read_start(vhd->stream, alloc_cb, tcphandler_read);
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
//	unsigned char buf[LWS_PRE + 20];
//	unsigned char *p = &buf[LWS_PRE];
//	int n, m;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__rn1));
		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);

		uv_tcp_init(lws_uv_getloop(vhd->context, 0), &vhd->client);
		common_vhd = vhd;
		int i;
		for(i = 0; i < MSG_RINGBUF_LEN; i++)
		{
			latest_msgs[i] = &internal_latest_msgs[i][LWS_PRE];
		}
		struct sockaddr_in dest;
		uv_ip4_addr("192.168.88.118", 22222, &dest);

		uv_tcp_connect(&vhd->conn, &vhd->client, (const struct sockaddr*)&dest, tcphandler_established);

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
//		lwsl_notice("                  got write callback\n");

		send_png++;

		if(send_png > 10)
		{
			send_png = 0;
			FILE *f_png = fopen("/home/hrst/rn1-server/acdcabba_0_128_128.map.png", "rb");
			if(!f_png)
			{
				lwsl_notice("err opening map file\n");
			}
			else
			{
				uint8_t pngdata_internal[LWS_PRE + 100000];
				uint8_t *pngdata = &pngdata_internal[LWS_PRE];
				pngdata[0] = 0xff; // map PNG message type id.
				pngdata[1] = 128;
				pngdata[2] = 128;
				int len = fread(&pngdata[3], 1, 99995, f_png);
				if(len < 100 || len > 99994)
				{
					lwsl_notice("Illegal png file.\n");
				}
				else
				{
					lwsl_notice("Sending png, len=%d\n", len);
					lws_write(wsi, pngdata, len+3, LWS_WRITE_BINARY);
				}
			}
		}
		else
			lws_write(wsi, latest_msgs[msg_ringbuf_rd], latest_msg_lens[msg_ringbuf_rd], LWS_WRITE_BINARY);

		msg_ringbuf_rd++; if(msg_ringbuf_rd >= MSG_RINGBUF_LEN) msg_ringbuf_rd = 0;
		if(msg_ringbuf_wr != msg_ringbuf_rd)
		{
			request_write_callback();
//			lwsl_notice("sending more, rd=%d wr=%d\n", msg_ringbuf_wr, msg_ringbuf_rd);
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
		256, /* rx buf size must be >= permessage-deflate rx size */ \
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
