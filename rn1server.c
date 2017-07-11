#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#define I32TOBUF(i_, b_, s_) {(b_)[(s_)] = ((i_)>>24)&0xff; (b_)[(s_)+1] = ((i_)>>16)&0xff; (b_)[(s_)+2] = ((i_)>>8)&0xff; (b_)[(s_)+3] = ((i_)>>0)&0xff; }
#define I16TOBUF(i_, b_, s_) {(b_)[(s_)] = ((i_)>>8)&0xff; (b_)[(s_)+1] = ((i_)>>0)&0xff; }
#define I16FROMBUF(b_, s_)  ((int16_t)( ((uint16_t)(b_)[(s_)+0]<<8) | ((uint16_t)(b_)[(s_)+1]<<0) ))
#define I32FROMBUF(b_, s_)  ((int32_t)( ((uint32_t)(b_)[(s_)+0]<<24) | ((uint32_t)(b_)[(s_)+1]<<16) | ((uint32_t)(b_)[(s_)+2]<<8) | ((uint32_t)(b_)[(s_)+3]<<0) ))

#define MAP_UNIT_W 40  // in mm
#define MAP_PAGE_W 256 // in map_units
#define MAP_W 256
#define MAP_MIDDLE_PAGE (MAP_W/2)
#define MAP_MIDDLE_UNIT (MAP_PAGE_W * MAP_MIDDLE_PAGE)


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
	int32_t view_start_x;
	int32_t view_start_y;
	int32_t view_end_x;
	int32_t view_end_y;
};

static int rsync_running = 0;

pid_t my_pid;
static void run_map_rsync()
{
	if(rsync_running)
	{
		lwsl_notice("rsync still running\n");
		return;
	}

	if((my_pid = fork()) == 0)
	{
		static char *argv[] = {"/bin/bash", "/home/hrst/rn1-server/do_map_sync.sh", NULL};
//		static char *argv[] = {"sudo", "-u", "hrst", "/home/hrst/rn1-server/map_sync.sh", NULL};
		if((execve(argv[0], (char **)argv , NULL)) == -1)
		{
			lwsl_err("run_map_rsync(): execve failed\n");
		}
	}
	else
	{
		rsync_running = 1;
	}
}

static int poll_map_rsync()
{
	if(!rsync_running)
		return -998;

	int status = 0;
	if(waitpid(my_pid , &status , WNOHANG) == 0)
		return -999;

	rsync_running = 0;
	lwsl_notice("rsync returned %d\n", status);
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
	poll_map_rsync();

	int len = ((tcpbuf.b.len_msb<<8) | tcpbuf.b.len_lsb)+3;
	if(len < 0 || len > 2000)
	{
		lwsl_err("parse_message(): illegal len=%d!\n", len);
		return;
	}

	if(tcpbuf.b.msgid == 136) // map sync request: don't relay, sync!
	{
		lwsl_notice("running map rsync\n");
		run_map_rsync();
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

uv_write_t write_req;
uv_buf_t write_uvbuf;

static void uv_tcp_write_cb(uv_write_t* req, int status)
{
	lwsl_notice("UV TCP WRITE CB status=%d\n", status);
	free(write_uvbuf.base);
	write_uvbuf.base = NULL;
}

static void do_route(int32_t x, int32_t y)
{
	if(write_uvbuf.base)
	{
		lwsl_notice("Previous TCP write unfinished.\n");
		return;
	}

	const int size = 12;
	write_uvbuf.base = malloc(size);
	write_uvbuf.len = size;
	write_uvbuf.base[0] = 56;
	write_uvbuf.base[1] = ((size-3)&0xff00)>>8;
	write_uvbuf.base[2] = (size-3)&0xff;
	I32TOBUF(x, write_uvbuf.base, 3);
	I32TOBUF(y, write_uvbuf.base, 7);
	write_uvbuf.base[11] = 0;
	uv_write(&write_req, common_vhd->stream, &write_uvbuf, 1, uv_tcp_write_cb);
}

static void do_charger()
{
	if(write_uvbuf.base)
	{
		lwsl_notice("Previous TCP write unfinished.\n");
		return;
	}

	const int size = 4;
	write_uvbuf.base = malloc(size);
	write_uvbuf.len = size;
	write_uvbuf.base[0] = 57;
	write_uvbuf.base[1] = ((size-3)&0xff00)>>8;
	write_uvbuf.base[2] = (size-3)&0xff;
	write_uvbuf.base[3] = 0;
	uv_write(&write_req, common_vhd->stream, &write_uvbuf, 1, uv_tcp_write_cb);
}

static void do_mode(int mode)
{
	if(write_uvbuf.base)
	{
		lwsl_notice("Previous TCP write unfinished.\n");
		return;
	}

	const int size = 4;
	write_uvbuf.base = malloc(size);
	write_uvbuf.len = size;
	write_uvbuf.base[0] = 58;
	write_uvbuf.base[1] = ((size-3)&0xff00)>>8;
	write_uvbuf.base[2] = (size-3)&0xff;
	write_uvbuf.base[3] = mode&0xff;
	uv_write(&write_req, common_vhd->stream, &write_uvbuf, 1, uv_tcp_write_cb);
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

static int png_send_state = 0;
static void do_send_png()
{
	png_send_state = 1;
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
		pss->view_start_x = -100;
		pss->view_start_y = -100;
		pss->view_end_x = 100;
		pss->view_end_y = 100;
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
	{
//		lwsl_notice("                  got write callback\n");

//		send_png++;

		static int xpage_s;
		static int ypage_s;
		static int xpage_e;
		static int ypage_e;

		static int xx, yy;

		if(png_send_state == 0)
		{
			lws_write(wsi, latest_msgs[msg_ringbuf_rd], latest_msg_lens[msg_ringbuf_rd], LWS_WRITE_BINARY);

			msg_ringbuf_rd++; if(msg_ringbuf_rd >= MSG_RINGBUF_LEN) msg_ringbuf_rd = 0;
			if(msg_ringbuf_wr != msg_ringbuf_rd)
			{
				request_write_callback();
	//			lwsl_notice("sending more, rd=%d wr=%d\n", msg_ringbuf_wr, msg_ringbuf_rd);
			}
		}

		if(png_send_state == 1)
		{
			xpage_s = (pss->view_start_x/MAP_UNIT_W + MAP_MIDDLE_UNIT) / MAP_PAGE_W;
			ypage_s = (pss->view_start_y/MAP_UNIT_W + MAP_MIDDLE_UNIT) / MAP_PAGE_W;
			xpage_e = (pss->view_end_x/MAP_UNIT_W + MAP_MIDDLE_UNIT) / MAP_PAGE_W;
			ypage_e = (pss->view_end_y/MAP_UNIT_W + MAP_MIDDLE_UNIT) / MAP_PAGE_W;
			xx = xpage_s;
			yy = ypage_s;
			png_send_state++;
		}
		if(png_send_state == 2)
		{
			char fname[1000];
			snprintf(fname, 999, "/home/hrst/rn1-server/acdcabba_0_%u_%u.map.png", xx, yy);
			FILE *f_png = fopen(fname, "rb");
			if(!f_png)
			{
//				if(errno != ENOENT)
					lwsl_notice("err %d opening map file\n", errno);
			}
			else
			{
				uint8_t pngdata_internal[LWS_PRE + 100000];
				uint8_t *pngdata = &pngdata_internal[LWS_PRE];
				pngdata[0] = 200; // map PNG message type id.
				int x = (xx*MAP_PAGE_W - MAP_MIDDLE_UNIT)*MAP_UNIT_W;
				int y = (yy*MAP_PAGE_W - MAP_MIDDLE_UNIT)*MAP_UNIT_W;
				lwsl_notice("Sending png map page ( %d , %d ), start mm coords ( %d , %d )\n", xx, yy, x, y);
				I32TOBUF(x, pngdata, 1);
				I32TOBUF(y, pngdata, 5);
				pngdata[9] = 1;
				int len = fread(&pngdata[10], 1, 99982, f_png);
				if(len < 100 || len > 99980)
				{
					lwsl_notice("Illegal png file.\n");
				}
				else
				{
					lwsl_notice("Sending png, len=%d\n", len);
					lws_write(wsi, pngdata, len+10, LWS_WRITE_BINARY);
					if(xx < xpage_e && yy < ypage_e) request_write_callback(); // to send more images
				}
			}
			xx++;
			if(xx > xpage_e)
			{
				xx = xpage_s;
				yy++;
				if(yy > ypage_e)
				{
					png_send_state = 0;
				}
			}
		}

	}
		break;

	case LWS_CALLBACK_RECEIVE:
		if(len == 17 && ((uint8_t*)in)[0] == 1)
		{
			pss->view_start_x = I32FROMBUF((uint8_t*)in, 1);
			pss->view_start_y = I32FROMBUF((uint8_t*)in, 5);
			pss->view_end_x = I32FROMBUF((uint8_t*)in, 9);
			pss->view_end_y = I32FROMBUF((uint8_t*)in, 13);
			lwsl_notice("View update: topleft ( %d , %d )  bottomright ( %d , %d)\n", pss->view_start_x, pss->view_start_y, pss->view_end_x, pss->view_end_y);
			do_send_png();
		}
		else if(len == 9 && ((uint8_t*)in)[0] == 2)
		{
			int32_t dest_x = I32FROMBUF((uint8_t*)in, 1);
			int32_t dest_y = I32FROMBUF((uint8_t*)in, 5);
			lwsl_notice("ROUTE DEST: %d, %d\n", dest_x, dest_y);
			do_route(dest_x, dest_y);
		}
		else if(len == 1 && ((uint8_t*)in)[0] == 3)
		{
			lwsl_notice("Charger request\n");
			do_charger();
		}
		else if(len == 2 && ((uint8_t*)in)[0] == 4)
		{
			lwsl_notice("Mode request\n");
			do_mode(((uint8_t*)in)[1]);
		}
		else
		{
			lwsl_notice("Unrecognized rx from client, len=%d, in[0]=0x%02x\n", (int)len, (len>0) ? (((uint8_t*)in)[0]) : (0));
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
