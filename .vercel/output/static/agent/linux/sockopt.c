/* Linux helpers: IP_TRANSPARENT, SO_ORIGINAL_DST, SO_MARK, TUN, UDP tproxy.
 * SO_MARK is set here. Connecting and waiting stay in Node so the process is not blocked.
 */
#define NAPI_VERSION 8
#define NODE_GYP_MODULE_NAME lexis_sockopt
#include <node_api.h>
#include <uv.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#define SO_ORIGINAL_DST 80
#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif
#ifndef IP_RECVORIGDSTADDR
#define IP_RECVORIGDSTADDR 20
#endif
#ifndef IP_ORIGDSTADDR
#define IP_ORIGDSTADDR 20
#endif
#ifndef IP_PKTINFO
#define IP_PKTINFO 8
#endif

typedef struct {
  uv_poll_t poll;
  napi_env env;
  napi_ref fn;
  int fd;
} PollBox;

static int take_i32(napi_env env, napi_callback_info info, int32_t *out) {
  size_t argc = 1;
  napi_value argv[1];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  if (argc < 1) return -1;
  return napi_get_value_int32(env, argv[0], out) == napi_ok ? 0 : -1;
}

static napi_value fail(napi_env env, const char *what) {
  napi_throw_error(env, NULL, what);
  return NULL;
}

static int family_of(napi_env env, napi_value value, int present, int *family) {
  int32_t n = 4;
  if (present && napi_get_value_int32(env, value, &n) != napi_ok) return -1;
  if (n == 6) {
    *family = AF_INET6;
    return 0;
  }
  if (n == 4) {
    *family = AF_INET;
    return 0;
  }
  return -1;
}

static napi_value fd_value(napi_env env, int fd) {
  napi_value out;
  napi_create_int32(env, fd, &out);
  return out;
}

static napi_value original_dest(napi_env env, napi_callback_info info) {
  int32_t fd = -1;
  if (take_i32(env, info, &fd) != 0) return fail(env, "缺少套接字");
  struct sockaddr_storage storage;
  memset(&storage, 0, sizeof(storage));
  socklen_t len = sizeof(storage);
  if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &storage, &len) != 0) {
    len = sizeof(storage);
    if (getsockopt(fd, SOL_IPV6, SO_ORIGINAL_DST, &storage, &len) != 0) {
      napi_value nil;
      napi_get_null(env, &nil);
      return nil;
    }
  }
  char host[INET6_ADDRSTRLEN];
  int port = 0;
  if (storage.ss_family == AF_INET) {
    struct sockaddr_in *v4 = (struct sockaddr_in *)&storage;
    inet_ntop(AF_INET, &v4->sin_addr, host, sizeof(host));
    port = ntohs(v4->sin_port);
  } else if (storage.ss_family == AF_INET6) {
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&storage;
    inet_ntop(AF_INET6, &v6->sin6_addr, host, sizeof(host));
    port = ntohs(v6->sin6_port);
  } else {
    napi_value nil;
    napi_get_null(env, &nil);
    return nil;
  }
  napi_value obj, host_v, port_v;
  napi_create_object(env, &obj);
  napi_create_string_utf8(env, host, NAPI_AUTO_LENGTH, &host_v);
  napi_create_int32(env, port, &port_v);
  napi_set_named_property(env, obj, "host", host_v);
  napi_set_named_property(env, obj, "port", port_v);
  return obj;
}

static napi_value listen_transparent(napi_env env, napi_callback_info info) {
  int32_t port = 0;
  if (take_i32(env, info, &port) != 0) return fail(env, "缺少端口");
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return fail(env, "不能打开套接字");
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one)) != 0) {
    close(fd);
    return fail(env, "IP_TRANSPARENT 失败");
  }
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, 128) != 0) {
    close(fd);
    return fail(env, "透明监听失败");
  }
  struct sockaddr_in bound;
  socklen_t blen = sizeof(bound);
  getsockname(fd, (struct sockaddr *)&bound, &blen);
  napi_value obj, fd_v, port_v;
  napi_create_object(env, &obj);
  napi_create_int32(env, fd, &fd_v);
  napi_create_int32(env, ntohs(bound.sin_port), &port_v);
  napi_set_named_property(env, obj, "fd", fd_v);
  napi_set_named_property(env, obj, "port", port_v);
  return obj;
}

static napi_value listen_transparent_udp(napi_env env, napi_callback_info info) {
  int32_t port = 0;
  if (take_i32(env, info, &port) != 0) return fail(env, "缺少端口");
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return fail(env, "不能打开套接字");
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one)) != 0) {
    close(fd);
    return fail(env, "IP_TRANSPARENT 失败");
  }
  setsockopt(fd, SOL_IP, IP_RECVORIGDSTADDR, &one, sizeof(one));
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) flags = 0;
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return fail(env, "透明监听失败");
  }
  struct sockaddr_in bound;
  socklen_t blen = sizeof(bound);
  getsockname(fd, (struct sockaddr *)&bound, &blen);
  napi_value obj, fd_v, port_v;
  napi_create_object(env, &obj);
  napi_create_int32(env, fd, &fd_v);
  napi_create_int32(env, ntohs(bound.sin_port), &port_v);
  napi_set_named_property(env, obj, "fd", fd_v);
  napi_set_named_property(env, obj, "port", port_v);
  return obj;
}

static napi_value mark_fd(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  int32_t fd = -1;
  int32_t mark = 0;
  if (argc < 2 || napi_get_value_int32(env, argv[0], &fd) != napi_ok || napi_get_value_int32(env, argv[1], &mark) != napi_ok) {
    return fail(env, "缺少套接字或标记");
  }
  if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) return fail(env, "SO_MARK 失败");
  napi_value nil;
  napi_get_undefined(env, &nil);
  return nil;
}

static int open_family_socket(int family) {
  return socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
}

static napi_value open_socket(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  int family = AF_INET;
  if (argc >= 1 && family_of(env, argv[0], 1, &family) != 0) return fail(env, "地址族无效");
  int fd = open_family_socket(family);
  if (fd < 0) return fail(env, "不能打开套接字");
  return fd_value(env, fd);
}

static napi_value create_marked(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  int32_t mark = 0;
  if (argc < 1 || napi_get_value_int32(env, argv[0], &mark) != napi_ok) return fail(env, "缺少标记");
  int family = AF_INET;
  if (argc >= 2 && family_of(env, argv[1], 1, &family) != 0) return fail(env, "地址族无效");
  int fd = open_family_socket(family);
  if (fd < 0) return fail(env, "不能打开套接字");
  if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
    close(fd);
    return fail(env, "SO_MARK 失败");
  }
  return fd_value(env, fd);
}

/* Kept so older callers still link. It only marks a new socket and returns it.
 * It does not resolve names or wait. */
static napi_value connect_marked(napi_env env, napi_callback_info info) {
  size_t argc = 4;
  napi_value argv[4];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  int32_t mark = 0;
  int32_t port = 0;
  if (argc < 3 || napi_get_value_int32(env, argv[0], &mark) != napi_ok || napi_get_value_int32(env, argv[2], &port) != napi_ok) {
    return fail(env, "缺少标记、地址或端口");
  }
  if (port < 1 || port > 65535) return fail(env, "端口无效");
  int fd = open_family_socket(AF_INET);
  if (fd < 0) return fail(env, "不能打开套接字");
  if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
    close(fd);
    return fail(env, "SO_MARK 失败");
  }
  return fd_value(env, fd);
}

static void fill_addr(struct sockaddr_in *addr, const char *host, int port) {
  memset(addr, 0, sizeof(*addr));
  addr->sin_family = AF_INET;
  addr->sin_port = htons((uint16_t)port);
  inet_pton(AF_INET, host, &addr->sin_addr);
}

static napi_value packet_object(napi_env env, const char *from_host, int from_port, const char *dest_host, int dest_port, const uint8_t *data, size_t len) {
  napi_value obj, from_v, from_port_v, dest_v, dest_port_v, buf;
  napi_create_object(env, &obj);
  napi_create_string_utf8(env, from_host, NAPI_AUTO_LENGTH, &from_v);
  napi_create_int32(env, from_port, &from_port_v);
  napi_create_string_utf8(env, dest_host, NAPI_AUTO_LENGTH, &dest_v);
  napi_create_int32(env, dest_port, &dest_port_v);
  napi_create_buffer_copy(env, len, data, NULL, &buf);
  napi_set_named_property(env, obj, "fromHost", from_v);
  napi_set_named_property(env, obj, "fromPort", from_port_v);
  napi_set_named_property(env, obj, "destHost", dest_v);
  napi_set_named_property(env, obj, "destPort", dest_port_v);
  napi_set_named_property(env, obj, "data", buf);
  return obj;
}

static napi_value recv_udp(napi_env env, napi_callback_info info) {
  int32_t fd = -1;
  if (take_i32(env, info, &fd) != 0) return fail(env, "缺少套接字");
  uint8_t buf[65535];
  char control[256];
  struct sockaddr_storage peer;
  struct iovec iov;
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  memset(&peer, 0, sizeof(peer));
  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);
  msg.msg_name = &peer;
  msg.msg_namelen = sizeof(peer);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);
  ssize_t n = recvmsg(fd, &msg, 0);
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      napi_value nil;
      napi_get_null(env, &nil);
      return nil;
    }
    return fail(env, "收包失败");
  }
  char from_host[INET6_ADDRSTRLEN] = "0.0.0.0";
  int from_port = 0;
  if (peer.ss_family == AF_INET) {
    struct sockaddr_in *v4 = (struct sockaddr_in *)&peer;
    inet_ntop(AF_INET, &v4->sin_addr, from_host, sizeof(from_host));
    from_port = ntohs(v4->sin_port);
  }
  char dest_host[INET6_ADDRSTRLEN] = "0.0.0.0";
  int dest_port = 0;
  for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level == SOL_IP && (cmsg->cmsg_type == IP_ORIGDSTADDR || cmsg->cmsg_type == IP_RECVORIGDSTADDR)) {
      struct sockaddr_in *orig = (struct sockaddr_in *)CMSG_DATA(cmsg);
      inet_ntop(AF_INET, &orig->sin_addr, dest_host, sizeof(dest_host));
      dest_port = ntohs(orig->sin_port);
    }
  }
  return packet_object(env, from_host, from_port, dest_host, dest_port, buf, (size_t)n);
}

static napi_value send_udp(napi_env env, napi_callback_info info) {
  size_t argc = 6;
  napi_value argv[6];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  int32_t fd = -1;
  int32_t to_port = 0;
  int32_t from_port = 0;
  if (argc < 6 || napi_get_value_int32(env, argv[0], &fd) != napi_ok || napi_get_value_int32(env, argv[3], &to_port) != napi_ok || napi_get_value_int32(env, argv[5], &from_port) != napi_ok) {
    return fail(env, "缺少回包参数");
  }
  void *data = NULL;
  size_t len = 0;
  if (napi_get_buffer_info(env, argv[1], &data, &len) != napi_ok) return fail(env, "回包没有正文");
  char to_host[64];
  char from_host[64];
  size_t copied = 0;
  if (napi_get_value_string_utf8(env, argv[2], to_host, sizeof(to_host), &copied) != napi_ok) return fail(env, "回包地址无效");
  if (napi_get_value_string_utf8(env, argv[4], from_host, sizeof(from_host), &copied) != napi_ok) return fail(env, "回包地址无效");
  struct sockaddr_in to;
  fill_addr(&to, to_host, to_port);
  char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
  memset(control, 0, sizeof(control));
  struct iovec iov;
  iov.iov_base = data;
  iov.iov_len = len;
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_name = &to;
  msg.msg_namelen = sizeof(to);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_IP;
  cmsg->cmsg_type = IP_PKTINFO;
  cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
  struct in_pktinfo *pkt = (struct in_pktinfo *)CMSG_DATA(cmsg);
  memset(pkt, 0, sizeof(*pkt));
  inet_pton(AF_INET, from_host, &pkt->ipi_spec_dst);
  if (sendmsg(fd, &msg, 0) < 0) return fail(env, "回包失败");
  napi_value nil;
  napi_get_undefined(env, &nil);
  return nil;
}

static void on_poll(uv_poll_t *handle, int status, int events) {
  (void)status;
  (void)events;
  PollBox *box = (PollBox *)handle;
  napi_handle_scope scope;
  napi_open_handle_scope(box->env, &scope);
  napi_value cb, global, result;
  napi_get_reference_value(box->env, box->fn, &cb);
  napi_get_global(box->env, &global);
  napi_call_function(box->env, global, cb, 0, NULL, &result);
  napi_close_handle_scope(box->env, scope);
}

static napi_value watch_udp(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  int32_t fd = -1;
  napi_valuetype kind;
  if (argc < 2 || napi_get_value_int32(env, argv[0], &fd) != napi_ok || napi_typeof(env, argv[1], &kind) != napi_ok || kind != napi_function) {
    return fail(env, "缺少套接字或回调");
  }
  uv_loop_t *loop = NULL;
  napi_get_uv_event_loop(env, &loop);
  PollBox *box = calloc(1, sizeof(PollBox));
  if (!box) return fail(env, "内存不足");
  box->env = env;
  box->fd = fd;
  napi_create_reference(env, argv[1], 1, &box->fn);
  if (uv_poll_init(loop, &box->poll, fd) != 0 || uv_poll_start(&box->poll, UV_READABLE, on_poll) != 0) {
    free(box);
    return fail(env, "不能守这个套接字");
  }
  napi_value nil;
  napi_get_undefined(env, &nil);
  return nil;
}

static napi_value open_tun(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  char name[IFNAMSIZ];
  memset(name, 0, sizeof(name));
  size_t copied = 0;
  if (argc < 1 || napi_get_value_string_utf8(env, argv[0], name, sizeof(name), &copied) != napi_ok) {
    strncpy(name, "lexis0", sizeof(name) - 1);
  }
  int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
  if (fd < 0) return fail(env, "打不开虚拟网卡");
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
  if (ioctl(fd, TUNSETIFF, &ifr) != 0) {
    close(fd);
    return fail(env, "虚拟网卡没有创建");
  }
  napi_value obj, fd_v, name_v;
  napi_create_object(env, &obj);
  napi_create_int32(env, fd, &fd_v);
  napi_create_string_utf8(env, ifr.ifr_name, NAPI_AUTO_LENGTH, &name_v);
  napi_set_named_property(env, obj, "fd", fd_v);
  napi_set_named_property(env, obj, "name", name_v);
  return obj;
}

static napi_value init(napi_env env, napi_value exports) {
  napi_value fn;
  napi_create_function(env, "originalDest", NAPI_AUTO_LENGTH, original_dest, NULL, &fn);
  napi_set_named_property(env, exports, "originalDest", fn);
  napi_create_function(env, "listenTransparent", NAPI_AUTO_LENGTH, listen_transparent, NULL, &fn);
  napi_set_named_property(env, exports, "listenTransparent", fn);
  napi_create_function(env, "listenTransparentUdp", NAPI_AUTO_LENGTH, listen_transparent_udp, NULL, &fn);
  napi_set_named_property(env, exports, "listenTransparentUdp", fn);
  napi_create_function(env, "markFd", NAPI_AUTO_LENGTH, mark_fd, NULL, &fn);
  napi_set_named_property(env, exports, "markFd", fn);
  napi_create_function(env, "openSocket", NAPI_AUTO_LENGTH, open_socket, NULL, &fn);
  napi_set_named_property(env, exports, "openSocket", fn);
  napi_create_function(env, "createMarked", NAPI_AUTO_LENGTH, create_marked, NULL, &fn);
  napi_set_named_property(env, exports, "createMarked", fn);
  napi_create_function(env, "connectMarked", NAPI_AUTO_LENGTH, connect_marked, NULL, &fn);
  napi_set_named_property(env, exports, "connectMarked", fn);
  napi_create_function(env, "recvUdp", NAPI_AUTO_LENGTH, recv_udp, NULL, &fn);
  napi_set_named_property(env, exports, "recvUdp", fn);
  napi_create_function(env, "sendUdp", NAPI_AUTO_LENGTH, send_udp, NULL, &fn);
  napi_set_named_property(env, exports, "sendUdp", fn);
  napi_create_function(env, "watchUdp", NAPI_AUTO_LENGTH, watch_udp, NULL, &fn);
  napi_set_named_property(env, exports, "watchUdp", fn);
  napi_create_function(env, "openTun", NAPI_AUTO_LENGTH, open_tun, NULL, &fn);
  napi_set_named_property(env, exports, "openTun", fn);
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
