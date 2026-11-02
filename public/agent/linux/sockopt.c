/* Linux helpers: IP_TRANSPARENT, SO_ORIGINAL_DST, SO_MARK, TUN. */
#define NAPI_VERSION 8
#define NODE_GYP_MODULE_NAME lexis_sockopt
#include <node_api.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#define SO_ORIGINAL_DST 80
#define IP_TRANSPARENT 19

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

static napi_value create_marked(napi_env env, napi_callback_info info) {
  int32_t mark = 0;
  if (take_i32(env, info, &mark) != 0) return fail(env, "缺少标记");
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return fail(env, "不能打开套接字");
  if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
    close(fd);
    return fail(env, "SO_MARK 失败");
  }
  napi_value out;
  napi_create_int32(env, fd, &out);
  return out;
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

static napi_value connect_marked(napi_env env, napi_callback_info info) {
  size_t argc = 4;
  napi_value argv[4];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  int32_t mark = 0;
  int32_t port = 0;
  int32_t timeout = 10000;
  char host[256];
  size_t host_len = 0;
  if (argc < 3 || napi_get_value_int32(env, argv[0], &mark) != napi_ok || napi_get_value_string_utf8(env, argv[1], host, sizeof(host), &host_len) != napi_ok || napi_get_value_int32(env, argv[2], &port) != napi_ok) {
    return fail(env, "缺少标记、地址或端口");
  }
  if (argc >= 4) napi_get_value_int32(env, argv[3], &timeout);
  if (port < 1 || port > 65535) return fail(env, "端口无效");
  if (timeout < 200) timeout = 200;
  if (timeout > 120000) timeout = 120000;
  char portbuf[8];
  snprintf(portbuf, sizeof(portbuf), "%d", port);
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo *res = NULL;
  if (getaddrinfo(host, portbuf, &hints, &res) != 0 || !res) return fail(env, "地址没有解析");
  int fd = -1;
  for (struct addrinfo *it = res; it; it = it->ai_next) {
    fd = socket(it->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) continue;
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
      close(fd);
      freeaddrinfo(res);
      return fail(env, "SO_MARK 失败");
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) flags = 0;
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int rc = connect(fd, it->ai_addr, it->ai_addrlen);
    if (rc != 0 && errno != EINPROGRESS) {
      close(fd);
      fd = -1;
      continue;
    }
    if (rc != 0) {
      struct pollfd pfd;
      pfd.fd = fd;
      pfd.events = POLLOUT;
      int waited = poll(&pfd, 1, timeout);
      int err = 0;
      socklen_t elen = sizeof(err);
      if (waited <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) {
        close(fd);
        fd = -1;
        continue;
      }
    }
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    break;
  }
  freeaddrinfo(res);
  if (fd < 0) return fail(env, "标记后拨号失败");
  napi_value out;
  napi_create_int32(env, fd, &out);
  return out;
}

static napi_value init(napi_env env, napi_value exports) {
  napi_value fn;
  napi_create_function(env, "originalDest", NAPI_AUTO_LENGTH, original_dest, NULL, &fn);
  napi_set_named_property(env, exports, "originalDest", fn);
  napi_create_function(env, "listenTransparent", NAPI_AUTO_LENGTH, listen_transparent, NULL, &fn);
  napi_set_named_property(env, exports, "listenTransparent", fn);
  napi_create_function(env, "markFd", NAPI_AUTO_LENGTH, mark_fd, NULL, &fn);
  napi_set_named_property(env, exports, "markFd", fn);
  napi_create_function(env, "createMarked", NAPI_AUTO_LENGTH, create_marked, NULL, &fn);
  napi_set_named_property(env, exports, "createMarked", fn);
  napi_create_function(env, "connectMarked", NAPI_AUTO_LENGTH, connect_marked, NULL, &fn);
  napi_set_named_property(env, exports, "connectMarked", fn);
  napi_create_function(env, "openTun", NAPI_AUTO_LENGTH, open_tun, NULL, &fn);
  napi_set_named_property(env, exports, "openTun", fn);
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
