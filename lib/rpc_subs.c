/* ----------------------------------------------------------------------- *
 *   
 *  rpc_subs.c - routines for rpc discovery
 *
 *   Copyright 2004 Ian Kent <raven@themaw.net> - All Rights Reserved
 *   Copyright 2004 Jeff Moyer <jmoyer@redaht.com> - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "config.h"

#include <rpc/types.h>
#include <rpc/rpc.h>
#include <rpc/pmap_prot.h>
#include <sys/socket.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <pthread.h>
#include <poll.h>

#ifdef WITH_LIBTIRPC
const rpcprog_t rpcb_prog = RPCBPROG;
const rpcvers_t rpcb_version = RPCBVERS;
#else
const rpcprog_t rpcb_prog = PMAPPROG;
const rpcvers_t rpcb_version = PMAPVERS;
#endif

#include "rpc_subs.h"
#include "replicated.h"
#include "automount.h"

/* #define STANDALONE */
#ifdef STANDALONE
#define error(logopt, msg, args...)	fprintf(stderr, msg "\n", ##args)
#else
#include "log.h"
#endif

#define MAX_IFC_BUF	1024
#define MAX_ERR_BUF	128

#define MAX_NETWORK_LEN		255

#define EXPPATHLEN 1024
#define EXPNAMELEN 255

#define MOUNTPROG 100005

#define MOUNTVERS	1
#define MOUNTVERS_NFSV3 3
#define MOUNTVERS_POSIX 2

#define MOUNTPROC_EXPORT 5

/* Get numeric value of the n bits starting at position p */
#define getbits(x, p, n)      ((x >> (p + 1 - n)) & ~(~0 << n))

static const rpcvers_t mount_vers[] = {
        MOUNTVERS_NFSV3,
        MOUNTVERS_POSIX,
        MOUNTVERS,
};

static int connect_nb(int, struct sockaddr *, socklen_t, struct timeval *);

/*
 *  Perform a non-blocking connect on the socket fd.
 *
 *  The input struct timeval always has tv_nsec set to zero,
 *  we only ever use tv_sec for timeouts.
 */
static int connect_nb(int fd, struct sockaddr *addr, socklen_t len, struct timeval *tout)
{
	struct pollfd pfd[1];
	int timeout = tout->tv_sec;
	int flags, ret;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return -errno;

	ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (ret < 0)
		return -errno;

	/* 
	 * From here on subsequent sys calls could change errno so
	 * we set ret = -errno to capture it in case we decide to
	 * use it later.
	 */
	ret = connect(fd, addr, len);
	if (ret < 0 && errno != EINPROGRESS) {
		ret = -errno;
		goto done;
	}

	if (ret == 0)
		goto done;

	if (timeout != -1) {
		if (timeout >= (INT_MAX - 1)/1000)
			timeout = INT_MAX - 1;
		else
			timeout = timeout * 1000;
	}

	pfd[0].fd = fd;
	pfd[0].events = POLLOUT;

	ret = poll(pfd, 1, timeout);
	if (ret <= 0) {
		if (ret == 0)
			ret = -ETIMEDOUT;
		else
			ret = -errno;
		goto done;
	}

	if (pfd[0].revents) {
		int status;

		len = sizeof(ret);
		status = getsockopt(fd, SOL_SOCKET, SO_ERROR, &ret, &len);
		if (status < 0) {
			char buf[MAX_ERR_BUF + 1];
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);

			/*
			 * We assume getsockopt amounts to a read on the
			 * descriptor and gives us the errno we need for
			 * the POLLERR revent case.
			 */
			ret = -errno;

			/* Unexpected case, log it so we know we got caught */
			if (pfd[0].revents & POLLNVAL)
				logerr("unexpected poll(2) error on connect:"
				       " %s", estr);

			goto done;
		}

		/* Oops - something wrong with connect */
		if (ret)
			ret = -ret;
	}

done:
	fcntl(fd, F_SETFL, flags);
	return ret;
}

#ifndef WITH_LIBTIRPC
static int rpc_do_create_client(struct sockaddr *addr, struct conn_info *info, int *fd, CLIENT **client)
{
	CLIENT *clnt = NULL;
	struct sockaddr_in in4_laddr;
	struct sockaddr_in *in4_raddr;
	int type, proto, ret;
	socklen_t slen;

	*client = NULL;

	proto = info->proto;
	if (proto == IPPROTO_UDP)
		type = SOCK_DGRAM;
	else
		type = SOCK_STREAM;

	/*
	 * bind to any unused port.  If we left this up to the rpc
	 * layer, it would bind to a reserved port, which has been shown
	 * to exhaust the reserved port range in some situations.
	 */
	in4_laddr.sin_family = AF_INET;
	in4_laddr.sin_port = htons(0);
	in4_laddr.sin_addr.s_addr = htonl(INADDR_ANY);
	slen = sizeof(struct sockaddr_in);

	if (!info->client && *fd == RPC_ANYSOCK) {
		struct sockaddr *laddr;

		*fd = open_sock(addr->sa_family, type, proto);
		if (*fd < 0)
			return -errno;

		laddr = (struct sockaddr *) &in4_laddr;
		if (bind(*fd, laddr, slen) < 0)
			return -errno;
	}

	in4_raddr = (struct sockaddr_in *) addr;
	in4_raddr->sin_port = htons(info->port);

	switch (info->proto) {
	case IPPROTO_UDP:
		clnt = clntudp_bufcreate(in4_raddr,
					 info->program, info->version,
					 info->timeout, fd,
					 info->send_sz, info->recv_sz);
		break;

	case IPPROTO_TCP:
		ret = connect_nb(*fd, addr, slen, &info->timeout);
		if (ret < 0)
			return ret;

		clnt = clnttcp_create(in4_raddr,
				      info->program, info->version, fd,
				      info->send_sz, info->recv_sz);
		break;

	default:
		break;
	}

	*client = clnt;

	return 0;
}
static int rpc_getport(struct conn_info *info,
		       struct pmap *parms, CLIENT *client,
		       unsigned short *port)
{
	enum clnt_stat status;

	/*
	 * Check to see if server is up otherwise a getport will take
	 * forever to timeout.
	 */
	status = clnt_call(client, PMAPPROC_NULL,
			 (xdrproc_t) xdr_void, 0, (xdrproc_t) xdr_void, 0,
			 info->timeout);

	if (status == RPC_SUCCESS) {
		status = clnt_call(client, PMAPPROC_GETPORT,
				 (xdrproc_t) xdr_pmap, (caddr_t) parms,
				 (xdrproc_t) xdr_u_short, (caddr_t) port,
				 info->timeout);
	}

	return status;
}
#else
static int rpc_do_create_client(struct sockaddr *addr, struct conn_info *info, int *fd, CLIENT **client)
{
	CLIENT *clnt = NULL;
	struct sockaddr_in in4_laddr;
	struct sockaddr_in6 in6_laddr;
	struct sockaddr *laddr = NULL;
	struct netbuf nb_addr;
	int type, proto;
	size_t slen;
	int ret;

	*client = NULL;

	proto = info->proto;
	if (proto == IPPROTO_UDP)
		type = SOCK_DGRAM;
	else
		type = SOCK_STREAM;

	/*
	 * bind to any unused port.  If we left this up to the rpc
	 * layer, it would bind to a reserved port, which has been shown
	 * to exhaust the reserved port range in some situations.
	 */
	if (addr->sa_family == AF_INET) {
		struct sockaddr_in *in4_raddr = (struct sockaddr_in *) addr;
		in4_laddr.sin_family = AF_INET;
		in4_laddr.sin_port = htons(0);
		in4_laddr.sin_addr.s_addr = htonl(INADDR_ANY);
		laddr = (struct sockaddr *) &in4_laddr;
		in4_raddr->sin_port = htons(info->port);
		slen = sizeof(struct sockaddr_in);
	} else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *in6_raddr = (struct sockaddr_in6 *) addr;
		in6_laddr.sin6_family = AF_INET6;
		in6_laddr.sin6_port = htons(0);
		in6_laddr.sin6_addr = in6addr_any;
		laddr = (struct sockaddr *) &in6_laddr;
		in6_raddr->sin6_port = htons(info->port);
		slen = sizeof(struct sockaddr_in6);
	} else
		return -EINVAL;

	/*
	 * bind to any unused port.  If we left this up to the rpc layer,
	 * it would bind to a reserved port, which has been shown to
	 * exhaust the reserved port range in some situations.
	 */
	if (!info->client && *fd == RPC_ANYSOCK) {
		*fd = open_sock(addr->sa_family, type, proto);
		if (*fd < 0) {
			ret = -errno;
			return ret;
		}

		if (bind(*fd, laddr, slen) < 0) {
			ret = -errno;
			return ret;
		}
	}

	nb_addr.maxlen = nb_addr.len = slen;
	nb_addr.buf = addr;

	if (info->proto == IPPROTO_UDP)
		clnt = clnt_dg_create(*fd, &nb_addr,
				      info->program, info->version,
				      info->send_sz, info->recv_sz);
	else if (info->proto == IPPROTO_TCP) {
		ret = connect_nb(*fd, addr, slen, &info->timeout);
		if (ret < 0)
			return ret;
		clnt = clnt_vc_create(*fd, &nb_addr,
				      info->program, info->version,
				      info->send_sz, info->recv_sz);
	} else
		return -EINVAL;

	/* Our timeout is in seconds */
	if (clnt && info->timeout.tv_sec)
		clnt_control(clnt, CLSET_TIMEOUT, (void *) &info->timeout);

	*client = clnt;

	return 0;
}

/*
 * Thankfully nfs-utils had already dealt with this.
 * Thanks to Chuck Lever for his nfs-utils patch series, much of
 * which is used here.
 */
static pthread_mutex_t proto_mutex = PTHREAD_MUTEX_INITIALIZER;

static enum clnt_stat rpc_get_netid(const sa_family_t family,
				    const int protocol, char **netid)
{
	char *nc_protofmly, *nc_proto, *nc_netid;
	struct netconfig *nconf;
	struct protoent *proto;
	void *handle;

	switch (family) {
	case AF_LOCAL:
	case AF_INET:
		nc_protofmly = NC_INET;
		break;
	case AF_INET6:
		nc_protofmly = NC_INET6;
		break;
	default:
		return RPC_UNKNOWNPROTO;
        }

	pthread_mutex_lock(&proto_mutex);
	proto = getprotobynumber(protocol);
	if (!proto) {
		pthread_mutex_unlock(&proto_mutex);
		return RPC_UNKNOWNPROTO;
	}
	nc_proto = strdup(proto->p_name);
	pthread_mutex_unlock(&proto_mutex);
	if (!nc_proto)
		return RPC_SYSTEMERROR;

	handle = setnetconfig();
	while ((nconf = getnetconfig(handle)) != NULL) {
		if (nconf->nc_protofmly != NULL &&
		    strcmp(nconf->nc_protofmly, nc_protofmly) != 0)
			continue;
		if (nconf->nc_proto != NULL &&
		    strcmp(nconf->nc_proto, nc_proto) != 0)
			continue;

		nc_netid = strdup(nconf->nc_netid);
		if (!nc_netid) {
			free(nc_proto);
			return RPC_SYSTEMERROR;
		}

		*netid = nc_netid;
		break;
	}
	endnetconfig(handle);
	free(nc_proto);

	return RPC_SUCCESS;
}

static char *rpc_sockaddr2universal(const struct sockaddr *addr)
{
	const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *) addr;
	const struct sockaddr_un *sun = (const struct sockaddr_un *) addr;
	const struct sockaddr_in *sin = (const struct sockaddr_in *) addr;
	char buf[INET6_ADDRSTRLEN + 8 /* for port information */];
	uint16_t port;
	size_t count;
	char *result;
	int len;

	switch (addr->sa_family) {
	case AF_LOCAL:
		return strndup(sun->sun_path, sizeof(sun->sun_path));
	case AF_INET:
		if (inet_ntop(AF_INET, (const void *)&sin->sin_addr.s_addr,
					buf, (socklen_t)sizeof(buf)) == NULL)
			goto out_err;
		port = ntohs(sin->sin_port);
		break;
	case AF_INET6:
		if (inet_ntop(AF_INET6, (const void *)&sin6->sin6_addr,
					buf, (socklen_t)sizeof(buf)) == NULL)
			goto out_err;
		port = ntohs(sin6->sin6_port);
		break;
	default:
		goto out_err;
	}

	count = sizeof(buf) - strlen(buf);
	len = snprintf(buf + strlen(buf), count, ".%u.%u",
			(unsigned)(port >> 8), (unsigned)(port & 0xff));
	/* before glibc 2.0.6, snprintf(3) could return -1 */
	if (len < 0 || (size_t)len > count)
		goto out_err;

	result = strdup(buf);
	return result;

out_err:
        return NULL;
}

static int rpc_universal2port(const char *uaddr)
{
	char *addrstr;
	char *p, *endptr;
	unsigned long portlo, porthi;
	int port = -1;

	addrstr = strdup(uaddr);
	if (!addrstr)
		return -1;

	p = strrchr(addrstr, '.');
	if (!p)
		goto out;

	portlo = strtoul(p + 1, &endptr, 10);
	if (*endptr != '\0' || portlo > 255)
		goto out;
	*p = '\0';

        p = strrchr(addrstr, '.');
        if (!p)
                goto out;

        porthi = strtoul(p + 1, &endptr, 10);
        if (*endptr != '\0' || porthi > 255)
                goto out;
        *p = '\0';

        port = (porthi << 8) | portlo;

out:
	free(addrstr);
	return port;
}

static enum clnt_stat rpc_rpcb_getport(CLIENT *client,
				       struct rpcb *parms,
				       struct timeval timeout,
				       unsigned short *port)
{
	rpcvers_t rpcb_version;
	struct rpc_err rpcerr;
	int s_port = 0;

	for (rpcb_version = RPCBVERS_4;
	     rpcb_version >= RPCBVERS_3;
	     rpcb_version--) {
		enum clnt_stat status;
		char *uaddr = NULL;

		CLNT_CONTROL(client, CLSET_VERS, (void *) &rpcb_version);
		status = CLNT_CALL(client, (rpcproc_t) RPCBPROC_GETADDR,
				  (xdrproc_t) xdr_rpcb, (void *) parms,
				  (xdrproc_t) xdr_wrapstring, (void *) &uaddr,
				  timeout);

		switch (status) {
		case RPC_SUCCESS:
			if ((uaddr == NULL) || (uaddr[0] == '\0'))
				return RPC_PROGNOTREGISTERED;

			s_port = rpc_universal2port(uaddr);
			xdr_free((xdrproc_t) xdr_wrapstring, (char *) &uaddr);
			if (s_port == -1) {
				return RPC_N2AXLATEFAILURE;
			}
			*port = s_port;
			return RPC_SUCCESS;

		case RPC_PROGVERSMISMATCH:
			clnt_geterr(client, &rpcerr);
			if (rpcerr.re_vers.low > RPCBVERS4)
				return status;
			continue;

		case RPC_PROGUNAVAIL:
			continue;

		case RPC_PROGNOTREGISTERED:
			continue;

		default:
			/* Most likely RPC_TIMEDOUT or RPC_CANTRECV */
			return status;
		}
	}

	return RPC_PROGNOTREGISTERED;
}

static enum clnt_stat rpc_getport(struct conn_info *info,
				  struct pmap *parms, CLIENT *client,
				  unsigned short *port)
{
	enum clnt_stat status;
	struct sockaddr *paddr, addr;
	struct rpcb rpcb_parms;
	char *netid, *raddr;

	if (info->addr)
		paddr = info->addr;
	else {
		if (!clnt_control(client, CLGET_SERVER_ADDR, (char *) &addr))
			return RPC_UNKNOWNADDR;
		paddr = &addr;
	}

	netid = NULL;
	status = rpc_get_netid(paddr->sa_family, info->proto, &netid);
	if (status != RPC_SUCCESS)
		return status;

	raddr = rpc_sockaddr2universal(paddr);
	if (!raddr) {
		free(netid);
		return RPC_UNKNOWNADDR;
	}

	memset(&rpcb_parms, 0, sizeof(rpcb_parms));
	rpcb_parms.r_prog   = parms->pm_prog;
	rpcb_parms.r_vers   = parms->pm_vers;
	rpcb_parms.r_netid  = netid;
	rpcb_parms.r_addr   = raddr;
	rpcb_parms.r_owner  = "";

	status = rpc_rpcb_getport(client, &rpcb_parms, info->timeout, port);

	free(netid);
	free(raddr);

	if (status == RPC_PROGNOTREGISTERED) {
		/* Last chance, version 2 uses a different procedure */
		rpcvers_t rpcb_version = PMAPVERS;
		CLNT_CONTROL(client, CLSET_VERS, (void *) &rpcb_version);
		status = clnt_call(client, PMAPPROC_GETPORT,
				  (xdrproc_t) xdr_pmap, (caddr_t) parms,
				  (xdrproc_t) xdr_u_short, (caddr_t) port,
				  info->timeout);
	}

	return status;
}
#endif

#if defined(HAVE_GETRPCBYNAME) || defined(HAVE_GETSERVBYNAME)
static pthread_mutex_t rpcb_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static rpcprog_t rpc_getrpcbyname(const rpcprog_t program)
{
#ifdef HAVE_GETRPCBYNAME
	static const char *rpcb_pgmtbl[] = {
		"rpcbind", "portmap", "portmapper", "sunrpc", NULL,
	};
	struct rpcent *entry;
	rpcprog_t prog_number;
	unsigned int i;

	pthread_mutex_lock(&rpcb_mutex);
	for (i = 0; rpcb_pgmtbl[i] != NULL; i++) {
		entry = getrpcbyname(rpcb_pgmtbl[i]);
		if (entry) {
			prog_number = entry->r_number;
			pthread_mutex_unlock(&rpcb_mutex);
			return prog_number;
		}
	}
	pthread_mutex_unlock(&rpcb_mutex);
#endif
	return program;
}

static unsigned short rpc_getrpcbport(const int proto)
{
#ifdef HAVE_GETSERVBYNAME
	static const char *rpcb_netnametbl[] = {
		"rpcbind", "portmapper", "sunrpc", NULL,
	};
	struct servent *entry;
	struct protoent *p_ent;
	unsigned short port;
	unsigned int i;

	pthread_mutex_lock(&rpcb_mutex);
	p_ent = getprotobynumber(proto);
	if (!p_ent)
		goto done;
	for (i = 0; rpcb_netnametbl[i] != NULL; i++) {
		entry = getservbyname(rpcb_netnametbl[i], p_ent->p_name);
		if (entry) {
			port = entry->s_port;
			pthread_mutex_unlock(&rpcb_mutex);
			return port;
		}
	}
done:
	pthread_mutex_unlock(&rpcb_mutex);
#endif
	return (unsigned short) htons(PMAPPORT);
}

/*
 * Create an RPC client
 */
static int create_client(struct conn_info *info, CLIENT **client)
{
	struct addrinfo *ai, *haddr;
	struct addrinfo hints;
	int fd, ret;

	fd = RPC_ANYSOCK;
	*client = NULL;

	if (info->client) {
		if (clnt_control(info->client, CLGET_FD, (char *) &fd))
			clnt_control(info->client, CLSET_FD_NCLOSE, NULL);
		else
			fd = RPC_ANYSOCK;
		clnt_destroy(info->client);
		info->client = NULL;
	}

	if (info->addr) {
		ret = rpc_do_create_client(info->addr, info, &fd, client);
		if (ret == 0)
			goto done;
		if (ret == -EHOSTUNREACH)
			goto out_close;
		if (ret == -EINVAL) {
			char buf[MAX_ERR_BUF];
			char *estr = strerror_r(-ret, buf, MAX_ERR_BUF);
			error(LOGOPT_ANY, "connect() failed: %s", estr);
			goto out_close;
		}

		if (fd != RPC_ANYSOCK) {
			close(fd);
			fd = RPC_ANYSOCK;
		}
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_ADDRCONFIG | AI_CANONNAME;
	hints.ai_family = AF_UNSPEC;
	if (info->proto == IPPROTO_UDP)
		hints.ai_socktype = SOCK_DGRAM;
	else
		hints.ai_socktype = SOCK_STREAM;

	ai = NULL;
	ret = getaddrinfo(info->host, NULL, &hints, &ai);
	if (ret) {
		error(LOGOPT_ANY,
		      "hostname lookup for %s failed: %s",
		      info->host, gai_strerror(ret));
		goto out_close;
	}

	haddr = ai;
	while (haddr) {
		if (haddr->ai_protocol != info->proto) {
			haddr = haddr->ai_next;
			continue;
		}

		ret = rpc_do_create_client(haddr->ai_addr, info, &fd, client);
		if (ret == 0)
			break;
		if (ret == -EHOSTUNREACH) {
			freeaddrinfo(ai);
			goto out_close;
		}

		if (fd != RPC_ANYSOCK) {
			close(fd);
			fd = RPC_ANYSOCK;
		}

		haddr = haddr->ai_next;
	}

	freeaddrinfo(ai);

done:
	if (!*client) {
		ret = -ENOTCONN;
		goto out_close;
	}

	/* Close socket fd on destroy, as is default for rpcowned fds */
	if  (!clnt_control(*client, CLSET_FD_CLOSE, NULL)) {
		clnt_destroy(*client);
		ret = -ENOTCONN;
		goto out_close;
	}

	return 0;

out_close:
	if (fd != RPC_ANYSOCK)
		close(fd);
	return ret;
}

int rpc_udp_getclient(struct conn_info *info,
		      unsigned int program, unsigned int version)
{
	CLIENT *client;
	int ret;

	if (!info->client) {
		info->proto = IPPROTO_UDP;
		info->timeout.tv_sec = RPC_TOUT_UDP;
		info->timeout.tv_usec = 0;
		info->send_sz = UDPMSGSIZE;
		info->recv_sz = UDPMSGSIZE;
	}

	info->program = program;
	info->version = version;

	ret = create_client(info, &client);
	if (ret < 0)
		return ret;

	info->client = client;

	return 0;
}

void rpc_destroy_udp_client(struct conn_info *info)
{
	if (!info->client)
		return;

	clnt_destroy(info->client);
	info->client = NULL;
	return;
}

int rpc_tcp_getclient(struct conn_info *info,
		      unsigned int program, unsigned int version)
{
	CLIENT *client;
	int ret;

	if (!info->client) {
		info->proto = IPPROTO_TCP;
		info->timeout.tv_sec = RPC_TOUT_TCP;
		info->timeout.tv_usec = 0;
		info->send_sz = 0;
		info->recv_sz = 0;
	}

	info->program = program;
	info->version = version;

	ret = create_client(info, &client);
	if (ret < 0)
		return ret;

	info->client = client;

	return 0;
}

void rpc_destroy_tcp_client(struct conn_info *info)
{
	struct linger lin = { 1, 0 };
	socklen_t lin_len = sizeof(struct linger);
	int fd;

	if (!info->client)
		return;

	if (!clnt_control(info->client, CLGET_FD, (char *) &fd))
		fd = -1;

	switch (info->close_option) {
	case RPC_CLOSE_NOLINGER:
		if (fd >= 0)
			setsockopt(fd, SOL_SOCKET, SO_LINGER, &lin, lin_len);
		break;
	}

	clnt_destroy(info->client);
	info->client = NULL;

	return;
}

int rpc_portmap_getclient(struct conn_info *info,
			  const char *host, struct sockaddr *addr, size_t addr_len,
			  int proto, unsigned int option)
{
	CLIENT *client;
	int ret;

	info->host = host;
	info->addr = addr;
	info->addr_len = addr_len;
	info->program = rpc_getrpcbyname(rpcb_prog);
	info->port = ntohs(rpc_getrpcbport(proto));
	/*
	 * When using libtirpc we might need to change the rpcbind version
	 * to qurey AF_INET addresses. Since we might not have an address
	 * yet set AF_INET rpcbind version in rpc_do_create_client() when
	 * we always have an address.
	 */
	info->version = rpcb_version;
	info->proto = proto;
	info->send_sz = RPCSMALLMSGSIZE;
	info->recv_sz = RPCSMALLMSGSIZE;
	info->timeout.tv_sec = PMAP_TOUT_UDP;
	info->timeout.tv_usec = 0;
	info->close_option = option;
	info->client = NULL;

	if (info->proto == IPPROTO_TCP)
		info->timeout.tv_sec = PMAP_TOUT_TCP;

	ret = create_client(info, &client);
	if (ret < 0)
		return ret;

	info->client = client;

	return 0;
}

int rpc_portmap_getport(struct conn_info *info,
			struct pmap *parms, unsigned short *port)
{
	struct conn_info pmap_info;
	CLIENT *client;
	enum clnt_stat status;
	int proto = info->proto;
	int ret;

	memset(&pmap_info, 0, sizeof(struct conn_info));

	pmap_info.proto = proto;

	if (proto == IPPROTO_TCP)
		pmap_info.timeout.tv_sec = PMAP_TOUT_TCP;
	else
		pmap_info.timeout.tv_sec = PMAP_TOUT_UDP;

	if (info->client)
		client = info->client;
	else {
		pmap_info.host = info->host;
		pmap_info.addr = info->addr;
		pmap_info.addr_len = info->addr_len;
		pmap_info.port = ntohs(rpc_getrpcbport(info->proto));
		pmap_info.program = rpc_getrpcbyname(rpcb_prog);
		/*
		 * When using libtirpc we might need to change the rpcbind
		 * version to qurey AF_INET addresses. Since we might not
		 * have an address yet set AF_INET rpcbind version in
		 * rpc_do_create_client() when we always have an address.
		 */
		pmap_info.version = rpcb_version;
		pmap_info.proto = info->proto;
		pmap_info.send_sz = RPCSMALLMSGSIZE;
		pmap_info.recv_sz = RPCSMALLMSGSIZE;

		ret = create_client(&pmap_info, &client);
		if (ret < 0)
			return ret;
	}

	status = rpc_getport(&pmap_info, parms, client, port);

	if (!info->client) {
		/*
		 * Only play with the close options if we think it
		 * completed OK
		 */
		if (proto == IPPROTO_TCP && status == RPC_SUCCESS) {
			struct linger lin = { 1, 0 };
			socklen_t lin_len = sizeof(struct linger);
			int fd;

			if (!clnt_control(client, CLGET_FD, (char *) &fd))
				fd = -1;

			switch (info->close_option) {
			case RPC_CLOSE_NOLINGER:
				if (fd >= 0)
					setsockopt(fd, SOL_SOCKET, SO_LINGER, &lin, lin_len);
				break;
			}
		}
		clnt_destroy(client);
	}

	if (status == RPC_TIMEDOUT)
		return -ETIMEDOUT;
	else if (status != RPC_SUCCESS)
		return -EIO;

	return 0;
}

int rpc_ping_proto(struct conn_info *info)
{
	CLIENT *client;
	enum clnt_stat status;
	int proto = info->proto;
	int ret;

	if (info->client)
		client = info->client;
	else {
		if (info->proto == IPPROTO_UDP) {
			info->send_sz = UDPMSGSIZE;
			info->recv_sz = UDPMSGSIZE;
		}
		ret = create_client(info, &client);
		if (ret < 0)
			return ret;
	}

	clnt_control(client, CLSET_TIMEOUT, (char *) &info->timeout);
	clnt_control(client, CLSET_RETRY_TIMEOUT, (char *) &info->timeout);

	status = clnt_call(client, NFSPROC_NULL,
			 (xdrproc_t) xdr_void, 0, (xdrproc_t) xdr_void, 0,
			 info->timeout);

	if (!info->client) {
		/*
		 * Only play with the close options if we think it
		 * completed OK
		 */
		if (proto == IPPROTO_TCP && status == RPC_SUCCESS) {
			struct linger lin = { 1, 0 };
			socklen_t lin_len = sizeof(struct linger);
			int fd;

			if (!clnt_control(client, CLGET_FD, (char *) &fd))
				fd = -1;

			switch (info->close_option) {
			case RPC_CLOSE_NOLINGER:
				if (fd >= 0)
					setsockopt(fd, SOL_SOCKET, SO_LINGER, &lin, lin_len);
				break;
			}
		}
		clnt_destroy(client);
	}

	if (status == RPC_TIMEDOUT)
		return -ETIMEDOUT;
	else if (status != RPC_SUCCESS)
		return -EIO;

	return 1;
}

static int __rpc_ping(const char *host,
		      unsigned long version, int proto, int port,
		      long seconds, long micros, unsigned int option)
{
	int status;
	struct conn_info info;

	info.proto = proto;
	info.host = host;
	info.addr = NULL;
	info.addr_len = 0;
	info.program = NFS_PROGRAM;
	info.version = version;
	info.send_sz = 0;
	info.recv_sz = 0;
	info.timeout.tv_sec = seconds;
	info.timeout.tv_usec = micros;
	info.close_option = option;
	info.client = NULL;

	status = RPC_PING_FAIL;


	if (port > 0)
		info.port = port;
	else {
		struct pmap parms;

		parms.pm_prog = NFS_PROGRAM;
		parms.pm_vers = version;
		parms.pm_prot = info.proto;
		parms.pm_port = 0;
		status = rpc_portmap_getport(&info, &parms, &info.port);
		if (status < 0)
			return status;
	}

	status = rpc_ping_proto(&info);

	return status;
}

int rpc_ping(const char *host, int port,
	     unsigned int version, long seconds, long micros,
	     unsigned int option)
{
	int status = 0;

	if ((version & NFS2_REQUESTED) && (version & TCP_REQUESTED)) {
		status = __rpc_ping(host, NFS2_VERSION,
				    IPPROTO_TCP, port, seconds, micros, option);
		if (status > 0)
			return RPC_PING_V2 | RPC_PING_TCP;
	}

	if ((version & NFS2_REQUESTED) && (version & UDP_REQUESTED)) {
		status = __rpc_ping(host, NFS2_VERSION,
				    IPPROTO_UDP, port, seconds, micros, option);
		if (status > 0)
			return RPC_PING_V2 | RPC_PING_UDP;
	}

	if ((version & NFS3_REQUESTED) && (version & TCP_REQUESTED)) {
		status = __rpc_ping(host, NFS3_VERSION,
				    IPPROTO_TCP, port, seconds, micros, option);
		if (status > 0)
			return RPC_PING_V3 | RPC_PING_TCP;
	}

	if ((version & NFS3_REQUESTED) && (version & UDP_REQUESTED)) {
		status = __rpc_ping(host, NFS3_VERSION,
				    IPPROTO_UDP, port, seconds, micros, option);
		if (status > 0)
			return RPC_PING_V3 | RPC_PING_UDP;
	}

	if (version & NFS4_REQUESTED) {
		/* UDP isn't recommended for NFSv4, don't check it. */
		status = __rpc_ping(host, NFS4_VERSION,
				    IPPROTO_TCP, port, seconds, micros, option);
		if (status > 0)
			return RPC_PING_V4 | RPC_PING_TCP;
	}

	return status;
}

double monotonic_elapsed(struct timespec start, struct timespec end)
{
	double t1, t2;

	t1 =  (double) start.tv_sec +
		((double) start.tv_nsec/(1000*1000*1000));
	t2 =  (double) end.tv_sec +
		((double) end.tv_nsec/(1000*1000*1000));
	return t2 - t1;
}

static bool_t xdr_host(XDR *xdrs, struct hostinfo *host)
{
	if (!xdr_string(xdrs, &host->name, EXPNAMELEN))
		return FALSE;
	return TRUE;
}

static bool_t xdr_hosts(XDR *xdrs, struct hostinfo **hosts)
{
	unsigned int size = sizeof(struct hostinfo);
	char **host;

	host = (char **) hosts;
	while (1) {
		if (!xdr_pointer(xdrs, host, size, (xdrproc_t) xdr_host))
			return FALSE;
		if (!*host)
			break;
		host = (char **) &((struct hostinfo *) *host)->next;
	}
	return TRUE;
}

static bool_t xdr_export(XDR *xdrs, struct exportinfo *export)
{
	if (!xdr_string(xdrs, &export->dir, EXPPATHLEN))
		return FALSE;
	if (!xdr_hosts(xdrs, &export->hosts))
		return FALSE;
	return TRUE;
}

bool_t xdr_exports(XDR *xdrs, struct exportinfo **exports)
{
	unsigned int size = sizeof(struct exportinfo);
	char **export;

	export = (char **) exports;
	while (1) {
		if (!xdr_pointer(xdrs, export, size, (xdrproc_t) xdr_export)) {
			if (*exports) {
				rpc_exports_free(*exports);
				*exports = NULL;
			}
			return FALSE;
		}
		if (!*export)
			break;
		export = (char **) &((struct exportinfo *) *export)->next;
	}
	return TRUE;
}

static int rpc_get_exports_proto(struct conn_info *info, struct exportinfo **exports)
{
	CLIENT *client;
	enum clnt_stat status;
	int proto = info->proto;
	unsigned int option = info->close_option;
	int vers_entry;
	int ret;

	if (info->proto == IPPROTO_UDP) {
		info->send_sz = UDPMSGSIZE;
		info->recv_sz = UDPMSGSIZE;
	}
	ret = create_client(info, &client);
	if (ret < 0)
		return 0;

	clnt_control(client, CLSET_TIMEOUT, (char *) &info->timeout);
	clnt_control(client, CLSET_RETRY_TIMEOUT, (char *) &info->timeout);

	client->cl_auth = authunix_create_default();
	if (client->cl_auth == NULL) {
		error(LOGOPT_ANY, "auth create failed");
		clnt_destroy(client);
		return 0;
	}

	vers_entry = 0;
	while (1) {
		status = clnt_call(client, MOUNTPROC_EXPORT,
				 (xdrproc_t) xdr_void, NULL,
				 (xdrproc_t) xdr_exports, (caddr_t) exports,
				 info->timeout);
		if (status == RPC_SUCCESS)
			break;
		if (status == RPC_SYSTEMERROR)
			break;
		if (++vers_entry > 2)
			break;
		CLNT_CONTROL(client, CLSET_VERS,
			    (void *) &mount_vers[vers_entry]);
	}

	/* Only play with the close options if we think it completed OK */
	if (proto == IPPROTO_TCP && status == RPC_SUCCESS) {
		struct linger lin = { 1, 0 };
		socklen_t lin_len = sizeof(struct linger);
		int fd;

		if (!clnt_control(client, CLGET_FD, (char *) &fd))
			fd = -1;

		switch (option) {
		case RPC_CLOSE_NOLINGER:
			if (fd >= 0)
				setsockopt(fd, SOL_SOCKET, SO_LINGER, &lin, lin_len);
			break;
		}
	}
	auth_destroy(client->cl_auth);
	clnt_destroy(client);

	if (status != RPC_SUCCESS)
		return 0;

	return 1;
}

static void rpc_export_free(struct exportinfo *export)
{
	struct hostinfo *host, *tmp;

	if (export->dir)
		free(export->dir);

	host = export->hosts;
	while (host) {
		if (host->name)
			free(host->name);
		tmp = host;
		host = host->next;
		free(tmp);
	}
	free(export);
}

void rpc_exports_free(struct exportinfo *exports)
{
	struct exportinfo *export, *tmp;

	export = exports;
	while (export) {
		tmp = export;
		export = export->next;
		rpc_export_free(tmp);
	}
	return;
}

struct exportinfo *rpc_get_exports(const char *host,
				   long seconds, long micros,
				   unsigned int option)
{
	struct conn_info info;
	struct exportinfo *exports = NULL;
	struct pmap parms;
	int status;

	info.host = host;
	info.addr = NULL;
	info.addr_len = 0;
	info.program = MOUNTPROG;
	info.version = mount_vers[0];
	info.send_sz = 0;
	info.recv_sz = 0;
	info.timeout.tv_sec = seconds;
	info.timeout.tv_usec = micros;
	info.close_option = option;
	info.client = NULL;

	parms.pm_prog = info.program;
	parms.pm_vers = info.version;
	parms.pm_port = 0;

	/* Try UDP first */
	info.proto = IPPROTO_UDP;

	parms.pm_prot = info.proto;

	status = rpc_portmap_getport(&info, &parms, &info.port);
	if (status < 0)
		goto try_tcp;

	status = rpc_get_exports_proto(&info, &exports);
	if (status)
		return exports;

try_tcp:
	info.proto = IPPROTO_TCP;

	parms.pm_prot = info.proto;

	status = rpc_portmap_getport(&info, &parms, &info.port);
	if (status < 0)
		return NULL;

	status = rpc_get_exports_proto(&info, &exports);
	if (!status)
		return NULL;

	return exports;
}

const char *get_addr_string(struct sockaddr *sa, char *name, socklen_t len)
{
	void *addr;

	if (len < INET6_ADDRSTRLEN)
		return NULL;

	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *) sa;
		addr = &(ipv4->sin_addr);
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *) sa;
		addr = &(ipv6->sin6_addr);
	} else {
		return NULL;
	}

	return inet_ntop(sa->sa_family, addr, name, len);
}
