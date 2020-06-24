// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Danny Lin <danny@kdrag0n.dev>.
 */
/*
 * Copyright (c) 2015, Sony Mobile Communications Inc.
 * Copyright (c) 2013, 2018-2019 The Linux Foundation. All rights reserved.
 */

#include <linux/module.h>
#include <linux/qrtr.h>

#include "qrtr.h"

static int sa_msm_to_qrtr(struct sockaddr_msm_ipc *maddr,
			  struct sockaddr_qrtr *qaddr)
{
	qaddr->sq_family = AF_QIPCRTR;

	switch (maddr->address.addrtype) {
	case MSM_IPC_ADDR_ID:
		qaddr->sq_node = maddr->address.addr.port_addr.node_id;
		qaddr->sq_port = maddr->address.addr.port_addr.port_id;
		break;
	case MSM_IPC_ADDR_NAME:
	{
		struct msm_ipc_server_info srv_info;
		int ret = qrtr_msm_ipc_lookup_server(&srv_info,
				maddr->address.addr.port_name.service,
				maddr->address.addr.port_name.instance,
				1, 0xffffffff);
		if (ret != 1) {
			pr_err_ratelimited("%s: MIQ: %s addr name lookup srv %d inst %d err %d\n", __func__, current->comm, maddr->address.addr.port_name.service, maddr->address.addr.port_name.instance, ret);
			return -ENODEV;
		}

		qaddr->sq_node = srv_info.node_id;
		qaddr->sq_port = srv_info.port_id;
		break;
	}
	default:
		pr_err_ratelimited("%s: MIQ: %s is using addr type %d\n", __func__, current->comm, maddr->address.addrtype);
		return -ENODEV;
	}

	return 0;
}

int sa_qrtr_to_msm(struct sockaddr_qrtr *qaddr, struct sockaddr_msm_ipc *maddr)
{
	maddr->family = AF_MSM_IPC;
	maddr->address.addrtype = MSM_IPC_ADDR_ID;
	maddr->address.addr.port_addr.node_id = qaddr->sq_node;
	maddr->address.addr.port_addr.port_id = qaddr->sq_port;

	return 0;
}

/*
static int msm_ipc_bind(struct socket *sock, struct sockaddr *saddr, int len)
{
	DECLARE_SOCKADDR(struct sockaddr_msm_ipc *, maddr, saddr);
	struct sockaddr_qrtr qaddr;

	if (len < sizeof(*maddr))
		return -EINVAL;

	if (maddr->family != AF_MSM_IPC)
		return -EAFNOSUPPORT;

	// TODO: is this conversion in the right direction?
	qaddr = sa_msm_to_qrtr(maddr);
	return qrtr_bind(sock, (struct sockaddr *)&qaddr, len);
}
*/

static int msm_ipc_bind(struct socket *sock, struct sockaddr *saddr, int len)
{
	DECLARE_SOCKADDR(struct sockaddr_msm_ipc *, maddr, saddr);
	struct qrtr_sock *ipc = qrtr_sk(sock->sk);
	struct qrtr_ctrl_pkt qpkt = {0};
	struct sock *sk = sock->sk;
	struct sockaddr_qrtr qaddr;
	struct msghdr msg = {0};
	struct kvec iov;

	if (len < sizeof(*maddr))
		return -EINVAL;

	if (maddr->family != AF_MSM_IPC)
		return -EAFNOSUPPORT;

	/* Set destination to ourself for qrtr-ns to handle */
	lock_sock(sk);
	qaddr = ipc->us;
	release_sock(sk);
	qaddr.sq_port = QRTR_PORT_CTRL;

	/* Construct new server control message */
	qpkt.cmd = cpu_to_le32(QRTR_TYPE_NEW_SERVER);
	qpkt.server.node = cpu_to_le32(qaddr.sq_node);
	qpkt.server.port = cpu_to_le32(qaddr.sq_port);
	qpkt.server.service = cpu_to_le32(maddr->address.addr.port_name.service);
	qpkt.server.instance = cpu_to_le32(maddr->address.addr.port_name.instance);
	if (maddr->address.addrtype != MSM_IPC_ADDR_NAME) {
		pr_warn_ratelimited("%s: MIQ: %s is using addr type id", __func__, current->comm);
	}
	pr_info("%s: MIQ: %s bind node %u port %u srv %u inst %u\n", __func__, current->comm, qpkt.server.node, qpkt.server.port, qpkt.server.service, qpkt.server.instance);

	/* Construct socket message */
	msg.msg_name = &qaddr;
	msg.msg_namelen = sizeof(qaddr);
	iov.iov_base = &qpkt;
	iov.iov_len = sizeof(qpkt);
	iov_iter_kvec(&msg.msg_iter, ITER_KVEC | WRITE, &iov, 1, sizeof(qpkt));

	return qrtr_sendmsg(sock, &msg, sizeof(qpkt));
}

static int msm_ipc_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
	DECLARE_SOCKADDR(struct sockaddr_msm_ipc *, maddr, msg->msg_name);
	struct sockaddr_qrtr qaddr;
	int ret;

	if (msg->msg_namelen < sizeof(*maddr))
		return -EINVAL;

	if (maddr->family != AF_MSM_IPC)
		return -EAFNOSUPPORT;

	/* Convert to qrtr sockaddr and leave it as NULL otherwise */
	if (maddr) {
		ret = sa_msm_to_qrtr(maddr, &qaddr);
		if (ret)
			return ret;

		msg->msg_name = &qaddr;
	}

	/* Always update size to prevent sanity checks from failing */
	msg->msg_namelen = sizeof(qaddr);
	return qrtr_sendmsg(sock, msg, len);
}

static int msm_ipc_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
			   int flags)
{
	DECLARE_SOCKADDR(struct sockaddr_qrtr *, qaddr, msg->msg_name);
	struct sockaddr_msm_ipc maddr;

	int ret = qrtr_recvmsg(sock, msg, size, flags);

	/* Convert to qrtr sockaddr and leave it as NULL otherwise */
	if (qaddr) {
		ret = sa_qrtr_to_msm(qaddr, &maddr);
		if (ret)
			return ret;

		// TODO: possible overflow?
		*(struct sockaddr_msm_ipc *)msg->msg_name = maddr;
	}

	/* Always update size to prevent sanity checks from failing */
	msg->msg_namelen = sizeof(maddr);
	return ret;
}

static int msm_ipc_connect(struct socket *sock, struct sockaddr *saddr, int len,
			   int flags)
{
	DECLARE_SOCKADDR(struct sockaddr_msm_ipc *, maddr, saddr);
	struct sockaddr_qrtr qaddr;
	int ret;

	if (len < sizeof(*maddr))
		return -EINVAL;

	if (maddr->family != AF_MSM_IPC)
		return -EAFNOSUPPORT;

	// TODO: why no addr NULL check?
	ret = sa_msm_to_qrtr(maddr, &qaddr);
	if (ret)
		return ret;

	return qrtr_connect(sock, (struct sockaddr *)&qaddr, sizeof(qaddr), flags);
}

static int msm_ipc_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	int ret;

	switch (cmd) {
	case IPC_ROUTER_IOCTL_LOOKUP_SERVER:
	{
		struct msm_ipc_server_info *srv_info = NULL;
		struct server_lookup_args server_arg;
		size_t srv_info_sz = 0;
		unsigned int n;

		ret = copy_from_user(&server_arg, (void __user *)arg,
				     sizeof(server_arg));
		if (ret) {
			ret = -EFAULT;
			break;
		}

		if (server_arg.num_entries_in_array < 0) {
			ret = -EINVAL;
			break;
		}

		if (server_arg.num_entries_in_array) {
			if (server_arg.num_entries_in_array >
				(SIZE_MAX / sizeof(*srv_info))) {
				ret = -EINVAL;
				break;
			}

			srv_info_sz = server_arg.num_entries_in_array *
					sizeof(*srv_info);
			srv_info = kmalloc(srv_info_sz, GFP_KERNEL);
			if (!srv_info) {
				ret = -ENOMEM;
				break;
			}
		}

		ret = qrtr_msm_ipc_lookup_server(srv_info,
				server_arg.port_name.service,
				server_arg.port_name.instance,
				server_arg.num_entries_in_array,
				server_arg.lookup_mask);
		if (ret < 0) {
			ret = -ENODEV;
			kfree(srv_info);
			break;
		}
		server_arg.num_entries_found = ret;

		ret = copy_to_user((void *)arg, &server_arg,
				   sizeof(server_arg));

		n = min(server_arg.num_entries_found,
			server_arg.num_entries_in_array);

		if (ret == 0 && n) {
			ret = copy_to_user((void *)(arg + sizeof(server_arg)),
					   srv_info, n * sizeof(*srv_info));
		}

		if (ret)
			ret = -EFAULT;
		kfree(srv_info);
		break;
	}
	case IPC_ROUTER_IOCTL_BIND_CONTROL_PORT:
	{
		struct qrtr_ctrl_pkt pkt = { .cmd = QRTR_TYPE_NEW_LOOKUP };
		struct qrtr_sock *ipc = qrtr_sk(sk);
		struct sock *sk = sock->sk;
		struct sockaddr_qrtr addr;
		struct msghdr msg = {
			.msg_name = &addr,
			.msg_namelen = sizeof(addr)
		};
		struct kvec iov = {
			.iov_base = &pkt,
			.iov_len = sizeof(pkt)
		};

		/* Set destination to ourself for qrtr-ns to handle */
		lock_sock(sk);
		addr = ipc->us;
		release_sock(sk);
		addr.sq_port = QRTR_PORT_CTRL;

		iov_iter_kvec(&msg.msg_iter, ITER_KVEC | WRITE, &iov, 1, sizeof(pkt));
		ret = qrtr_sendmsg(sock, &msg, sizeof(pkt));
		break;
	}
	case IPC_ROUTER_IOCTL_CONFIG_SEC_RULES:
		pr_warn_ratelimited("%s: MIQ: %s is using ioctl CONFIG_SEC_RULES\n", __func__, current->comm);
		ret = 0;
		break;
	default:
		pr_warn_ratelimited("%s: MIQ: %s is using ioctl %lu\n", __func__, current->comm, cmd);
		ret = -ENOIOCTLCMD;
		break;
	}

	return ret;
}

static const struct proto_ops msm_ipc_proto_ops = {
	.family			= AF_MSM_IPC,
	.owner			= THIS_MODULE,
	.release		= qrtr_release,
	.bind			= msm_ipc_bind,
	.connect		= msm_ipc_connect,
	.socketpair		= sock_no_socketpair,
	.accept			= sock_no_accept,
	.getname		= sock_no_getname,
	.poll			= datagram_poll,
	.ioctl			= msm_ipc_ioctl,
	.listen			= sock_no_listen,
	.shutdown		= sock_no_shutdown,
	.setsockopt		= sock_no_setsockopt,
	.getsockopt		= sock_no_getsockopt,
	.sendmsg		= msm_ipc_sendmsg,
	.recvmsg		= msm_ipc_recvmsg,
	.mmap			= sock_no_mmap,
	.sendpage		= sock_no_sendpage,
};

static struct proto msm_ipc_proto = {
	.name		= "MSM_IPC",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct qrtr_sock),
};

static int msm_ipc_create(struct net *net, struct socket *sock,
		       int protocol, int kern)
{
	struct qrtr_sock *ipc;
	struct sock *sk;

	if (sock->type != SOCK_DGRAM)
		return -EPROTOTYPE;

	sk = sk_alloc(net, AF_MSM_IPC, GFP_KERNEL, &msm_ipc_proto, kern);
	if (!sk)
		return -ENOMEM;

	sock_set_flag(sk, SOCK_ZAPPED);

	sock_init_data(sock, sk);
	sock->ops = &msm_ipc_proto_ops;

	ipc = qrtr_sk(sk);
	ipc->us.sq_family = AF_QIPCRTR;
	ipc->us.sq_node = qrtr_local_nid;
	ipc->us.sq_port = 0;
	ipc->state = QRTR_STATE_INIT;

	return 0;
}

static const struct net_proto_family msm_ipc_family = {
	.owner	= THIS_MODULE,
	.family	= AF_MSM_IPC,
	.create	= msm_ipc_create,
};

static int __init msm_ipc_proto_init(void)
{
	int rc;

	rc = proto_register(&msm_ipc_proto, 1);
	if (rc)
		return rc;

	rc = sock_register(&msm_ipc_family);
	if (rc) {
		proto_unregister(&msm_ipc_proto);
		return rc;
	}

	return 0;
}
postcore_initcall(msm_ipc_proto_init);

static void __exit msm_ipc_proto_fini(void)
{
	sock_unregister(msm_ipc_family.family);
	proto_unregister(&msm_ipc_proto);
}
module_exit(msm_ipc_proto_fini);
