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
#include <uapi/linux/msm_ipc.h>

#include "qrtr.h"

static int send_ctrl_pkt(struct socket *sock, struct qrtr_ctrl_pkt *pkt)
{
	struct qrtr_sock *ipc = qrtr_sk(sock->sk);
	struct sockaddr_qrtr addr = ipc->us;
	struct msghdr msg = {
		.msg_name = &addr,
		.msg_namelen = sizeof(addr)
	};
	struct kvec iov = {
		.iov_base = pkt,
		.iov_len = sizeof(*pkt)
	};
	int ret;

	addr.sq_port = QRTR_PORT_CTRL;
	iov_iter_kvec(&msg.msg_iter, WRITE | ITER_KVEC, &iov, 1, sizeof(*pkt));

	/* Bypass sock and call qrtr directly to avoid msm_ipc translation */
	ret = qrtr_sendmsg(sock, &msg, sizeof(*pkt));
	if (ret < 0) {
		pr_err_ratelimited("%s: SARU: %s send ctrl pkt %d\n", __func__, current->comm, ret);
		return ret;
	}

	/* Callers don't need length */
	return 0;
}

static int recv_ctrl_pkt(struct socket *sock, struct qrtr_ctrl_pkt *pkt)
{
	mm_segment_t oldfs = get_fs();
	struct msghdr msg = {0};
	struct kvec iov = {
		.iov_base = pkt,
		.iov_len = sizeof(*pkt)
	};
	int ret;

	/* Bypass sock and call qrtr directly to avoid msm_ipc translation */
	iov_iter_kvec(&msg.msg_iter, READ | ITER_KVEC, &iov, 1, sizeof(*pkt));
	set_fs(KERNEL_DS);
	ret = qrtr_recvmsg(sock, &msg, sizeof(*pkt), 0);
	set_fs(oldfs);
	if (ret < 0) {
		pr_err("%s: SARU: %s recv ctrl pkt %d\n", __func__, current->comm, ret);
	}

	return ret;
}

static int lookup_server(struct sock *req_sk,
			 struct msm_ipc_server_info *srv_info,
			 u32 service, u32 instance, int limit, u32 mask)
{
	struct net *net = sock_net(req_sk);
	struct qrtr_ctrl_pkt pkt = {
		.cmd = cpu_to_le32(QRTR_TYPE_NEW_LOOKUP),
		.server = {
			.service = cpu_to_le32(service),
			/* Request all instances so we can apply a mask */
			.instance = 0
			//.instance = cpu_to_le32(instance)
		}
	};
	struct socket *sock;
	int found = 0;
	int ret;

	/* Open a new socket to make sure we don't mix up packets */
	ret = sock_create_kern(net, AF_QIPCRTR, SOCK_DGRAM, 0, &sock);
	if (ret) {
		pr_err_ratelimited("%s: SARU: %s sock create failed\n", __func__, current->comm);
		return ret;
	}

	/* Send the lookup packet to make qrtr-ns start sending servers */
	ret = send_ctrl_pkt(sock, &pkt);
	if (ret < 0) {
		pr_err_ratelimited("%s: SARU: %s send pkt failed\n", __func__, current->comm);
		goto out;
	}

	/* Each discovered server is a QRTR_TYPE_NEW_SERVER packet */
	while ((ret = recv_ctrl_pkt(sock, &pkt)) > 0) {
		u32 type = le32_to_cpu(pkt.cmd);

		// TODO: what if too short? need to check size first before type=
		if (ret < sizeof(pkt) || type != QRTR_TYPE_NEW_SERVER) {
			pr_warn_ratelimited("%s: SARU: %s pkt small/wrong type\n", __func__, current->comm);
			continue;
		}

		/* Zero-filled packet indicates end */
		if (!pkt.server.service && !pkt.server.instance &&
		    !pkt.server.node && !pkt.server.port) {
			pr_warn_ratelimited("%s: SARU: %s zero pkt\n", __func__, current->comm);
			break;
		}

		pr_info("SARU: compare with: srv=0x%x inst=0x%x node=0x%x port=0x%x\n", pkt.server.service, pkt.server.instance, pkt.server.node, pkt.server.port);

		if ((pkt.server.instance & mask) != instance)
			continue;

		if (found < limit) {
			srv_info[found].node_id = pkt.server.node;
			srv_info[found].port_id = pkt.server.port;
			srv_info[found].service = pkt.server.service;
			srv_info[found].instance = pkt.server.instance;
		}

		found++;
	}

	ret = found;
out:
	sock_release(sock);
	return ret;
}

static int sa_msm_to_qrtr(struct socket *sock,
			  struct sockaddr_msm_ipc *maddr,
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
		int ret;

		ret = lookup_server(sock->sk, &srv_info,
				maddr->address.addr.port_name.service,
				maddr->address.addr.port_name.instance,
				1, 0xffffffff);
		// TODO: propagate negative error if returned
		if (ret != 1) {
			pr_err_ratelimited("%s: SARU: %s addr name lookup srv %d inst %d err %d\n", __func__, current->comm, maddr->address.addr.port_name.service, maddr->address.addr.port_name.instance, ret);
			return -ENODEV;
		}

		qaddr->sq_node = srv_info.node_id;
		qaddr->sq_port = srv_info.port_id;
		break;
	}
	default:
		pr_err_ratelimited("%s: SARU: %s is using addr type %d\n", __func__, current->comm, maddr->address.addrtype);
		return -ENODEV;
	}

	return 0;
}

void sa_qrtr_to_msm(struct sockaddr_qrtr *qaddr, struct sockaddr_msm_ipc *maddr)
{
	maddr->family = AF_MSM_IPC;
	maddr->address.addrtype = MSM_IPC_ADDR_ID;
	maddr->address.addr.port_addr.node_id = qaddr->sq_node;
	maddr->address.addr.port_addr.port_id = qaddr->sq_port;
}

static int msm_ipc_bind(struct socket *sock, struct sockaddr *saddr, int len)
{
	DECLARE_SOCKADDR(struct sockaddr_msm_ipc *, maddr, saddr);
	struct qrtr_sock *ipc = qrtr_sk(sock->sk);
	struct qrtr_ctrl_pkt pkt = {0};

	if (len < sizeof(*maddr))
		return -EINVAL;

	if (maddr->family != AF_MSM_IPC)
		return -EAFNOSUPPORT;

	/* Construct new server control message */
	pkt.cmd = cpu_to_le32(QRTR_TYPE_NEW_SERVER);
	pkt.server.node = cpu_to_le32(ipc->us.sq_node);
	pkt.server.port = cpu_to_le32(ipc->us.sq_port);
	pkt.server.service = cpu_to_le32(maddr->address.addr.port_name.service);
	pkt.server.instance = cpu_to_le32(maddr->address.addr.port_name.instance);
	if (maddr->address.addrtype != MSM_IPC_ADDR_NAME) {
		pr_warn_ratelimited("%s: SARU: %s is using addr type id", __func__, current->comm);
	}
	pr_info("%s: SARU: %s bind node %u port %u srv %u inst %u\n", __func__, current->comm, pkt.server.node, pkt.server.port, pkt.server.service, pkt.server.instance);

	/* Construct socket message */
	return send_ctrl_pkt(sock, &pkt);
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
		ret = sa_msm_to_qrtr(sock, maddr, &qaddr);
		if (ret)
			return ret;

		msg->msg_name = &qaddr;
	}

	/* Always update size to prevent sanity checks from failing */
	msg->msg_namelen = sizeof(qaddr);
	ret = qrtr_sendmsg(sock, msg, len);
	if (ret < 0)
		pr_err_ratelimited("%s: SARU: %s sendmsg %d\n", __func__, current->comm, ret);
	return ret;
}

static int msm_ipc_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
			   int flags)
{
	DECLARE_SOCKADDR(struct sockaddr_qrtr *, qaddr, msg->msg_name);
	struct sockaddr_msm_ipc maddr;
	int ret;
	
	ret = qrtr_rcvmsg(sock, msg, size, flags);
	if (ret < 0)
		pr_err_ratelimited("%s: SARU: %s recvmsg %d\n", __func__, current->comm, ret);

	/* Convert to qrtr sockaddr and leave it as NULL otherwise */
	if (qaddr) {
		sa_qrtr_to_msm(qaddr, &maddr);
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
	struct sockaddr_qrtr *qaddr_ptr;
	struct sockaddr_qrtr qaddr;
	int ret;

	if (len < sizeof(*maddr))
		return -EINVAL;

	if (maddr->family != AF_MSM_IPC)
		return -EAFNOSUPPORT;

	if (saddr) {
		ret = sa_msm_to_qrtr(sock, maddr, &qaddr);
		if (ret)
			return ret;
		
		qaddr_ptr = &qaddr;
	} else {
		qaddr_ptr = NULL;
	}

	return qrtr_connect(sock, (struct sockaddr *)qaddr_ptr, sizeof(qaddr),
			    flags);
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

		ret = lookup_server(sock->sk, srv_info,
				    server_arg.port_name.service,
				    server_arg.port_name.instance,
				    server_arg.num_entries_in_array,
				    server_arg.lookup_mask);
		// TODO: propagate negative error if returned
		if (ret < 0) {
			ret = -ENODEV;
			kfree(srv_info);
			break;
		}
		server_arg.num_entries_found = ret;
 
		printk("SARU: srv=0x%x inst=0x%x n_req=%d n_found=%d mask=0x%x\n",
			server_arg.port_name.service, server_arg.port_name.instance,
			server_arg.num_entries_in_array,
			server_arg.num_entries_found,
			server_arg.lookup_mask);

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
		struct qrtr_ctrl_pkt pkt = {
			.cmd = cpu_to_le32(QRTR_TYPE_NEW_LOOKUP),
			.server = {
				.service = 0,
				.instance = 0
			}
		};

		ret = send_ctrl_pkt(sock, &pkt);
		break;
	}
	case IPC_ROUTER_IOCTL_CONFIG_SEC_RULES:
		ret = 0;
		break;
	default:
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
