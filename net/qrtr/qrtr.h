/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __QRTR_H_
#define __QRTR_H_

#include <linux/types.h>
#include <linux/kthread.h>
#include <net/sock.h>
#include <uapi/linux/qrtr.h>

struct sk_buff;

/* qrtr socket states */
#define QRTR_STATE_MULTI	-2
#define QRTR_STATE_INIT	-1

/* endpoint node id auto assignment */
#define QRTR_EP_NID_AUTO (-1)
#define QRTR_EP_NET_ID_AUTO (1)

#define QRTR_DEL_PROC_MAGIC	0xe111

/**
 * struct qrtr_endpoint - endpoint handle
 * @xmit: Callback for outgoing packets
 *
 * The socket buffer passed to the xmit function becomes owned by the endpoint
 * driver.  As such, when the driver is done with the buffer, it should
 * call kfree_skb() on failure, or consume_skb() on success.
 */
struct qrtr_endpoint {
	int (*xmit)(struct qrtr_endpoint *ep, struct sk_buff *skb);
	/* private: not for endpoint use */
	struct qrtr_node *node;
};

int qrtr_endpoint_register(struct qrtr_endpoint *ep, unsigned int net_id,
			   bool rt);

void qrtr_endpoint_unregister(struct qrtr_endpoint *ep);

int qrtr_endpoint_post(struct qrtr_endpoint *ep, const void *data, size_t len);

int qrtr_peek_pkt_size(const void *data);

/**
 * struct qrtr_node - endpoint node
 * @ep_lock: lock for endpoint management and callbacks
 * @ep: endpoint
 * @ref: reference count for node
 * @nid: node id
 * @net_id: network cluster identifer
 * @hello_sent: hello packet sent to endpoint
 * @qrtr_tx_flow: remote port tx flow control list
 * @resume_tx: wait until remote port acks control flag
 * @qrtr_tx_lock: lock for qrtr_tx_flow
 * @rx_queue: receive queue
 * @item: list item for broadcast list
 * @kworker: worker thread for recv work
 * @task: task to run the worker thread
 * @read_data: scheduled work for recv work
 * @say_hello: scheduled work for initiating hello
 * @ws: wakeupsource avoid system suspend
 * @ilc: ipc logging context reference
 */
struct qrtr_node {
	struct mutex ep_lock;
	struct qrtr_endpoint *ep;
	struct kref ref;
	unsigned int nid;
	unsigned int net_id;
	atomic_t hello_sent;
	atomic_t hello_rcvd;

	struct radix_tree_root qrtr_tx_flow;
	struct wait_queue_head resume_tx;
	struct mutex qrtr_tx_lock;	/* for qrtr_tx_flow */

	struct sk_buff_head rx_queue;
	struct list_head item;

	struct kthread_worker kworker;
	struct task_struct *task;
	struct kthread_work read_data;
	struct kthread_work say_hello;

	struct wakeup_source *ws;

	void *ilc;
};

struct qrtr_sock {
	/* WARNING: sk must be the first member */
	struct sock sk;
	struct sockaddr_qrtr us;
	struct sockaddr_qrtr peer;

	int state;
};

static inline struct qrtr_sock *qrtr_sk(struct sock *sk)
{
	BUILD_BUG_ON(offsetof(struct qrtr_sock, sk) != 0);
	return container_of(sk, struct qrtr_sock, sk);
}

extern unsigned int qrtr_local_nid;

/* Protocol ops for use in msm_ipc_compat */
int qrtr_bind(struct socket *sock, struct sockaddr *saddr, int len);
int qrtr_sendmsg(struct socket *sock, struct msghdr *msg, size_t len);
int qrtr_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags);
int qrtr_connect(struct socket *sock, struct sockaddr *saddr, int len, int flags);
int qrtr_release(struct socket *sock);

#endif
