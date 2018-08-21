/*
 *
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/reciprocal_div.h>
#include <net/netlink.h>
#include <linux/version.h>
#include "pkt_sched.h"
#include "tart_config.h"
#include "codel6.h"

/* The TART Principles:
 * (or, how to have your tart and eat it too)
 *
 * Be the fastest fq_codel based shaper possible.

 * - An overall bandwidth shaper, to move the bottleneck away
 *   from dumb CPE equipment and bloated MACs.  This operates
 *   in deficit mode (as in sch_fq), eliminating the need for
 *   any sort of burst parameter (eg. token bucket depth).
 *   Burst support is limited to that necessary to overcome
 *   scheduling latency.
 *
 * - Each queue is actively managed by Codel.  This serves
 *   flows fairly, and signals congestion early via ECN
 *   (if available) and/or packet drops, to keep latency low.
 *   The codel parameters are auto-tuned based on the bandwidth
 *   setting, as is necessary at low bandwidths.
 *
 * The configuration parameters are kept deliberately simple
 * for ease of use.  Everything has sane defaults.  Complete
 * generality of configuration is *not* a goal.
 *
 */

#ifndef TART_VERSION
#define TART_VERSION "unknown"
#endif
static char *tart_version __attribute__((used)) = "Cake version: "
		TART_VERSION;

struct tart_flow {
	struct sk_buff	  *head;
	struct sk_buff	  *tail;
	struct list_head  flowchain;
	s32		  deficit;
	u32		  backlog;
	u32		  dropped; /* Drops (or ECN marks) on this flow */
	struct codel_vars cvars;
}; /* please try to keep this structure <= 64 bytes */

struct tart_tin_data {
	struct tart_flow *flows;/* Flows table [flows_cnt] */
	u16	 flows_cnt;	/* number of flows - must be multiple of
				 */
	u16	quantum;	/* psched_mtu(qdisc_dev(sch)); */

	u32	drop_overlimit;

	struct list_head new_flows; /* list of new flows */
	struct list_head old_flows; /* list of old flows */

	/* time_next = time_this + ((len * rate_ns) >> rate_shft) */
	u64	tin_time_next_packet;
	u32	tin_rate_ns;
	u32	tin_rate_bps;
	u16	tin_rate_shft;

	u16	tin_quantum_prio;
	u16	tin_quantum_band;
	s32	tin_deficit;
	u32	tin_backlog;
	u32	tin_dropped;
	u32	tin_ecn_mark;

	u32	packets;
	u64	bytes;
	u32	max_backlog;
	flow *  worst_flow; // idx?
}; /* number of tins is small, so size of this struct doesn't matter much */

struct tart_sched_data {
	struct tart_tin_data *tins;
	struct codel_params cparams;
	/* time_next = time_this + ((len * rate_ns) >> rate_shft) */
	u16		rate_shft;
	u64		time_next_packet;
	u32		rate_ns;
	u32		rate_bps;
	u16		rate_flags;
	s16		rate_overhead;
	u32		interval;
	u32		target;

	/* resource tracking */
	u32		buffer_used;
	u32		buffer_limit;
	u32		buffer_config_limit;

	/* indices for dequeue */
	u16		cur_tin;
	u16		cur_flow;

	struct qdisc_watchdog watchdog;

};

enum {
	TART_FLAG_ATM = 0x0001,
	TART_FLAG_WASH = 0x0100
};

static inline u32
tart_hash(struct tart_tin_data *q, const struct sk_buff *skb, int flow_mode)
{
	WARN_ONCE("skb not hashed");
}

/* helper functions : might be changed when/if skb use a standard list_head */
/* remove one skb from head of slot queue */

static inline struct sk_buff *dequeue_head(struct tart_flow *flow)
{
	struct sk_buff *skb = flow->head;

	flow->head = skb->next;
	skb->next = NULL;
	return skb;
}

/* add skb to flow queue (tail add) */

static inline void
flow_queue_add(struct tart_flow *flow, struct sk_buff *skb)
{
	if (!flow->head)
		flow->head = skb;
	else
		flow->tail->next = skb;
	flow->tail = skb;
	skb->next = NULL;
}

static inline u32 tart_overhead(struct tart_sched_data *q, u32 in)
{
	u32 out = in + q->rate_overhead;

	if (q->rate_flags & TART_FLAG_ATM) {
		out += 47;
		out /= 48;
		out *= 53;
	}

	return out;
}

// fat flow track all the time
// FIXME: do a bulk drop

static unsigned int tart_drop(struct Qdisc *sch)
{
	struct tart_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	tin = 0;
	struct tart_tin_data *b;
	struct tart_flow *flow;

	/* Queue is full;
	 * find the fat flow and drop a packet.
	 */

	b = &q->tins[0];
	flow = &b->flows[b->idx];
	skb = dequeue_head(flow);
	len = qdisc_pkt_len(skb);

	q->buffer_used      -= skb->truesize;
	b->backlogs[idx]    -= len;
	b->tin_backlog      -= len;
	sch->qstats.backlog -= len;

	b->tin_dropped++;
	sch->qstats.drops++;
	flow->dropped++;

	kfree_skb(skb);
	sch->q.qlen--;

	return idx + (tin << 16);
}

static inline void tart_wash_diffserv(struct sk_buff *skb)
{
	switch (skb->protocol) {
	case htons(ETH_P_IP):
		ipv4_change_dsfield(ip_hdr(skb), INET_ECN_MASK, 0);
		break;
	case htons(ETH_P_IPV6):
		ipv6_change_dsfield(ipv6_hdr(skb), INET_ECN_MASK, 0);
		break;
	default:
		break;
	};
}

static void tart_reconfigure(struct Qdisc *sch);

static s32 tart_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct tart_sched_data *q = qdisc_priv(sch);
	u32 idx, tin;
	struct tart_tin_data *b;
	struct tart_flow *flow;
	u32 len = qdisc_pkt_len(skb);
	u64 now = codel_get_time();
	tart_wash_diffserv(skb);

	b = &q->tins[0];

	/* choose flow to insert into */
	idx = tart_hash(b, skb, q->flow_mode);
	flow = &b->flows[idx];

	/* ensure shaper state isn't stale */
	if (!b->tin_backlog) {
		if (b->tin_time_next_packet < now)
			b->tin_time_next_packet = now;

		if (!sch->q.qlen)
			if (q->time_next_packet < now)
				q->time_next_packet = now;
	}

		/* not splitting */
		get_codel_cb(skb)->enqueue_time = now;
		flow_queue_add(flow, skb);

		/* stats */
		sch->q.qlen++;
		b->packets++;
		b->bytes            += len;
		b->backlogs[idx]    += len;
		sch->qstats.backlog += len;
		q->buffer_used      += skb->truesize;

	/* flowchain */
	if (list_empty(&flow->flowchain)) {
		list_add_tail(&flow->flowchain, &b->new_flows);
		flow->deficit = b->quantum;
		flow->dropped = 0;
	}

	if (q->buffer_used > q->buffer_limit) {
		u32  dropped = 0;

		while (q->buffer_used > q->buffer_limit) {
			dropped++;
			tart_drop(sch);
		}
		b->drop_overlimit += dropped;
		qdisc_tree_decrease_qlen(sch, dropped);
	}
	return NET_XMIT_SUCCESS;
}

/* Callback from codel_dequeue(); sch->qstats.backlog is already handled. */
static struct sk_buff *custom_dequeue(struct codel_vars *vars,
				      struct Qdisc *sch)
{
	struct tart_sched_data *q = qdisc_priv(sch);
	struct tart_tin_data *b = &q->tins[0];
	struct tart_flow *flow = &b->flows[q->cur_flow];
	struct sk_buff *skb = NULL;
	u32 len;

	if (flow->head) {
		skb = dequeue_head(flow);
		len = qdisc_pkt_len(skb);
		b->backlogs[q->cur_flow] -= len;
		q->buffer_used           -= skb->truesize;
		sch->q.qlen--;
	}
	return skb;
}

/* Discard leftover packets from a tin no longer in use. */
static void tart_clear_tin(struct Qdisc *sch)
{
	struct tart_sched_data *q = qdisc_priv(sch);
	struct tart_tin_data *b = &q->tins[0];

	q->cur_tin = tin;
	for (q->cur_flow = 0; q->cur_flow < b->flows_cnt; q->cur_flow++)
		while (custom_dequeue(NULL, sch))
			;
}

static struct sk_buff *tart_dequeue(struct Qdisc *sch)
{
	struct tart_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	struct tart_tin_data *b = &q->tins[q->cur_tin];
	struct tart_flow *flow;
	struct list_head *head;
	u16 prev_drop_count, prev_ecn_mark;
	u32 len;
	codel_time_t now = ktime_get_ns();
	s32 i;

begin:
	if (!sch->q.qlen)
		return NULL;

	/* global hard shaper */
	if (q->time_next_packet > now) {
		sch->qstats.overlimits++;
		codel_watchdog_schedule_ns(&q->watchdog, q->time_next_packet,
					   true);
		return NULL;
	}

retry:
	/* service this class */
	head = &b->new_flows;
	if (list_empty(head)) {
		head = &b->old_flows;

		if (unlikely(list_empty(head))) {
			goto begin;
		}
	}
	flow = list_first_entry(head, struct tart_flow, flowchain);
	q->cur_flow = flow - b->flows;

	if (flow->deficit <= 0) {
		flow->deficit += b->quantum; // why not handle overhead here?
		list_move_tail(&flow->flowchain, &b->old_flows);
		goto retry;
	}

	prev_drop_count = flow->cvars.drop_count;
	prev_ecn_mark   = flow->cvars.ecn_mark;

	skb = codel_dequeue(sch, &flow->cvars, &q->cparams, now,
			    q->buffer_used >
			    (q->buffer_limit >> 2) + (q->buffer_limit >> 1));

	b->tin_dropped  += flow->cvars.drop_count - prev_drop_count;
	b->tin_ecn_mark += flow->cvars.ecn_mark   - prev_ecn_mark;
	flow->cvars.ecn_mark = 0;
	flow->dropped        += flow->cvars.drop_count - prev_drop_count;

	if (!skb) {
		/* codel dropped the last packet in this queue; try again */
		if ((head == &b->new_flows) &&
		    !list_empty(&b->old_flows)) {
			list_move_tail(&flow->flowchain, &b->old_flows);
		} else {
			list_del_init(&flow->flowchain);
		}
		goto begin;
	}

	qdisc_bstats_update(sch, skb);
	if (flow->cvars.drop_count && sch->q.qlen) {
		qdisc_tree_decrease_qlen(sch, flow->cvars.drop_count);
		flow->cvars.drop_count = 0;
	}

	len = tart_overhead(q, qdisc_pkt_len(skb));

	flow->deficit -= len;
	b->tin_deficit -= len;

	for (i = 0; i >= 0; i--, b--)
		b->tin_time_next_packet +=
			(len * (u64)b->tin_rate_ns) >> b->tin_rate_shft;
	q->time_next_packet += (len * (u64)q->rate_ns) >> q->rate_shft;

	return skb;
}

static void tart_reset(struct Qdisc *sch)
{
	tart_clear_tin(sch);
}

static const struct nla_policy tart_policy[TCA_TART_MAX + 1] = {
	[TCA_TART_BASE_RATE]     = { .type = NLA_U32 },
	[TCA_TART_ATM]           = { .type = NLA_U32 },
	[TCA_TART_OVERHEAD]      = { .type = NLA_S32 },
	[TCA_TART_RTT]           = { .type = NLA_U32 },
	[TCA_TART_TARGET]        = { .type = NLA_U32 },
	[TCA_TART_MEMORY]        = { .type = NLA_U32 },
};

static void tart_set_rate(struct tart_tin_data *b, u64 rate)
{
	/* convert byte-rate into time-per-byte
	 * so it will always unwedge in reasonable time.
	 */
	static const u64 MIN_RATE = 64;
	u64 rate_ns = 0;
	u8  rate_shft = 0;

	b->quantum = 1514;
	if (rate) {
		b->quantum = max(min(rate >> 12, 1514ULL), 300ULL);
		rate_shft = 32;
		rate_ns = ((u64) NSEC_PER_SEC) << rate_shft;
		do_div(rate_ns, max(MIN_RATE, rate));
		while (!!(rate_ns >> 32)) {
			rate_ns >>= 1;
			rate_shft--;
		}
	} /* else unlimited, ie. zero delay */

	b->tin_rate_bps  = rate;
	b->tin_rate_ns   = rate_ns;
	b->tin_rate_shft = rate_shft;
}

static void tart_reconfigure(struct Qdisc *sch)
{
	struct tart_sched_data *q = qdisc_priv(sch);
	int c;

	tart_config_besteffort(sch);

	BUG_ON(q->tin_cnt > TART_MAX_TINS);
	for (c = q->tin_cnt; c < TART_MAX_TINS; c++)
		tart_clear_tin(sch, c);

	q->rate_ns   = q->tins[0].tin_rate_ns;
	q->rate_shft = q->tins[0].tin_rate_shft;

	if (q->buffer_config_limit) {
		q->buffer_limit = q->buffer_config_limit;
	} else if (q->rate_bps) {
		u64 t = (u64) q->rate_bps * q->interval;

		do_div(t, USEC_PER_SEC / 4);
		q->buffer_limit = max_t(u32, t, 65536U);

	} else {
		q->buffer_limit = ~0;
	}

	q->cparams.target = max_t(u64,US2TIME(q->target),0);
	q->cparams.interval = US2TIME(q->interval);

	sch->flags &= ~TCQ_F_CAN_BYPASS;

	q->buffer_limit = min(q->buffer_limit,
		max(sch->limit * psched_mtu(qdisc_dev(sch)),
		    q->buffer_config_limit));
}

static int tart_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct tart_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_TART_MAX + 1];
	int err;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_TART_MAX, opt, tart_policy);
	if (err < 0)
		return err;

	if (tb[TCA_TART_BASE_RATE])
		q->rate_bps = nla_get_u32(tb[TCA_TART_BASE_RATE]);

	if (tb[TCA_TART_ATM]) {
		if (!!nla_get_u32(tb[TCA_TART_ATM]))
			q->rate_flags |= TART_FLAG_ATM;
		else
			q->rate_flags &= ~TART_FLAG_ATM;
	}

	if (tb[TCA_TART_OVERHEAD])
		q->rate_overhead = nla_get_s32(tb[TCA_TART_OVERHEAD]);

	if (tb[TCA_TART_RTT]) {
		q->interval = nla_get_u32(tb[TCA_TART_RTT]);

		if (!q->interval)
			q->interval = 1;
	}

	if (tb[TCA_TART_TARGET]) {
		q->target = nla_get_u32(tb[TCA_TART_TARGET]);

		if (!q->target)
			q->target = 6000;
	}

	if (q->tins) {
		sch_tree_lock(sch);
		tart_reconfigure(sch);
		sch_tree_unlock(sch);
	}

	return 0;
}

static void *tart_zalloc(size_t sz)
{
	void *ptr = kzalloc(sz, GFP_KERNEL | __GFP_NOWARN);

	if (!ptr)
		ptr = vzalloc(sz);
	return ptr;
}

static void tart_free(void *addr)
{
	if (addr)
		kvfree(addr);
}

static void tart_destroy(struct Qdisc *sch)
{
	struct tart_sched_data *q = qdisc_priv(sch);

	qdisc_watchdog_cancel(&q->watchdog);

	if (q->tins) {
		u32 i;

		for (i = 0; i < TART_MAX_TINS; i++) {
			tart_free(q->tins[i].flows);
		}
		tart_free(q->tins);
	}
}

static int tart_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct tart_sched_data *q = qdisc_priv(sch);
	int i, j;

	sch->limit = 1024;
	q->rate_bps = 0; /* unlimited by default */

	q->interval = 60000; /* 60ms default */
	q->target   =  6000; /* 6ms: codel RFC argues
			       * for 5 to 10% of interval
			       */

	q->cur_tin = 0;
	q->cur_flow  = 0;

	if (opt) {
		int err = tart_change(sch, opt);

		if (err)
			return err;
	}

	qdisc_watchdog_init(&q->watchdog, sch);

	q->tins = tart_zalloc(TART_MAX_TINS * sizeof(struct tart_tin_data));
	if (!q->tins)
		goto nomem;

	for (i = 0; i < TART_MAX_TINS; i++) {
		struct tart_tin_data *b = q->tins + i;

		b->flows_cnt = 1024;
		INIT_LIST_HEAD(&b->new_flows);
		INIT_LIST_HEAD(&b->old_flows);
		/* codel_params_init(&b->cparams); */

		b->flows    = tart_zalloc(b->flows_cnt *
					     sizeof(struct tart_flow));
		if (!b->flows)
			goto nomem;

		for (j = 0; j < b->flows_cnt; j++) {
			struct tart_flow *flow = b->flows + j;

			INIT_LIST_HEAD(&flow->flowchain);
			codel_vars_init(&flow->cvars);
		}
	}

	tart_reconfigure(sch);
	return 0;

nomem:
	tart_destroy(sch);
	return -ENOMEM;
}

static int tart_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct tart_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (!opts)
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_TART_BASE_RATE, q->rate_bps))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_TART_ATM, !!(q->rate_flags & TART_FLAG_ATM)))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_TART_OVERHEAD, q->rate_overhead))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_TART_RTT, q->interval))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_TART_TARGET, q->target))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_TART_AUTORATE,
			!!(q->rate_flags & TART_FLAG_AUTORATE_INGRESS)))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_TART_MEMORY, q->buffer_config_limit))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	return -1;
}

static int tart_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	/* reuse fq_codel stats format */
	struct tart_sched_data *q = qdisc_priv(sch);
	struct tc_tart_xstats *st = tart_zalloc(sizeof(*st));
	int i;

	if (!st)
		return -1;

	BUG_ON(q->tin_cnt > TC_TART_MAX_TINS);

	st->version = 3;
	st->max_tins = TC_TART_MAX_TINS;
	st->tin_cnt = q->tin_cnt;

	for (i = 0; i < q->tin_cnt; i++) {
		struct tart_tin_data *b = &q->tins[i];

		st->threshold_rate[i]     = b->tin_rate_bps;
		st->target_us[i]          = codel_time_to_us(q->cparams.target);
		st->interval_us[i]        =
			codel_time_to_us(q->cparams.interval);

		/* TODO FIXME: add missing aspects of these composite stats */
		st->sent[i].packets       = b->packets;
		st->sent[i].bytes         = b->bytes;
		st->dropped[i].packets    = b->tin_dropped;
		st->ecn_marked[i].packets = b->tin_ecn_mark;
		st->backlog[i].bytes      = b->tin_backlog;

	}
	st->memory_limit      = q->buffer_limit;
	st->memory_used       = 0;

	i = gnet_stats_copy_app(d, st, sizeof(*st));
	tart_free(st);
	return i;
}

static struct Qdisc *tart_leaf(struct Qdisc *sch, unsigned long arg)
{
	return NULL;
}

static unsigned long tart_get(struct Qdisc *sch, u32 classid)
{
	return 0;
}

static unsigned long tart_bind(struct Qdisc *sch, unsigned long parent,
			       u32 classid)
{
	return 0;
}

static void tart_put(struct Qdisc *q, unsigned long cl)
{
}

static struct tcf_proto **tart_find_tcf(struct Qdisc *sch, unsigned long cl)
{
	return NULL;
}

static int tart_dump_tin(struct Qdisc *sch, unsigned long cl,
			 struct sk_buff *skb, struct tcmsg *tcm)
{
	tcm->tcm_handle |= TC_H_MIN(cl);
	return 0;
}

static int tart_dump_class_stats(struct Qdisc *sch, unsigned long cl,
				 struct gnet_dump *d)
{
	/* reuse fq_codel stats format */
	struct tart_sched_data *q = qdisc_priv(sch);
	struct tart_tin_data *b = q->tins;
	u32 tin = 0, idx = cl - 1;
	struct gnet_stats_queue qs = {0};
	struct tc_fq_codel_xstats xstats;

	while (tin < q->tin_cnt && idx >= b->flows_cnt) {
		idx -= b->flows_cnt;
		tin++;
		b++;
	}

	if (tin < q->tin_cnt && idx >= b->flows_cnt) {
		const struct tart_flow *flow = &b->flows[idx];
		const struct sk_buff *skb = flow->head;

		memset(&xstats, 0, sizeof(xstats));
		xstats.type = TCA_FQ_CODEL_XSTATS_CLASS;
		xstats.class_stats.deficit = flow->deficit;
		xstats.class_stats.ldelay = 0;
		xstats.class_stats.count = flow->cvars.count;
		xstats.class_stats.lastcount = 0;
		xstats.class_stats.dropping = flow->cvars.dropping;
		if (flow->cvars.dropping) {
			codel_tdiff_t delta = flow->cvars.drop_next -
				codel_get_time();

			xstats.class_stats.drop_next = (delta >= 0) ?
				codel_time_to_us(delta) :
				-codel_time_to_us(-delta);
		}
		while (skb) {
			qs.qlen++;
			skb = skb->next;
		}
		qs.backlog = b->backlogs[idx];
		qs.drops = flow->dropped;
	}
	if (codel_stats_copy_queue(d, NULL, &qs, 0) < 0)
		return -1;
	if (tin < q->tin_cnt && idx >= b->flows_cnt)
		return gnet_stats_copy_app(d, &xstats, sizeof(xstats));
	return 0;
}

static void tart_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct tart_sched_data *q = qdisc_priv(sch);
	unsigned int i, j, k;

	if (arg->stop)
		return;

	for (j = k = 0; j < q->tin_cnt; j++) {
		struct tart_tin_data *b = &q->tins[j];

		for (i = 0; i < b->flows_cnt; i++, k++) {
			if (list_empty(&b->flows[i].flowchain) ||
			    arg->count < arg->skip) {
				arg->count++;
				continue;
			}
			if (arg->fn(sch, k + 1, arg) < 0) {
				arg->stop = 1;
				break;
			}
			arg->count++;
		}
	}
}

static const struct Qdisc_class_ops tart_class_ops = {
	.leaf		=	tart_leaf,
	.get		=	tart_get,
	.put		=	tart_put,
	.tcf_chain	=	tart_find_tcf,
	.bind_tcf	=	tart_bind,
	.unbind_tcf	=	tart_put,
	.dump		=	tart_dump_tin,
	.dump_stats	=	tart_dump_class_stats,
	.walk		=	tart_walk,
};

static struct Qdisc_ops tart_qdisc_ops __read_mostly = {
	.cl_ops		=	&tart_class_ops,
	.id		=	"tart",
	.priv_size	=	sizeof(struct tart_sched_data),
	.enqueue	=	tart_enqueue,
	.dequeue	=	tart_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.drop		=	tart_drop,
	.init		=	tart_init,
	.reset		=	tart_reset,
	.destroy	=	tart_destroy,
	.change		=	tart_change,
	.dump		=	tart_dump,
	.dump_stats	=	tart_dump_stats,
	.owner		=	THIS_MODULE,
};

static int __init tart_module_init(void)
{
	return register_qdisc(&tart_qdisc_ops);
}

static void __exit tart_module_exit(void)
{
	unregister_qdisc(&tart_qdisc_ops);
}

module_init(tart_module_init)
module_exit(tart_module_exit)
MODULE_AUTHOR("Dave Taht");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("The Tart shaper. Version: " TART_VERSION);
