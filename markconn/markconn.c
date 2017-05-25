#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netlink/cli/ct.h>


#define MARK_GOOD	31337
#define MARK_BAD	666

#define CT_ATTR_FAMILY		(1UL << 0)
#define CT_ATTR_PROTO		(1UL << 1)
#define CT_ATTR_ORIG_SRC_PORT	(1UL << 10)
#define CT_ATTR_ORIG_DST_PORT	(1UL << 11)
#define CT_ATTR_MARK		(1UL << 5)

#define NLHDR_COMMON                            \
	int                     ce_refcnt;      \
	struct nl_object_ops *  ce_ops;         \
	struct nl_cache *       ce_cache;       \
	struct nl_list_head     ce_list;        \
	int                     ce_msgtype;     \
	int                     ce_flags;       \
	uint32_t                ce_mask;

union nfnl_ct_protoinfo {
	struct {
		uint8_t         state;
	} tcp;
};

union nfnl_ct_proto
{
	struct {
		uint16_t        src;
		uint16_t        dst;
	} port;
	struct {
		uint16_t        id;
		uint8_t         type;
		uint8_t         code;
	} icmp;
};

struct nfnl_ct_dir {
	struct nl_addr *        src;
	struct nl_addr *        dst;
	union nfnl_ct_proto     proto;
	uint64_t                packets;
	uint64_t                bytes;
};

struct xnfnl_ct {
	NLHDR_COMMON

	uint8_t                 ct_family;
	uint8_t                 ct_proto;
	union nfnl_ct_protoinfo ct_protoinfo;

	uint32_t                ct_status;
	uint32_t                ct_status_mask;
	uint32_t                ct_timeout;
	uint32_t                ct_mark;
	uint32_t                ct_use;
	uint32_t                ct_id;
	uint16_t                ct_zone;

	struct nfnl_ct_dir      ct_orig;
	struct nfnl_ct_dir      ct_repl;

	struct nfnl_ct_timestamp ct_tstamp;
};



void exit_error(int code, const char *fnname) {
	const char *msg = nl_geterror(code);

	fprintf(stderr, "Fatal error returned by %s: %s\n", fnname, msg);
	exit(EXIT_FAILURE);
}

void mark_connection(const char *srcip, uint16_t srcport, const char *dstip, uint16_t dstport, int mark) {
	struct nfnl_ct *ct = NULL;
	struct nl_addr *src_addr = NULL, *dst_addr = NULL;
	struct nl_sock *sk = NULL;
	int res;

	if ((ct = nfnl_ct_alloc()) == NULL) {
		fprintf(stderr, "Error: nfnl_ct_alloc() returned NULL");
		exit(EXIT_FAILURE);
	}

	nfnl_ct_set_family(ct, AF_INET);
	nfnl_ct_set_proto(ct, IPPROTO_TCP);

	if ((res = nl_addr_parse(srcip, AF_INET, &src_addr)) != 0) {
		fprintf(stderr, "Error: could not parse source IP: %s\n", srcip);
		exit_error(res, "nl_addr_parse");
	}

	if ((res = nfnl_ct_set_src(ct, 0, src_addr)) != 0) {
		fprintf(stderr, "Error: could not set source IP: %s\n", srcip);
		exit_error(res, "nfnl_ct_set_src");
	}

	if ((res = nl_addr_parse(dstip, AF_INET, &dst_addr)) != 0) {
		fprintf(stderr, "Error: could not parse destination IP: %s\n", dstip);
		exit_error(res, "nl_addr_parse");
	}

	if ((res = nfnl_ct_set_dst(ct, 0, dst_addr)) != 0) {
		fprintf(stderr, "Error: could not set destination IP: %s\n", dstip);
		exit_error(res, "nfnl_ct_set_dst");
	}

	nfnl_ct_set_src_port(ct, 0, srcport);
	nfnl_ct_set_dst_port(ct, 0, dstport);

	nfnl_ct_set_mark(ct, mark);

	if ((sk = nl_socket_alloc()) == NULL) {
		fprintf(stderr, "Error: nl_socket_alloc() returned NULL");
		exit(EXIT_FAILURE);
	}

	if ((res = nl_connect(sk, NETLINK_NETFILTER)) != 0) {
		exit_error(res, "nl_connect");
	}

	if ((res = nfnl_ct_add(sk, ct, NLM_F_REQUEST|NLM_F_ACK)) != 0) {
		exit_error(res, "nfnl_ct_add");
	}

	nl_addr_put(src_addr);
	nl_addr_put(dst_addr);

	nl_socket_free(sk);
	return;
}

int main(int argc, char *argv[]) {
	int sport, dport;
	int mark = MARK_BAD;

	if ((argc != 5) && (argc != 6)) {
		fprintf(stderr, "Usage: %s <srcip> <srcport> <dstip> <dstport> [mark#]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	sport = atoi(argv[2]);
	dport = atoi(argv[4]);

	if (!sport || sport > 65535) {
		fprintf(stderr, "Invalid source port specified.\n");
		exit(EXIT_FAILURE);
	}

	if (!dport || dport > 65535) {
		fprintf(stderr, "Invalid destination port specified.\n");
		exit(EXIT_FAILURE);
	}

	if (argc == 6) {
		mark = atoi(argv[5]);

		if (!mark) {
			fprintf(stderr, "Invalid mark value specified.\n");
			exit(EXIT_FAILURE);
		}

	}

	mark_connection(argv[1], sport, argv[3], dport, mark);
	printf("OK. Marked %d.\n", mark);
	exit(0);
}
