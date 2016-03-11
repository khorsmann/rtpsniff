/* vim: set ts=8 sw=4 sts=4 et: */
/*======================================================================
Copyright (C) 2008,2009,2014 OSSO B.V. <walter+rtpsniff@osso.nl>
This file is part of RTPSniff.

RTPSniff is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

RTPSniff is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License along
with RTPSniff.  If not, see <http://www.gnu.org/licenses/>.
======================================================================*/

#include "rtpsniff.h"
#include "endian.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netpacket/packet.h> /* linux-specific: struct_ll and PF_PACKET */

/* Static constants (also found in linux/if_ether.h) */
#if BYTE_ORDER == LITTLE_ENDIAN
# define ETH_P_ALL 0x0300   /* all frames */
# define ETH_P_IP 0x0008    /* IP frames */
# define ETH_P_8021Q 0x0081 /* 802.1q vlan frames */
#elif BYTE_ORDER == BIG_ENDIAN
# define ETH_P_ALL 0x0003   /* all frames */
# define ETH_P_IP 0x0800    /* IP frames */
# define ETH_P_8021Q 0x8100 /* 802.1q vlan frames */
#endif


/* Ethernet header */
struct sniff_ether {
    uint8_t dest[6];        /* destination host address */
    uint8_t source[6];      /* source host address */
    uint16_t type;          /* ETH_P_* type */
    uint16_t pcp_cfi_vid;   /* 3bit prio, 1bit format indic, 12bit vlan (0=no, fff=reserved) */
    uint16_t type2;         /* encapsulated type */
};

/* IP header */
struct sniff_ip {
    /* Take care, place the bitmasks in high order first. */
    uint8_t hl:4,           /* header length */
            ver:4;          /* version */
    uint8_t  tos;           /* type of service */
    uint16_t len;           /* total length */
    uint16_t id;            /* identification */
    uint16_t off;           /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    uint8_t  ttl;           /* time to live */
    uint8_t  proto;         /* protocol */
    uint16_t sum;           /* checksum */
    uint32_t src;           /* source address */
    uint32_t dst;           /* dest address */
};

#define PROTO_TCP 6
#define PROTO_UDP 17

/* UDP header */
struct sniff_udp {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t sum;
};

/* RTP header */
struct sniff_rtp {
    /* Take care, place the bitmasks in high order first. */
    uint8_t cc:4,
            x:1,
            p:1,
            ver:2;
    uint8_t pt:7,
            m:1;
    uint16_t seq;
    uint32_t stamp;
    uint32_t ssrc;
    u_int32_t csrc;
    /* ... */
};


/* Payloads */
#define PT_ULAW 0
#define PT_G723	4
#define PT_ALAW 8
#define PT_G729	18
#define PT_GSM  3
#define PT_G722 9
#define PT_L16_STEREO 10
#define PT_L16_MONO 11
#define PT_QCELP 12

typedef struct _kv {
  u_int32_t  key;
  u_int32_t  value;
} kv;

/* Clockrates */
static const kv clockrate[] = {
  {0, 8000},
  {4, 8000},
  {8, 8000},
  {18, 8000},
  {3, 8000},
  {9, 8000},
  {10, 44100},
  {11, 44100},
  {12, 8000}
};

#define CLOCK_SIZE  (sizeof clockrate / sizeof clockrate[0])

static u_int32_t get_clockrate(u_int32_t key)
{
  size_t i;
  for (i = 0; i < CLOCK_SIZE; i++) {
    if (clockrate[i].key == key)
      return clockrate[i].value;
  }
  return 1;
}


static struct memory_t *sniff__memory;
static pcap_t *sniff__handle;


static void sniff__switch_memory(int signum);
static void sniff__loop_done(int signum);


void sniff_help() {
    printf(
        "/*********************"
        " module: sniff (pcap+rtp) *******************************/\n"
        "Sniff uses libpcap to listen for all incoming and outgoing RTP packets.\n"
        "\n"
    );
}


/* RTCP Stuff */

typedef struct _rtcp_header
{
#if BYTE_ORDER == BIG_ENDIAN
	uint16_t version:2;
	uint16_t padding:1;
	uint16_t rc:5;
	uint16_t type:8;
#elif BYTE_ORDER == LITTLE_ENDIAN
	uint16_t rc:5;
	uint16_t padding:1;
	uint16_t version:2;
	uint16_t type:8;
#endif
	uint16_t length:16;
} rtcp_header_t;

#define rtcp_header_get_length(ch)       ntohs((ch)->length)

typedef struct _sender_info
{
	uint32_t ntp_timestamp_msw;
	uint32_t ntp_timestamp_lsw;
	uint32_t rtp_timestamp;
	uint32_t senders_packet_count;
	uint32_t senders_octet_count;
} sender_info_t;

#define sender_info_get_ntp_timestamp_msw(si) ((si)->ntp_timestamp_msw)
#define sender_info_get_ntp_timestamp_lsw(si) ((si)->ntp_timestamp_lsw)
#define sender_info_get_rtp_timestamp(si) ((si)->rtp_timestamp)
#define sender_info_get_packet_count(si) ntohl((si)->senders_packet_count)
#define sender_info_get_octet_count(si) ntohl((si)->senders_octet_count)

/*! \brief RTCP Report Block (http://tools.ietf.org/html/rfc3550#section-6.4.1) */
typedef struct _report_block
{

	uint32_t ssrc;
	uint8_t fl_cnpl;
	uint8_t lost[3];
	uint32_t ext_high_seq_num_rec;
	uint32_t interarrival_jitter;
	uint32_t lsr;
	uint32_t delay_snc_last_sr;
} report_block_t;

#define report_block_get_ssrc(rb) ntohl((rb)->ssrc)
#define report_block_get_fraction_lost(rb) ntohl((rb)->fl_cnpl)
#define report_block_get_cum_packet_loss(rb) ntohl((rb)->lost[0])
#define report_block_get_high_ext_seq(rb) ntohl(((report_block_t*)(rb))->ext_high_seq_num_rec)
#define report_block_get_interarrival_jitter(rb) ntohl(((report_block_t*)(rb))->interarrival_jitter)
#define report_block_get_last_SR_time(rb) ntohl(((report_block_t*)(rb))->lsr)
#define report_block_get_last_SR_delay(rb) ntohl(((report_block_t*)(rb))->delay_snc_last_sr)
typedef struct _rtcp_rr
{
	rtcp_header_t header;
	uint32_t ssrc;
	report_block_t rb[1];
} rtcp_rr_t;

typedef struct _rtcp_sr
{
	rtcp_header_t header;
	uint32_t ssrc;
	sender_info_t si;
	report_block_t rb[1];
} rtcp_sr_t;


/* ... */

/* Main */

static void sniff_got_packet(u_char *args, const struct pcap_pkthdr *header,
                        const u_char *packet) {
    time_t sec = header->ts.tv_sec;
    long int usec = header->ts.tv_usec;
    uint64_t now = (uint32_t)sec * 1000000 + usec;
    int64_t off;
    uint16_t report_type = 0;

    struct sniff_ether *ether = (struct sniff_ether*)packet;
    struct sniff_ip *ip;
    struct sniff_udp *udp;
    uint16_t sport;
    uint16_t dport;
    struct sniff_rtp *rtp;

    if (ether->type == ETH_P_IP) {
        ip = (struct sniff_ip*)(packet + 14);
    } else if (ether->type == ETH_P_8021Q && ether->type2 == ETH_P_IP) {
        ip = (struct sniff_ip*)(packet + 18);
    } else {
        /* Skip. */
        return;
    }

    if (ip->proto != PROTO_UDP) {
        return;
    }

    udp = (struct sniff_udp*)(ip + 1);
    sport = htons(udp->sport);
    dport = htons(udp->dport);
    rtp = (struct sniff_rtp*)(udp + 1);

    /*
    u_char *rtcp;
    rtcp = (u_char *)rtp;
    if (rtcp[0] == 0x80 || rtcp[0] == 0x81) {
		if (rtcp[1] == 0xc8 || rtcp[1] == 0xc9) {
			// printf("RTCP Packet detected!\n");
			report_type = 1;
		}
    }
    */

    if ( (rtp->pt >= 72 && rtp->pt <= 76) && (sport % 2 && dport % 2) ) report_type = 1; // RTCP
    if (rtp->pt >= 101 && rtp->pt <= 102) report_type = 2; //  DTMF

    if (ntohs(udp->len) < sizeof(struct sniff_rtp)) {
        return;
    }
    if (rtp->ver != 2) {
        return;
    }

    {
        int recently_active = sniff__memory->active;
        struct rtpstat_t *curmem = sniff__memory->rtphash[recently_active];
        uint16_t seq = ntohs(rtp->seq);
        struct rtpstat_t find = {
            .src_ip = ntohl(ip->src),
            .dst_ip = ntohl(ip->dst),
            .src_port = sport,
            .dst_port = dport,
            /* ignore: tlen, vlan */
            .ssrc = ntohl(rtp->ssrc),
            /* the rest: zero */
        };
        struct rtpstat_t *old;


#if 0
        fprintf(stderr, "len: %hhu, %hhu, %hhu, %hhu, %hhu, %hhu\n",
                rtp->ver, rtp->p, rtp->x, rtp->cc, rtp->m, rtp->pt);
#endif

        HASH_FIND(hh, curmem, &find.HASH_FIRST, HASH_SIZE(find), old);
        if (!old) {
            struct rtpstat_t *rtpstat = malloc(sizeof(*rtpstat));
            if (rtpstat) {
                memcpy(rtpstat, &find, sizeof(*rtpstat));
                /* ignore: rtp->stamp */
                rtpstat->seq = seq;
                rtpstat->packets = 1;
		rtpstat->min_diff_usec = (uint64_t)-1;
		rtpstat->prev = now;
		rtpstat->timestamp = 0;
		rtpstat->jitter = 0;

		// Report Type
		rtpstat->report_type = report_type;

		// Payload
		rtpstat->enc = rtp->pt;
		rtpstat->clockrate = get_clockrate(rtp->pt);

	        // fprintf(stderr, "NEW LEG: codec=%hhu, clockrate=%d\n", rtpstat->enc, rtpstat->clockrate);


	        // fprintf(stderr, "NEW LEG: %hhu, %hhu\n", rtpstat->report_type, rtp->pt);

                HASH_ADD(hh, curmem, HASH_FIRST, HASH_SIZE(*rtpstat), rtpstat);
            }
        } else {

          if (old->report_type == 0) {
	  // RTP Packet
	  int skip = 0;

            if (old->seq + 1 == seq) {
                /* Excellent! */
            } else {
                int16_t diff = seq - old->seq;
                if (diff < -15 || 15 < diff) {
                    old->jumps += 1;
                } else if (diff > 0) {
                    old->missed += 1;
                    old->misssize += (diff - 1);
		    skip = 1;
                } else {
                    old->late += 1;
                }
            }

	    if (skip == 0) {
		   off = now - old->prev;
	           if (off >= 0) {
	        	    if (off < old->min_diff_usec)
	        	        old->min_diff_usec = off;
	        	    if (off > old->max_diff_usec)
	        	        old->max_diff_usec = off;
	            } else {
	        	    /* Got packets out of order! Ignoring timestamp! */
	        	    old->out_of_order += 1;
	            }
	    }

	    off = (rtp->stamp - old->timestamp) / old->clockrate / 100;
	    old->jitter = (( 15 * old->jitter) + off) / 16;

            old->packets += 1;
            old->seq = seq;
	    old->prev = now;

          } else if (old->report_type == 1) {
	  // RTCP Packet

		// printf("Processing RTCP... \n");
		rtcp_header_t *rtcp = (rtcp_header_t *)rtp;

		if(rtcp->version != 2)
		{
			// printf("wrong RTCP version! \n");
			return;
		} else {
			// printf("valid RTCP! \n");
			if (rtcp->type == 201) {
				rtcp_rr_t *rr = (rtcp_rr_t*)rtcp;
				if(rr->header.rc > 0) {
					fprintf(stderr, "RTCP type: %hhu, ssrc: %hhu, seq: %d, lost: %d, jitter: %d, tot_lost: %d, lasr_sr: %d, sr_delay: %d \n",
						//	ntohl(rr->ssrc), 
							rtcp->type,
							report_block_get_ssrc(&rr->rb[0]),
							report_block_get_high_ext_seq(&rr->rb[0]),
							report_block_get_fraction_lost(&rr->rb[0]),
							report_block_get_interarrival_jitter(&rr->rb[0]),
							report_block_get_cum_packet_loss(&rr->rb[0]),
							report_block_get_last_SR_time(&rr->rb[0]),
							report_block_get_last_SR_delay(&rr->rb[0])
					);
			            old->packets += 1;
				    old->missed = report_block_get_cum_packet_loss(&rr->rb[0]) - old->missed;
				    old->jitter = (15 * old->jitter + report_block_get_interarrival_jitter(&rr->rb[0]))/16;
				    old->prev = report_block_get_last_SR_time(&rr->rb[0]);
				}
			} else if (rtcp->type == 200) {
				rtcp_sr_t *sr = (rtcp_sr_t*)rtcp;
					fprintf(stderr, "RTCP ntp_ts_msw: %hhu, ntp_ts_lsw: %hhu, octets: %hhu, rtp_ts: %hhu, packets: %hhu \n",
							sender_info_get_ntp_timestamp_msw(&sr->si),
							sender_info_get_ntp_timestamp_lsw(&sr->si),
							sender_info_get_octet_count(&sr->si),
							sender_info_get_rtp_timestamp(&sr->si),
							sender_info_get_packet_count(&sr->si));

				if(sr->header.rc > 0) {
					fprintf(stderr, "RTCP RC type: %hhu, ssrc: %hhu, seq: %hhu, lost: %hhu, jitter: %hhu, tot_lost: %hhu, lasr_sr: %hhu, sr_delay: %hhu \n",
							// ntohl(sr->ssrc), 
							rtcp->type,
							report_block_get_ssrc(&sr->rb[0]),
							report_block_get_high_ext_seq(&sr->rb[0]),
							report_block_get_fraction_lost(&sr->rb[0]),
							report_block_get_interarrival_jitter(&sr->rb[0]),
							report_block_get_cum_packet_loss(&sr->rb[0]),
							report_block_get_last_SR_time(&sr->rb[0]),
							report_block_get_last_SR_delay(&sr->rb[0])
					);

			         //   old->packets += 1;
				 //   old->missed = report_block_get_cum_packet_loss(&sr->rb[0]) - old->missed;
				 //   old->jitter = (15 * old->jitter + report_block_get_interarrival_jitter(&sr->rb[0]))/16;
				 //   old->prev = report_block_get_last_SR_time(&sr->rb[0]);
				}

			}
		}


          }

        }

        /* HASH_ADD may have mutated the pointer. */
        sniff__memory->rtphash[recently_active] = curmem;
    }
}

int sniff_snaplen() {
    return (sizeof(struct sniff_ether) +
            sizeof(struct sniff_ip) +
            sizeof(struct sniff_udp) +
            sizeof(struct sniff_rtp));
}

void sniff_loop(pcap_t *handle, struct memory_t *memory) {
    struct pcap_stat stat = {0,};

    /* Set memory and other globals */
    sniff__handle = handle;
    sniff__memory = memory;

    /* Add signal handlers */
    util_signal_set(SIGUSR1, sniff__switch_memory);
    util_signal_set(SIGINT, sniff__loop_done);
    util_signal_set(SIGHUP, sniff__loop_done);
    util_signal_set(SIGQUIT, sniff__loop_done);
    util_signal_set(SIGTERM, sniff__loop_done);

#ifndef NDEBUG
    fprintf(stderr, "sniff_loop: Starting loop (mem %p/%p/%i).\n",
            memory->rtphash[0], memory->rtphash[1], memory->active);
#endif

    /* This uses the fast PACKET_RX_RING if available. */
    pcap_loop(handle, 0, sniff_got_packet, NULL);

#ifndef NDEBUG
    fprintf(stderr, "sniff_loop: Ended loop at user/system request.\n");
#endif

    if (pcap_stats(handle, &stat) < 0) {
            fprintf(stderr, "pcap_stats: %s\n", pcap_geterr(handle));
            return;
    }

    // FIXME: move this to out_*
    //fprintf(stderr, "%u packets captured\n", packets_captured);
    // and how many minutes? produce a grand total?
    fprintf(stderr, "%u packets received by filter\n", stat.ps_recv);
    fprintf(stderr, "%u packets dropped by kernel\n", stat.ps_drop);
    fprintf(stderr, "%u packets dropped by interface\n", stat.ps_ifdrop);

    /* Remove signal handlers */
    util_signal_set(SIGUSR1, SIG_IGN);
    util_signal_set(SIGINT, SIG_IGN);
    util_signal_set(SIGHUP, SIG_IGN);
    util_signal_set(SIGQUIT, SIG_IGN);
    util_signal_set(SIGTERM, SIG_IGN);
}

static void sniff__switch_memory(int signum) {
    int recently_active = sniff__memory->active;
    sniff__memory->active = !recently_active;
#ifndef NDEBUG
    fprintf(stderr, "sniff__switch_memory: Switched from memory %d (%p) to %d (%p).\n",
            recently_active, sniff__memory->rtphash[recently_active],
            !recently_active, sniff__memory->rtphash[!recently_active]);
#endif
}

static void sniff__loop_done(int signum) {
    pcap_breakloop(sniff__handle);
}

void sniff_release(struct rtpstat_t **memory) {
    struct rtpstat_t *rtpstat, *tmp;
    HASH_ITER(hh, *memory, rtpstat, tmp) {
        HASH_DEL(*memory, rtpstat);
        free(rtpstat);
    }
}
