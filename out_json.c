/* vim: set ts=8 sw=4 sts=4 et: */
/*======================================================================
Copyright (C) 2008,2009,2014 OSSO B.V. <walter+rtpsniff@osso.nl>
Copyright (C) 2016 QXIP BV <info@qxip.nl>
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
#include <json/json.h>
#include <stdio.h>


void out_help() {
    printf(
        "/*********************"
        " module: out (console) **********************************/\n"
        "This is the JSON output module.\n"
        "FIXME: define what it does...\n"
        "\n"
    );
}

int out_open(char const *config_file) {
    return 0;
}

void out_close() {
}

void out_write(uint32_t unixtime_begin, uint32_t interval, struct rtpstat_t *memory) {
    char src_ip[16];
    char dst_ip[16];
    unsigned streams = 0;
    unsigned packets = 0;
    unsigned lost = 0;
    unsigned late = 0;
    unsigned ooo = 0;
    unsigned dmin = 0;
    unsigned dmax = 0;
    unsigned davg = 0;
    unsigned jitter = 0;

    double latency = 0;
    double mos = 0;
    double r_factor = 0;

    unsigned rtcpstreams = 0;
    unsigned rtcppackets = 0;
    unsigned rtcplost = 0;
    unsigned rtcplate = 0;

    struct rtpstat_t *rtpstat, *tmp;

    HASH_ITER(hh, memory, rtpstat, tmp) {

     if (rtpstat->report_type == 1 ) { /* RTCP */
     // if (rtpstat->report_type == 1 || ( rtpstat->src_port % 2 && rtpstat->dst_port % 2) ) { /* RTCP */

        rtcpstreams += 1;
        rtcppackets += rtpstat->packets;
        rtcplost += rtpstat->misssize;
        rtcplate += rtpstat->late;

     } else { /* RTP */

        streams += 1;
        packets += rtpstat->packets;
        lost += rtpstat->misssize;
        late += rtpstat->late;

	ooo += rtpstat->out_of_order;
	dmin += rtpstat->min_diff_usec / streams;
	dmax += rtpstat->max_diff_usec / streams;
		if (dmin > dmax) dmin = 0;
	davg = (dmax + dmin) / 2;

	jitter += rtpstat->jitter / streams;

	/* MOS */

	latency = (davg + (jitter * 2) + 10) / 1000;

  	if(latency < 160) {
  	  r_factor = 93.2 - (latency / 40);
  	} else {
  	  r_factor = 93.2 - (latency - 120) / 10;
  	}
  	r_factor = r_factor - (lost * 2.5);

  	mos = 1 + (0.035) * (r_factor) +
  	  (0.000007) * (r_factor) * ((r_factor) - 60)
  	  * (100 - (r_factor));

	if (mos < 0) mos = 0;
	if (mos > 5) mos = 5;

	// fprintf(stderr, "NEW MOS: %.2f \n", (double)mos);


        /* Reports individual Streams with significant issues */
        if (rtpstat->packets < 20)
            continue;
        /* Streams with issues */
        if (rtpstat->missed == 0 && rtpstat->late == 0 && rtpstat->jumps == 0)
            continue;
        /* Packets lost minimum 5% */
        if (rtpstat->misssize * 100 / rtpstat->packets < 5)
            continue;

        sprintf(src_ip, "%hhu.%hhu.%hhu.%hhu",
                rtpstat->src_ip >> 24, (rtpstat->src_ip >> 16) & 0xff,
                (rtpstat->src_ip >> 8) & 0xff, rtpstat->src_ip & 0xff);
        sprintf(dst_ip, "%hhu.%hhu.%hhu.%hhu",
                rtpstat->dst_ip >> 24, (rtpstat->dst_ip >> 16) & 0xff,
                (rtpstat->dst_ip >> 8) & 0xff, rtpstat->dst_ip & 0xff);

        json_object *jobj = json_object_new_object();
        json_object *jtimestamp = json_object_new_int(unixtime_begin);
        json_object *jtype 	= json_object_new_string("rtp_report");
        json_object *jsrcip 	= json_object_new_string(src_ip);
        json_object *jdstip 	= json_object_new_string(dst_ip);
        json_object *jsrcp 	= json_object_new_int(rtpstat->src_port);
        json_object *jdstp 	= json_object_new_int(rtpstat->dst_port);
        json_object *jssrc 	= json_object_new_int(rtpstat->ssrc);
        json_object *jpackets 	= json_object_new_int(rtpstat->packets);
        json_object *jlate 	= json_object_new_int(rtpstat->late);
        json_object *jmissed 	= json_object_new_int(rtpstat->missed);
        json_object *jmisssize 	= json_object_new_int(rtpstat->misssize);
        json_object *jjumps 	= json_object_new_int(rtpstat->jumps);

        json_object *jooo 	= json_object_new_int(rtpstat->out_of_order);
        json_object *jdmin 	= json_object_new_int64(rtpstat->min_diff_usec);
        json_object *jdmax 	= json_object_new_int64(rtpstat->max_diff_usec);

	json_object_object_add(jobj,"timestamp", jtimestamp);
        json_object_object_add(jobj,"ssrc", jssrc);
        json_object_object_add(jobj,"src_ip", jsrcip);
        json_object_object_add(jobj,"dst_ip", jdstip);
        json_object_object_add(jobj,"src_port", jsrcp);
        json_object_object_add(jobj,"dst_port", jdstp);
	json_object_object_add(jobj,"packets", jpackets);
	json_object_object_add(jobj,"lost", jmissed);
	json_object_object_add(jobj,"lost_size", jmisssize);
	json_object_object_add(jobj,"late", jlate);
	json_object_object_add(jobj,"burst", jjumps);

	json_object_object_add(jobj,"out_of_seq", jooo);
	json_object_object_add(jobj,"delay_min", jdmin);
	json_object_object_add(jobj,"delay_max", jdmax);

         json_object *jjitter 	= json_object_new_int64(rtpstat->jitter);
	 json_object_object_add(jobj,"jitter", jjitter);

         json_object *jmos 	= json_object_new_int(mos*100);
	 json_object_object_add(jobj,"mos", jmos);

	json_object_object_add(jobj,"type", jtype);

        printf ("%s\n",json_object_to_json_string(jobj));

      }
    }

    if (packets) {

        json_object *jobj = json_object_new_object();

        json_object *jtimestamp = json_object_new_int(unixtime_begin);
        json_object *jinterval = json_object_new_int(interval);
        json_object *jtype = json_object_new_string("rtp_stat");
        json_object *jstreams = json_object_new_int(streams);
        json_object *jpackets = json_object_new_int(packets);
        json_object *jlost = json_object_new_int(lost);
        json_object *jlate = json_object_new_int(late);
        json_object *jlostp = json_object_new_int((100.0 * lost / packets)*100);
        json_object *jlatep = json_object_new_int((100.0 * late / packets)*100);

        json_object *jooo 	= json_object_new_int(ooo);
        json_object *jdmin 	= json_object_new_int64(dmin);
        json_object *jdmax 	= json_object_new_int64(dmax);
        json_object *jdavg 	= json_object_new_int64(davg);

	json_object_object_add(jobj,"timestamp", jtimestamp);
        json_object_object_add(jobj,"interval", jinterval);
	json_object_object_add(jobj,"streams", jstreams);
	json_object_object_add(jobj,"packets", jpackets);
	json_object_object_add(jobj,"lost", jlost);
	json_object_object_add(jobj,"late", jlate);
	json_object_object_add(jobj,"lost_perc", jlostp);
	json_object_object_add(jobj,"late_perc", jlatep);

	json_object_object_add(jobj,"out_of_seq", jooo);
	json_object_object_add(jobj,"delay_min", jdmin);
	json_object_object_add(jobj,"delay_max", jdmax);
	json_object_object_add(jobj,"delay_avg", jdavg);

         json_object *jjitter 	= json_object_new_int64(jitter);
	 json_object_object_add(jobj,"jitter", jjitter);

         json_object *jmos 	= json_object_new_int(mos*100);
	 json_object_object_add(jobj,"mos", jmos);

	json_object_object_add(jobj,"type", jtype);

        printf ("%s\n",json_object_to_json_string(jobj));
    }

    if (rtcppackets) {

        json_object *jobj = json_object_new_object();

        json_object *jtimestamp = json_object_new_int(unixtime_begin);
        json_object *jinterval = json_object_new_int(interval);
        json_object *jtype = json_object_new_string("rtcp_stat");
        json_object *jstreams = json_object_new_int(rtcpstreams);
        json_object *jpackets = json_object_new_int(rtcppackets);
        json_object *jlost = json_object_new_int(rtcplost);
        json_object *jlate = json_object_new_int(rtcplate);
        json_object *jlostp = json_object_new_int((100.0 * rtcplost / rtcppackets)*100);
        json_object *jlatep = json_object_new_int((100.0 * rtcplate / rtcppackets)*100);

	json_object_object_add(jobj,"timestamp", jtimestamp);
        json_object_object_add(jobj,"interval", jinterval);
	json_object_object_add(jobj,"streams", jstreams);
	json_object_object_add(jobj,"packets", jpackets);
	json_object_object_add(jobj,"lost", jlost);
	json_object_object_add(jobj,"late", jlate);
	json_object_object_add(jobj,"lost_perc", jlostp);
	json_object_object_add(jobj,"late_perc", jlatep);
	json_object_object_add(jobj,"type", jtype);

        printf ("%s\n",json_object_to_json_string(jobj));
    }

    fflush(stdout);
}
