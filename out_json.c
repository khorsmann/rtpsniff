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

    struct rtpstat_t *rtpstat, *tmp;

    /*
    json_object *jobj = json_object_new_object();
    json_object *jtimestamp = json_object_new_int(unixtime_begin);
    json_object *jinterval = json_object_new_int(interval);
    // json_object *jmemory = json_object_new_string(memory);
    json_object *jtype = json_object_new_string("storage");
    json_object_object_add(jobj,"timestamp", jtimestamp);
    json_object_object_add(jobj,"interval", jinterval);
    // json_object_object_add(jobj,"memory", jmemory);
    json_object_object_add(jobj,"type", jtype);
    printf ("%s\n",json_object_to_json_string(jobj));
    */


    HASH_ITER(hh, memory, rtpstat, tmp) {
        streams += 1;
        packets += rtpstat->packets;
        lost += rtpstat->misssize;
        late += rtpstat->late;

        /* Streams with significant amounts of packets */
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
        printf("RTP: %s:%hu > %s:%hu"
                ", ssrc: %" PRIu32
                ", packets: %" PRIu32
                ", seq: %" PRIu16
                ", missed: %" PRIu16
                ", misssize: %" PRIu16
                ", late: %" PRIu16
                ", jump: %" PRIu16
                "\n",
                src_ip, rtpstat->src_port,
                dst_ip, rtpstat->dst_port,
                rtpstat->ssrc,
                rtpstat->packets,
                rtpstat->seq,
                rtpstat->missed,
                rtpstat->misssize,
                rtpstat->late,
                rtpstat->jumps);
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
        json_object *jlostp = json_object_new_double(100.0 * lost / packets);
        json_object *jlatep = json_object_new_double(100.0 * late / packets);

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
