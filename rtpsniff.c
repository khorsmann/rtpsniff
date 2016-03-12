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
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int timer_interval = 10;

static void exit_error(const char* errbuf) {
    fprintf(stderr, "RTPSniff: Initialization failed or bad command line "
                    "options. See -h for help:\n%s\n", errbuf);
    exit(EXIT_FAILURE);
}

int main(int argc, char const *const *argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    pcap_t *handle = NULL;
    int bufsize;

    struct memory_t memory = {
        .rtphash = {NULL, NULL},
        .active = 0,
        .request_switch = 0,
    };

    // Parse Arguments and Options
    int i;
    int buffer = 100;
    char * dev = "eth0";
    char * bpf = "udp and portrange 10000-30000";

    for(i = 1; i < argc; ++i) {
      if (strcmp(argv[i], "-f") == 0 || 
          strcmp(argv[i], "--filter") == 0) {
        if (i+1 == argc) {
          exit_error("Missing BPF filter");
        }
	// sprintf(bpf, "%s", argv[++i]);
	bpf = argv[++i];

      }
      else if (strcmp(argv[i], "-i") == 0 || 
               strcmp(argv[i], "--interface") == 0) {
        if (i+1 == argc) {
          exit_error("Missing interface name!");
        }
	// sprintf(dev, "%s", argv[++i]);
	dev = argv[++i];

      }
      else if (strcmp(argv[i], "-b") == 0 || 
               strcmp(argv[i], "--buffer") == 0) {
        if (i+1 == argc) {
          exit_error("Missing buffer size");
        }
        buffer = atoi(argv[++i]);

      }
      else if (strcmp(argv[i], "-t") == 0 || 
               strcmp(argv[i], "--timer") == 0) {
        if (i+1 == argc) {
          exit_error("Missing timer size");
        }
        timer_interval = atoi(argv[++i]);

      }
      else if (strcmp(argv[i], "-v") == 0 ||
               strcmp(argv[i], "--verbose") == 0) {
         fprintf(stderr, "RTPSniff: Initialization [device: %s] [bpf: '%s'] [ring buffer: %dk pps] [interval: %ds] \n", dev, bpf, buffer, timer_interval);

      }
      else if (strcmp(argv[i], "-h") == 0 ||
               strcmp(argv[i], "--help") == 0) {
        rtpsniff_help();
        sniff_help();
        timer_help();
        out_help();
        return 0;

      }
    }


    /* Try initialization */
    errbuf[0] = '\0';
    if (!dev || !bpf )
        exit_error("Missing arguments");
    if ((handle = pcap_create(dev, errbuf)) == NULL)
        exit_error(errbuf);
    if ((pcap_set_snaplen(handle, sniff_snaplen()) != 0) ||
            (pcap_set_timeout(handle, 1000) != 0) ||
            /* frame size is 128 for our snaplen,
             * we need to hold MAX_KPPS*1000*128 bytes if we poll and flush
             * every second. add a little extra for kicks.
             * If you set this too low, the "packets dropped by kernel" total
             * will increase dramatically. Note that that figure will always
             * show some packets because of startup/shutdown misses. */
            (pcap_set_buffer_size(handle, (bufsize = buffer * 1024 * 192)) != 0) ||
            (pcap_activate(handle) != 0) ||
            (pcap_compile(handle, &fp, bpf, 0, PCAP_NETMASK_UNKNOWN) == -1) ||
            (pcap_setfilter(handle, &fp) == -1)) {
        fprintf(stderr, "RTPSniff: Initialization failed: %s\n", pcap_geterr(handle));
        if (handle)
            pcap_close(handle);
        exit(EXIT_FAILURE);
    }


#ifndef NDEBUG
    fprintf(stderr, "rtpsniff: Initialized a packet ring buffer of %d KB, "
                    "should safely handle more than %d thousand packets per second.\n",
            bufsize / 1024, atoi(argv[2]));
#endif

    /* Initialize updater thread */
    timer_loop_bg(&memory);

    /* Start the main loop (ends on INT/HUP/TERM/QUIT or error) */
    sniff_loop(handle, &memory);

    /* Finish updater thread */
    timer_loop_stop();

    /* Finish/close open stuff */
    sniff_release(&memory.rtphash[0]);
    sniff_release(&memory.rtphash[1]);

    out_close();
    pcap_close(handle);
    return 0;
}

void rtpsniff_help() {
    printf(
        "Usage:\n"
        "  rtpsniff {args}\n"
        "\n"
        "Arguments:\n"

        "  -i   IFACE is the interface to sniff on.\n"
        "  -f   PCAP_FILTER is the common BPF filter.\n"
        "  -b   MAX_KPPS is the amount of Kpackets per second you expect. if you\n"
        "       go too low, the buffers won't be sufficient.\n"
        "  -t   TIMER output interval in seconds.\n"
        "  -v   VERBOSE output mode.\n"
        "  -h   HELP output for loaded modules.\n"
        "\n"
        "Example:\n"
        "  rtpsniff -i eth0 -b 100 -f 'udp and portrange 10000-30000'\n"
        "\n"
    );
}
