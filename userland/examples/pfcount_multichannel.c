/*
 * (C) 2003-20 - ntop
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "pfring.h"

#include "pfutils.c"

#define DEFAULT_DEVICE "mlx:mlx5_1"
#define ALARM_SLEEP 1
#define DEFAULT_SNAPLEN 1400
#define MAX_NUM_THREADS 64

typedef struct thread_stats {
  u_int64_t numPkts;
  u_int64_t numBytes;

  pfring *ring;
  pthread_t pd_thread;
  int core_affinity;

  volatile u_int64_t do_shutdown;
} t_thread_stats;

int num_channels = 1;

struct timeval startTime;
u_int8_t use_extended_pkt_header = 1, wait_for_packet = 1, do_shutdown = 0;
u_int numCPU;

t_thread_stats *threads;

void print_stats() {
  pfring_stat pfringStat;
  struct timeval endTime;
  double delta_abs;
  static u_int64_t lastPkts[MAX_NUM_THREADS] = {0};
  u_int64_t diff;
  static struct timeval lastTime;
  int i;
  unsigned long long bytes_received = 0, pkt_received = 0, pkt_dropped = 0;
  unsigned long long pkt_received_last = 0;
  double pkt_thpt = 0, tot_thpt = 0, delta_last;
  char buf1[64];

  if (startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    return;
  }

  gettimeofday(&endTime, NULL);
  delta_abs = delta_time(&endTime, &startTime);
  delta_last = delta_time(&endTime, &lastTime);

  for (i = 0; i < num_channels; i++) {
    bytes_received += threads[i].numBytes, pkt_received += threads[i].numPkts;

    if (pfring_stats(threads[i].ring, &pfringStat) >= 0) {
      double thpt = ((double)8 * threads[i].numBytes) / (delta_abs * 1000);

      fprintf(stderr,
              "======Channel=%d======\n"
              "%u recv / %u dropped]\n"
              "%u recv / %.1f %% dropped\n",
              i, (unsigned int)threads[i].numPkts,
              (unsigned int)pfringStat.drop,
              (unsigned int)(threads[i].numPkts + pfringStat.drop),
              threads[i].numPkts == 0
                  ? 0
                  : (double)(pfringStat.drop * 100) /
                        (double)(threads[i].numPkts + pfringStat.drop));
      fprintf(stderr, "%lu pkts - %lu bytes",
              (long unsigned int)threads[i].numPkts,
              (long unsigned int)threads[i].numBytes);
      fprintf(
          stderr, " [%s pps - %.2f Mbit/sec]\n",
          pfring_format_numbers((double)(threads[i].numPkts * 1000) / delta_abs,
                                buf1, sizeof(buf1), 1),
          thpt);
      pkt_dropped += pfringStat.drop;

      if (lastTime.tv_sec > 0) {
        double pps;

        diff = threads[i].numPkts - lastPkts[i];
        pkt_received_last += diff;
        tot_thpt += thpt;
        pps = ((double)diff / (double)(delta_last / 1000));
        fprintf(
            stderr, "[%llu pkts][%.1f ms][%s pps]\n",
            (long long unsigned int)diff, delta_last,
            pfring_format_numbers(((double)diff / (double)(delta_last / 1000)),
                                  buf1, sizeof(buf1), 1));
        pkt_thpt += pps;
      }

      lastPkts[i] = threads[i].numPkts;
    }
  }

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;

  fprintf(stderr, "=========================\n");
  fprintf(stderr,
          "Aggregate stats (all channels): [%s pps][%.2f Mbit/sec][%llu pkts "
          "rcvd][%llu pkts dropped][%llu pkts total]\n",
          pfring_format_numbers((double)(pkt_received_last * 1000) /
                                    (double)delta_last,
                                buf1, sizeof(buf1), 1),
          tot_thpt, pkt_received, pkt_dropped, pkt_received + pkt_dropped);
  fprintf(stderr, "=========================\n\n");
}

void sigproc(int sig) {
  static int called = 0;
  int i;

  fprintf(stderr, "Leaving...\n");
  if (called)
    return;
  else
    called = 1;
  do_shutdown = 1;
  print_stats();

  for (i = 0; i < num_channels; i++) {
    threads[i].do_shutdown = 1;
    fprintf(stderr, "Shutting down socket %d\n", i);
    pfring_shutdown(threads[i].ring);
  }
}

void my_sigalarm(int sig) {
  if (do_shutdown)
    return;
  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

void printHelp(void) {
  printf("pfcount_multichannel\n(C) 2005-21 ntop.org\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name (No device@channel)\n");
  printf("-l <len>        Capture length\n");
  printf("-m              Don't capture extended packet information "
         "(nanoseconds)\n");
  printf("-w <watermark>  Watermark\n");
  printf("-p <poll wait>  Poll wait (msec)\n");
  printf("-b <cpu %%>     CPU pergentage priority (0-99)\n");
  printf("-a              Active packet wait\n");
  printf("-g <id:id...>   Specifies the thread affinity mask. Each <id> "
         "represents\n"
         "                the core id where the i-th will bind. Example: -g "
         "7:6:5:4\n"
         "                binds thread <device>@0 on coreId 7, <device>@1 on "
         "coreId 6\n"
         "                and so on.\n");
}

void *packet_consumer_thread(void *_id) {
  long thread_id = (long)_id;

  if (numCPU > 1) {
    /* Bind this thread to a specific core */
    cpu_set_t cpuset;
    u_long core_id;
    int s;

    if (threads[thread_id].core_affinity != -1)
      core_id = threads[thread_id].core_affinity % numCPU;
    else
      core_id = (thread_id + 1) % numCPU;

    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    if ((s = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),
                                    &cpuset)) != 0)
      fprintf(stderr, "Error while binding thread %ld to core %ld: errno=%i\n",
              thread_id, core_id, s);
    else {
      printf("Set thread %lu on core %lu/%u\n", thread_id, core_id, numCPU);
    }
  }

  char pathbuf[256];
  sprintf(pathbuf, "/data%ld/%ld.pcap", thread_id % 8 + 1, thread_id + 1);
  pcap_t *pt = pcap_open_dead_with_tstamp_precision(DLT_EN10MB, 16384 /* MTU */,
                                                    PCAP_TSTAMP_PRECISION_NANO);
  if (pt == NULL) {
    printf("Unable to open dump file %s:\n", pathbuf);
    return (void *)(-1);
  }
  pcap_dumper_t *dumper = pcap_dump_open(pt, pathbuf);
  if (dumper == NULL) {
    printf("Unable to create dump file %s:\n", pathbuf);
    return (void *)(-1);
  }

  while (!do_shutdown) {
    u_char *buffer = NULL;
    struct pfring_pkthdr hdr;

    if (pfring_recv(threads[thread_id].ring, &buffer, 0, &hdr,
                    wait_for_packet) > 0) {
      pcap_dump((u_char *)dumper, (struct pcap_pkthdr *)&hdr, buffer);
      threads[thread_id].numPkts++;
      threads[thread_id].numBytes +=
          hdr.len + 24 /* 8 Preamble + 4 CRC + 12 IFG */;
    } else {
      // if(wait_for_packet == 0)
      //   usleep(1); //sched_yield();
    }
  }

  pcap_dump_close(dumper);
  return (NULL);
}

int main(int argc, char *argv[]) {
  char *device = NULL, c, *bind_mask = NULL;
  int snaplen = DEFAULT_SNAPLEN, rc, watermark = 0;
  long i;
  u_int16_t cpu_percentage = 0, poll_duration = 0;
  u_int32_t version;
  u_int32_t flags = 0;
  pfring *ring[MAX_NUM_RX_CHANNELS];
  int threads_core_affinity[MAX_NUM_RX_CHANNELS];

  memset(threads_core_affinity, -1, sizeof(threads_core_affinity));
  startTime.tv_sec = 0;
  numCPU = sysconf(_SC_NPROCESSORS_ONLN);

  while ((c = getopt(argc, argv, "hi:l:ma:w:b:p:g:")) != -1) {
    switch (c) {
    case 'h':
      printHelp();
      return (0);
      break;
    case 'a':
      wait_for_packet = 0;
      break;
    case 'l':
      snaplen = atoi(optarg);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'm':
      use_extended_pkt_header = 0;
      break;
    case 'w':
      watermark = atoi(optarg);
      break;
    case 'b':
      cpu_percentage = atoi(optarg);
      break;
    case 'p':
      poll_duration = atoi(optarg);
      break;
    case 'g':
      bind_mask = strdup(optarg);
      break;
    }
  }

  if (device == NULL)
    device = DEFAULT_DEVICE;

  if (bind_mask != NULL) {
    char *id = strtok(bind_mask, ":");
    int idx = 0;

    while (id != NULL) {
      threads_core_affinity[idx++] = atoi(id) % numCPU;
      if (idx >= MAX_NUM_THREADS)
        break;
      id = strtok(NULL, ":");
    }
  }

  bind2node(threads_core_affinity[0]);

  if ((threads = calloc(MAX_NUM_THREADS, sizeof(t_thread_stats))) == NULL)
    return -1;

  printf("Capturing from %s\n", device);

  flags |= PF_RING_PROMISC;
  flags |= PF_RING_ZC_SYMMETRIC_RSS;
  if (use_extended_pkt_header)
    flags |= PF_RING_LONG_HEADER;

  num_channels = pfring_open_multichannel(device, snaplen, flags, ring);

  if (num_channels <= 0) {
    fprintf(stderr, "pfring_open_multichannel() returned %d [%s]\n",
            num_channels, strerror(errno));
    return (-1);
  }

  if (num_channels > MAX_NUM_THREADS) {
    printf("WARNING: Too many channels (%d), using %d channels\n", num_channels,
           MAX_NUM_THREADS);
    num_channels = MAX_NUM_THREADS;
  } else if (num_channels > numCPU) {
    printf("WARNING: More channels (%d) than available cores (%d)\n",
           num_channels, numCPU);
  } else {
    printf("Found %d channels\n", num_channels);
  }

  pfring_version(ring[0], &version);
  printf("Using PF_RING v.%d.%d.%d\n", (version & 0xFFFF0000) >> 16,
         (version & 0x0000FF00) >> 8, version & 0x000000FF);

  for (i = 0; i < num_channels; i++) {
    char buf[32];

    threads[i].ring = ring[i];
    threads[i].core_affinity = threads_core_affinity[i];

    snprintf(buf, sizeof(buf), "pfcount_multichannel-thread %ld", i);
    pfring_set_application_name(threads[i].ring, buf);

    if ((rc = pfring_set_direction(threads[i].ring, rx_only_direction)) != 0)
      fprintf(stderr, "pfring_set_direction returned %d", rc);

    if ((rc = pfring_set_socket_mode(threads[i].ring, recv_only_mode)) != 0)
      fprintf(stderr, "pfring_set_socket_mode returned [rc=%d]\n", rc);

    if (watermark > 0) {
      if ((rc = pfring_set_poll_watermark(threads[i].ring, watermark)) != 0)
        fprintf(stderr,
                "pfring_set_poll_watermark returned [rc=%d][watermark=%d]\n",
                rc, watermark);
    }

    if (poll_duration > 0)
      pfring_set_poll_duration(threads[i].ring, poll_duration);

    pfring_enable_ring(threads[i].ring);
  }

  for (i = 0; i < num_channels; i++)
    pthread_create(&threads[i].pd_thread, NULL, packet_consumer_thread,
                   (void *)i);

  if (cpu_percentage > 0) {
    if (cpu_percentage > 99)
      cpu_percentage = 99;
    pfring_config(cpu_percentage);
  }

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);
  signal(SIGALRM, my_sigalarm);
  alarm(ALARM_SLEEP);

  for (i = 0; i < num_channels; i++) {
    pthread_join(threads[i].pd_thread, NULL);
    pfring_close(threads[i].ring);
  }

  return (0);
}
