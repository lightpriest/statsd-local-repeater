/*
MIT License

Copyright (c) 2017 Or Cohen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <netdb.h>
#include <pcap.h>
#include <netinet/if_ether.h>

static pcap_t *pcap;
static struct addrinfo* target_addr = 0;
static int target_fd;

static void handler(u_char *arg, const struct pcap_pkthdr *header,
  const u_char *packet);

int main(int argc, char **argv) {
  char *dev = "lo";
  int snaplen = 2048;
  char *source = NULL, *dest = NULL;
  char *source_host = "127.0.0.1", *source_port = "8125";
  char *dest_host = "127.0.0.1", *dest_port = "8126";
  char *pcap_filter_fmt = "udp and dst %s and port %s";
  int verbose = 0;

  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program bpf;
  struct addrinfo hints;
  int c, ret;

  while ((c = getopt (argc, argv, "vhi:s:d:")) != -1)
    switch (c)
      {
      case 'i':
        dev = optarg;
        break;
      case 's':
        source = optarg;
        break;
      case 'd':
        dest = optarg;
        break;
      case 'v':
        verbose = 1;
        break;
      case 'h':
      case '?':
        if (optopt == 'i' || optopt == 's' || optopt == 'd')
          fprintf (stderr, "Option -%c requires an argument.\n\n", optopt);
        else if (isprint (optopt) && c != 'h')
          fprintf (stderr, "Unknown option `-%c'.\n\n", optopt);
        else if (c != 'h')
          fprintf (stderr,
                   "Unknown option character `\\x%x'.\n\n",
                   optopt);
        fprintf(stderr,
          "statsd-local-repeater [-hv] [-i lo] [-l 2048] "
          "[-s 127.0.0.1:8125] [-d 127.0.0.1:8126]\n\n");
        fprintf(stderr,
          "Sniff UDP traffic with a filter (-s) and duplicate \n"
          "arriving packets to a different destination (-d)\n\n");
        fprintf(stderr, "-i\tInterface to listen. Default: lo\n");
        fprintf(stderr, "-s\tSource to filter. Default: 127.0.0.1:8125\n");
        fprintf(stderr, "-d\tDestination to send. Default: 127.0.0.1:8126\n");
        fprintf(stderr, "-v\tBe verbose\n");
        fprintf(stderr, "-h\tShow this help\n");
        return 1;
      }

  /* Parse source argument, if supplied */
  if (source != NULL) {
    source_host = strsep(&source, ":");
    if (source != NULL) {
      source_port = source;
    }
  }

  /* Parse destination argument, if supplied */
  if (dest != NULL) {
    dest_host = strsep(&dest, ":");
    if (dest != NULL) {
      dest_port = dest;
    }
  }

  if (verbose) fprintf(stderr, "Opening pcap dev: %s\n", dev);
  pcap = pcap_open_live(dev, snaplen, 0, 1, errbuf);
  if (!pcap) {
    fprintf(stderr, "%s\n", errbuf);
    exit(1);
  }

  /* Build pcap filter from format */
  size_t chars = snprintf(NULL, 0, pcap_filter_fmt, source_host, source_port);
  char *filter = malloc(chars + 1);
  sprintf(filter, pcap_filter_fmt, source_host, source_port);

  /* Compile pcap filter */
  if (verbose) fprintf(stderr, "Compiling filter: %s\n", filter);
  ret = pcap_compile(pcap, &bpf, filter, 1, 0);
  if (ret != 0) {
    pcap_perror(pcap, "pcap_compile");
    exit(1);
  }

  /* Set the pcap filter */
  if (verbose) fprintf(stderr, "Setting filter: %s\n", filter);
  ret = pcap_setfilter(pcap, &bpf);
  if (ret != 0) {
    pcap_perror(pcap, "pcap_setfilter");
    exit(1);
  }
  pcap_freecode(&bpf);

  /* hints required for getaddrinfo */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family=AF_UNSPEC;
  hints.ai_socktype=SOCK_DGRAM;
  hints.ai_protocol=0;
  hints.ai_flags=AI_ADDRCONFIG;

  if (verbose) fprintf(stderr, "getaddrinfo: %s:%s\n", dest_host, dest_port);
  ret = getaddrinfo(dest_host, dest_port, &hints, &target_addr);
  if (ret != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
    exit(1);
  }

  target_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (target_fd == -1) {
    fprintf(stderr, "socket() failed: %d", errno);
    exit(1);
  }

  if (verbose) fprintf(stderr, "Starting pcap loop\n");
  fprintf(stderr, "Sniffing and repeating...\n");
  fprintf(stderr, "%s:%s -> %s:%s\n",
    source_host, source_port, dest_host, dest_port);
  pcap_loop(pcap, -1, handler, NULL);

  pcap_close(pcap);

  return 0;
}

static void handler(u_char *arg, const struct pcap_pkthdr *header,
  const u_char *packet) {

  struct ether_header *eth_header;
  eth_header = (struct ether_header *) packet;
  if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
  printf("Not an IP packet. Skipping...\n\n");
  return;
  }

  /* Pointers to start point of various headers */
  const u_char *ip_header;
  const u_char *payload;

  /* Header lengths in bytes */
  int ethernet_header_length = 14; /* Doesn't change */
  int ip_header_length;
  int udp_header_length;
  int payload_length;

  ip_header = packet + ethernet_header_length;
  ip_header_length = ((*ip_header) & 0x0F);
  ip_header_length = ip_header_length * 4;

  u_char protocol = *(ip_header + 9);
  if (protocol != IPPROTO_UDP) {
  printf("Not a UDP packet. Skipping...\n\n");
  return;
  }

  udp_header_length = 8;

  /* Add up all the header sizes to find the payload offset */
  int total_headers_size = ethernet_header_length +
        ip_header_length + udp_header_length;
  payload_length = header->caplen -
  (ethernet_header_length + ip_header_length + udp_header_length);
  payload = packet + total_headers_size;

  if (payload_length > 0) {
    int ret = sendto(target_fd, payload, payload_length, 0,
      target_addr->ai_addr, target_addr->ai_addrlen);
    if (ret == -1) {
      fprintf(stderr, "sendto() failed: %d", errno);
      exit(1);
    }
  }

  return;
}
