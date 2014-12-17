/* This program prints the payload of UDP packets to a given port
   contained in a .pcap file. It preceeds each line with the absolute time in UTC.

   It is based on
   http://inst.eecs.berkeley.edu/~ee122/fa07/projects/p2files/packet_parser.c

   but I don't know the author or the license of that file.

   This file needs the package libpcap-dev to be installed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include <pcap.h>

#define VERSION "0.1"

struct UDP_hdr {
  u_short	uh_sport;		/* source port */
  u_short	uh_dport;		/* destination port */
  u_short	uh_ulen;		/* datagram length */
  u_short	uh_sum;			/* datagram checksum */
};

/* UDP destination port */
unsigned long int dest_port;

/* Some helper functions, which we define at the end of this file. */

/* Returns a string representation of a timestamp. */
const char *timestamp_string(struct timeval ts);

/* Report a problem with dumping the packet with the given timestamp. */
void problem_pkt(struct timeval ts, const char *reason);

/* Report the specific problem of a packet being too short. */
void too_short(struct timeval ts, const char *truncated_hdr);

/* dump_UDP_packet()
 *
 * This routine parses a packet, expecting Ethernet, IP, and UDP headers.
 * It extracts the UDP source and destination port numbers along with the UDP
 * packet length by casting structs over a pointer that we move through
 * the packet.  We can do this sort of casting safely because libpcap
 * guarantees that the pointer will be aligned.
 *
 * The "ts" argument is the timestamp associated with the packet.
 *
 * Note that "capture_len" is the length of the packet *as captured by the
 * tracing program*, and thus might be less than the full length of the
 * packet.  However, the packet pointer only holds that much data, so
 * we have to be careful not to read beyond it.
 */
void dump_UDP_packet(const unsigned char *packet, struct timeval ts,
		     unsigned int capture_len)
{
  struct ip *ip;
  struct UDP_hdr *udp;
  unsigned int IP_header_length;
  int i;

  /* For simplicity, we assume Ethernet encapsulation. */

  if (capture_len < sizeof(struct ether_header))
    {
      /* We didn't even capture a full Ethernet header, so we
       * can't analyze this any further.
       */
      too_short(ts, "Ethernet header");
      return;
    }

  /* Skip over the Ethernet header. */
  packet += sizeof(struct ether_header);
  capture_len -= sizeof(struct ether_header);

  if (capture_len < sizeof(struct ip))
    { /* Didn't capture a full IP header */
      too_short(ts, "IP header");
      return;
    }

  ip = (struct ip*) packet;
  IP_header_length = ip->ip_hl * 4;	/* ip_hl is in 4-byte words */

  if (capture_len < IP_header_length)
    { /* didn't capture the full IP header including options */
      too_short(ts, "IP header with options");
      return;
    }

  if (ip->ip_p != IPPROTO_UDP)
    return;

  /* Skip over the IP header to get to the UDP header. */
  packet += IP_header_length;
  capture_len -= IP_header_length;

  if (capture_len < sizeof(struct UDP_hdr))
    {
      too_short(ts, "UDP header");
      return;
    }
	
  udp = (struct UDP_hdr*) packet;

  packet += sizeof(struct UDP_hdr);
  capture_len -= sizeof(struct UDP_hdr);
	
  if (ntohs(udp->uh_ulen)-8 > capture_len) {
    too_short(ts, "payload");
    return;
  }

  if (ntohs(udp->uh_dport) != dest_port)
    return;

  printf("%s ", timestamp_string(ts));

  for(i=0; i < capture_len; i++)
    printf("%c", isprint(packet[i]) ? packet[i] : '.');
  printf("\n");
}


int main(int argc, char *argv[])
{
  pcap_t *pcap;
  const unsigned char *packet;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr header;
  char *end;

  /* We expect exactly two arguments: the destination udp port and the name of the file to dump. */
  if ( argc != 3 )
    {
      fprintf(stderr, "#ERR program requires two args: <udp destination port> <pcap file name>\n\n");
      fprintf(stderr, "This program will print UDP packet payloads selected by a destination port and preceeded with a timestamp.\n");
      fprintf(stderr, "%s version %s compiled %s %s\n", argv[0], VERSION, __DATE__, __TIME__);
      exit(1);
    }

  /* Skip over the program name. */
  ++argv; --argc;

  dest_port = strtoul(argv[0], &end, 10);
  if (argv[0] == end || dest_port >= (1<<16)) {
    fprintf(stderr, "#ERR invalid UDP destination port number %s\n", argv[0]);
    exit(1);
  }

  argv++;
  argc--;

  pcap = pcap_open_offline(argv[0], errbuf);
  if (pcap == NULL)
    {
      fprintf(stderr, "#ERR reading pcap file: %s\n", errbuf);
      exit(1);
    }

  /* Now just loop through extracting packets as long as we have
   * some to read.
   */
  while ((packet = pcap_next(pcap, &header)) != NULL)
    dump_UDP_packet(packet, header.ts, header.caplen);

  // terminate
  return 0;
}


/* Note, this routine returns a pointer into a static buffer, and
 * so each call overwrites the value returned by the previous call.
 */
const char *timestamp_string(struct timeval ts)
{
  static char buf[256];
  time_t tval = ts.tv_sec;
  struct tm *tm;
  size_t nr;

  tm = gmtime(&tval);

  nr = strftime(buf, sizeof(buf)-7, "%d-%m-%Y %H:%M:%S", tm);

  snprintf(buf+nr, sizeof(buf)-nr, ".%06lu", ts.tv_usec);

  return buf;
}

void problem_pkt(struct timeval ts, const char *reason)
{
  fprintf(stderr, "%s: %s\n", timestamp_string(ts), reason);
}

void too_short(struct timeval ts, const char *truncated_hdr)
{
  fprintf(stderr, "packet with timestamp %s is truncated and lacks a full %s\n",
	  timestamp_string(ts), truncated_hdr);
}
