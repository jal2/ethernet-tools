/*! \file

  This program mirrors UDP packets with a given MC destination address to a
  certain port and resends them.
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define ADDR "192.168.80.50"
#define PORT 9999
#define MCADDR "224.1.0.1"
/* IP address we use as the source address when sending */
#define TX_SRCIP "192.168.80.110"

//
// Define the IP header. Make the version and length fields one
// character since we can't declare two 4-bit fields without
// the compiler aligning them on at least a 1-byte boundary.
//
typedef struct ip_hdr
{
    unsigned char  ip_verlen;        // IP version & length
    unsigned char  ip_tos;           // IP type of service
    unsigned short ip_totallength;   // Total length
    unsigned short ip_id;            // Unique identifier 
    unsigned short ip_offset;        // Fragment offset field
    unsigned char  ip_ttl;           // Time to live
    unsigned char  ip_protocol;      // Protocol(TCP, UDP, etc.)
    unsigned short ip_checksum;      // IP checksum
    unsigned int   ip_srcaddr;       // Source address
    unsigned int   ip_destaddr;      // Destination address
} IP_HDR_t;
//
// Define the UDP header 
//
typedef struct udp_hdr
{
    unsigned short src_portno;       // Source port number
    unsigned short dst_portno;       // Destination port number
    unsigned short udp_length;       // UDP packet length
    unsigned short udp_checksum;     // UDP checksum (optional)
} UDP_HDR_t;

// define the UDP pseudo header used to calculate the UDP checksum
typedef struct udp_pseudo
{
  unsigned int   ip_srcaddr;       // Source address
  unsigned int   ip_destaddr;      // Destination address
  unsigned char  dummy;
  unsigned char  ip_protocol;      // Protocol(TCP, UDP, etc.)
  unsigned short int udp_length;
} UDP_PSEUDO_t;

/* checksum is broken */
#if 0
/*! calculate the 2 complement sum of an array of uint16_t
  \param[in] len size in bytes ! */
unsigned long int checksum(const void *buf, unsigned int len)
{
  const uint16_t *ptr = buf;
  unsigned long int retval = 0;
  while (len > 1) {
    retval += *ptr++;
    len -= 2;
  }

  if (len) {
    retval += *((unsigned char *)ptr);
  }

  return retval;
}

/*! calculate the UDP checksum */
unsigned short int udp_checksum(UDP_PSEUDO_t *udp_ps, UDP_HDR_t *udp_hd, const unsigned char *buf,
				unsigned int buf_len)
{
    unsigned long sum;

    sum = checksum(udp_ps, sizeof(udp_ps));
    sum += checksum(udp_hd, sizeof(udp_hd));
    sum += checksum(buf, buf_len);

    /* make it the one complement */
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >>16); 

    return (unsigned short int)(~sum); 
}
#endif /* #if 0 */

/*! send a UDP packet via a raw socket */
int send_raw_udp(int s, const char *dest_ip, unsigned short int dest_port,
		 const char *src_ip, unsigned short int src_port,
		 unsigned char *buf, unsigned int buf_len)
{
  IP_HDR_t iphdr;
  UDP_HDR_t udphdr;
  UDP_PSEUDO_t udp_pseudo;
  unsigned int udp_len = sizeof(UDP_HDR_t) + buf_len;
  unsigned int ip_len = sizeof(IP_HDR_t) + udp_len;
  unsigned char obuf[4096];
  unsigned int obuf_len;
  struct sockaddr_in remote;
  int rc;

  assert(sizeof(obuf) >= ip_len);

  printf("#DBG raw send to %s:%u from %s:%u\n", dest_ip, dest_port,
	 src_ip, src_port);
  //
  // IP version goes in the high-order 4 bits of ip_verlen. The
  // IP header length (in 32-bit words) goes in the lower 4 bits.
  //
  iphdr.ip_verlen = (4 << 4) | (sizeof(iphdr) / 4);
  iphdr.ip_tos = 0;                         // IP type of service
  iphdr.ip_totallength = htons(ip_len); // Total packet len
  iphdr.ip_id = 0;                 // Unique identifier: set to 0
  iphdr.ip_offset = 0;             // Fragment offset field
  iphdr.ip_ttl = 128;              // Time to live
  iphdr.ip_protocol = 0x11;        // Protocol(UDP) 
  iphdr.ip_checksum = 0 ;          // IP checksum
  iphdr.ip_srcaddr = inet_addr(src_ip);     // Source address
  iphdr.ip_destaddr = inet_addr(dest_ip);      // Destination address

  udphdr.src_portno = htons(src_port);
  udphdr.dst_portno = htons(dest_port);
  udphdr.udp_length = htons(udp_len);
  udphdr.udp_checksum = 0;

  /* build the UDP pseudo-header for calculating the UDP checksum */
  udp_pseudo.ip_srcaddr = iphdr.ip_srcaddr;
  udp_pseudo.ip_destaddr = iphdr.ip_destaddr;
  udp_pseudo.dummy = 0;
  udp_pseudo.ip_protocol = iphdr.ip_protocol;
  udp_pseudo.udp_length = udphdr.udp_length;

  /* no need to fill the IP checksum */

  /* set UDP checksum to 0000 -> none, this is a valid packet */
  // udphdr.udp_checksum = udp_checksum(&udp_pseudo, &udphdr, buf, buf_len);

  printf("counter 0x%08x: UDP checksum 0x%04x\n",
	 (buf[0]<<24) | (buf[1]<<16) | (buf[2]<< 8) | buf[3], udphdr.udp_checksum);

  /* try to send it */
  /* copy IP header, UDP header and payload into obuf */
  memcpy(obuf, &iphdr, sizeof(iphdr));
  memcpy(obuf + sizeof(iphdr), &udphdr, sizeof(udphdr));
  memcpy(obuf + sizeof(iphdr) + sizeof(udphdr), buf, buf_len);
  obuf_len = sizeof(iphdr) + sizeof(udphdr) + buf_len;

  /* fill dummy sockaddr_in struct */
  remote.sin_family = AF_INET;
  remote.sin_port = htons(dest_port);
  remote.sin_addr.s_addr = inet_addr(dest_ip);
   
  rc = sendto(s, obuf, obuf_len, 0, (struct sockaddr *)&remote, sizeof(remote));

  if (rc < 0) {
    perror("sendto");
  }

  return rc;
}


/*! this proc creates a raw UDP socket */
int create_raw_udp_socket(void)
{
  int s = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
  int rc;
  int on = 1;

  if (s < 0) {
    perror("socket (raw)");
    return s;
  }
  
  rc = setsockopt(s, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
  if (rc < 0) {
    perror("setsockopt(HDRINCL)");
    close(s);
    return -1;
  }

  return s;
}

int main(int argc, char **argv)
{
  int s;
  int raw_s;
  struct sockaddr_in addr, dest;
  int on = 1;
  int off = 0;
  char buf[4096];
  int rc;

  s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (s < 0) {
    perror("socket");
    return 1;
  }

  raw_s = create_raw_udp_socket();
  if (raw_s < 0)
    return 2;

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(PORT);
  
  if (bind(s, (struct sockaddr *)&addr, sizeof(addr))) {
    perror("bind");
    return 2;
  }

  /* join mc group for MCADDR */
  {
    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = inet_addr(MCADDR);
    mreq.imr_interface.s_addr = inet_addr(ADDR);

    if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		   &mreq, sizeof(mreq))) {
      perror("setsockopt (MC membership)");
      return 3;
    }
  }

  /* we don't want to receive our own MC packets */
  if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, &off, sizeof(off))) {
    perror("setsockopt(MC_LOOP)");
    return 4;
  }
  
  if (setsockopt(raw_s, IPPROTO_IP, IP_MULTICAST_LOOP, &off, sizeof(off))) {
    perror("setsockopt(MC_LOOP)");
    return 4;
  }
  
  /* we reuse addr for sendto, but must set the s_addr */
  addr.sin_addr.s_addr = inet_addr(MCADDR);

  while (1) {
    int rx, tx;
    struct sockaddr_in sin;
    int sin_len;

    sin_len = sizeof(sin);
    rx = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&sin, &sin_len);

    if (rx < 0) {
      perror("recvfrom");
      return 4;
    }

    if (rx == 0) {
      fprintf(stderr, "peer shutdown\n");
      return 5;
    }

    printf("#DBG rx 0x%x bytes\n", rx);

#if 0
    tx = sendto(s, buf, rx, 0, (struct sockaddr *)&addr, sizeof(addr));

    if (tx < 0) {
      perror("sendto");
      return 6;
    }
    printf("#DBG mirrored %u bytes\n", rx);
#else
    /* we send the packet back with a sender ip address set to TX_SRCIP */
    if (send_raw_udp(raw_s, MCADDR, PORT, TX_SRCIP, PORT, buf, rx) < 0)
      fprintf(stderr, "#ERR failed to send raw\n");
    else
      printf("#DBG mirrored %u bytes to raw socket\n", rx);
#endif    
  }
}
