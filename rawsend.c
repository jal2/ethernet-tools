/* $Id: ethsend.c,v 1.4 2006-10-30 12:58:52 joerga Exp $ */

/* This program lets you send arbitrary ethernet packets */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/ethernet.h>

static int verbose = 0;
static int use_own_mac_addr = 0;

#define MAX_PAYLOAD_LEN 4096

static unsigned char buf[MAX_PAYLOAD_LEN];
static unsigned char *payload = buf;

#define VERSION "0.1"

#define MIN(x,y) ((x) < (y) ? (x) : (y))

#define dbg(fmt, ...) \
 do {\
   if (verbose) \
     fprintf(stderr, "#DBG %s: " fmt "\n", __FUNCTION__ , ## __VA_ARGS__); \
 } while (0)

#define err(fmt, ...) fprintf(stderr, "#ERR %s: " fmt "\n", __FUNCTION__ , ## __VA_ARGS__)

/* convert a hexnumber < 0xf into a digit */
#define HEX2DIGIT(x) ((x) < 10 ? (x)+'0' : (x)+'A'-10)

/* convert a hex digit into it's value */
#define DIGIT2HEX(x) \
  ((x) >= '0' && (x) <= '9' ? (x) - '0' :\
   (x) >= 'a' && (x) <= 'f' ? (x) - 'a' + 10 :\
   (x) >= 'A' && (x) <= 'F' ? (x) - 'A' + 10 : 0)
 

/*! hexdumps a buffer into a string

  example: print a mac address

  unsigned char mac[6] = { ...};
  char obuf[3*6];
  printf("%s\n", hexdump(mac, obuf, sizeof(obuf), ':'));

  Be careful not to use the same output buffer twice in the same
  call to printf!

  \param[in] addr memory buffer to dump
  \param[out] buf output string
  \param[in] buf_sz size of buf in bytes
  \param[in] delim delimiter between the bytes, 0 == no delimiter

  \return output buffer
*/
static char *
hex2str(void *addr, char *buf, size_t buf_sz, int delim)
{
	unsigned char *src=addr;
	char *start = buf;

	while (buf_sz > 2) {
		*buf++ = HEX2DIGIT(*src>>4);
		*buf++ = HEX2DIGIT(*src&0xf);
		buf_sz -= 2;
		if (delim) {
			*buf++ = delim;
			buf_sz--;
		}
		src++;
	}

	/* remove last delimiter */
	if (delim)
		buf--;

	*buf='\0';
	return start;
}

/*! delay in milliseconds

   A signal may interrupt the select and we wait a shorter time.

   \param[in] time_ms time in milliseconds
*/
static void
delay_ms(unsigned long int time_ms)
{
	struct timeval tv;

	if (!time_ms)
		return;
	
	tv.tv_sec = time_ms / 1000;
	tv.tv_usec = (time_ms - (tv.tv_sec * 1000)) * 1000;
	
	select(0, NULL, NULL, NULL, &tv);
}

/*! print the usage information for this program

  \param[in] name name of the program
*/
static void
usage(const char *name)
{
	fprintf(stderr, "%s version " VERSION " compiled at " __DATE__ " "
		__TIME__ "\n", name);
	fprintf(stderr, "\nUsage:\t%s <options> [<byte0> <byte1> ...]\n\n", name);
	fprintf(stderr, "options:\n");
	fprintf(stderr, "-w <ms>      - wait for ms milliseconds after sending a packet (default: 100)\n");
	fprintf(stderr, "-v           - verbose output\n");
	fprintf(stderr, "-o           - use own mac address as SA (default: no)\n");
	fprintf(stderr, "-t           - set socket tx buffer size\n");
	fprintf(stderr, "-c <offset>  - counting mode: increment byte at offset (from DA) by one in each msg\n");
	fprintf(stderr, "-n <number>  - send a number of msgs (default: 1) - zero for an infinite number\n");
	fprintf(stderr, "-i <interf>  - use this net device (default: eth0)\n");
	fprintf(stderr, "-s <src_mac>\n");
	fprintf(stderr, "-d <dst_mac> - source, destination MAC address (default: taken from payload)\n");
	fprintf(stderr, "<byteX>      - payload\n");
	fprintf(stderr, "\nAfter processing src_mac, dst_mac and the payload the program "
		"appends any bytes read from stdin to the payload\n");
}

/*! read a MAC address from a string in xx:xx:xx:xx:xx:xx format
  \param[in] str MAC address in a string
  \param[out] addr binary MAC address
  
  \return 0 on success, -1 on failure
*/
int
read_mac(char *str, char *addr)
{
	int i;
	for(i=0; i < 6; i++) {
		/* string not long enough */
		if (!*str || !*(str+1) || (i < 5 && *(str+2) != ':'))
			return -1;
		*addr = DIGIT2HEX(*str) << 4 | DIGIT2HEX(*(str+1));
		str += 2;
		if (i < 5)
			str++;
		addr++;
	}
	return 0;
}

int
main(int argc, char *argv[])
{
	
	int anr; /* index of argv[] to process */
	char *if_name = "eth0";
	char *endp;
	
	int s;
	struct sockaddr_ll sa;
	struct ifreq ifr;
	int if_idx;
	
	int payload_len = 0;
	
	int i,rc;
	unsigned long int wait_ms = 100;
	int is_mgmt = 0;
	int msg_nr = 1;
	char dst_mac[6], src_mac[6];
	int dst_mac_valid = 0, src_mac_valid = 0;
	char obuf1[3*6], obuf2[3*6];
	unsigned int txbuf_sz=0;
	unsigned int old_txbuf_sz;
	int count_offs = -1;
	
	/* scan the options */
	anr=1;
	while (anr < argc && argv[anr][0] == '-') {
		switch (argv[anr][1]) {
			
		case 'w':
			wait_ms= strtoul(argv[++anr], &endp, 0);
			if (endp == argv[anr]) {
				err("invalid port mask: %s", argv[anr]);
				usage(argv[0]);
				return 2;
			}
			break;
			
			
		case 'n':
			msg_nr = strtoul(argv[++anr], &endp, 0);
			if (endp == argv[anr]) {
				err("invalid number: %s", argv[anr]);
				usage(argv[0]);
				return 2;
			}
			break;
			
		case 'c':
			count_offs = strtoul(argv[++anr], &endp, 0);
			if (endp == argv[anr]) {
				err("invalid counting offset: %s", argv[anr]);
				usage(argv[0]);
				return 2;
			}
			break;
			
		case 'h':
			usage(argv[0]);
			return 0;
			break;
			
		case 'i':
			if_name = argv[++anr];
			break;
			
		case 'v':
			verbose = 1;
			break;
			
		case 'o':
			use_own_mac_addr = 1;
			src_mac_valid = 1;
			memset(src_mac, 0, 6);
			break;
			
		case 's':
			if (read_mac(argv[++anr], src_mac)) {
				err("invalid src_mac %s", argv[anr]);
				return 2;
			}
			src_mac_valid = 1;
			break;
			
		case 'd':
			if (read_mac(argv[++anr], dst_mac)) {
				err("invalid dst_mac %s", argv[anr]);
				return 2;
			}
			dst_mac_valid = 1;
			break;

		case 't':
			txbuf_sz= strtoul(argv[++anr], &endp, 0
);
			if (endp == argv[anr]) {
				err("invalid tx buffer size: %s", argv[anr]);
				usage(argv[0]);
				return 2;
			}
			break;
			
		default:
			err("unknown option: %s", argv[anr]);
			usage(argv[0]);
			return 2;
		} /* switch */
		anr++;
	}

	fprintf(stderr, "%s version " VERSION " compiled at " __DATE__ " " __TIME__ "\n", argv[0]);

	if (!msg_nr)
		fprintf(stderr, "sending an infinite number of packets - press ^C to interrupt\n");

	dbg("if name %s dst_mac %s src_mac %s txbuf_sz x%x is_mgmt %d wait_ms %lu\n",
	    if_name,
	    dst_mac_valid ? hex2str(dst_mac, obuf1, sizeof(obuf1), ':') : "-",
	    src_mac_valid ? (use_own_mac_addr ? "<own>" : hex2str(src_mac, obuf2, sizeof(obuf2), ':')) :  "-",
	    txbuf_sz, is_mgmt, wait_ms);

	/* fill the payload */
	if (dst_mac_valid) {
		memcpy(payload, dst_mac, 6);
		payload_len = 6;
		if (src_mac_valid) {
			memcpy(payload+payload_len, src_mac, 6);
			payload_len +=6;
		}
	}
	
	/* get the bytes from cmdline */
	while (payload_len < MAX_PAYLOAD_LEN && anr < argc) {
		payload[payload_len] = strtoul(argv[anr], &endp, 16);
		if (endp == argv[anr]) {
			err("invalid value: %s", argv[anr]);
			usage(argv[0]);
			return 2;
		}
		anr++;
		payload_len++;
	}

	if (!isatty(fileno(stdin))) {
	  /* get payload bytes from stdin */
#if 0
	  /* make read from stdin nonblocking */
	  if (fcntl(0, F_SETFL, fcntl(0, F_GETFL) | O_NONBLOCK) < 0) {
	    err("cannot set stdin to non-blocking read (errno %m)");
	    return 3;
	  }
#endif
	  while (payload_len < MAX_PAYLOAD_LEN) {
	    rc = read(0, payload+payload_len, MAX_PAYLOAD_LEN-payload_len);

	    if (rc < 0) {
	      if (errno == EAGAIN) {
		dbg("no payload on stdin");
	      } else {
		err("reading from stdin returned %m");
		return 4;
	      }
	    } else
	      payload_len += rc;
	    if (rc == 0) {
	      dbg("EOF on stdin");
	      break;
	    }
	  } /* while (payload_len < MAX_PAYLOAD_LEN) */

	} /* if (!isatty(fileno(stdin))) */

	if (count_offs != -1 && count_offs >= payload_len) {
		err("counting offset (x%x) is larger than payload length (x%x)",
		    count_offs, payload_len);
		return 5;
	}

		
	/*create RAW socket */
	if ((s=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		if (errno == EPERM) {
			err("unprivileged to open a raw socket - try as root\n");
		} else {
			err("cannot create raw socket (errno %m)");
		}
		return 5;
	}
	
	/* write interface name*/
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, if_name, IFNAMSIZ-1);
	ifr.ifr_name[IFNAMSIZ-1] = '\0';
	
	/*get the interface index*/
	if (ioctl(s,SIOCGIFINDEX,&ifr) < 0) {
		err("getting the interface index for %s failed (errno %m)", if_name);
		return 6;
	}
		
	if (verbose || txbuf_sz) {
		socklen_t l;
		
		/* report the current tx buf size */
		l = sizeof(old_txbuf_sz);
		if (rc=getsockopt(s, SOL_SOCKET, SO_SNDBUF, &old_txbuf_sz, &l)) {
			err("getsockopt(%d, SOL_SOCKET, SO_SNDBUF, %p, %lu) returned %d (errno %m)",
			    s, &old_txbuf_sz, sizeof(old_txbuf_sz), rc);
		}

		dbg("(old) TX buf size x%x", old_txbuf_sz);
		
		if (txbuf_sz) {
			if (rc=setsockopt(s, SOL_SOCKET, SO_SNDBUF, &txbuf_sz, sizeof(txbuf_sz))) {
				err("setsockopt(%d, SOL_SOCKET, SO_SNDBUF, &x%x, %lu) returned %d (errno %m)",
				    s, txbuf_sz, sizeof(txbuf_sz), rc);
				return 6;
			} else
				dbg("new TX buf size x%x", txbuf_sz);
		}
	}
	
	if_idx = ifr.ifr_ifindex;
	
	/* check whether the interface is up or down */
	ioctl(s, SIOCGIFFLAGS, &ifr);
	if ((ifr.ifr_flags & IFF_UP) == 0) {
		err("interface %s is down", if_name);
		return 7;
	}

	dbg("if %s idx %d is up", if_name, if_idx);
	
	memset(&sa, 0, sizeof(struct sockaddr_ll));
	sa.sll_family    = AF_PACKET;
	sa.sll_protocol  = htons(ETH_P_ALL);
	sa.sll_ifindex   = if_idx;

	if (bind(s,(struct sockaddr*)&sa, (socklen_t)sizeof(struct sockaddr_ll))) {
		err("binding the raw socket to if index %d failed (errno %m)",
		    if_idx);
		return 8;
	}

	if (use_own_mac_addr) {
		memset(&sa,0,sizeof (sa));
		sa.sll_family    = AF_PACKET;
		sa.sll_ifindex   = if_idx;
		sa.sll_protocol  = htons(ETH_P_ALL);

		/* obtain own MAC address */
		if (ioctl(s,SIOCGIFHWADDR,&ifr)) {
			err("cannot obtain own MAC address");
			return 9;
		} else {
			char obuf[3*6];
			dbg("own MAC addr is %s", hex2str(ifr.ifr_hwaddr.sa_data, obuf, sizeof(obuf), ':'));
		}
		memcpy(payload+6, ifr.ifr_hwaddr.sa_data, 6);
	}
	
	if (verbose) {
#define BLOCK_SZ 16
		char obuf[2*BLOCK_SZ+1] __attribute__ ((unused));
		int i=0;
		
		dbg("payload x%x:", payload_len);
		while (i < payload_len) {
			dbg("%s", hex2str(payload+i, obuf, MIN(sizeof(obuf),2*(payload_len-i)+1), 0));
			i += BLOCK_SZ;
		}
#undef BLOCK_SZ
		dbg("sending x%x packets", msg_nr);
	}
	
	/* send the msg */
	i=0;
	while (!msg_nr || (i < msg_nr)) {
		if ((rc=send(s, payload, payload_len, 0)) != payload_len) {
			err("sending %d bytes returned %d (errno %m)", payload_len, rc);
		}
		if (count_offs != -1)
			payload[count_offs]++;
		i++;
		/* don't wait after the last packet */
		if (!msg_nr || i < msg_nr)
			delay_ms(wait_ms);
	}

		close(s);

	return 0;
}
