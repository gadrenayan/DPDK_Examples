#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#define IP4_HDRLEN 20
#define UDP_HDRLEN 8
#define ETH_HDRLEN 14
#define SOCK_PATH "/root/DPDK/uds/dpdk_master_server"

/* Function prototypes */
uint16_t checksum (uint16_t *, int);
uint16_t udp4_checksum (struct ip, struct udphdr, uint8_t *, int);
char * allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
int *allocate_intmem (int);

/* checksum for IP*/
uint16_t checksum (uint16_t *addr, int len)
{
	int count = len;
	register uint32_t sum = 0;
	uint16_t answer = 0;
	
	// Sum up 2-byte values until none or only one byte left
	while (count > 1) {
		sum += *(addr++);
		count -= 2;
	}

	// Add left over byte if any.
	if (count > 0) {
		sum += *(uint8_t *)addr;
	}

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	// checksum is 1's complement of sum.
	answer = ~sum;
	
	return (answer);
}

// Build IPv4 UDP pseudo-header and call checksum function.
uint16_t
udp4_checksum (struct ip iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen)
{
	char buf[IP_MAXPACKET];
	char *ptr;
	int chksumlen = 0;
	int i;

	ptr = &buf[0];  // ptr points to beginning of buffer buf

	// Copy source IP address into buf (32 bits)
	memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
	ptr += sizeof (iphdr.ip_src.s_addr);
	chksumlen += sizeof (iphdr.ip_src.s_addr);

	// Copy destination IP address into buf (32 bits)
	memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
	ptr += sizeof (iphdr.ip_dst.s_addr);
	chksumlen += sizeof (iphdr.ip_dst.s_addr);

	// Copy zero field to buf (8 bits)
	*ptr = 0; ptr++;
	chksumlen += 1;

	// Copy transport layer protocol to buf (8 bits)
	memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
	ptr += sizeof (iphdr.ip_p);
	chksumlen += sizeof (iphdr.ip_p);

	// Copy UDP length to buf (16 bits)
	memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
	ptr += sizeof (udphdr.len);
	chksumlen += sizeof (udphdr.len);

	// Copy UDP source port to buf (16 bits)
	memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
	ptr += sizeof (udphdr.source);
	chksumlen += sizeof (udphdr.source);

	// Copy UDP destination port to buf (16 bits)
	memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
	ptr += sizeof (udphdr.dest);
	chksumlen += sizeof (udphdr.dest);

	// Copy UDP length again to buf (16 bits)
	memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
	ptr += sizeof (udphdr.len);
	chksumlen += sizeof (udphdr.len);

	// Copy UDP checksum to buf (16 bits)
	// Zero, since we don't know it yet
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	chksumlen += 2;

	// Copy payload to buf
	memcpy (ptr, payload, payloadlen);
	ptr += payloadlen;
	chksumlen += payloadlen;

	// Pad to the next 16-bit boundary
	for (i=0; i<payloadlen%2; i++, ptr++) {
		*ptr = 0;
		ptr++;
		chksumlen++;
	}

	return checksum ((uint16_t *) buf, chksumlen);
}

/* Allocate memory for an array of characters */
char * allocate_strmem (int len) 
{
	void * tmp;

	if (len <= 0) 
	{
		fprintf(stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
		exit(EXIT_FAILURE);
	}
	
	tmp = (char *) malloc (len * sizeof(char));
	if (tmp != NULL) {
		memset(tmp, 0, len * sizeof(char));
		return (tmp);
	} else {
		fprintf(stderr, "ERROR: cannot allocate memory for array allocate_strmem().\n");
		exit (EXIT_FAILURE);
	}

}

/* Allocate memory for an array of unsigned chars */
uint8_t * allocate_ustrmem (int len)
{
	void * tmp;
	if (len <= 0) {
		fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
		exit (EXIT_FAILURE);
	}

	tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
	if (tmp != NULL) {
		memset (tmp, 0, len * sizeof (uint8_t));
		return tmp;
	} else {
		fprintf(stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
		exit (EXIT_FAILURE);
	}
}

/* Allocate memory for an array of ints */
int * allocate_intmem (int len)
{
	void * tmp;
	if (len <= 0) {
		fprintf(stderr, "ERROR: cannot allocate memory because len = %i in allocate_intmem().\n", len);
		exit (EXIT_FAILURE);
	}

	tmp = (int *) malloc (len * sizeof(int));
	if (tmp != NULL) {
		memset (tmp, 0, len * sizeof(len));
		return tmp;
	} else {
		fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
		exit (EXIT_FAILURE);
	}
}

int main(void) {
	int status, datalen, *ip_flags;
	char *interface, *target, *src_ip, *dst_ip;
	int nwrite = 0;
	char if_name[IFNAMSIZ] = "";

	struct ip iphdr;
	struct udphdr udphdr;
	struct ethhdr ethhdr;
	uint8_t *data, *packet;
	int pipe_fd;
	
	
	/* Allocate memory for various arrays */
	datalen = 4;
	data = allocate_ustrmem (datalen);
	packet = allocate_ustrmem (ETH_HDRLEN + IP4_HDRLEN + UDP_HDRLEN + datalen); /* 14 + 20 + 8 + 4 */
	interface = allocate_strmem (40);
	target = allocate_strmem (40);

	src_ip = allocate_strmem (INET_ADDRSTRLEN);
	dst_ip = allocate_strmem (INET_ADDRSTRLEN);

	ip_flags = allocate_intmem (4);

	strcpy (src_ip, "192.168.10.2");
	strcpy (dst_ip, "192.168.10.1");
	strcpy (target, "www.google.com");
	ethhdr.h_dest[5] = 0x01;
	ethhdr.h_dest[4] = 0x05;
	ethhdr.h_dest[3] = 0x0E;
	ethhdr.h_dest[2] = 0xAA;
	ethhdr.h_dest[1] = 0xBB;
	ethhdr.h_dest[0] = 0xCC;

	ethhdr.h_source[5] = 0x01;
	ethhdr.h_source[4] = 0x05;
	ethhdr.h_source[3] = 0x0E;
	ethhdr.h_source[2] = 0xDD;
	ethhdr.h_source[1] = 0xEE;
	ethhdr.h_source[0] = 0xFF;

	ethhdr.h_proto = htons(ETH_P_IP);
	strncpy(if_name, "gnatap", IFNAMSIZ-1);
	strcpy (interface, "eth0");

	printf("Trying to connect...\n");

	/* UDP Data */
	datalen = 4;
	data[0] = 'T';
	data[1] = 'E';
	data[2] = 'S';
	data[3] = 'T';

	/* IPv4 Header data */
	iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t); 		/* Number of 32 bit words in the header = 20 / 4 = 5 */
	iphdr.ip_v = 4;							/* Ip Version 4 */
	iphdr.ip_tos = 0;						/* Type of service */
	iphdr.ip_len = htons(ETH_HDRLEN + IP4_HDRLEN + UDP_HDRLEN + datalen);	/* IP Header + UDP Header + datalen */
	iphdr.ip_id = htons(0); 				/* Unused, single datagram */

	// Fill in the Flags and Fragmentation offset (3, 13 bits): 0 since single datagram */
	ip_flags[0] = 0;	// Zero Flag (1 bit)
	ip_flags[1] = 0; 	// Do not fragment flag (1 bit)
	ip_flags[2] = 0;	// More fragments following flag (1 bit)
	ip_flags[3] = 0; 	// Fragmentation offset (13 bits)

	iphdr.ip_off = htons((ip_flags[0] << 15) + (ip_flags[1] << 14) + (ip_flags[2] << 13) + ip_flags[3]);
	iphdr.ip_ttl = 255; 		// Default to maximum value
	iphdr.ip_p = IPPROTO_UDP;	// Transport Layer 17 for UDP
	
	// Source IPv4 address (32 bits)
	if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
		fprintf(stderr, "inet_pton() failed.\n Error message: %s", strerror(status));
		exit (EXIT_FAILURE);
	}

	// Destination IPv4 address (32 bits)
	if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
		fprintf(stderr, "inet_pton() failed.\n Error Message: %s", strerror(status));
		exit (EXIT_FAILURE);
	}

	// Calculating Checksum (16 bits): set to 0 when calculating checksum
	iphdr.ip_sum = 0;
	iphdr.ip_sum = checksum ((uint16_t *)&iphdr, IP4_HDRLEN);

	/* UDP Header */
	udphdr.source = htons (4950);
	udphdr.dest = htons (4950);
	udphdr.len = htons (UDP_HDRLEN + datalen);
	udphdr.check = udp4_checksum(iphdr, udphdr, data, datalen);

	printf("Prepare Packet\n");
	/* Prepare Packet to Send |--ETH HEADER--|--IPv4 HEADER--|---UDP HEADER--| ---DATA---| */
	memcpy (packet, &ethhdr, ETH_HDRLEN * sizeof(uint8_t));
	memcpy (packet + ETH_HDRLEN, &iphdr, IP4_HDRLEN * sizeof(uint8_t));
	memcpy (packet + ETH_HDRLEN + IP4_HDRLEN, &udphdr, UDP_HDRLEN * sizeof (uint8_t));
	memcpy (packet + ETH_HDRLEN + IP4_HDRLEN + UDP_HDRLEN, data, datalen * sizeof (uint8_t));

	/* Send Packet through PIPE interface */	
	pipe_fd = open(SOCK_PATH, O_WRONLY);
	printf("connected\n");
	while (1) {
		sleep(2);
		if ((nwrite = write(pipe_fd, packet, ETH_HDRLEN + IP4_HDRLEN + UDP_HDRLEN + datalen) == -1)) {
			perror("send");
			exit(1);
		}
	}
	close(pipe_fd);

	return 0;
}
