
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>


// IPv4 header len without options
#define IP4_HDRLEN 20

// ICMP header len for echo req
#define ICMP_HDRLEN 8 

#define SOURCE_IP "1.2.3.4"
// i.e the gateway or ping to google.com for their ip-address
#define DESTINATION_IP "8.8.8.8"

unsigned short calculate_checksum(unsigned short * paddress, int len);

int main () 
{    
    char temp[IP_MAXPACKET] = {'\0'};
    int enable = 1;

    // struct for icmphdr & iphdr
    struct icmphdr *icmp = (struct icmphdr*)(temp + sizeof(struct iphdr)); // ICMP-header
    struct iphdr *ip = (struct iphdr*)temp;

    // ICMP header
    icmp->type = 8;
    icmp->checksum = 0;
    icmp->checksum = calculate_checksum((unsigned short *)icmp, sizeof(struct icmp));
    
    // IP header
    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 20;
    ip->saddr = inet_addr(SOURCE_IP);
    ip->daddr = inet_addr(DESTINATION_IP);
    ip->protocol = IPPROTO_ICMP;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmp));


    // Create raw socket for IP-RAW 
    int sock = -1;
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) 
    {
        fprintf (stderr, "socket() failed with error: %d\n", errno);
        fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }

    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)))
    {
        perror("Something is wrong\n");
        exit(1);
    }

    struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));

    dest_in.sin_family = AF_INET;
    dest_in.sin_addr.s_addr = ip->daddr;

    // Send the packet using sendto() for sending datagrams.
    if (sendto (sock, ip, ntohs(ip->tot_len), 0, (struct sockaddr *) &dest_in, sizeof (dest_in)) == -1) 
    {
        fprintf (stderr, "sendto() feiled with error: %d", errno);
        return -1;
    }
    
    //Close the socket
    close(sock);

    printf("All Work succefully\n");

    exit(0);
}

// Compute checksum 
unsigned short calculate_checksum(unsigned short * paddress, int len) {
	int nleft = len;
	int sum = 0;
	unsigned short * w = paddress;
	unsigned short answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*((unsigned char *)&answer) = *((unsigned char *)w);
		sum += answer;
	}

	// add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
	answer = ~sum;                      // truncate to 16 bits

	return answer;
}
