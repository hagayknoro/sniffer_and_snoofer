#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_ether.h> 
#include <sys/types.h>
#include <stdint.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
	
/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};

//function declertion
void send_raw_ip_packet(struct iphdr *ip);
int spoofing(struct iphdr *ip);
unsigned short calculate_checksum(unsigned short * paddress, int len);
void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


int main()
{
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_if_t *alldevsp , *device;
    struct bpf_program bpf;
    bpf_u_int32 net;

    char *dev , devs[100][100];
	int count = 1 , n;
	
	//First get the list of available devices
	printf("Finding available devices ... ");
	if( pcap_findalldevs( &alldevsp , errbuf) )
	{
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
	printf("Done");
	
	//Print the available devices
	printf("\nAvailable Devices are :\n");
	for(device = alldevsp ; device != NULL ; device = device->next)
	{
		printf("%d. %s - %s\n" , count , device->name , device->description);
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);
		}
		count++;
	}
	
	//Ask user which device to sniff
	printf("Enter the number of the device you want to sniff : ");
	scanf("%d" , &n);
	dev = devs[n];

    char filter_exp[] = "icmp";
    // Step 1: Open live pcap session on NIC with name lo
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); 
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 3;
    } 
    
    // Step 2: Compile filter_exp into BPF psuedo-code
    if (pcap_compile(handle, &bpf, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 5;
    }

    pcap_setfilter(handle, &bpf);                             
    
    printf("Befor loop\n");

    // Step 3: Capture packets 
    pcap_loop(handle, -1, callback, NULL);                

    pcap_close(handle);   //Close the handle 
    return 0;
}

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


void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("in callbabk\n");

    struct ethheader *eth = (struct ethheader *)packet;
    struct icmphdr *icmp = (struct icmphdr*)(packet + sizeof(struct ethheader));
    struct iphdr *ip = (struct iphdr*)(packet + sizeof(struct ethheader));;

    
    if (ntohs(eth->ether_type) == 0x0800) 
    { // 0x0800 is IP type
        ip = (struct iphdr*)(packet + sizeof(struct ether_header));

        switch(ip->protocol) {                               
            case IPPROTO_TCP:
                printf("   Protocol: TCP\n");
                return;
            case IPPROTO_UDP:
                printf("   Protocol: UDP\n");
                return;
            case IPPROTO_ICMP:
                printf("   Protocol: ICMP\n");
			    spoofing(ip);
                return;
            default:
                printf("   Protocol: others\n");
                return;
        }
    }
}

int spoofing(struct iphdr *ip) 
{
	char temp[IP_MAXPACKET] = {'\0'};

    int ip_header_len = ip->ihl*4;    

    memset((char*)temp, 0, IP_MAXPACKET);
    memcpy((char*)temp, ip, ntohs(ip->tot_len));

    struct icmphdr *icmp = (struct icmphdr*)(temp + ip_header_len); // ICMP-header
    struct iphdr *NewIp = (struct iphdr*)temp;

    NewIp->saddr = ip->daddr;
    NewIp->daddr = ip->saddr;
    NewIp->ttl = 50;

    icmp->type = 0;

    printf("Done spoofing starting send\n");

    send_raw_ip_packet (NewIp);

    return(0);
}

void send_raw_ip_packet(struct iphdr *ip) 
{
    struct sockaddr_in dest_in;

    int enable = 1;


    // Step 1: Create a raw network socket.
    int sock = -1;
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) 
    {
        fprintf (stderr, "socket() failed with error: %d\n", errno);
        fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        exit(1);
    }

    // Step 2: Set socket option.
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)))
    {
        perror("Something is wrong\n");
        exit(1);
    }

    // Step 3: Provide needed information about destination.
    memset (&dest_in, 0, sizeof (struct sockaddr_in));

    dest_in.sin_family = AF_INET;
    dest_in.sin_addr.s_addr = ip->daddr;

    // Step 4: Send the packet out.
    // Send the packet using sendto() for sending datagrams.
    if (sendto (sock, ip, ntohs(ip->tot_len), 0, (struct sockaddr *) &dest_in, sizeof (dest_in)) == -1) 
    {
        fprintf (stderr, "sendto() failed with error: %d\n", errno);
        exit(1);
    }

    close(sock);

    printf("All Work succefully\n");
}

