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

#define MAX_PACKET_SIZE 65535

// IP header struct
struct iphdr {
    unsigned int ihl:4;
    unsigned int version:4;
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
};

// TCP header struct
struct tcphdr {
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
    u_int16_t res1:4;
    u_int16_t doff:4;
    u_int16_t fin:1;
    u_int16_t syn:1;
    u_int16_t rst:1;
    u_int16_t psh:1;
    u_int16_t ack:1;
    u_int16_t urg:1;
    u_int16_t res2:2;
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};

// ICMP header struct
struct icmphdr {
    u_int8_t type;
    u_int8_t code;
    u_int16_t checksum;
    union {
        struct {
            u_int16_t id;
            u_int16_t sequence;
        } echo;
        u_int32_t gateway;
        struct {
            u_int16_t __unused;
            u_int16_t mtu;
        } frag;
    } un;
};


void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main()
{
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_if_t *alldevsp , *device;
    struct bpf_program bpf;

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

    handle = pcap_open_live(dev, MAX_PACKET_SIZE, 1, 0, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 3;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported.\n", dev);
        return 4;
    }
    //the sbiffer is able to filter packets of tcp and icmp protocol, and only tcp by the user choice. 
    char filter_exp[] = "tcp"; //for filtering only tcp packt
    // char filter_exp[] = "tcp or icmp"; //for filterin tcp ang icmp packt

    if (pcap_compile(handle, &bpf, filter_exp, 0, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 5;
    }

    if (pcap_setfilter(handle, &bpf) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 6;
    }

    FILE *fp = fopen("318813367_207689647.txt", "w");
    if (fp == NULL) {
        fprintf(stderr, "Couldn't open file for writing: %s\n", strerror(errno));
        return 7;
    }

    pcap_loop(handle, -1, callback, (u_char *)fp);
    fclose(fp);
    pcap_freecode(&bpf);
    pcap_close(handle);
    return 0;
}

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    FILE *fp = (FILE *)args;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct icmphdr *icmp;

    int size_ip;
    int size_tcp;

    ip = (struct iphdr*)(packet + sizeof(struct ether_header));
    size_ip = ip->ihl*4;
    if (ip->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + size_ip);
        size_tcp = tcp->doff*4;

        char source_ip[INET_ADDRSTRLEN];
        char dest_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->saddr), source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip->daddr), dest_ip, INET_ADDRSTRLEN);
        fprintf(fp, "{ source_ip: %s, dest_ip: %s, source_port: %d, dest_port: %d, timestamp: %ld, total_length: %d, cache_flag: %d,steps_flag: %d, type_flag: %d, status_code: %d, cache_control: %d, data: %s }\n", source_ip, dest_ip, ntohs(tcp->source),ntohs(tcp->dest), header->ts.tv_sec, header->len, 0, 0, 0, 0, 0, packet + sizeof(struct ether_header) + size_ip + size_tcp);
    }
    //for filterin tcp ang icmp packt uncommand the lins below.
    
    // else if (ip->protocol == IPPROTO_ICMP) 
    // {
    //     icmp = (struct icmphdr*)(packet + sizeof(struct ether_header) + size_ip);

    //     char source_ip[INET_ADDRSTRLEN];
    //     char dest_ip[INET_ADDRSTRLEN];
    //     inet_ntop(AF_INET, &(ip->saddr), source_ip, INET_ADDRSTRLEN);
    //     inet_ntop(AF_INET, &(ip->daddr), dest_ip, INET_ADDRSTRLEN);
    //     fprintf(fp, "{ source_ip: %s, dest_ip: %s, source_port: %d, dest_port: %d, timestamp: %ld, total_length: %d, cache_flag: %d,steps_flag: %d, type_flag: %d, status_code: %d, cache_control: %d, data: %s }\n", source_ip, dest_ip, 0, 0, header->ts.tv_sec,header->len, 0, 0, icmp->type, icmp->code, 0, packet + sizeof(struct ether_header) + size_ip + sizeof(struct icmphdr));
    // }
}


