#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include "arp.h"

char this_mac[6];
char bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char dst_mac[6] =	{0x00, 0x00, 0x00, 0x22, 0x22, 0x22};
char src_mac[6] =	{0x00, 0x00, 0x00, 0x33, 0x33, 0x33};

union eth_buffer buffer_u;

int main(int argc, char *argv[])
{
	struct ifreq if_idx, if_mac, ifopts;
	char ifName[IFNAMSIZ];
	struct sockaddr_ll socket_address;
	int sockfd, numbytes;
	
	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");
	
	/* Set interface to promiscuous mode */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

	/* Get the index of the interface */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;

	/* Get the MAC address of the interface */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR");	
	memcpy(this_mac, if_mac.ifr_hwaddr.sa_data, 6);
	    
	/* End of configuration. Now we can send and receive data using raw sockets. */


	/* To send data (in this case we will cook an ARP packet and broadcast it =])... */
	
	/* fill the Ethernet frame header */
	memcpy(buffer_u.cooked_data.ethernet.dst_addr, bcast_mac, 6);
	memcpy(buffer_u.cooked_data.ethernet.src_addr, src_mac, 6);
	buffer_u.cooked_data.ethernet.eth_type = htons(ETH_P_ARP);

	/* fill payload data (incomplete ARP request example) */
	buffer_u.cooked_data.payload.arp.hw_type = htons(1);
	buffer_u.cooked_data.payload.arp.prot_type = htons(ETH_P_IP);
	buffer_u.cooked_data.payload.arp.hlen = 6;
	buffer_u.cooked_data.payload.arp.plen = 4;
	buffer_u.cooked_data.payload.arp.operation = htons(1);
	memcpy(buffer_u.cooked_data.payload.arp.src_hwaddr, src_mac, 6);
	memset(buffer_u.cooked_data.payload.arp.src_paddr, 0, 6);
	memset(buffer_u.cooked_data.payload.arp.tgt_hwaddr, 0, 6);
	memset(buffer_u.cooked_data.payload.arp.tgt_paddr, 0, 6);

	/* Send it.. */
	memcpy(socket_address.sll_addr, dst_mac, 6);
		if (sendto(sockfd, buffer_u.raw_data, sizeof(struct eth_hdr) + sizeof(struct arp_packet), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
			printf("Send failed\n");

	
	/* To receive data (in this case we will inspect ARP and IP packets)... */
	
	while (1){
		numbytes = recvfrom(sockfd, buffer_u.raw_data, ETH_LEN, 0, NULL, NULL);
		if (numbytes > 0) {
			if (buffer_u.cooked_data.ethernet.eth_type == ntohs(ETH_P_ARP)){
				printf("ARP packet, %d bytes - operation %d\n", numbytes, ntohs(buffer_u.cooked_data.payload.arp.operation));
				
				uint8_t *sourceMAC = buffer_u.cooked_data.payload.arp.src_hwaddr;
				uint8_t *destinationMAC = buffer_u.cooked_data.payload.arp.tgt_hwaddr;
				uint8_t *sourceIP = buffer_u.cooked_data.payload.arp.src_paddr;
				uint8_t *destinationIP = buffer_u.cooked_data.payload.arp.tgt_paddr;
				
				printf("Etherner Header:\n");
				printf("MAC Source: %x:%x:%x:%x:%x:%x\n", sourceMAC[0], sourceMAC[1],sourceMAC[2], sourceMAC[3], sourceMAC[4], sourceMAC[5]);
				printf("MAC Destination: %x:%x:%x:%x:%x:%x\n", destinationMAC[0], destinationMAC[1],destinationMAC[2], destinationMAC[3], destinationMAC[4], destinationMAC[5]);
				printf("IP Source: %d.%d.%d.%d\n", sourceIP[0],sourceIP[1], sourceIP[2], sourceIP[3]);
				printf("IP Destination: %d.%d.%d.%d\n", destinationIP[0], destinationIP[1], destinationIP[2], destinationIP[3]);
				// continue;
			}
			//if (buffer_u.cooked_data.ethernet.eth_type == ntohs(ETH_P_IP)){
				//printf("IP packet, %d bytes - src ip: %d.%d.%d.%d dst ip: %d.%d.%d.%d proto: %d\n",
					//numbytes,
					//buffer_u.cooked_data.payload.ip.src[0], buffer_u.cooked_data.payload.ip.src[1],
					//buffer_u.cooked_data.payload.ip.src[2], buffer_u.cooked_data.payload.ip.src[3],
					//buffer_u.cooked_data.payload.ip.dst[0], buffer_u.cooked_data.payload.ip.dst[1],
					//buffer_u.cooked_data.payload.ip.dst[2], buffer_u.cooked_data.payload.ip.dst[3],
					//buffer_u.cooked_data.payload.ip.proto
				//);
				//continue;
			//}
					
			printf("got a packet, %d bytes\n", numbytes);
		}
	}

	return 0;
}
