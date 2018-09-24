#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <arpa/inet.h>


/* Cabecera ARP */
struct arp_hdr {
	unsigned short int hardware;
	unsigned short int protocol;
	char hw_addr_len;  
	char proto_addr_len;
	unsigned short operation;
	char src_addr[6];
	char src_ip[4];
	char dst_addr[6];
	char dst_ip[4];
};


int main () {

	/* socket */
	int sock;

	/* Tamaño del buffer capaz de contener un paquete ARP */
	unsigned int buffer_size = sizeof(struct arp_hdr) + sizeof(struct ether_header);

	/* Buffer que contendra el paquete ARP */
	unsigned char buffer[buffer_size];
	memset(buffer,0,buffer_size);

	/* Cabecera ethernet */
	struct ether_header *eth = (struct ether_header *)buffer;

	/* Cabecera ARP */
	struct arp_hdr *arp = (struct arp_hdr *)(buffer + sizeof(struct ether_header));

	/* Direcciones MAC del protocolo ETH */
	char src_mac_eth[] = {0x00,0x1F,0x3C,0x4F,0x65,0x55};
	char dst_mac_eth[] = {0x00, 0x00, 0x00, 0xaa, 0x00, 0x02};

	/* Direcciones MAC del protocolo ARP*/
	char src_mac[] = {0x00,0x1F,0x3C,0x4F,0x65,0x55};
	char dst_mac[] = {0x00, 0x00, 0x00, 0xaa, 0x00, 0x02};
	
	/* Direcciones IP */
	char src_ip[] = {10,0,0,20};
	char dst_ip[] = {10,0,0,22};

	/* Dispositivo  */

	char dev[5];
	strncpy(dev, "eth0", 5);

	/* Creacion del socket */
	if ((sock = socket(AF_INET,SOCK_PACKET,htons(ETH_P_ARP)))==-1) { 
		
		perror("socket()"); 
		exit(EXIT_FAILURE); 
	}

	/* Rellena la cabecera ethernet */
	memcpy(eth->ether_dhost,dst_mac_eth,ETHER_ADDR_LEN);
	memcpy(eth->ether_shost,src_mac_eth,ETHER_ADDR_LEN);
	eth->ether_type = htons(ETHERTYPE_ARP);

	/* Rellena la cabecera ARP */
	arp->hardware = htons(ARPHRD_ETHER);
	arp->protocol = htons(ETH_P_IP);
	arp->hw_addr_len = 6;  	
	arp->proto_addr_len = 4;
	arp->operation = htons(ARPOP_REPLY);
	memcpy(arp->src_addr, src_mac,6);
	memcpy(arp->src_ip, src_ip, 4);
	memcpy(arp->dst_addr, dst_mac, 6);
	memcpy(arp->dst_ip, dst_ip, 4);

	/* Dispositivo utilizado "eth0" */
	struct sockaddr addr;
	strncpy(addr.sa_data, dev, sizeof(addr.sa_data));

	/* Envio del paquete ARP */

	// for(;;){
		if ((sendto(sock, buffer, buffer_size, 0, &addr, sizeof(struct sockaddr)))==-1) {
			perror("sendto()");
			exit(EXIT_FAILURE);
		}
		// sleep(1);
	// }

	return 0;
}