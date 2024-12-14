#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <sys/ioctl.h>

void sendArpRequest(const std::string& ipAddress, const std::string& interfaceName) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        perror("Socket creation failed");
        return;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interfaceName.c_str(), IFNAMSIZ - 1);
    
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Failed to get MAC address");
        close(sockfd);
        return;
    }

    unsigned char srcMac[6];
    memcpy(srcMac, ifr.ifr_hwaddr.sa_data, 6);

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(ipAddress.c_str());

    struct ether_arp arpReq;
    memset(&arpReq, 0, sizeof(arpReq));
    
    // Заполнение ARP-запроса
    memcpy(arpReq.arp_sha, srcMac, 6); // MAC-адрес отправителя
    memset(arpReq.arp_tha, 0x00, 6);   // MAC-адрес получателя (неизвестен)
    arpReq.arp_spa = inet_addr("0.0.0.0"); // IP-адрес отправителя
    arpReq.arp_tpa = dest.sin_addr.s_addr; // IP-адрес получателя
    arpReq.arp_hrd = htons(ARPHRD_ETHER); // Тип аппаратного адреса
    arpReq.arp_pro = htons(ETH_P_IP); // Тип протокола
    arpReq.arp_hln = ETH_ALEN; // Длина аппаратного адреса
    arpReq.arp_pln = sizeof(in_addr_t); // Длина протокольного адреса
    arpReq.arp_op = htons(ARPOP_REQUEST); // Тип операции (ARP-запрос)

    struct sockaddr sdest;
    memset(&sdest, 0, sizeof(sdest));
    sdest.sa_family = AF_PACKET;

    struct ethhdr ethHeader;
    memset(&ethHeader, 0, sizeof(ethHeader));
    
    // Заполнение заголовка Ethernet
    memcpy(ethHeader.h_source, srcMac, 6);
    memset(ethHeader.h_dest, 0xff, 6); // Широковещательный адрес
    ethHeader.h_proto = htons(ETH_P_ARP);

    // Отправка ARP-запроса
    if (sendto(sockfd, &ethHeader, sizeof(ethHeader), 0, &sdest, sizeof(sdest)) < 0) {
        perror("Failed to send Ethernet header");
    }
    
    if (sendto(sockfd, &arpReq, sizeof(arpReq), 0, &sdest, sizeof(sdest)) < 0) {
        perror("Failed to send ARP request");
    }

    close(sockfd);
}

int main() {
    std::string ipAddress;
    std::string interfaceName;

    std::cout << "Введите IP-адрес для проверки: ";
    std::cin >> ipAddress;

    std::cout << "Введите имя интерфейса (например, eth0): ";
    std::cin >> interfaceName;

    while (true) {
        sendArpRequest(ipAddress, interfaceName);
        std::cout << "ARP-запрос отправлен для " << ipAddress << std::endl;
        sleep(5); // Ждем 5 секунд перед следующей проверкой
    }

    return 0;
}
