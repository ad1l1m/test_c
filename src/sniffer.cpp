#include <pcap.h>
#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>

struct ethernet_header {
    u_char dest[6];
    u_char src[6];
    u_short type;
};

struct ip_header {
    u_char ver_ihl;      // версия + длина заголовка
    u_char tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char ttl;
    u_char proto;
    u_short crc;
    u_int saddr;
    u_int daddr;
};

struct tcp_header {
    u_short source;
    u_short dest;
    u_int seq;
    u_int ack_seq;
    u_char doff_reserved;
    u_char flags;
    u_short window;
    u_short check;
    u_short urg_ptr;
};

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // 1. Ethernet
    const ethernet_header *eth = (ethernet_header *)packet;

    // проверка: это IPv4?
    if (ntohs(eth->type) != 0x0800) {
        return;
    }

    // 2. IP header
    const ip_header *ip = (ip_header *)(packet + sizeof(ethernet_header));

    int ip_header_length = (ip->ver_ihl & 0x0F) * 4;

    // IP адреса
    struct in_addr src, dst;
    src.s_addr = ip->saddr;
    dst.s_addr = ip->daddr;

    std::cout << inet_ntoa(src) << " -> " << inet_ntoa(dst);

    // 3. TCP
    if (ip->proto == IPPROTO_TCP) {

        const tcp_header *tcp = (tcp_header *)(
            packet + sizeof(ethernet_header) + ip_header_length
        );

        std::cout << " | TCP ";

        std::cout << ntohs(tcp->source) << " -> " << ntohs(tcp->dest);

    }

    // 4. UDP
    else if (ip->proto == IPPROTO_UDP) {

        std::cout << " | UDP";

    }

    std::cout << std::endl;
}

void start_sniffing() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    // 1. Получаем список интерфейсов
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return;
    }

    // 2. Берем первый интерфейс (потом сделаем выбор)
    pcap_if_t *device = alldevs;
    if (!device) {
        std::cerr << "No devices found" << std::endl;
        return;
    }

    std::cout << "Using device: " << device->name << std::endl;

    // 3. Открываем интерфейс
    pcap_t *handle = pcap_open_live(
        device->name,
        BUFSIZ,
        1,      // promiscuous mode
        1000,   // timeout
        errbuf
    );

    if (!handle) {
        std::cerr << "Could not open device: " << errbuf << std::endl;
        return;
    }

    // 4. Запускаем capture loop
    pcap_loop(handle, 0, packet_handler, nullptr);

    pcap_close(handle);
    pcap_freealldevs(alldevs);
}