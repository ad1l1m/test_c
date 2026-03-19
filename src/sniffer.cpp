#include <pcap.h>
#include <iostream>

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    std::cout << "Packet captured: length = " << header->len << std::endl;
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