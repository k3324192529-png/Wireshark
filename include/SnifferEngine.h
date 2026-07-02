#ifndef SNIFFER_ENGINE_H
#define SNIFFER_ENGINE_H

#include <pcap.h>
#include <string>
#include <vector>
#include "PcapDumper.h"

class SnifferEngine {
public:
    SnifferEngine();
    ~SnifferEngine();

    bool initDevices();
    void showDevices();
    bool startSniffing(int choice, const std::string& filterExpr);
    void stopSniffing();

    static void packetCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* pkt_data);

private:
    pcap_if_t* alldevs;
    std::vector<pcap_if_t*> devList;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    static PcapDumper dumperModule;
};

#endif