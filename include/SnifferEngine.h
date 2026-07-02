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

    bool initDevices();                               // 获取网卡列表
    void showDevices();                               // 打印网卡供用户选择
    bool startSniffing(int choice, const std::string& filterExpr); // 开始捕获（含 BPF 过滤）
    void stopSniffing();                              // 停止捕获

    // 静态回调函数，供 pcap_loop 调用
    static void packetCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* pkt_data);

private:
    pcap_if_t* alldevs;
    std::vector<pcap_if_t*> devList;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    static PcapDumper dumperModule; // 静态实例，方便回调函数内直接访问写入
};

#endif