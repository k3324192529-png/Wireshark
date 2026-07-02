#ifndef PCAP_DUMPER_H
#define PCAP_DUMPER_H

#include <pcap.h>
#include <string>

class PcapDumper {
public:
    PcapDumper();
    ~PcapDumper();

    // 打开一个 pcap 文件准备写入
    bool open(pcap_t* handle, const std::string& filename);
    
    // 写入单个数据包
    void dump(const struct pcap_pkthdr* header, const u_char* pkt_data);
    
    // 关闭文件
    void close();

private:
    pcap_dumper_t* dumper; // Npcap 原生的文件写入句柄
};

#endif