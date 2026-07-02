#include "../include/PcapDumper.h"
#include <iostream>

PcapDumper::PcapDumper() : dumper(nullptr) {}

PcapDumper::~PcapDumper() {
    close();
}

bool PcapDumper::open(pcap_t* handle, const std::string& filename) {
    if (handle == nullptr) return false;
    
    // 使用 Npcap 核心 API 打开本地文件
    dumper = pcap_dump_open(handle, filename.c_str());
    if (dumper == nullptr) {
        std::cerr << "[错误] 无法创建 PCAP 备份文件！" << std::endl;
        return false;
    }
    std::cout << "[OK] PCAP 备份文件已创建: " << filename << std::endl;
    return true;
}

void PcapDumper::dump(const struct pcap_pkthdr* header, const u_char* pkt_data) {
    if (dumper != nullptr) {
        // 无损实时写入文件
        pcap_dump(reinterpret_cast<u_char*>(dumper), header, pkt_data);
    }
}

void PcapDumper::close() {
    if (dumper != nullptr) {
        pcap_dump_close(dumper);
        dumper = nullptr;
        std::cout << "[OK] PCAP 备份文件已安全关闭并保存。" << std::endl;
    }
}