#include "../include/PcapDumper.h"
#include <iostream>

PcapDumper::PcapDumper() : dumper(nullptr) {}

PcapDumper::~PcapDumper() {
    close();
}

bool PcapDumper::open(pcap_t* handle, const std::string& filename) {
    if (!handle) return false;
    dumper = pcap_dump_open(handle, filename.c_str());
    if (!dumper) {
        std::cerr << "[错误] 无法创建 PCAP 备份文件！" << std::endl;
        return false;
    }
    std::cout << "[OK] PCAP 备份文件已创建: " << filename << std::endl;
    return true;
}

void PcapDumper::dump(const struct pcap_pkthdr* header, const u_char* pkt_data) {
    if (dumper) {
        pcap_dump(reinterpret_cast<u_char*>(dumper), header, pkt_data);
    }
}

void PcapDumper::close() {
    if (dumper) {
        pcap_dump_close(dumper);
        dumper = nullptr;
        std::cout << "[OK] PCAP 备份文件已安全关闭并保存。" << std::endl;
    }
}