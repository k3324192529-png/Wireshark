#include "../include/SnifferEngine.h"
#include "../include/ProtocolParser.h"
#include <iostream>

PcapDumper SnifferEngine::dumperModule;

SnifferEngine::SnifferEngine() : alldevs(nullptr), adhandle(nullptr) {}

SnifferEngine::~SnifferEngine() {
    stopSniffing();
    if (alldevs) pcap_freealldevs(alldevs);
}

bool SnifferEngine::initDevices() {
    if (pcap_findalldevs_ex("rpcap://", NULL, &alldevs, errbuf) == -1) {
        std::cerr << "获取设备列表出错: " << errbuf << std::endl;
        return false;
    }
    for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
        devList.push_back(d);
    }
    return !devList.empty();
}

void SnifferEngine::showDevices() {
    int i = 0;
    for (auto d : devList) {
        std::cout << ++i << ". " << d->name << (d->description ? d->description : " (没有描述)") << std::endl;
    }
}

bool SnifferEngine::startSniffing(int choice, const std::string& filterExpr) {
    if (choice < 1 || choice > static_cast<int>(devList.size())) return false;

    adhandle = pcap_open(devList[choice - 1]->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 50, NULL, errbuf);
    if (!adhandle) return false;

    // 绑定 BPF 过滤器
    if (!filterExpr.empty()) {
        struct bpf_program fcode;
        if (pcap_compile(adhandle, &fcode, filterExpr.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0) {
            std::cerr << "[警告] BPF 语法错误，忽略过滤规则。" << std::endl;
        } else {
            pcap_setfilter(adhandle, &fcode);
            std::cout << "[OK] BPF 过滤规则生效: " << filterExpr << std::endl;
        }
    }

    // 开启文件存储
    dumperModule.open(adhandle, "traffic.pcap");
    std::cout << "\n[OK] 混杂模式引擎启动成功... (Ctrl+C 退出)\n" << std::endl;

    pcap_loop(adhandle, 0, SnifferEngine::packetCallback, nullptr);
    return true;
}

void SnifferEngine::stopSniffing() {
    if (adhandle) {
        pcap_breakloop(adhandle);
        pcap_close(adhandle);
        adhandle = nullptr;
    }
    dumperModule.close();
}

void SnifferEngine::packetCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    dumperModule.dump(header, pkt_data);           // 1. 同学 A 的存储流
    ProtocolParser::parse(header, pkt_data);       // 2. 同学 B 的解析流
}