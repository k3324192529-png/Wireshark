#include "../include/SnifferEngine.h"
#include "../include/ProtocolParser.h"
#include <iostream>

// 初始化静态成员
PcapDumper SnifferEngine::dumperModule;

SnifferEngine::SnifferEngine() : alldevs(nullptr), adhandle(nullptr) {}

SnifferEngine::~SnifferEngine() {
    stopSniffing();
    if (alldevs != nullptr) {
        pcap_freealldevs(alldevs);
    }
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
    if (choice < 1 || choice > static_cast<int>(devList.size())) {
        std::cerr << "无效的网卡选择。" << std::endl;
        return false;
    }

    // 1. 打开网卡（开启有线网卡的混杂模式）
    adhandle = pcap_open(devList[choice - 1]->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 50, NULL, errbuf);
    if (adhandle == nullptr) {
        std::cerr << "无法打开网卡: " << errbuf << std::endl;
        return false;
    }

    // 2. 核心功能：设置 BPF 过滤器
    if (!filterExpr.empty()) {
        struct bpf_program fcode;
        // 编译过滤表达式（例如 "tcp port 80" 或 "ip src 192.168.1.1"）
        if (pcap_compile(adhandle, &fcode, filterExpr.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0) {
            std::cerr << "[警告] BPF 过滤表达式语法错误，忽略过滤规则。" << std::endl;
        } else {
            // 应用过滤规则到内核层
            pcap_setfilter(adhandle, &fcode);
            std::cout << "[OK] BPF 过滤规则已生效: " << filterExpr << std::endl;
        }
    }

    // 3. 开启 PCAP 持久化存储，保存到本地的 traffic.pcap
    dumperModule.open(adhandle, "traffic.pcap");

    std::cout << "\n[OK] 抓包引擎已就绪，开始监听... (按 Ctrl+C 强制退出)\n" << std::endl;

    // 4. 进入阻塞捕获循环
    pcap_loop(adhandle, 0, SnifferEngine::packetCallback, nullptr);
    return true;
}

void SnifferEngine::stopSniffing() {
    if (adhandle != nullptr) {
        pcap_breakloop(adhandle);
        pcap_close(adhandle);
        adhandle = nullptr;
    }
    dumperModule.close();
}

// 核心自来水阀门：抓到一个包，同时喂给同学 B 的解析器和同学 A 的存储器
void SnifferEngine::packetCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    // 1. 喂给同学 A 自己的存储模块：无损存盘
    dumperModule.dump(header, pkt_data);

    // 2. 投递给同学 B 的解析引擎：进行多层剥离解析
    ProtocolParser::parse(header, pkt_data);
}