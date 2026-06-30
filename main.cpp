#include <iostream>
#include <vector>
#include <iomanip>
#define HAVE_REMOTE
#include <pcap.h>

// 1. 【核心数据结构】定义以太网帧头结构体（必须强制 1 字节对齐，完美匹配底层硬件报文）
#pragma pack(push, 1)
struct EthernetHeader {
    uint8_t dest_mac[6];   // 目的 MAC 地址
    uint8_t src_mac[6];    // 源 MAC 地址
    uint16_t type;         // 上层协议类型 (网络字节序，大端)
};
#pragma pack(pop)

// 2. 【核心回调函数】每当 Npcap 驱动在网卡上抓到一个包，就会自动“拍”一下这个函数
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    std::cout << "\n------------------------------------------------------------" << std::endl;
    std::cout << "[捕获到原始报文] 时间戳: " << header->ts.tv_sec << "s | 捕获长度: " << header->len << " 字节" << std::endl;

    // 边界安全检查：确保抓到的数据至少大于一个以太网头部的长度
    if (header->len >= sizeof(EthernetHeader)) {
        // 利用 C++ 的 reinterpret_cast，直接把裸字节流指针强转为结构体指针（零拷贝，极致性能）
        const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(pkt_data);
        
        // 打印源 MAC 地址 (格式化为经典的 XX:XX:XX:XX:XX:XX)
        std::cout << "  [链路层] 源  MAC: ";
        for(int i = 0; i < 6; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)eth->src_mac[i] << (i == 5 ? "" : ":");
        }
        
        // 打印目的 MAC 地址
        std::cout << "\n  [链路层] 目的 MAC: ";
        for(int i = 0; i < 6; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)eth->dest_mac[i] << (i == 5 ? "" : ":");
        }
        
        // 核心卡点：网络传输用的是“大端序”，而 Intel/AMD 电脑是“小端序”。
        // 必须用 ntohs() 函数把网络字节序转为主机字节序，否则读取到的协议号是反的！
        // 自己手动交换高低字节，完美替代 ntohs() 且不依赖任何底层套接字库
        uint16_t eth_type = (eth->type << 8) | (eth->type >> 8);
        std::cout << std::dec << "\n  [链路层] 上层协议号: 0x" << std::hex << eth_type;
        
        // 根据协议号进行分流解析判断
        if (eth_type == 0x0800) std::cout << " -> (IPv4 协议 -> 准备移交网络层解析)";
        else if (eth_type == 0x0806) std::cout << " -> (ARP 协议)";
        else if (eth_type == 0x86dd) std::cout << " -> (IPv6 协议)";
        std::cout << std::dec << std::endl;
    }
}

int main() {
    system("chcp 65001 > nul");

    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 获取本地网卡列表
    if (pcap_findalldevs_ex("rpcap://", NULL, &alldevs, errbuf) == -1) {
        std::cerr << "获取设备列表出错: " << errbuf << std::endl;
        return 1;
    }

    // 将网卡存入 vector 容器
    int i = 0;
    std::vector<pcap_if_t*> dev_list;
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        std::cout << ++i << ". " << d->name << (d->description ? d->description : " (没有描述)") << std::endl;
        dev_list.push_back(d);
    }

    if (i == 0) {
        std::cout << "未找到任何可用网卡！" << std::endl;
        return 0;
    }

    int choice;
    std::cout << "\n请输入你想抓包的网卡编号 (1-" << i << "): ";
    std::cin >> choice;

    if (choice < 1 || choice > i) {
        std::cout << "无效选择。" << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    // 3. 【打开网卡】利用 pcap_open 开启混杂模式（Promiscuous Mode），可以捕获通过该网卡的所有流量
    pcap_t *adhandle = pcap_open(dev_list[choice - 1]->name, 
                                 65536,                        // 捕获每个包的最大字节数
                                 0,    // 关闭混杂模式
                                 1000,                         // 读取超时时间为 1000ms
                                 NULL, errbuf);

    if (adhandle == NULL) {
        std::cerr << "无法打开网卡: " << dev_list[choice - 1]->name << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    std::cout << "\n[OK] 抓包引擎成功挂载到网卡上！开始实时监听... (按 Ctrl+C 强制退出)\n" << std::endl;
    
    // 已经成功打开网卡，设备列表的链表内存可以还给系统了
    pcap_freealldevs(alldevs);

    // 4. 【开启捕获循环】主线程会在这里死循环阻塞，每抓到一个包，就自动调用一次 packet_handler
    // 第二个参数 0 代表无限抓取，直到手动退出
    pcap_loop(adhandle, 0, packet_handler, NULL);

    pcap_close(adhandle);
    return 0;
}