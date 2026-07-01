#include <iostream>
#include <vector>
#include <iomanip>
#define HAVE_REMOTE
#include <pcap.h>
#include "include/ProtocolParser.h" 

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    // 直接委托给 ProtocolParser 进行逐层解析
    ProtocolParser::parse(header, pkt_data);
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