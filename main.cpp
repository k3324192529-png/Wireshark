#include <iostream>
#include <vector>
#define HAVE_REMOTE
#include <pcap.h>

int main() {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 1. C++ 风格：获取本机网络设备列表
   if (pcap_findalldevs_ex("rpcap://", NULL, &alldevs, errbuf) == -1){
        std::cerr << "获取设备列表出错: " << errbuf << std::endl;
        return 1;
    }

    // 2. 用 C++ 容器或标准流遍历打印
    int i = 0;
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        std::cout << ++i << ". " << d->name;
        if (d->description) {
            std::cout << " (" << d->description << ")\n";
        } else {
            std::cout << " (没有相关设备描述)\n";
        }
    }

    if (i == 0) {
        std::cout << "\n未找到任何接口！请确保 Npcap 驱动已正确安装。" << std::endl;
        return 0;
    }

    // 3. 释放设备列表内存
    pcap_freealldevs(alldevs);
    return 0;
}