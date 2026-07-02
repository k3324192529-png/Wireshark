#include <iostream>
#include <string>
#include "include/SnifferEngine.h"

int main() {
    system("chcp 65001 > nul"); // 解决终端乱码

    SnifferEngine engine;
    
    std::cout << "=== 欢迎使用局域网协议分析与抓包系统 ===" << std::endl;
    if (!engine.initDevices()) {
        std::cerr << "未找到任何可用网卡适配器。" << std::endl;
        return 1;
    }

    engine.showDevices();

    int choice;
    std::cout << "\n请输入你想抓包的网卡编号: ";
    std::cin >> choice;

    std::cin.ignore(); 
    std::string filterExpr;
    std::cout << "请输入 BPF 过滤规则 (若不需要请直接按回车，如 icmp 或 tcp): ";
    std::getline(std::cin, filterExpr);

    // 启动主引擎
    engine.startSniffing(choice, filterExpr);

    return 0;
}