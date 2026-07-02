#include <iostream>
#include <string>
#include "include/SnifferEngine.h"

int main() {
    system("chcp 65001 > nul"); // 防止乱码

    SnifferEngine engine;
    
    std::cout << "=== 正在初始化网络抓包与协议解析系统 ===" << std::endl;
    if (!engine.initDevices()) {
        std::cerr << "初始化网络设备失败，程序退出。" << std::endl;
        return 1;
    }

    engine.showDevices();

    int choice;
    std::cout << "\n请输入你想抓包的网卡编号: ";
    std::cin >> choice;

    std::cin.ignore(); // 吃掉回车符
    std::string filterExpr;
    std::cout << "请输入 BPF 过滤规则 (若不需要请输入回车，如: tcp port 80): ";
    std::getline(std::cin, filterExpr);

    // 启动主引擎
    engine.startSniffing(choice, filterExpr);

    return 0;
}