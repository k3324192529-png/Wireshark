#include "../include/PacketStats.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <algorithm>

// 映射协议名称
static const char* getProtoName(int type) {
    switch(type) {
        case 1: return "TCP";
        case 2: return "UDP";
        case 3: return "ICMP";
        case 4: return "ARP";
        case 5: return "IPv4";
        case 6: return "IPv6";
        case 7: return "DNS";
        case 8: return "HTTP";
        default: return "OTHER";
    }
}

/**
 * PacketStats类的构造函数
 * 初始化数据包统计相关的成员变量
 */
PacketStats::PacketStats() : total_packets(0), total_bytes(0), last_total_bytes(0) {
    start_time = std::chrono::steady_clock::now();
    last_refresh_time = start_time;
}

/**
 * 获取PacketStats类的单例实例
 * 这是一个单例模式的实现，使用局部静态变量确保线程安全且只创建一个实例
 * @return 返回PacketStats类的单例引用
 */
PacketStats& PacketStats::getInstance() {
    static PacketStats instance;  // 静态局部变量，确保只初始化一次
    return instance;             // 返回已创建的实例引用
}

/**
 * 更新协议统计信息
 * @param proto_type 协议类型
 * @param length 数据包长度
 */
void PacketStats::updateProtocol(int proto_type, uint32_t length) {
    total_packets++;
    total_bytes += length;
    
    proto_map[proto_type].first++;        // 包数量 +1
    proto_map[proto_type].second += length; // 字节数累加

    // 优化体验：每抓到 150 个包自动刷新一次屏幕，防止频繁清屏导致终端闪烁
    // if (total_packets % 150 == 0) {
    //     refreshScreen();
    // }
}

/**
 * 更新IP数据包统计信息的函数
 * @param src_ip 源IP地址字符串
 * @param length 数据包长度
 */
void PacketStats::updateIP(const std::string& src_ip, uint32_t length) {
    if (src_ip.empty()) return;
    ip_map[src_ip].first++;
    ip_map[src_ip].second += length;
}

/**
 * @brief 刷新屏幕并显示实时网络流量统计信息
 * 该函数负责计算和显示网络流量统计数据，包括系统运行时间、
 * 总捕获包数、总吞吐量、实时网速以及协议分布和活跃IP排行榜
 */
void PacketStats::refreshScreen() {
    auto now = std::chrono::steady_clock::now();
    auto total_duration = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
    auto interval_duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_refresh_time).count();
    
    if (interval_duration == 0) return;

    // 计算当前瞬时速率 (KB/s)
    double speed = static_cast<double>(total_bytes - last_total_bytes) / 1024.0 / (interval_duration / 1000.0);
    
    last_total_bytes = total_bytes;
    last_refresh_time = now;

    // 执行 Windows 终端清屏命令
    system("cls");

        std::cout << "==========================================================================" << std::endl;
    std::cout << "                📊  实时网络流量监控与统计看板                 " << std::endl;
    std::cout << "==========================================================================" << std::endl;
    std::cout << " [系统运行时间]: " << total_duration << " 秒 "
              << " | [总捕获包数]: " << total_packets << " 个"
              << " | [总吞吐量]: " << std::fixed << std::setprecision(2) << (total_bytes / 1024.0 / 1024.0) << " MB" << std::endl;
    std::cout << " [实时网速]:     " << std::fixed << std::setprecision(2) << speed << " KB/s" << std::endl;
    std::cout << "--------------------------------------------------------------------------" << std::endl;

    // 1. 打印协议分布占比（带简易进度条）
    std::cout << "\n [1. 协议分布统计]:" << std::endl;
    for (auto const& [proto, data] : proto_map) {
        double pct = (total_packets > 0) ? (static_cast<double>(data.first) / total_packets * 100.0) : 0.0;
        int bar_width = static_cast<int>(pct / 5); // 每 5% 绘制一个 '='
        
        std::cout << "  " << std::left << std::setw(6) << getProtoName(proto) << " ➔ "
                  << "数量: " << std::setw(6) << data.first << " | 占比: " 
                  << std::setw(6) << std::fixed << std::setprecision(1) << pct << "%  "
                  << "[";
        for(int k=0; k<20; ++k) {
            if(k < bar_width) std::cout << "=";
            else if(k == bar_width) std::cout << ">";
            else std::cout << ".";
        }
        std::cout << "]" << std::endl;
    }

    // 2. 打印发包 Top 5 IP 排行榜
    std::cout << "\n [2. 活跃源 IP 排行榜 (Top 5)]:" << std::endl;
    std::vector<std::pair<std::string, std::pair<uint64_t, uint64_t>>> ip_list(ip_map.begin(), ip_map.end());
    // 按发包数量降序排序
    std::sort(ip_list.begin(), ip_list.end(), [](const auto& a, const auto& b) {
        return a.second.first > b.second.first;
    });

    int count = 0;
    std::cout << "   排名    源 IP 地址               发包数量      总数据量(Bytes)" << std::endl;
    for (auto const& item : ip_list) {
        if (++count > 5) break;
        std::cout << "   " << std::left << std::setw(7) << ("#" + std::to_string(count))
                  << std::setw(24) << item.first
                  << std::setw(14) << item.second.first
                  << item.second.second << std::endl;
    }
    std::cout << "==========================================================================" << std::endl;

}

//

// ------------------------------------------------------------
// 实现预留出来的 extern 接口，实现了对 PacketStats 单例的访问和更新
// ------------------------------------------------------------
void update_stats_by_protocol(int proto_type, uint32_t length, const std::string& src_ip) {
    PacketStats::getInstance().updateProtocol(proto_type, length);
}

void update_stats_by_ip(const std::string& src_ip, uint32_t length) {
    PacketStats::getInstance().updateIP(src_ip, length);
}