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

//  ip地址截断辅助函数
static std::string formatIP(const std::string& ip, size_t max_len = 30) {
    if (ip.length() <= max_len) return ip;
    return ip.substr(0, max_len - 3) + "...";
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

    // ========================================================================
    // 核心修改：干掉原本的 if (total_packets % 150 == 0)
    // 改为严格的时间判定。计算当前时间和上一次刷新的时间差
    // ========================================================================
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_refresh_time).count();
    
    // 只有当距离上一次刷新过去了 200 毫秒（0.2秒）以上时，才触发清屏刷新
    if (duration >= 200) {
        refreshScreen();
    }
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

    // 保留原本的强力清屏
    system("cls");
    std::cout << std::setfill(' ') << std::right << std::dec;  // 防御性重置

    // 🌟 拓宽至 115 字符，完美匹配下面的 Wireshark 宽度
    std::cout << "===================================================================================================================" << std::endl;
    std::cout << "                                     📊  实时网络流量监控与统计看板                                     " << std::endl;
    std::cout << "===================================================================================================================" << std::endl;
    std::cout << " [系统运行时间]: " << std::setw(4) << total_duration << " 秒 "
              << " | [总捕获包数]: " << std::setw(6) << total_packets << " 个"
              << " | [总吞吐量]: " << std::fixed << std::setprecision(2) << std::setw(6) << (total_bytes / 1024.0 / 1024.0) << " MB"
              << " | [实时网速]: " << std::fixed << std::setprecision(2) << std::setw(7) << speed << " KB/s" << std::endl;
    std::cout << "-------------------------------------------------------------------------------------------------------------------" << std::endl;

    // 1. 打印协议分布占比（将进度条拉长，让版面更饱满）
    std::cout << "\n [1. 协议分布统计]:" << std::endl;
    for (auto const& [proto, data] : proto_map) {
        double pct = (total_packets > 0) ? (static_cast<double>(data.first) / total_packets * 100.0) : 0.0;
        int bar_width = static_cast<int>(pct / 2.5); // 拓宽进度条，最高绘制 40 个字符
        
        std::cout << "  " << std::left << std::setw(8) << getProtoName(proto) << " ➔ "
                  << "数量: " << std::setw(8) << data.first << " | 占比: " 
                  << std::setw(6) << std::fixed << std::setprecision(1) << pct << "%  "
                  << "[";
        for(int k=0; k<40; ++k) {
            if(k < bar_width) std::cout << "=";
            else if(k == bar_width) std::cout << ">";
            else std::cout << ".";
        }
        std::cout << "]" << std::endl;
    }

   // 2. 打印发包 Top 5 IP 排行榜（🌟 纯手工空格拼接，彻底无视编译流污染）
    std::cout << "\n [2. 活跃源 IP 排行榜 (Top 5)]:" << std::endl;
    std::vector<std::pair<std::string, std::pair<uint64_t, uint64_t>>> ip_list(ip_map.begin(), ip_map.end());
    std::sort(ip_list.begin(), ip_list.end(), [](const auto& a, const auto& b) {
        return a.second.first > b.second.first;
    });

    // 🌟 手动用普通空格硬拉出来的表头
    std::cout << "   排名    源 IP 地址                      发包数量            总数据量(Bytes)" << std::endl;

    int count = 0;
    for (auto const& item : ip_list) {
        if (++count > 5) break;
        
        // 1. 准备好每一列的原始字符串数据
        std::string rank_str = "#" + std::to_string(count);
        std::string ip_str = item.first;
        std::string pkts_str = std::to_string(item.second.first);
        std::string bytes_str = std::to_string(item.second.second);

        // 2. 纯手工计算需要补多少个空格（严格对齐每一列的左边缘起点）
        std::string pad_rank  = (rank_str.length() < 8)   ? std::string(8 - rank_str.length(), ' ') : "";
        std::string pad_ip    = (ip_str.length() < 32)    ? std::string(32 - ip_str.length(), ' ') : "";
        std::string pad_pkts  = (pkts_str.length() < 20)  ? std::string(20 - pkts_str.length(), ' ') : "";

        // 3. 一口气朴实无华地打印出来
        std::cout << "   " 
                  << rank_str  << pad_rank
                  << ip_str    << pad_ip
                  << pkts_str  << pad_pkts
                  << bytes_str << std::endl;
    }

    std::cout << "===================================================================================================================" << std::endl;

    // 3. 在大盘最底下，把攒着的 Wireshark 流水画上去
    extern const std::vector<std::string>& get_packet_logs();
    const auto& logs = get_packet_logs();

    if (!logs.empty()) {
        std::cout << "\n 📦 [3. 实时抓包流水日志 (每10个包抽样滚动)]" << std::endl;
        std::cout << std::left 
                  << std::setw(8)  << "No." 
                  << std::setw(12) << "Time" 
                  << std::setw(20) << "Source" 
                  << std::setw(20) << "Destination" 
                  << std::setw(10) << "Protocol" 
                  << std::setw(8)  << "Length" 
                  << "Info" << std::endl;
        std::cout << "-------------------------------------------------------------------------------------------------------------------" << std::endl;

        for (const auto& log_line : logs) {
            std::cout << log_line << std::endl;
        }
    }
}

// ------------------------------------------------------------
// 实现预留出来的 extern 接口，实现了对 PacketStats 单例的访问和更新
// ------------------------------------------------------------
void update_stats_by_protocol(int proto_type, uint32_t length, const std::string& src_ip) {
    PacketStats::getInstance().updateProtocol(proto_type, length);
}

void update_stats_by_ip(const std::string& src_ip, uint32_t length) {
    PacketStats::getInstance().updateIP(src_ip, length);
}