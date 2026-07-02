#ifndef PACKET_STATS_H
#define PACKET_STATS_H

#include <string>
#include <unordered_map>
#include <cstdint>
#include <chrono>

class PacketStats {
public:
    // 获取全局单例
    static PacketStats& getInstance();

    // 投喂数据的核心方法
    void updateProtocol(int proto_type, uint32_t length);
    void updateIP(const std::string& src_ip, uint32_t length);
    
    // 渲染刷新看板
    void refreshScreen();

private:
    PacketStats(); // 构造函数私有化
    
    uint64_t total_packets;
    uint64_t total_bytes;
    
    // 核心数据库：统计各协议的 [包数量, 总字节数]
    std::unordered_map<int, std::pair<uint64_t, uint64_t>> proto_map;
    // 核心数据库：统计各个 IP 的 [发包数量, 总字节数]
    std::unordered_map<std::string, std::pair<uint64_t, uint64_t>> ip_map;

    // 用来计算每秒吞吐率的时间戳
    std::chrono::steady_clock::time_point start_time;
    uint64_t last_total_bytes;
    std::chrono::steady_clock::time_point last_refresh_time;
};

#endif