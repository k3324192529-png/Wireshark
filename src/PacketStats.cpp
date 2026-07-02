#include "../include/PacketStats.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <algorithm>

// 映射协议名称
static const char* getProtoName(int type) {

}

/**
 * PacketStats类的构造函数
 * 初始化数据包统计相关的成员变量
 */
PacketStats::PacketStats() : total_packets(0), total_bytes(0), last_total_bytes(0) {

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

}

/**
 * 更新IP数据包统计信息的函数
 * @param src_ip 源IP地址字符串
 * @param length 数据包长度
 */
void PacketStats::updateIP(const std::string& src_ip, uint32_t length) {

}

/**
 * @brief 刷新屏幕并显示实时网络流量统计信息
 * 该函数负责计算和显示网络流量统计数据，包括系统运行时间、
 * 总捕获包数、总吞吐量、实时网速以及协议分布和活跃IP排行榜
 */
void PacketStats::refreshScreen() {

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