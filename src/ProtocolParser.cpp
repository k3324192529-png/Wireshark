#include "../include/ProtocolParser.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <chrono>
#include <vector>

extern void update_stats_by_protocol(int proto_type, uint32_t length, const std::string& src_ip);
extern void update_stats_by_ip(const std::string& src_ip, uint32_t length);

// 协议类型枚举（与同学C约定，增加 OTHER）
enum ProtoType {
    PROTO_TCP  = 1,
    PROTO_UDP  = 2,
    PROTO_ICMP = 3,
    PROTO_ARP  = 4,
    PROTO_IPv4 = 5,   // 保留，但不再用于统计
    PROTO_IPv6 = 6,
    PROTO_DNS  = 7,
    PROTO_HTTP = 8,
    PROTO_OTHER = 9   // 新增：其他协议
};

// 全局变量：当前包的捕获长度
static uint32_t g_caplen = 0;

// 日志相关
static uint32_t packet_counter = 0;
static bool is_first_packet = true;
static long long start_sec = 0;
static long long start_usec = 0;

struct CurrentPacketInfo {
    std::string src_ip;
    std::string dest_ip;
    std::string proto_name;
    std::string info_str;
} cur_pkt;

static std::vector<std::string> log_buffer;

// 供外部获取日志
const std::vector<std::string>& get_packet_logs() {
    return log_buffer;
}

// ICMP类型名称
static const char* icmpTypeName(uint8_t type) {
    switch(type) {
        case 0:  return "Echo Reply";
        case 3:  return "Destination Unreachable";
        case 4:  return "Source Quench";
        case 5:  return "Redirect";
        case 8:  return "Echo Request";
        case 11: return "Time Exceeded";
        default: return "Unknown";
    }
}

// ------------------------------------------------------------
// 统一入口
// ------------------------------------------------------------
void ProtocolParser::parse(const struct pcap_pkthdr* header, const u_char* pkt_data) {
    g_caplen = header->caplen;   // 保存捕获长度

    if (g_caplen < sizeof(EthernetHeader)) {
        std::cerr << "[Parser] 警告：捕获长度小于以太网头大小，跳过此包。" << std::endl;
        return;
    }

    // 初始化时间基准
    if (is_first_packet) {
        start_sec = header->ts.tv_sec;
        start_usec = header->ts.tv_usec;
        is_first_packet = false;
    }

    packet_counter++;

    // 清空当前包信息
    cur_pkt.src_ip = "Unknown";
    cur_pkt.dest_ip = "Unknown";
    cur_pkt.proto_name = "ETHERNET";
    cur_pkt.info_str = "Ethernet Frame";

    // 解析以太网层（内部会继续向上解析）
    parseEthernet(pkt_data, g_caplen);

    // 每10个包记录一条日志
    if (packet_counter % 10 == 0) {
        // 计算相对时间
        long long diff_sec = header->ts.tv_sec - start_sec;
        long long diff_usec = header->ts.tv_usec - start_usec;
        double rel_time = diff_sec + (diff_usec / 1000000.0);

        std::ostringstream oss;
        oss << std::left
            << std::setw(8)  << packet_counter
            << std::setw(12) << std::fixed << std::setprecision(6) << rel_time
            << std::setw(20) << cur_pkt.src_ip
            << std::setw(20) << cur_pkt.dest_ip
            << std::setw(10) << cur_pkt.proto_name
            << std::setw(8)  << g_caplen
            << cur_pkt.info_str;

        log_buffer.push_back(oss.str());
        if (log_buffer.size() > 10) {
            log_buffer.erase(log_buffer.begin());
        }
    }
}

// ------------------------------------------------------------
// 以太网层
// ------------------------------------------------------------
void ProtocolParser::parseEthernet(const u_char* data, uint32_t len) {
    if (len < sizeof(EthernetHeader)) return;

    const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(data);
    uint16_t eth_type = ntoh16(eth->type);

    const u_char* next_data = data + sizeof(EthernetHeader);
    uint32_t remaining = len - sizeof(EthernetHeader);

    switch (eth_type) {
        case 0x0800:  // IPv4
            cur_pkt.proto_name = "IPv4";
            parseIPv4(next_data, remaining);
            break;
        case 0x86DD:  // IPv6
            cur_pkt.proto_name = "IPv6";
            parseIPv6(next_data, remaining);
            break;
        case 0x0806:  // ARP
            cur_pkt.proto_name = "ARP";
            cur_pkt.src_ip = "Who has object?";
            cur_pkt.dest_ip = "Broadcast";
            cur_pkt.info_str = "ARP Request / Reply";
            // [优化] ARP 直接统计，只此一次
            update_stats_by_protocol(PROTO_ARP, g_caplen, "");
            break;
        default:
            cur_pkt.proto_name = "OTHER";
            cur_pkt.info_str = "Unknown Ethernet Type";
            // 其他链路层协议归为 OTHER 统计
            update_stats_by_protocol(PROTO_OTHER, g_caplen, "");
            break;
    }
}

// ------------------------------------------------------------
// IPv4 解析
// ------------------------------------------------------------
void ProtocolParser::parseIPv4(const u_char* data, uint32_t len) {
    if (len < sizeof(IPv4Header)) return;

    const IPv4Header* ip = reinterpret_cast<const IPv4Header*>(data);
    uint8_t ihl = (ip->ver_ihl & 0x0F) * 4;
    if (ihl < 20 || ihl > 60) return;

    uint16_t total_len = ntoh16(ip->total_len);
    uint8_t protocol = ip->protocol;

    cur_pkt.src_ip = ipToString(ip->src_ip);
    cur_pkt.dest_ip = ipToString(ip->dest_ip);

    // IP 排行榜（不影响总包数）
    update_stats_by_ip(cur_pkt.src_ip, g_caplen);

    if (total_len > len) total_len = len;
    if (len < ihl) return;

    const u_char* next_data = data + ihl;
    uint32_t remaining = len - ihl;

    // 根据传输层协议分发，统计由子层负责
    switch (protocol) {
        case 6:   // TCP
            cur_pkt.proto_name = "TCP";
            parseTCP(next_data, remaining);
            break;
        case 17:  // UDP
            cur_pkt.proto_name = "UDP";
            parseUDP(next_data, remaining);
            break;
        case 1:   // ICMP
            cur_pkt.proto_name = "ICMP";
            parseICMP(next_data, remaining);
            break;
        default:   // 其他 IPv4 协议
            cur_pkt.proto_name = "OTHER";
            {
                std::stringstream ss;
                ss << "IPv4 Protocol " << (int)protocol;
                cur_pkt.info_str = ss.str();
            }
            // [优化] 未知上层协议，统计为 OTHER
            update_stats_by_protocol(PROTO_OTHER, g_caplen, cur_pkt.src_ip);
            break;
    }
}

// ------------------------------------------------------------
// IPv6 解析
// ------------------------------------------------------------
void ProtocolParser::parseIPv6(const u_char* data, uint32_t len) {
    if (len < sizeof(IPv6Header)) return;

    const IPv6Header* ip6 = reinterpret_cast<const IPv6Header*>(data);
    uint8_t next_header = ip6->next_header;
    cur_pkt.src_ip = ipv6ToString(ip6->src_ip);
    cur_pkt.dest_ip = ipv6ToString(ip6->dest_ip);

    // IP 排行榜
    update_stats_by_ip(cur_pkt.src_ip, g_caplen);

    const u_char* next_data = data + sizeof(IPv6Header);
    uint32_t remaining = len - sizeof(IPv6Header);

    switch (next_header) {
        case 6:   // TCP
            cur_pkt.proto_name = "TCP";
            parseTCP(next_data, remaining);
            break;
        case 17:  // UDP
            cur_pkt.proto_name = "UDP";
            parseUDP(next_data, remaining);
            break;
        case 1:   // ICMP
            cur_pkt.proto_name = "ICMP";
            parseICMP(next_data, remaining);
            break;
        default:
            cur_pkt.proto_name = "OTHER";
            cur_pkt.info_str = "IPv6 Other Header";
            // [优化] 未知上层，统计为 OTHER
            update_stats_by_protocol(PROTO_OTHER, g_caplen, cur_pkt.src_ip);
            break;
    }
}

// ------------------------------------------------------------
// TCP 解析
// ------------------------------------------------------------
void ProtocolParser::parseTCP(const u_char* data, uint32_t len) {
    if (len < sizeof(TCPHeader)) return;

    const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(data);
    uint16_t src_port = ntoh16(tcp->src_port);
    uint16_t dest_port = ntoh16(tcp->dest_port);
    uint8_t data_offset = (tcp->offset_res >> 4) * 4;

    if (data_offset < 20 || data_offset > 60) return;

    // 构建信息字符串
    std::stringstream ss;
    ss << src_port << " → " << dest_port << " [";
    if (tcp->flags & 0x02) ss << "SYN ";
    if (tcp->flags & 0x10) ss << "ACK ";
    if (tcp->flags & 0x01) ss << "FIN ";
    if (tcp->flags & 0x04) ss << "RST ";
    ss << "] Seq=" << ntoh32(tcp->seq_num);
    cur_pkt.info_str = ss.str();

    // 判断是否为应用层协议（DNS/HTTP）
    int proto_type = PROTO_TCP;   // 默认 TCP
    const u_char* payload = nullptr;
    uint32_t payload_len = 0;

    if (len > data_offset) {
        payload = data + data_offset;
        payload_len = len - data_offset;

        if (src_port == 53 || dest_port == 53) {
            proto_type = PROTO_DNS;
            cur_pkt.proto_name = "DNS";
            parseDNS(payload, payload_len);
        } else if (src_port == 80 || dest_port == 80 ||
                   src_port == 443 || dest_port == 443) {
            proto_type = PROTO_HTTP;
            cur_pkt.proto_name = "HTTP";
            parseHTTP(payload, payload_len);
        }
    }

    // [优化] 每个包只统计一次（传输层或应用层）
    update_stats_by_protocol(proto_type, g_caplen, cur_pkt.src_ip);
}

// ------------------------------------------------------------
// UDP 解析
// ------------------------------------------------------------
void ProtocolParser::parseUDP(const u_char* data, uint32_t len) {
    if (len < sizeof(UDPHeader)) return;

    const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(data);
    uint16_t src_port = ntoh16(udp->src_port);
    uint16_t dest_port = ntoh16(udp->dest_port);
    uint16_t udp_len = ntoh16(udp->length);

    std::stringstream ss;
    ss << src_port << " → " << dest_port << " Len=" << udp_len;
    cur_pkt.info_str = ss.str();

    int proto_type = PROTO_UDP;
    const u_char* payload = data + sizeof(UDPHeader);
    uint32_t payload_len = len - sizeof(UDPHeader);

    if (src_port == 53 || dest_port == 53) {
        proto_type = PROTO_DNS;
        cur_pkt.proto_name = "DNS";
        parseDNS(payload, payload_len);
    }

    // [优化] 统计一次
    update_stats_by_protocol(proto_type, g_caplen, cur_pkt.src_ip);
}

// ------------------------------------------------------------
// ICMP 解析
// ------------------------------------------------------------
void ProtocolParser::parseICMP(const u_char* data, uint32_t len) {
    if (len < sizeof(ICMPHeader)) return;

    const ICMPHeader* icmp = reinterpret_cast<const ICMPHeader*>(data);
    std::stringstream ss;
    ss << "Type=" << (int)icmp->type << " (" << icmpTypeName(icmp->type) << ") Code=" << (int)icmp->code;
    cur_pkt.info_str = ss.str();

    // [优化] ICMP 在此统计一次
    update_stats_by_protocol(PROTO_ICMP, g_caplen, cur_pkt.src_ip);
}

// ------------------------------------------------------------
// DNS 解析（仅头部）
// ------------------------------------------------------------
void ProtocolParser::parseDNS(const u_char* data, uint32_t len) {
    if (len < sizeof(DNSHeader)) return;

    const DNSHeader* dns = reinterpret_cast<const DNSHeader*>(data);
    uint16_t id = ntoh16(dns->id);
    uint16_t qdcount = ntoh16(dns->qdcount);
    uint16_t ancount = ntoh16(dns->ancount);

    std::stringstream ss;
    ss << "Standard query 0x" << std::hex << id << std::dec << " Questions:" << qdcount << " Answers:" << ancount;
    cur_pkt.info_str = ss.str();
    // 注意：统计已在 TCP/UDP 中完成，这里不再调用
}

// ------------------------------------------------------------
// HTTP 解析（仅显示首行）
// ------------------------------------------------------------
void ProtocolParser::parseHTTP(const u_char* data, uint32_t len) {
    if (len == 0) {
        cur_pkt.info_str = "Empty HTTP payload";
        return;
    }

    if (std::strncmp((const char*)data, "GET", 3) == 0 ||
        std::strncmp((const char*)data, "POST", 4) == 0 ||
        std::strncmp((const char*)data, "HTTP", 4) == 0) {
        std::stringstream ss;
        for (uint32_t i = 0; i < len && i < 50; ++i) {
            char c = static_cast<char>(data[i]);
            if (c == '\r' || c == '\n') break;
            if (c >= 32 && c <= 126) ss << c;
            else ss << '.';
        }
        cur_pkt.info_str = ss.str();
    } else {
        cur_pkt.info_str = "HTTP payload (non-request/response)";
    }
    // 统计已在 TCP 中完成
}

// ------------------------------------------------------------
// 辅助函数（不变）
// ------------------------------------------------------------
std::string ProtocolParser::ipToString(uint32_t ip) {
    uint32_t host_ip = ntoh32(ip);
    std::ostringstream oss;
    oss << ((host_ip >> 24) & 0xFF) << '.'
        << ((host_ip >> 16) & 0xFF) << '.'
        << ((host_ip >> 8) & 0xFF) << '.'
        << (host_ip & 0xFF);
    return oss.str();
}

std::string ProtocolParser::ipv6ToString(const uint8_t* ip) {
    std::ostringstream oss;
    for (int i = 0; i < 16; i += 2) {
        if (i > 0) oss << ':';
        oss << std::hex << std::setw(2) << std::setfill('0')
            << (int)ip[i] << std::setw(2) << std::setfill('0') << (int)ip[i+1];
    }
    return oss.str();
}

void ProtocolParser::printMac(const uint8_t* mac) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)mac[0];
    for (int i = 1; i < 6; ++i) {
        std::cout << ':' << std::setw(2) << std::setfill('0') << (int)mac[i];
    }
    std::cout << std::dec << std::setfill(' ');
}