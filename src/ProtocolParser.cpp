#include "../include/ProtocolParser.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>

// ------------------------------------------------------------
// 全局统计接口（预留，待同学C实现后接入）
// 此处声明外部函数，实际在 PacketStats 中定义
// 同学B只需要在解析到各层时调用这些接口即可
// ------------------------------------------------------------
extern void update_stats_by_protocol(int proto_type, uint32_t length, const std::string& src_ip);
extern void update_stats_by_ip(const std::string& src_ip, uint32_t length);

// 协议类型常量（与同学C约定）
enum ProtoType {
    PROTO_TCP = 1,
    PROTO_UDP = 2,
    PROTO_ICMP = 3,
    PROTO_ARP = 4,
    PROTO_IPv4 = 5,
    PROTO_IPv6 = 6,
    PROTO_DNS = 7,
    PROTO_HTTP = 8
};

// ------------------------------------------------------------
// 入口函数
// ------------------------------------------------------------
void ProtocolParser::parse(const struct pcap_pkthdr* header, const u_char* pkt_data) {
    uint32_t caplen = header->caplen;   // 实际捕获的长度
    if (caplen < sizeof(EthernetHeader)) {
        std::cerr << "[Parser] 包太小，不足以解析以太网头" << std::endl;
        return;
    }

    // 从链路层开始解析
    parseEthernet(pkt_data, caplen);
}

// ------------------------------------------------------------
// 以太网层解析
// ------------------------------------------------------------
void ProtocolParser::parseEthernet(const u_char* data, uint32_t len) {
    if (len < sizeof(EthernetHeader)) return;

    const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(data);
    uint16_t eth_type = ntoh16(eth->type);

    // 打印信息（可暂留，便于调试）
    std::cout << "[链路层] ";
    printMac(eth->src_mac);
    std::cout << " -> ";
    printMac(eth->dest_mac);
    std::cout << "  类型: 0x" << std::hex << eth_type << std::dec << std::endl;

    // 根据类型向上传递
    const u_char* next_data = data + sizeof(EthernetHeader);
    uint32_t remaining = len - sizeof(EthernetHeader);

    switch (eth_type) {
        case 0x0800:  // IPv4
            parseIPv4(next_data, remaining);
            break;
        case 0x86DD:  // IPv6
            parseIPv6(next_data, remaining);
            break;
        case 0x0806:  // ARP
            // 可以统计ARP包，调用更新接口
            // update_stats_by_protocol(PROTO_ARP, len, "");
            break;
        default:
            // 其他协议忽略
            break;
    }
}

// ------------------------------------------------------------
// IPv4 解析
// ------------------------------------------------------------
void ProtocolParser::parseIPv4(const u_char* data, uint32_t len) {
    if (len < sizeof(IPv4Header)) return;

    const IPv4Header* ip = reinterpret_cast<const IPv4Header*>(data);
    uint8_t ihl = (ip->ver_ihl & 0x0F) * 4;   // 首部长度（单位：字节）
    uint16_t total_len = ntoh16(ip->total_len);
    uint8_t protocol = ip->protocol;
    uint32_t src_ip = ip->src_ip;
    uint32_t dest_ip = ip->dest_ip;

    std::string src_str = ipToString(src_ip);
    std::string dest_str = ipToString(dest_ip);
    std::cout << "[网络层] IPv4  " << src_str << " -> " << dest_str
              << "  协议: " << (int)protocol << std::endl;

    // 统计IPv4包（调用同学C接口）
    // update_stats_by_protocol(PROTO_IPv4, total_len, src_str);

    // 检查是否有足够数据
    if (len < ihl) return;
    const u_char* next_data = data + ihl;
    uint32_t remaining = len - ihl;

    // 根据协议字段继续向上
    switch (protocol) {
        case 6:   // TCP
            parseTCP(next_data, remaining);
            // 投喂TCP统计（源IP）
            // update_stats_by_protocol(PROTO_TCP, total_len, src_str);
            break;
        case 17:  // UDP
            parseUDP(next_data, remaining);
            // update_stats_by_protocol(PROTO_UDP, total_len, src_str);
            break;
        case 1:   // ICMP
            parseICMP(next_data, remaining);
            // update_stats_by_protocol(PROTO_ICMP, total_len, src_str);
            break;
        default:
            break;
    }
}

// ------------------------------------------------------------
// IPv6 解析（简化版本，仅提取源/目的地址和下一头部）
// ------------------------------------------------------------
void ProtocolParser::parseIPv6(const u_char* data, uint32_t len) {
    if (len < sizeof(IPv6Header)) return;

    const IPv6Header* ip6 = reinterpret_cast<const IPv6Header*>(data);
    uint8_t next_header = ip6->next_header;
    std::string src_str = ipv6ToString(ip6->src_ip);
    std::string dest_str = ipv6ToString(ip6->dest_ip);

    std::cout << "[网络层] IPv6  " << src_str << " -> " << dest_str
              << "  下一头部: " << (int)next_header << std::endl;

    // 统计IPv6
    // update_stats_by_protocol(PROTO_IPv6, 0, src_str);

    const u_char* next_data = data + sizeof(IPv6Header);
    uint32_t remaining = len - sizeof(IPv6Header);

    // 与IPv4类似，处理上层协议
    switch (next_header) {
        case 6:   parseTCP(next_data, remaining); break;
        case 17:  parseUDP(next_data, remaining); break;
        case 1:   parseICMP(next_data, remaining); break;
        default:  break;
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
    uint8_t data_offset = (tcp->offset_res >> 4) * 4;  // 首部长度

    std::cout << "[传输层] TCP  " << src_port << " -> " << dest_port
              << "  标志: 0x" << std::hex << (int)tcp->flags << std::dec << std::endl;

    // 统计TCP（端口信息可一并记录）
    // update_stats_by_protocol(PROTO_TCP, 0, "");

    // 检查是否有应用层数据
    if (len < data_offset) return;
    const u_char* payload = data + data_offset;
    uint32_t payload_len = len - data_offset;

    // 根据端口判断上层协议
    if (src_port == 53 || dest_port == 53) {
        parseDNS(payload, payload_len);
    } else if (src_port == 80 || dest_port == 80 ||
               src_port == 443 || dest_port == 443) {
        parseHTTP(payload, payload_len);
    }
    // 其他端口忽略
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

    std::cout << "[传输层] UDP  " << src_port << " -> " << dest_port
              << "  长度: " << udp_len << std::endl;

    // 统计UDP
    // update_stats_by_protocol(PROTO_UDP, udp_len, "");

    // 应用层（DNS通常使用UDP 53）
    const u_char* payload = data + sizeof(UDPHeader);
    uint32_t payload_len = len - sizeof(UDPHeader);

    if (src_port == 53 || dest_port == 53) {
        parseDNS(payload, payload_len);
    }
}

// ------------------------------------------------------------
// ICMP 解析
// ------------------------------------------------------------
void ProtocolParser::parseICMP(const u_char* data, uint32_t len) {
    if (len < sizeof(ICMPHeader)) return;

    const ICMPHeader* icmp = reinterpret_cast<const ICMPHeader*>(data);
    std::cout << "[网络控制] ICMP  类型: " << (int)icmp->type
              << "  代码: " << (int)icmp->code << std::endl;

    // 统计ICMP
    // update_stats_by_protocol(PROTO_ICMP, 0, "");
}

// ------------------------------------------------------------
// DNS 解析（仅解析头部，不展开问题/资源记录）
// ------------------------------------------------------------
void ProtocolParser::parseDNS(const u_char* data, uint32_t len) {
    if (len < sizeof(DNSHeader)) return;

    const DNSHeader* dns = reinterpret_cast<const DNSHeader*>(data);
    uint16_t id = ntoh16(dns->id);
    uint16_t qdcount = ntoh16(dns->qdcount);
    uint16_t ancount = ntoh16(dns->ancount);

    std::cout << "[应用层] DNS  事务ID: " << id
              << "  问题数: " << qdcount
              << "  回答数: " << ancount << std::endl;

    // 统计DNS
    // update_stats_by_protocol(PROTO_DNS, 0, "");
}

// ------------------------------------------------------------
// HTTP 解析（仅提取请求行或状态行）
// ------------------------------------------------------------
void ProtocolParser::parseHTTP(const u_char* data, uint32_t len) {
    // 简单起见，只打印前几个可打印字符（假设是文本）
    std::cout << "[应用层] HTTP (前32字节): ";
    for (uint32_t i = 0; i < len && i < 32; ++i) {
        char c = static_cast<char>(data[i]);
        if (c >= 32 && c <= 126) std::cout << c;
        else std::cout << '.';
    }
    std::cout << std::endl;

    // 统计HTTP
    // update_stats_by_protocol(PROTO_HTTP, 0, "");
}

// ------------------------------------------------------------
// 辅助函数实现
// ------------------------------------------------------------
std::string ProtocolParser::ipToString(uint32_t ip) {
    // 将网络字节序的IP转为主机序（便于按字节拆分）
    uint32_t host_ip = ntoh32(ip);
    std::ostringstream oss;
    oss << ((host_ip >> 24) & 0xFF) << '.'
        << ((host_ip >> 16) & 0xFF) << '.'
        << ((host_ip >> 8) & 0xFF) << '.'
        << (host_ip & 0xFF);
    return oss.str();
}

std::string ProtocolParser::ipv6ToString(const uint8_t* ip) {
    // 简化显示，每16位一组
    std::ostringstream oss;
    for (int i = 0; i < 16; i += 2) {
        if (i > 0) oss << ':';
        oss << std::hex << std::setw(2) << std::setfill('0')
            << (int)ip[i] << std::setw(2) << std::setfill('0') << (int)ip[i+1];
    }
    return oss.str();
}

void ProtocolParser::printMac(const uint8_t* mac) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << (int)mac[0];
    for (int i = 1; i < 6; ++i) {
        std::cout << ':' << std::setw(2) << std::setfill('0') << (int)mac[i];
    }
    std::cout << std::dec;
}