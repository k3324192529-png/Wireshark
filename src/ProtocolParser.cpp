#include "../include/ProtocolParser.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>

// ------------------------------------------------------------
// 与同学C的统计接口（外部声明，待同学C实现）
// ------------------------------------------------------------
extern void update_stats_by_protocol(int proto_type, uint32_t length, const std::string& src_ip);
extern void update_stats_by_ip(const std::string& src_ip, uint32_t length);

// 协议类型枚举（与同学C约定）
enum ProtoType {
    PROTO_TCP  = 1,
    PROTO_UDP  = 2,
    PROTO_ICMP = 3,
    PROTO_ARP  = 4,
    PROTO_IPv4 = 5,
    PROTO_IPv6 = 6,
    PROTO_DNS  = 7,
    PROTO_HTTP = 8
};

// ------------------------------------------------------------
// 统一入口
// ------------------------------------------------------------
void ProtocolParser::parse(const struct pcap_pkthdr* header, const u_char* pkt_data) {
    uint32_t caplen = header->caplen;   // 实际捕获的字节数

    // 检查是否足以包含以太网头
    if (caplen < sizeof(EthernetHeader)) {
        std::cerr << "[Parser] 警告：捕获长度小于以太网头大小，跳过此包。" << std::endl;
        return;
    }

    // 从链路层开始解析
    parseEthernet(pkt_data, caplen);
}

// ------------------------------------------------------------
// 以太网层解析
// ------------------------------------------------------------
void ProtocolParser::parseEthernet(const u_char* data, uint32_t len) {
    if (len < sizeof(EthernetHeader)) {
        std::cerr << "[Parser] 以太网头数据不足。" << std::endl;
        return;
    }

    const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(data);
    uint16_t eth_type = ntoh16(eth->type);  // 转为本地字节序

    // 打印链路层信息（便于调试，后续可改为日志）
    std::cout << "[链路层] ";
    printMac(eth->src_mac);
    std::cout << " -> ";
    printMac(eth->dest_mac);
    std::cout << "  类型: 0x" << std::hex << eth_type << std::dec << std::endl;

    // 根据以太网类型向上传递
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
            // 可调用统计接口：update_stats_by_protocol(PROTO_ARP, len, "");
            break;
        default:
            // 其他协议（如VLAN、MPLS等）暂不处理
            break;
    }
}

// ------------------------------------------------------------
// IPv4 解析
// ------------------------------------------------------------
void ProtocolParser::parseIPv4(const u_char* data, uint32_t len) {
    if (len < sizeof(IPv4Header)) {
        std::cerr << "[Parser] IPv4头数据不足。" << std::endl;
        return;
    }

    const IPv4Header* ip = reinterpret_cast<const IPv4Header*>(data);

    // 提取首部长度（单位：4字节），必须 ≥ 5（即20字节）
    uint8_t ihl = (ip->ver_ihl & 0x0F) * 4;
    if (ihl < 20 || ihl > 60) {
        std::cerr << "[Parser] 无效的IPv4首部长度: " << (int)ihl << std::endl;
        return;
    }

    uint16_t total_len = ntoh16(ip->total_len);   // 总长度（含首部+数据）
    uint8_t protocol = ip->protocol;
    uint32_t src_ip = ip->src_ip;
    uint32_t dest_ip = ip->dest_ip;

    std::string src_str = ipToString(src_ip);
    std::string dest_str = ipToString(dest_ip);

    std::cout << "[网络层] IPv4  " << src_str << " -> " << dest_str
              << "  协议: " << (int)protocol << std::endl;

    // 调用统计接口（待同学C实现）
    // update_stats_by_protocol(PROTO_IPv4, total_len, src_str);

    // 检查整个IP包长度是否大于捕获长度
    if (total_len > len) {
        std::cerr << "[Parser] IPv4报文长度大于实际捕获长度，可能截断。" << std::endl;
        // 仍尝试解析，但使用实际捕获长度
        total_len = len;
    }

    // 跳过IP首部，进入上层协议数据
    if (len < ihl) {
        std::cerr << "[Parser] IPv4首部长度超出捕获长度。" << std::endl;
        return;
    }
    const u_char* next_data = data + ihl;
    uint32_t remaining = len - ihl;

    // 根据协议号分发
    switch (protocol) {
        case 6:   // TCP
            parseTCP(next_data, remaining);
            // update_stats_by_protocol(PROTO_TCP, 0, src_str);
            break;
        case 17:  // UDP
            parseUDP(next_data, remaining);
            // update_stats_by_protocol(PROTO_UDP, 0, src_str);
            break;
        case 1:   // ICMP
            parseICMP(next_data, remaining);
            // update_stats_by_protocol(PROTO_ICMP, 0, src_str);
            break;
        default:
            // 其他协议（如IGMP、OSPF等）暂不解析
            break;
    }
}

// ------------------------------------------------------------
// IPv6 解析
// ------------------------------------------------------------
void ProtocolParser::parseIPv6(const u_char* data, uint32_t len) {
    if (len < sizeof(IPv6Header)) {
        std::cerr << "[Parser] IPv6头数据不足。" << std::endl;
        return;
    }

    const IPv6Header* ip6 = reinterpret_cast<const IPv6Header*>(data);
    uint8_t next_header = ip6->next_header;
    std::string src_str = ipv6ToString(ip6->src_ip);
    std::string dest_str = ipv6ToString(ip6->dest_ip);

    std::cout << "[网络层] IPv6  " << src_str << " -> " << dest_str
              << "  下一头部: " << (int)next_header << std::endl;

    // update_stats_by_protocol(PROTO_IPv6, 0, src_str);

    const u_char* next_data = data + sizeof(IPv6Header);
    uint32_t remaining = len - sizeof(IPv6Header);

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
    if (len < sizeof(TCPHeader)) {
        std::cerr << "[Parser] TCP头数据不足。" << std::endl;
        return;
    }

    const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(data);
    uint16_t src_port = ntoh16(tcp->src_port);
    uint16_t dest_port = ntoh16(tcp->dest_port);
    uint8_t data_offset = (tcp->offset_res >> 4) * 4;  // 首部长度（字节）

    if (data_offset < 20 || data_offset > 60) {
        std::cerr << "[Parser] 无效的TCP首部长度: " << (int)data_offset << std::endl;
        return;
    }

    std::cout << "[传输层] TCP  " << src_port << " -> " << dest_port
              << "  标志: 0x" << std::hex << (int)tcp->flags << std::dec << std::endl;

    // update_stats_by_protocol(PROTO_TCP, 0, "");

    if (len < data_offset) {
        std::cerr << "[Parser] TCP首部长度超出捕获长度。" << std::endl;
        return;
    }

    const u_char* payload = data + data_offset;
    uint32_t payload_len = len - data_offset;

    // 根据端口识别应用层协议
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
    if (len < sizeof(UDPHeader)) {
        std::cerr << "[Parser] UDP头数据不足。" << std::endl;
        return;
    }

    const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(data);
    uint16_t src_port = ntoh16(udp->src_port);
    uint16_t dest_port = ntoh16(udp->dest_port);
    uint16_t udp_len = ntoh16(udp->length);   // UDP数据报总长度

    std::cout << "[传输层] UDP  " << src_port << " -> " << dest_port
              << "  长度: " << udp_len << std::endl;

    // update_stats_by_protocol(PROTO_UDP, udp_len, "");

    const u_char* payload = data + sizeof(UDPHeader);
    uint32_t payload_len = len - sizeof(UDPHeader);

    // DNS通常使用UDP 53
    if (src_port == 53 || dest_port == 53) {
        parseDNS(payload, payload_len);
    }
}

// ------------------------------------------------------------
// ICMP 解析
// ------------------------------------------------------------
void ProtocolParser::parseICMP(const u_char* data, uint32_t len) {
    if (len < sizeof(ICMPHeader)) {
        std::cerr << "[Parser] ICMP头数据不足。" << std::endl;
        return;
    }

    const ICMPHeader* icmp = reinterpret_cast<const ICMPHeader*>(data);
    std::cout << "[网络控制] ICMP  类型: " << (int)icmp->type
              << "  代码: " << (int)icmp->code << std::endl;

    // update_stats_by_protocol(PROTO_ICMP, 0, "");
}

// ------------------------------------------------------------
// DNS 解析（仅头部，不遍历问题/资源记录）
// ------------------------------------------------------------
void ProtocolParser::parseDNS(const u_char* data, uint32_t len) {
    if (len < sizeof(DNSHeader)) {
        std::cerr << "[Parser] DNS头数据不足。" << std::endl;
        return;
    }

    const DNSHeader* dns = reinterpret_cast<const DNSHeader*>(data);
    uint16_t id = ntoh16(dns->id);
    uint16_t qdcount = ntoh16(dns->qdcount);
    uint16_t ancount = ntoh16(dns->ancount);

    std::cout << "[应用层] DNS  事务ID: " << id
              << "  问题数: " << qdcount
              << "  回答数: " << ancount << std::endl;

    // update_stats_by_protocol(PROTO_DNS, 0, "");
}

// ------------------------------------------------------------
// HTTP 解析（仅打印前32个可打印字符）
// ------------------------------------------------------------
void ProtocolParser::parseHTTP(const u_char* data, uint32_t len) {
    if (len == 0) {
        std::cout << "[应用层] HTTP  空负载" << std::endl;
        return;
    }

    std::cout << "[应用层] HTTP (前32字节): ";
    for (uint32_t i = 0; i < len && i < 32; ++i) {
        char c = static_cast<char>(data[i]);
        if (c >= 32 && c <= 126) std::cout << c;
        else std::cout << '.';
    }
    std::cout << std::endl;

    // update_stats_by_protocol(PROTO_HTTP, 0, "");
}

// ------------------------------------------------------------
// 辅助函数实现
// ------------------------------------------------------------
std::string ProtocolParser::ipToString(uint32_t ip) {
    // 将网络序IP转换为主机序，再按字节拆分为点分十进制
    uint32_t host_ip = ntoh32(ip);
    std::ostringstream oss;
    oss << ((host_ip >> 24) & 0xFF) << '.'
        << ((host_ip >> 16) & 0xFF) << '.'
        << ((host_ip >> 8) & 0xFF) << '.'
        << (host_ip & 0xFF);
    return oss.str();
}

std::string ProtocolParser::ipv6ToString(const uint8_t* ip) {
    // 简化显示：每组16位（2字节）用十六进制表示
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