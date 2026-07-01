#ifndef PROTOCOL_PARSER_H
#define PROTOCOL_PARSER_H

#include <pcap.h>
#include <cstdint>
#include <string>

// ------------------------------------------------------------
// 协议头部结构体（强制1字节对齐，匹配网络报文）
// ------------------------------------------------------------
#pragma pack(push, 1)

// 以太网帧头
struct EthernetHeader {
    uint8_t  dest_mac[6];
    uint8_t  src_mac[6];
    uint16_t type;          // 网络字节序（大端）
};

// IPv4 头
struct IPv4Header {
    uint8_t  ver_ihl;          // 版本(4bit) + 首部长度(4bit)
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;         // 上层协议号（TCP=6, UDP=17, ICMP=1）
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
    // 选项部分（此处忽略，首部长度最小20字节）
};

// IPv6 头
struct IPv6Header {
    uint32_t version_tc_flow;  // 版本(4bit) + 流量类别(8bit) + 流标签(20bit)
    uint16_t payload_len;
    uint8_t  next_header;      // 同IPv4的protocol
    uint8_t  hop_limit;
    uint8_t  src_ip[16];
    uint8_t  dest_ip[16];
};

// TCP 头
struct TCPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  offset_res;       // 数据偏移(4bit) + 保留(3bit) + NS(1bit)
    uint8_t  flags;            // CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

// UDP 头
struct UDPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

// ICMP 头（仅支持常用的类型/代码）
struct ICMPHeader {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    // 其余字段（如标识、序号等）不定义，解析时根据类型决定
};

// DNS 头
struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// HTTP 无固定头部，仅用于标识，不定义结构体，直接解析文本

#pragma pack(pop)

// ------------------------------------------------------------
// ProtocolParser 类（静态工具类）
// ------------------------------------------------------------
class ProtocolParser {
public:
    // 统一入口：供同学A在回调中调用
    static void parse(const struct pcap_pkthdr* header, const u_char* pkt_data);

private:
    // 各层解析函数（内部使用）
    static void parseEthernet(const u_char* data, uint32_t len);
    static void parseIPv4(const u_char* data, uint32_t len);
    static void parseIPv6(const u_char* data, uint32_t len);
    static void parseTCP(const u_char* data, uint32_t len);
    static void parseUDP(const u_char* data, uint32_t len);
    static void parseICMP(const u_char* data, uint32_t len);
    static void parseDNS(const u_char* data, uint32_t len);
    static void parseHTTP(const u_char* data, uint32_t len);

    // 工具函数：将大端16位/32位转为主机字节序（手动实现，无需依赖系统）
    static inline uint16_t ntoh16(uint16_t val) {
        return (val << 8) | (val >> 8);
    }
    static inline uint32_t ntoh32(uint32_t val) {
        return ((val & 0xFF000000) >> 24) |
               ((val & 0x00FF0000) >> 8)  |
               ((val & 0x0000FF00) << 8)  |
               ((val & 0x000000FF) << 24);
    }

    // 辅助：将IP地址转为字符串（用于日志和统计）
    static std::string ipToString(uint32_t ip);
    static std::string ipv6ToString(const uint8_t* ip);

    // 辅助：打印MAC地址
    static void printMac(const uint8_t* mac);
};

#endif // PROTOCOL_PARSER_H