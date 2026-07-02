#ifndef PROTOCOL_PARSER_H
#define PROTOCOL_PARSER_H

#include <pcap.h>
#include <cstdint>
#include <string>

/**
 * @brief 协议解析器（静态工具类）
 * 
 * 逐层解析网络数据包：以太网 → IPv4/IPv6 → TCP/UDP/ICMP → DNS/HTTP。
 * 所有结构体使用 #pragma pack(1) 确保内存布局与网络报文完全一致。
 */
class ProtocolParser {
public:
    /**
     * @brief 统一解析入口（供抓包回调函数调用）
     * @param header  pcap 包头（包含时间戳、长度等信息）
     * @param pkt_data 原始报文数据（从以太网头开始）
     */
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

    // 大端序 ↔ 主机字节序转换（手动位运算，不依赖系统函数）
    static inline uint16_t ntoh16(uint16_t val) {
        return (val << 8) | (val >> 8);
    }
    static inline uint32_t ntoh32(uint32_t val) {
        return ((val & 0xFF000000) >> 24) |
               ((val & 0x00FF0000) >> 8)  |
               ((val & 0x0000FF00) << 8)  |
               ((val & 0x000000FF) << 24);
    }

    // IP地址格式化辅助函数
    static std::string ipToString(uint32_t ip);
    static std::string ipv6ToString(const uint8_t* ip);
    static void printMac(const uint8_t* mac);
};

// ------------------------------------------------------------
// 协议头部结构体（强制1字节对齐）
// ------------------------------------------------------------
#pragma pack(push, 1)

/**
 * @brief 以太网帧头（14字节）
 */
struct EthernetHeader {
    uint8_t  dest_mac[6];   ///< 目的MAC地址
    uint8_t  src_mac[6];    ///< 源MAC地址
    uint16_t type;          ///< 上层协议类型（网络字节序，如0x0800=IPv4）
};

/**
 * @brief IPv4头（最小20字节，不含选项）
 */
struct IPv4Header {
    uint8_t  ver_ihl;       ///< 高4位：版本（=4），低4位：首部长度（单位4字节）
    uint8_t  tos;           ///< 服务类型（区分服务）
    uint16_t total_len;     ///< 总长度（含IP头+数据，网络字节序）
    uint16_t id;            ///< 标识符（分片用）
    uint16_t flags_frag;    ///< 高3位标志 + 13位片偏移
    uint8_t  ttl;           ///< 生存时间（跳数）
    uint8_t  protocol;      ///< 上层协议号（6=TCP,17=UDP,1=ICMP）
    uint16_t checksum;      ///< 头部校验和
    uint32_t src_ip;        ///< 源IP地址（网络字节序）
    uint32_t dest_ip;       ///< 目的IP地址（网络字节序）
    // 选项部分（需根据首部长度计算偏移）
};

/**
 * @brief IPv6头（40字节）
 */
struct IPv6Header {
    uint32_t version_tc_flow; ///< 版本(4bit)+流量类别(8bit)+流标签(20bit)
    uint16_t payload_len;     ///< 载荷长度（不含IPv6头）
    uint8_t  next_header;     ///< 下一个头部类型（同IPv4的protocol）
    uint8_t  hop_limit;       ///< 跳数限制
    uint8_t  src_ip[16];      ///< 源IPv6地址
    uint8_t  dest_ip[16];     ///< 目的IPv6地址
};

/**
 * @brief TCP头（20字节，不含选项）
 */
struct TCPHeader {
    uint16_t src_port;        ///< 源端口（网络字节序）
    uint16_t dest_port;       ///< 目的端口（网络字节序）
    uint32_t seq_num;         ///< 序列号（网络字节序）
    uint32_t ack_num;         ///< 确认号（网络字节序）
    uint8_t  offset_res;      ///< 高4位：数据偏移（单位4字节），低4位保留
    uint8_t  flags;           ///< 控制标志位（CWR/ECE/URG/ACK/PSH/RST/SYN/FIN）
    uint16_t window;          ///< 窗口大小（网络字节序）
    uint16_t checksum;        ///< 校验和
    uint16_t urgent_ptr;      ///< 紧急指针
};

/**
 * @brief UDP头（8字节）
 */
struct UDPHeader {
    uint16_t src_port;        ///< 源端口（网络字节序）
    uint16_t dest_port;       ///< 目的端口（网络字节序）
    uint16_t length;          ///< UDP数据报长度（含头+数据，网络字节序）
    uint16_t checksum;        ///< 校验和
};

/**
 * @brief ICMP头（4字节，类型/代码/校验和）
 */
struct ICMPHeader {
    uint8_t  type;            ///< 类型（如0=Echo Reply, 8=Echo Request）
    uint8_t  code;            ///< 代码（进一步细分类型）
    uint16_t checksum;        ///< 校验和（网络字节序）
    // 后续字段（标识、序号等）因类型而异，不在此定义
};

/**
 * @brief DNS头（12字节）
 */
struct DNSHeader {
    uint16_t id;              ///< 事务ID（网络字节序）
    uint16_t flags;           ///< 标志字段（QR/Opcode/AA/TC/RD/RA等）
    uint16_t qdcount;         ///< 问题数
    uint16_t ancount;         ///< 回答资源记录数
    uint16_t nscount;         ///< 权威名称服务器记录数
    uint16_t arcount;         ///< 附加资源记录数
};

#pragma pack(pop)

#endif // PROTOCOL_PARSER_H