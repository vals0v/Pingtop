#include "net_discovery.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <bit>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <ifaddrs.h>
#include <mutex>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sstream>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>

namespace pingtop {

namespace {

[[nodiscard]] constexpr std::uint16_t host_to_net16(std::uint16_t val) noexcept {
    if constexpr (std::endian::native == std::endian::little) {
        return static_cast<std::uint16_t>((val >> 8U) | (val << 8U));
    } else {
        return val;
    }
}

[[nodiscard]] constexpr std::uint32_t net_to_host32(std::uint32_t val) noexcept {
    if constexpr (std::endian::native == std::endian::little) {
        return ((val & 0x000000FFU) << 24U) |
               ((val & 0x0000FF00U) << 8U)  |
               ((val & 0x00FF0000U) >> 8U)  |
               ((val & 0xFF000000U) >> 24U);
    } else {
        return val;
    }
}

[[nodiscard]] std::string trim_copy(std::string_view sv) {
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front())) != 0) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back())) != 0) {
        sv.remove_suffix(1);
    }
    return std::string(sv);
}

// Fast non-blocking hostname lookup from /etc/hosts & Tailscale status (never blocks on DNS timeout)
[[nodiscard]] std::unordered_map<std::string, std::string> build_fast_host_map() {
    std::unordered_map<std::string, std::string> hosts_map;

    std::ifstream hosts_file("/etc/hosts");
    if (hosts_file.is_open()) {
        std::string line;
        while (std::getline(hosts_file, line)) {
            const auto hash = line.find('#');
            if (hash != std::string::npos) {
                line.erase(hash);
            }
            std::istringstream iss(line);
            std::string ip, name;
            if (iss >> ip >> name) {
                if (!ip.starts_with("127.") && !ip.starts_with("::") && name != "localhost") {
                    const auto dot = name.find('.');
                    hosts_map[ip] = (dot != std::string::npos && dot > 0) ? name.substr(0, dot) : name;
                }
            }
        }
    }
    return hosts_map;
}

[[nodiscard]] std::size_t skip_dns_name(const std::uint8_t* pkt, std::size_t len, std::size_t pos) noexcept {
    while (pos < len) {
        const std::uint8_t b = pkt[pos];
        if (b == 0) {
            return pos + 1;
        }
        if ((b & 0xC0U) == 0xC0U) {
            return (pos + 2 <= len) ? (pos + 2) : len;
        }
        pos += static_cast<std::size_t>(b) + 1;
    }
    return len;
}

[[nodiscard]] std::string query_dns_txt_record(const std::string& qname) {
    int sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        return {};
    }
    const int flags = ::fcntl(sock, F_GETFL, 0);
    if (flags >= 0) {
        (void)::fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }

    std::vector<std::uint8_t> req;
    req.reserve(64);
    const std::uint16_t tx_id = 0x5054U;
    req.push_back(static_cast<std::uint8_t>(tx_id >> 8U));
    req.push_back(static_cast<std::uint8_t>(tx_id & 0xFFU));
    req.push_back(0x01);
    req.push_back(0x00);
    req.push_back(0x00); req.push_back(0x01);
    req.push_back(0x00); req.push_back(0x00);
    req.push_back(0x00); req.push_back(0x00);
    req.push_back(0x00); req.push_back(0x00);

    std::size_t start = 0;
    while (start < qname.size()) {
        const auto dot = qname.find('.', start);
        const std::size_t end = (dot == std::string::npos) ? qname.size() : dot;
        const std::size_t label_len = end - start;
        if (label_len == 0 || label_len > 63) {
            ::close(sock);
            return {};
        }
        req.push_back(static_cast<std::uint8_t>(label_len));
        for (std::size_t i = start; i < end; ++i) {
            req.push_back(static_cast<std::uint8_t>(qname[i]));
        }
        start = end + 1;
    }
    req.push_back(0x00);
    req.push_back(0x00); req.push_back(0x10); // QTYPE = TXT
    req.push_back(0x00); req.push_back(0x01); // QCLASS = IN

    sockaddr_in dns_addr{};
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = host_to_net16(53);
    (void)::inet_pton(AF_INET, "1.1.1.1", &dns_addr.sin_addr);

    (void)::sendto(
        sock,
        req.data(),
        req.size(),
        0,
        reinterpret_cast<const sockaddr*>(&dns_addr),
        sizeof(dns_addr)
    );

    pollfd pfd{sock, POLLIN, 0};
    std::string txt_result;
    if (::poll(&pfd, 1, 120) > 0) {
        std::uint8_t resp[512]{};
        const ssize_t n = ::recvfrom(sock, resp, sizeof(resp), 0, nullptr, nullptr);
        if (n > 12) {
            const auto len = static_cast<std::size_t>(n);
            const std::uint16_t ancount = static_cast<std::uint16_t>((resp[6] << 8U) | resp[7]);
            std::size_t pos = skip_dns_name(resp, len, 12);
            pos += 4;

            for (std::uint16_t a = 0; a < ancount && pos + 10 <= len; ++a) {
                pos = skip_dns_name(resp, len, pos);
                if (pos + 10 > len) {
                    break;
                }
                const std::uint16_t rtype = static_cast<std::uint16_t>((resp[pos] << 8U) | resp[pos + 1]);
                const std::uint16_t rdlen = static_cast<std::uint16_t>((resp[pos + 8] << 8U) | resp[pos + 9]);
                pos += 10;
                if (rtype == 16 && rdlen >= 1 && pos + rdlen <= len) {
                    const std::size_t tlen = std::min<std::size_t>(resp[pos], static_cast<std::size_t>(rdlen - 1));
                    txt_result.assign(reinterpret_cast<const char*>(resp + pos + 1), tlen);
                    break;
                }
                pos += rdlen;
            }
        }
    }

    ::close(sock);
    return txt_result;
}

} // namespace

bool NetDiscovery::is_tailscale_ip(std::string_view ip) noexcept {
    in_addr addr{};
    std::string s(ip);
    if (::inet_pton(AF_INET, s.c_str(), &addr) != 1) {
        return false;
    }
    const std::uint32_t h = net_to_host32(addr.s_addr);
    return (h & 0xFFC00000U) == 0x64400000U;
}

HostCategory NetDiscovery::classify_ip_category(std::string_view ip, HostCategory fallback) noexcept {
    in_addr addr{};
    std::string ip_str(ip);
    if (::inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
        return fallback;
    }
    const std::uint32_t h = net_to_host32(addr.s_addr);
    if ((h & 0xFFC00000U) == 0x64400000U) {
        return HostCategory::Vpn;
    }
    if ((h & 0xFF000000U) == 0x0A000000U ||
        (h & 0xFFF00000U) == 0xAC100000U ||
        (h & 0xFFFF0000U) == 0xC0A80000U ||
        (h & 0xFFFF0000U) == 0xA9FE0000U) {
        return HostCategory::LocalLan;
    }
    return fallback;
}

std::string NetDiscovery::lookup_asn_and_geo(const std::string& ip) {
    if (ip.empty() || ip == "DNS Error" || ip.starts_with("*")) {
        return "---";
    }

    static std::mutex cache_mutex;
    static std::unordered_map<std::string, std::string> cache = {
        {"1.1.1.1", "US AS13335 Cloudflare"},
        {"1.0.0.1", "US AS13335 Cloudflare"},
        {"2606:4700:4700::1111", "US AS13335 Cloudflare"},
        {"2606:4700:4700::1001", "US AS13335 Cloudflare"},
        {"8.8.8.8", "US AS15169 Google"},
        {"8.8.4.4", "US AS15169 Google"},
        {"2001:4860:4860::8888", "US AS15169 Google"},
        {"2001:4860:4860::8844", "US AS15169 Google"},
        {"9.9.9.9", "CH AS19281 Quad9"},
        {"149.112.112.112", "CH AS19281 Quad9"},
        {"2620:fe::fe", "CH AS19281 Quad9"},
        {"208.67.222.222", "US AS36692 OpenDNS"},
        {"100.100.100.100", "VPN Tailscale MagicDNS"}
    };

    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        if (const auto it = cache.find(ip); it != cache.end()) {
            return it->second;
        }
    }

    auto store_and_return = [&](std::string val) {
        std::lock_guard<std::mutex> lock(cache_mutex);
        cache[ip] = val;
        return val;
    };

    if (is_tailscale_ip(ip)) {
        return store_and_return("VPN Tailscale CGNAT");
    }

    if (classify_ip_category(ip, HostCategory::Internet) == HostCategory::LocalLan) {
        return store_and_return("LAN Private Network");
    }

    if (ip.find(':') != std::string::npos) {
        if (ip.starts_with("fe80:") || ip.starts_with("fc") || ip.starts_with("fd")) {
            return store_and_return("LAN IPv6 Local");
        }
        return store_and_return("IPv6 Global Unicast");
    }

    unsigned int a = 0, b = 0, c = 0, d = 0;
    if (std::sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4 &&
        a <= 255 && b <= 255 && c <= 255 && d <= 255) {
        const std::string origin_q = std::to_string(d) + "." + std::to_string(c) + "." +
                                     std::to_string(b) + "." + std::to_string(a) +
                                     ".origin.asn.cymru.com";
        const std::string origin_txt = query_dns_txt_record(origin_q);
        if (!origin_txt.empty()) {
            std::vector<std::string> parts;
            std::size_t start = 0;
            while (start < origin_txt.size()) {
                const auto bar = origin_txt.find('|', start);
                const std::size_t end = (bar == std::string::npos) ? origin_txt.size() : bar;
                parts.push_back(trim_copy(std::string_view(origin_txt).substr(start, end - start)));
                if (bar == std::string::npos) {
                    break;
                }
                start = bar + 1;
            }

            if (parts.size() >= 3 && !parts[0].empty()) {
                std::string asn = parts[0];
                const auto space_pos = asn.find(' ');
                if (space_pos != std::string::npos) {
                    asn = asn.substr(0, space_pos);
                }
                const std::string country = parts[2].empty() ? "??" : parts[2];

                std::string org_short;
                const std::string asn_txt = query_dns_txt_record("AS" + asn + ".asn.cymru.com");
                if (!asn_txt.empty()) {
                    const auto last_bar = asn_txt.rfind('|');
                    if (last_bar != std::string::npos && last_bar + 1 < asn_txt.size()) {
                        org_short = trim_copy(std::string_view(asn_txt).substr(last_bar + 1));
                        const auto comma = org_short.find(',');
                        if (comma != std::string::npos) {
                            org_short = org_short.substr(0, comma);
                        }
                        const auto sp = org_short.find(' ');
                        if (sp != std::string::npos && sp > 3) {
                            org_short = org_short.substr(0, sp);
                        }
                    }
                }

                std::string result = country + " AS" + asn;
                if (!org_short.empty()) {
                    result += " " + org_short;
                }
                return store_and_return(std::move(result));
            }
        }
    }

    return store_and_return("WAN Public IP");
}

std::uint16_t NetDiscovery::detect_route_mtu(const std::string& ip, bool is_ipv6) noexcept {
    if (is_tailscale_ip(ip) || is_ipv6) {
        return 1280;
    }

    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    if (::inet_pton(AF_INET, ip.c_str(), &sin.sin_addr) == 1) {
        int sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        if (sock < 0) {
            sock = ::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        }
        if (sock >= 0) {
#if defined(__APPLE__)
            const int df = 1;
            (void)::setsockopt(sock, IPPROTO_IP, IP_DONTFRAG, &df, sizeof(df));
#elif defined(__linux__) && defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)
            const int pmtu = IP_PMTUDISC_DO;
            (void)::setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu));
#endif
            const int flags = ::fcntl(sock, F_GETFL, 0);
            if (flags >= 0) {
                (void)::fcntl(sock, F_SETFL, flags | O_NONBLOCK);
            }
            // Test Jumbo Frames (9000B SAN/Ceph, 4470B, 4096B, 2000B) down to standard 1500B & tunnels
            static constexpr std::array<std::uint16_t, 9> kCandidates = {
                9000, 4470, 4096, 2000, 1500, 1492, 1420, 1380, 1280
            };
            std::vector<std::uint8_t> dummy(9000, 0);
            for (std::uint16_t cand : kCandidates) {
                const std::size_t payload_sz = static_cast<std::size_t>(cand - 20);
                const ssize_t rc = ::sendto(
                    sock,
                    dummy.data(),
                    payload_sz,
                    0,
                    reinterpret_cast<const sockaddr*>(&sin),
                    sizeof(sin)
                );
                if (rc >= 0 || errno != EMSGSIZE) {
                    ::close(sock);
                    return cand;
                }
            }
            ::close(sock);
        }
    }
    return 1500;
}

std::vector<std::string> NetDiscovery::get_local_ips() {
    std::vector<std::string> ips;
    ifaddrs* ifaddr = nullptr;
    if (::getifaddrs(&ifaddr) == 0 && ifaddr != nullptr) {
        for (const auto* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET) {
                continue;
            }
            char ip[INET_ADDRSTRLEN]{};
            const auto* sin = reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr);
            if (::inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip)) != nullptr) {
                ips.emplace_back(ip);
            }
        }
        ::freeifaddrs(ifaddr);
    }
    return ips;
}

std::optional<std::string> NetDiscovery::detect_default_gateway() {
#if defined(__linux__)
    std::ifstream route_file("/proc/net/route");
    if (route_file.is_open()) {
        std::string line;
        if (std::getline(route_file, line)) {
            while (std::getline(route_file, line)) {
                std::istringstream iss(line);
                std::string iface, dest_hex, gw_hex;
                if (iss >> iface >> dest_hex >> gw_hex) {
                    if (dest_hex == "00000000") {
                        const unsigned long gw_val = std::strtoul(gw_hex.c_str(), nullptr, 16);
                        in_addr addr{};
                        addr.s_addr = static_cast<in_addr_t>(gw_val);
                        char ip_buf[INET_ADDRSTRLEN]{};
                        if (::inet_ntop(AF_INET, &addr, ip_buf, sizeof(ip_buf)) != nullptr) {
                            return std::string(ip_buf);
                        }
                    }
                }
            }
        }
    }
#elif defined(__APPLE__)
    FILE* pipe = ::popen("/usr/sbin/netstat -rn -f inet 2>/dev/null", "r");
    if (pipe != nullptr) {
        char line[512]{};
        while (std::fgets(line, sizeof(line), pipe) != nullptr) {
            std::istringstream iss(line);
            std::string dest, gw;
            if (iss >> dest >> gw) {
                if (dest == "default") {
                    in_addr test_addr{};
                    if (::inet_pton(AF_INET, gw.c_str(), &test_addr) == 1) {
                        ::pclose(pipe);
                        return gw;
                    }
                }
            }
        }
        ::pclose(pipe);
    }
#endif
    return std::nullopt;
}

std::vector<DiscoveredTarget> NetDiscovery::discover_lan_devices() {
    std::vector<DiscoveredTarget> targets;
    const auto local_ips = get_local_ips();
    const auto gw = detect_default_gateway();
    const auto host_map = build_fast_host_map();

#if defined(__APPLE__)
    FILE* pipe = ::popen("/usr/sbin/arp -an 2>/dev/null", "r");
    if (pipe != nullptr) {
        char line[512]{};
        while (std::fgets(line, sizeof(line), pipe) != nullptr) {
            const char* open_paren = std::strchr(line, '(');
            const char* close_paren = std::strchr(line, ')');
            if (open_paren != nullptr && close_paren != nullptr && close_paren > open_paren + 1) {
                std::string ip(open_paren + 1, static_cast<std::size_t>(close_paren - open_paren - 1));
                if (std::strstr(line, "ff:ff:ff:ff:ff:ff") != nullptr ||
                    std::strstr(line, "(incomplete)") != nullptr ||
                    ip.starts_with("224.") || ip.starts_with("239.") || ip.ends_with(".255")) {
                    continue;
                }
                if (std::find(local_ips.begin(), local_ips.end(), ip) != local_ips.end()) {
                    continue;
                }
                if (gw.has_value() && *gw == ip) {
                    continue;
                }
                const auto it = host_map.find(ip);
                const std::string label = (it != host_map.end())
                    ? ("LAN: " + it->second)
                    : ("LAN Device (" + ip + ")");
                targets.push_back({ip, label, HostCategory::LocalLan});
            }
        }
        ::pclose(pipe);
    }
#elif defined(__linux__)
    std::ifstream arp_file("/proc/net/arp");
    if (arp_file.is_open()) {
        std::string line;
        if (std::getline(arp_file, line)) {
            while (std::getline(arp_file, line)) {
                std::istringstream iss(line);
                std::string ip, hw_type, flags, mac, mask, dev;
                if (iss >> ip >> hw_type >> flags >> mac >> mask >> dev) {
                    if (flags == "0x0" || mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff") {
                        continue;
                    }
                    if (std::find(local_ips.begin(), local_ips.end(), ip) != local_ips.end()) {
                        continue;
                    }
                    if (gw.has_value() && *gw == ip) {
                        continue;
                    }
                    const auto it = host_map.find(ip);
                    const std::string label = (it != host_map.end())
                        ? ("LAN: " + it->second)
                        : ("LAN Device (" + ip + ")");
                    targets.push_back({ip, label, HostCategory::LocalLan});
                }
            }
        }
    }
#endif
    return targets;
}

[[nodiscard]] static bool is_vpn_iface(std::string_view name) noexcept {
    return name.starts_with("utun") ||
           name.starts_with("tun")  ||
           name.starts_with("tap")  ||
           name.starts_with("wg")   ||
           name.starts_with("tailscale") ||
           name.starts_with("zt")   ||
           name.starts_with("ppp")  ||
           name.starts_with("nebula") ||
           name.starts_with("wireguard");
}

std::vector<DiscoveredTarget> NetDiscovery::discover_vpn_and_tailscale() {
    std::vector<DiscoveredTarget> targets;
    const auto local_ips = get_local_ips();
    auto host_map = build_fast_host_map();
    bool tailscale_detected = false;

    // 1. Check interfaces for Tailscale CGNAT (100.64.0.0/10), point-to-point VPNs, and VPN tun/tap IPs
    ifaddrs* ifaddr = nullptr;
    if (::getifaddrs(&ifaddr) == 0 && ifaddr != nullptr) {
        for (const auto* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET || ifa->ifa_name == nullptr) {
                continue;
            }
            char local_buf[INET_ADDRSTRLEN]{};
            const auto* sin = reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr);
            if (::inet_ntop(AF_INET, &sin->sin_addr, local_buf, sizeof(local_buf)) != nullptr) {
                if (is_tailscale_ip(local_buf)) {
                    tailscale_detected = true;
                }
            }
            if ((ifa->ifa_flags & IFF_POINTOPOINT) != 0 && ifa->ifa_dstaddr != nullptr) {
                const auto* dst_sin = reinterpret_cast<const sockaddr_in*>(ifa->ifa_dstaddr);
                char dst_ip[INET_ADDRSTRLEN]{};
                if (::inet_ntop(AF_INET, &dst_sin->sin_addr, dst_ip, sizeof(dst_ip)) != nullptr) {
                    const std::string dst_str(dst_ip);
                    if (!dst_str.starts_with("127.")) {
                        const std::string label = is_tailscale_ip(dst_str)
                            ? ("Tailscale (" + std::string(ifa->ifa_name) + ")")
                            : ("VPN (" + std::string(ifa->ifa_name) + ")");
                        targets.push_back({dst_str, label, HostCategory::Vpn});
                    }
                }
            }
        }
        ::freeifaddrs(ifaddr);
    }

    // 2. Universal Kernel Routing Table Discovery for ANY VPN (WireGuard, OpenVPN, custom tun/tap, Nebula, ZeroTier)
#if defined(__APPLE__)
    {
        FILE* rpipe = ::popen("/usr/sbin/netstat -rn -f inet 2>/dev/null", "r");
        if (rpipe != nullptr) {
            char rline[512]{};
            while (std::fgets(rline, sizeof(rline), rpipe) != nullptr) {
                std::istringstream iss(rline);
                std::string dest, gw, flags, netif;
                if (iss >> dest >> gw >> flags >> netif) {
                    if (is_vpn_iface(netif) && dest != "default") {
                        const auto slash = dest.find('/');
                        const std::string ip = (slash != std::string::npos) ? dest.substr(0, slash) : dest;
                        in_addr test_addr{};
                        if (::inet_pton(AF_INET, ip.c_str(), &test_addr) == 1) {
                            if (!ip.starts_with("127.") && !ip.starts_with("224.") &&
                                !ip.starts_with("239.") && !ip.starts_with("255.") &&
                                !ip.ends_with(".255") &&
                                std::find(local_ips.begin(), local_ips.end(), ip) == local_ips.end()) {
                                const auto it = host_map.find(ip);
                                std::string label = (it != host_map.end())
                                    ? ("VPN (" + netif + "): " + it->second)
                                    : (is_tailscale_ip(ip) ? ("Tailscale: " + ip) : ("VPN (" + netif + "): " + ip));
                                targets.push_back({ip, std::move(label), HostCategory::Vpn});
                            }
                        }
                    }
                }
            }
            ::pclose(rpipe);
        }
    }
#elif defined(__linux__)
    {
        std::ifstream route_file("/proc/net/route");
        if (route_file.is_open()) {
            std::string rline;
            if (std::getline(route_file, rline)) {
                while (std::getline(route_file, rline)) {
                    std::istringstream iss(rline);
                    std::string iface, dest_hex, gw_hex, flags_hex;
                    if (iss >> iface >> dest_hex >> gw_hex >> flags_hex) {
                        if (is_vpn_iface(iface)) {
                            const unsigned long dest_val = std::strtoul(dest_hex.c_str(), nullptr, 16);
                            const unsigned long gw_val = std::strtoul(gw_hex.c_str(), nullptr, 16);
                            for (unsigned long val : {dest_val, gw_val}) {
                                if (val != 0) {
                                    in_addr addr{};
                                    addr.s_addr = static_cast<in_addr_t>(val);
                                    char ip_buf[INET_ADDRSTRLEN]{};
                                    if (::inet_ntop(AF_INET, &addr, ip_buf, sizeof(ip_buf)) != nullptr) {
                                        const std::string ip(ip_buf);
                                        if (!ip.starts_with("127.") && !ip.starts_with("224.") &&
                                            !ip.starts_with("239.") && !ip.ends_with(".255") &&
                                            std::find(local_ips.begin(), local_ips.end(), ip) == local_ips.end()) {
                                            const auto it = host_map.find(ip);
                                            std::string label = (it != host_map.end())
                                                ? ("VPN (" + iface + "): " + it->second)
                                                : (is_tailscale_ip(ip) ? ("Tailscale: " + ip) : ("VPN (" + iface + "): " + ip));
                                            targets.push_back({ip, std::move(label), HostCategory::Vpn});
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
#endif

    // 3. WireGuard CLI discovery (wg show all dump)
    {
        const std::array<const char*, 3> wg_bins = {
            "/usr/bin/wg",
            "/usr/local/bin/wg",
            "/opt/homebrew/bin/wg"
        };
        for (const auto* bin : wg_bins) {
            if (::access(bin, X_OK) != 0) {
                continue;
            }
            std::string cmd = std::string(bin) + " show all dump 2>/dev/null";
            FILE* pipe = ::popen(cmd.c_str(), "r");
            if (pipe != nullptr) {
                char line[1024]{};
                while (std::fgets(line, sizeof(line), pipe) != nullptr) {
                    std::istringstream iss(line);
                    std::string iface, pubkey, psk, endpoint, allowed_ips;
                    if (iss >> iface >> pubkey >> psk >> endpoint >> allowed_ips) {
                        std::istringstream aiss(allowed_ips);
                        std::string item;
                        while (std::getline(aiss, item, ',')) {
                            const auto slash = item.find('/');
                            const std::string ip = (slash != std::string::npos) ? item.substr(0, slash) : item;
                            in_addr test_addr{};
                            if (::inet_pton(AF_INET, ip.c_str(), &test_addr) == 1) {
                                if (!ip.starts_with("127.") && !ip.starts_with("0.") &&
                                    std::find(local_ips.begin(), local_ips.end(), ip) == local_ips.end()) {
                                    const auto it = host_map.find(ip);
                                    const std::string label = (it != host_map.end())
                                        ? ("WG: " + it->second)
                                        : ("WG (" + iface + "): " + ip);
                                    targets.push_back({ip, label, HostCategory::Vpn});
                                }
                            }
                        }
                    }
                }
                ::pclose(pipe);
                break;
            }
        }
    }

    // 4. Query Tailscale / Headscale CLI if Tailscale is detected or present
    {
        const std::array<const char*, 5> tailscale_bins = {
            "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
            "/Applications/Tailscale.app/Contents/Resources/tailscale",
            "/opt/homebrew/bin/tailscale",
            "/usr/local/bin/tailscale",
            "/usr/bin/tailscale"
        };
        for (const auto* bin : tailscale_bins) {
            if (::access(bin, X_OK) != 0) {
                continue;
            }
            std::string cmd = "\"" + std::string(bin) + "\" status 2>/dev/null";
            FILE* pipe = ::popen(cmd.c_str(), "r");
            if (pipe != nullptr) {
                char line[512]{};
                while (std::fgets(line, sizeof(line), pipe) != nullptr) {
                    std::istringstream iss(line);
                    std::string ip, name;
                    if (iss >> ip >> name) {
                        if (is_tailscale_ip(ip) &&
                            std::find(local_ips.begin(), local_ips.end(), ip) == local_ips.end()) {
                            tailscale_detected = true;
                            host_map[ip] = name;
                            targets.push_back({ip, "TS: " + name, HostCategory::Vpn});
                        }
                    }
                }
                ::pclose(pipe);
                break;
            }
        }
    }

    // 5. ZeroTier CLI discovery (zerotier-cli listpeers)
    {
        const std::array<const char*, 4> zt_bins = {
            "/usr/sbin/zerotier-cli",
            "/usr/bin/zerotier-cli",
            "/usr/local/bin/zerotier-cli",
            "/opt/homebrew/bin/zerotier-cli"
        };
        for (const auto* bin : zt_bins) {
            if (::access(bin, X_OK) != 0) {
                continue;
            }
            std::string cmd = std::string(bin) + " listpeers 2>/dev/null";
            FILE* pipe = ::popen(cmd.c_str(), "r");
            if (pipe != nullptr) {
                char line[512]{};
                while (std::fgets(line, sizeof(line), pipe) != nullptr) {
                    std::istringstream iss(line);
                    std::string ztaddr, ver, role, lat, link, tx, rx, path;
                    if (iss >> ztaddr >> ver >> role >> lat >> link >> tx >> rx >> path) {
                        const auto slash = path.find('/');
                        const std::string ip = (slash != std::string::npos) ? path.substr(0, slash) : path;
                        in_addr test_addr{};
                        if (::inet_pton(AF_INET, ip.c_str(), &test_addr) == 1 && !ip.starts_with("127.")) {
                            targets.push_back({ip, "ZeroTier: " + ztaddr, HostCategory::Vpn});
                        }
                    }
                }
                ::pclose(pipe);
                break;
            }
        }
    }

    // 6. Discover active SSH sessions (port 22) and VPN peers via socket inspection
#if defined(__APPLE__)
    {
        FILE* pipe = ::popen("/usr/sbin/lsof -iTCP -sTCP:ESTABLISHED -n -P 2>/dev/null", "r");
        if (pipe != nullptr) {
            char line[512]{};
            while (std::fgets(line, sizeof(line), pipe) != nullptr) {
                std::string_view sv(line);
                const auto arrow_pos = sv.find("->");
                if (arrow_pos == std::string_view::npos) {
                    continue;
                }
                std::istringstream iss{std::string(sv.substr(0, arrow_pos))};
                std::string app_name;
                iss >> app_name;

                std::string_view rem_part = sv.substr(arrow_pos + 2);
                const auto space_pos = rem_part.find(' ');
                if (space_pos != std::string_view::npos) {
                    rem_part = rem_part.substr(0, space_pos);
                }
                const auto colon_pos = rem_part.rfind(':');
                if (colon_pos == std::string_view::npos || colon_pos == 0 || colon_pos + 1 >= rem_part.size()) {
                    continue;
                }

                const std::string rem_ip(rem_part.substr(0, colon_pos));
                const std::string rem_port_str(rem_part.substr(colon_pos + 1));

                in_addr test_addr{};
                if (::inet_pton(AF_INET, rem_ip.c_str(), &test_addr) != 1 || rem_ip.starts_with("127.")) {
                    continue;
                }

                const long rem_port = std::strtol(rem_port_str.c_str(), nullptr, 10);
                const bool is_ts = is_tailscale_ip(rem_ip);
                const auto name_it = host_map.find(rem_ip);
                const std::string peer_name = (name_it != host_map.end()) ? name_it->second : "";

                if (rem_port == 22 || (app_name == "ssh" && rem_port != 443)) {
                    const HostCategory cat = is_ts ? HostCategory::Vpn : classify_ip_category(rem_ip, HostCategory::Internet);
                    const std::string srv_label = is_ts
                        ? (!peer_name.empty() ? ("TS: " + peer_name) : "Tailscale Server")
                        : (!peer_name.empty() ? ("SSH: " + peer_name) : "SSH Server");
                    const std::string ssh_label = "SSH [" + app_name + "]";

                    targets.push_back({rem_ip, srv_label, cat});
                    if (rem_port > 0 && rem_port <= 65535) {
                        targets.push_back({rem_ip + ":" + std::to_string(rem_port), ssh_label, cat});
                    }
                    if (is_ts) {
                        tailscale_detected = true;
                    }
                } else if (is_ts) {
                    tailscale_detected = true;
                    const std::string peer_label = !peer_name.empty() ? ("TS: " + peer_name) : "Tailscale Peer";
                    targets.push_back({rem_ip, peer_label, HostCategory::Vpn});
                    if (rem_port > 0 && rem_port <= 65535) {
                        targets.push_back({
                            rem_ip + ":" + std::to_string(rem_port),
                            "TS [" + app_name + "]",
                            HostCategory::Vpn
                        });
                    }
                }
            }
            ::pclose(pipe);
        }
    }
#elif defined(__linux__)
    {
        std::ifstream tcp_file("/proc/net/tcp");
        if (tcp_file.is_open()) {
            std::string line;
            if (std::getline(tcp_file, line)) {
                while (std::getline(tcp_file, line)) {
                    std::istringstream iss(line);
                    std::string sl, local_hex, rem_hex, state_hex;
                    if (iss >> sl >> local_hex >> rem_hex >> state_hex) {
                        if (state_hex != "01") {
                            continue;
                        }
                        const auto colon = rem_hex.find(':');
                        if (colon == std::string::npos) {
                            continue;
                        }
                        const unsigned long ip_num = std::strtoul(rem_hex.substr(0, colon).c_str(), nullptr, 16);
                        const unsigned long port_num = std::strtoul(rem_hex.substr(colon + 1).c_str(), nullptr, 16);
                        in_addr addr{};
                        addr.s_addr = static_cast<in_addr_t>(ip_num);
                        char ip_buf[INET_ADDRSTRLEN]{};
                        if (::inet_ntop(AF_INET, &addr, ip_buf, sizeof(ip_buf)) == nullptr) {
                            continue;
                        }
                        const std::string rem_ip(ip_buf);
                        if (rem_ip.starts_with("127.")) {
                            continue;
                        }

                        const bool is_ts = is_tailscale_ip(rem_ip);
                        const auto name_it = host_map.find(rem_ip);
                        const std::string display_peer = (name_it != host_map.end()) ? name_it->second : rem_ip;

                        if (port_num == 22) {
                            const HostCategory cat = is_ts ? HostCategory::Vpn : classify_ip_category(rem_ip, HostCategory::Internet);
                            const std::string prefix = is_ts ? "Tailscale SSH: " : "SSH Server: ";
                            targets.push_back({rem_ip, (is_ts ? "Tailscale: " : "Server: ") + display_peer, cat});
                            targets.push_back({rem_ip + ":22", prefix + display_peer, cat});
                            if (is_ts) {
                                tailscale_detected = true;
                            }
                        } else if (is_ts) {
                            tailscale_detected = true;
                            targets.push_back({rem_ip, "Tailscale: " + display_peer, HostCategory::Vpn});
                        }
                    }
                }
            }
        }
    }
#endif

    if (tailscale_detected) {
        targets.push_back({"100.100.100.100", "Tailscale MagicDNS", HostCategory::Vpn});
    }

    // Deduplicate by target IP while preserving the most specific human-readable label
    std::vector<DiscoveredTarget> unique_targets;
    std::unordered_map<std::string, std::size_t> ip_to_idx;

    for (auto& t : targets) {
        if (const auto it = ip_to_idx.find(t.ip); it != ip_to_idx.end()) {
            auto& existing = unique_targets[it->second];
            if ((t.label.starts_with("TS: ") || t.label.starts_with("WG: ") ||
                 t.label.starts_with("SSH [") || t.label.starts_with("ZeroTier: ")) &&
                (existing.label.starts_with("VPN (") || existing.label.starts_with("Tailscale: "))) {
                existing.label = std::move(t.label);
            }
        } else {
            ip_to_idx[t.ip] = unique_targets.size();
            unique_targets.push_back(std::move(t));
        }
    }

    return unique_targets;
}

std::vector<DiscoveredTarget> NetDiscovery::discover_datacenter_infra() {
    std::vector<DiscoveredTarget> targets;
    const auto local_ips = get_local_ips();
    const auto gw = detect_default_gateway();
    const auto host_map = build_fast_host_map();

    auto is_local_or_gw = [&](const std::string& ip) {
        if (ip.starts_with("127.") || ip.starts_with("0.") || ip.starts_with("224.") ||
            ip.starts_with("239.") || ip.ends_with(".255")) {
            return true;
        }
        if (gw.has_value() && *gw == ip) {
            return true;
        }
        return std::find(local_ips.begin(), local_ips.end(), ip) != local_ips.end();
    };

    // 1. Linux Bridges, LACP Bonds, Proxmox/KVM vmbr, Docker & CNI Container Networks
    ifaddrs* ifaddr = nullptr;
    if (::getifaddrs(&ifaddr) == 0 && ifaddr != nullptr) {
        for (const auto* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET || ifa->ifa_name == nullptr) {
                continue;
            }
            if ((ifa->ifa_flags & IFF_UP) == 0 || (ifa->ifa_flags & IFF_LOOPBACK) != 0) {
                continue;
            }
            const std::string ifname(ifa->ifa_name);
            const bool is_dc_bridge =
                ifname.starts_with("bond") || ifname.starts_with("team") ||
                ifname.starts_with("br")   || ifname.starts_with("vmbr") ||
                ifname.starts_with("docker") || ifname.starts_with("cni") ||
                ifname.starts_with("flannel") || ifname.starts_with("calico") ||
                ifname.starts_with("vxlan") || ifname.starts_with("virbr") ||
                ifname.starts_with("ovs");

            if (is_dc_bridge) {
                char ip_buf[INET_ADDRSTRLEN]{};
                const auto* sin = reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr);
                if (::inet_ntop(AF_INET, &sin->sin_addr, ip_buf, sizeof(ip_buf)) != nullptr) {
                    const std::string ip_str(ip_buf);
                    std::string kind = "Bridge";
                    if (ifname.starts_with("bond") || ifname.starts_with("team")) {
                        kind = "LACP Bond";
                    } else if (ifname.starts_with("docker") || ifname.starts_with("cni") ||
                               ifname.starts_with("flannel") || ifname.starts_with("calico")) {
                        kind = "Container Net";
                    } else if (ifname.starts_with("vmbr") || ifname.starts_with("virbr")) {
                        kind = "Hypervisor Br";
                    } else if (ifname.starts_with("vxlan")) {
                        kind = "VXLAN Fabric";
                    }
                    targets.push_back({ip_str, kind + " (" + ifname + ")", HostCategory::LocalLan});
                }
            }
        }
        ::freeifaddrs(ifaddr);
    }

    // 2. Out-of-Band Management: IPMI / BMC / iDRAC / iLO discovery via ipmitool & hostname heuristics
    {
        for (const auto& [ip, name] : host_map) {
            std::string lower_name = name;
            std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            if (lower_name.find("ipmi") != std::string::npos ||
                lower_name.find("idrac") != std::string::npos ||
                lower_name.find("ilo") != std::string::npos ||
                lower_name.find("bmc") != std::string::npos) {
                targets.push_back({ip, "BMC/IPMI: " + name, HostCategory::LocalLan});
                targets.push_back({ip + ":443", "BMC HTTPS: " + name, HostCategory::LocalLan});
            }
        }

        const std::array<const char*, 3> ipmi_bins = {
            "/usr/bin/ipmitool",
            "/usr/sbin/ipmitool",
            "/usr/local/bin/ipmitool"
        };
        for (const auto* bin : ipmi_bins) {
            if (::access(bin, X_OK) != 0) {
                continue;
            }
            std::string cmd = std::string(bin) + " lan print 2>/dev/null";
            FILE* pipe = ::popen(cmd.c_str(), "r");
            if (pipe != nullptr) {
                char line[512]{};
                std::string bmc_ip;
                std::string bmc_gw;
                while (std::fgets(line, sizeof(line), pipe) != nullptr) {
                    const std::string_view sv(line);
                    const auto colon = sv.find(':');
                    if (colon == std::string_view::npos) {
                        continue;
                    }
                    const std::string key = trim_copy(sv.substr(0, colon));
                    const std::string val = trim_copy(sv.substr(colon + 1));
                    in_addr test_addr{};
                    if (key == "IP Address" && ::inet_pton(AF_INET, val.c_str(), &test_addr) == 1 && val != "0.0.0.0") {
                        bmc_ip = val;
                    } else if (key == "Default Gateway IP" && ::inet_pton(AF_INET, val.c_str(), &test_addr) == 1 && val != "0.0.0.0") {
                        bmc_gw = val;
                    }
                }
                ::pclose(pipe);
                if (!bmc_ip.empty()) {
                    targets.push_back({bmc_ip, "Local BMC / IPMI", HostCategory::LocalLan});
                    targets.push_back({bmc_ip + ":443", "Local BMC WebUI", HostCategory::LocalLan});
                }
                if (!bmc_gw.empty() && !is_local_or_gw(bmc_gw)) {
                    targets.push_back({bmc_gw, "OOB IPMI Gateway", HostCategory::LocalLan});
                }
                break;
            }
        }
    }

    // 3. LLDP Top-of-Rack (ToR) Switch discovery via lldpctl
    {
        const std::array<const char*, 3> lldp_bins = {
            "/usr/sbin/lldpctl",
            "/usr/bin/lldpctl",
            "/usr/local/sbin/lldpctl"
        };
        for (const auto* bin : lldp_bins) {
            if (::access(bin, X_OK) != 0) {
                continue;
            }
            std::string cmd = std::string(bin) + " -f keyvalue 2>/dev/null";
            FILE* pipe = ::popen(cmd.c_str(), "r");
            if (pipe != nullptr) {
                char line[512]{};
                std::string last_sysname;
                while (std::fgets(line, sizeof(line), pipe) != nullptr) {
                    const std::string_view sv(line);
                    const auto eq = sv.find('=');
                    if (eq == std::string_view::npos) {
                        continue;
                    }
                    const std::string_view key = sv.substr(0, eq);
                    const std::string val = trim_copy(sv.substr(eq + 1));
                    if (key.ends_with(".chassis.name")) {
                        last_sysname = val;
                    } else if (key.ends_with(".chassis.mgmt-ip")) {
                        in_addr test_addr{};
                        if (::inet_pton(AF_INET, val.c_str(), &test_addr) == 1 && !is_local_or_gw(val)) {
                            const std::string label = last_sysname.empty()
                                ? ("ToR Switch (" + val + ")")
                                : ("ToR Switch: " + last_sysname);
                            targets.push_back({val, label, HostCategory::LocalLan});
                        }
                    }
                }
                ::pclose(pipe);
                break;
            }
        }
    }

    // 4. Local / Cluster DNS Resolvers (/etc/resolv.conf) & NTP Servers (/etc/chrony*, /etc/ntp.conf)
    {
        std::ifstream resolv("/etc/resolv.conf");
        if (resolv.is_open()) {
            std::string line;
            while (std::getline(resolv, line)) {
                const auto hash = line.find('#');
                if (hash != std::string::npos) {
                    line.erase(hash);
                }
                std::istringstream iss(line);
                std::string kw, ip;
                if ((iss >> kw >> ip) && kw == "nameserver") {
                    in_addr test_addr{};
                    if (::inet_pton(AF_INET, ip.c_str(), &test_addr) == 1 &&
                        !ip.starts_with("127.") && ip != "1.1.1.1" && ip != "8.8.8.8" && ip != "9.9.9.9" &&
                        (!gw.has_value() || *gw != ip) && !is_tailscale_ip(ip)) {
                        const HostCategory cat = classify_ip_category(ip, HostCategory::LocalLan);
                        targets.push_back({"dns://" + ip, "System DNS (" + ip + ")", cat});
                    }
                }
            }
        }

        const std::array<const char*, 3> ntp_confs = {
            "/etc/chrony/chrony.conf",
            "/etc/chrony.conf",
            "/etc/ntp.conf"
        };
        for (const auto* conf_path : ntp_confs) {
            std::ifstream ntp_in(conf_path);
            if (!ntp_in.is_open()) {
                continue;
            }
            std::string line;
            while (std::getline(ntp_in, line)) {
                const auto hash = line.find('#');
                if (hash != std::string::npos) {
                    line.erase(hash);
                }
                std::istringstream iss(line);
                std::string kw, target;
                if ((iss >> kw >> target) && (kw == "server" || kw == "peer")) {
                    in_addr test_addr{};
                    if (::inet_pton(AF_INET, target.c_str(), &test_addr) == 1 && !target.starts_with("127.")) {
                        const HostCategory cat = classify_ip_category(target, HostCategory::LocalLan);
                        targets.push_back({target, "NTP Clock (" + target + ")", cat});
                    }
                }
            }
            break;
        }
    }

    // 5. Active Datacenter Infrastructure Sessions: BGP (:179), Ceph (:6789/:3300), K8s (:6443), etcd (:2379), iSCSI (:3260)
#if defined(__linux__)
    {
        std::ifstream tcp_file("/proc/net/tcp");
        if (tcp_file.is_open()) {
            std::string line;
            if (std::getline(tcp_file, line)) {
                while (std::getline(tcp_file, line)) {
                    std::istringstream iss(line);
                    std::string sl, local_hex, rem_hex, state_hex;
                    if (iss >> sl >> local_hex >> rem_hex >> state_hex) {
                        if (state_hex != "01") {
                            continue;
                        }
                        const auto lcolon = local_hex.find(':');
                        const auto rcolon = rem_hex.find(':');
                        if (lcolon == std::string::npos || rcolon == std::string::npos) {
                            continue;
                        }
                        const unsigned long lport = std::strtoul(local_hex.substr(lcolon + 1).c_str(), nullptr, 16);
                        const unsigned long ip_num = std::strtoul(rem_hex.substr(0, rcolon).c_str(), nullptr, 16);
                        const unsigned long rport = std::strtoul(rem_hex.substr(rcolon + 1).c_str(), nullptr, 16);

                        in_addr addr{};
                        addr.s_addr = static_cast<in_addr_t>(ip_num);
                        char ip_buf[INET_ADDRSTRLEN]{};
                        if (::inet_ntop(AF_INET, &addr, ip_buf, sizeof(ip_buf)) == nullptr) {
                            continue;
                        }
                        const std::string rem_ip(ip_buf);
                        if (rem_ip.starts_with("127.")) {
                            continue;
                        }
                        const HostCategory cat = classify_ip_category(rem_ip, HostCategory::LocalLan);
                        if (rport == 179 || lport == 179) {
                            targets.push_back({rem_ip + ":179", "BGP Peer (" + rem_ip + ")", cat});
                        } else if (rport == 6789 || rport == 3300) {
                            targets.push_back({rem_ip + ":" + std::to_string(rport), "Ceph MON (" + rem_ip + ")", cat});
                        } else if (rport == 6443) {
                            targets.push_back({rem_ip + ":6443", "K8s API (" + rem_ip + ")", cat});
                        } else if (rport == 2379) {
                            targets.push_back({rem_ip + ":2379", "etcd Peer (" + rem_ip + ")", cat});
                        } else if (rport == 3260) {
                            targets.push_back({rem_ip + ":3260", "iSCSI SAN (" + rem_ip + ")", cat});
                        }
                    }
                }
            }
        }
    }
#endif

    return targets;
}

std::vector<DiscoveredTarget> NetDiscovery::discover_all() {
    std::vector<DiscoveredTarget> all;
    if (const auto gw = detect_default_gateway(); gw.has_value()) {
        all.push_back({*gw, "Router / Gateway", HostCategory::LocalLan});
        all.push_back({"dns://" + *gw, "Router DNS", HostCategory::LocalLan});
    }
    for (auto& dc : discover_datacenter_infra()) {
        all.push_back(std::move(dc));
    }
    for (auto& dev : discover_lan_devices()) {
        all.push_back(std::move(dev));
    }
    for (auto& vpn : discover_vpn_and_tailscale()) {
        all.push_back(std::move(vpn));
    }
    return all;
}

void NetDiscovery::sample_net_interfaces(
    std::vector<NetInterfaceStats>& net_interfaces,
    std::chrono::steady_clock::time_point& last_net_sample_time,
    std::chrono::steady_clock::time_point now
) {
    const bool first_sample = (last_net_sample_time.time_since_epoch().count() == 0);
    const double dt_sec = first_sample
        ? 0.0
        : std::chrono::duration<double>(now - last_net_sample_time).count();
    last_net_sample_time = now;

    struct RawCounter {
        std::string   ipv4;
        std::uint16_t mtu{1500};
        std::uint64_t rx{0};
        std::uint64_t tx{0};
        std::uint64_t rx_err{0};
        std::uint64_t tx_err{0};
        std::uint64_t rx_drop{0};
        std::uint64_t tx_drop{0};
        std::string   bond_info;
    };
    std::vector<std::pair<std::string, RawCounter>> counters;

    auto find_or_add = [&](const std::string& name) -> RawCounter& {
        for (auto& kv : counters) {
            if (kv.first == name) {
                return kv.second;
            }
        }
        counters.push_back({name, RawCounter{}});
        return counters.back().second;
    };

    ifaddrs* ifaddr = nullptr;
    if (::getifaddrs(&ifaddr) == 0 && ifaddr != nullptr) {
        for (const auto* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr || ifa->ifa_name == nullptr) {
                continue;
            }
            if ((ifa->ifa_flags & IFF_UP) == 0 || (ifa->ifa_flags & IFF_LOOPBACK) != 0) {
                continue;
            }
            const std::string name(ifa->ifa_name);
            if (ifa->ifa_addr->sa_family == AF_INET) {
                char ip_buf[INET_ADDRSTRLEN]{};
                const auto* sin = reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr);
                if (::inet_ntop(AF_INET, &sin->sin_addr, ip_buf, sizeof(ip_buf)) != nullptr) {
                    find_or_add(name).ipv4 = ip_buf;
                }
            }
#if defined(__APPLE__)
            else if (ifa->ifa_addr->sa_family == AF_LINK && ifa->ifa_data != nullptr) {
                const auto* ifd = static_cast<const if_data*>(ifa->ifa_data);
                auto& c = find_or_add(name);
                c.rx = static_cast<std::uint64_t>(ifd->ifi_ibytes);
                c.tx = static_cast<std::uint64_t>(ifd->ifi_obytes);
                c.rx_err = static_cast<std::uint64_t>(ifd->ifi_ierrors);
                c.tx_err = static_cast<std::uint64_t>(ifd->ifi_oerrors);
                c.rx_drop = static_cast<std::uint64_t>(ifd->ifi_iqdrops);
                if (ifd->ifi_mtu > 0 && ifd->ifi_mtu <= 65535) {
                    c.mtu = static_cast<std::uint16_t>(ifd->ifi_mtu);
                }
            }
#endif
        }
        ::freeifaddrs(ifaddr);
    }

#if defined(__linux__)
    std::ifstream dev_file("/proc/net/dev");
    if (dev_file.is_open()) {
        std::string line;
        std::getline(dev_file, line);
        std::getline(dev_file, line);
        while (std::getline(dev_file, line)) {
            const auto colon = line.find(':');
            if (colon == std::string::npos) {
                continue;
            }
            const std::string name = trim_copy(std::string_view(line).substr(0, colon));
            if (name == "lo") {
                continue;
            }
            std::istringstream iss(line.substr(colon + 1));
            std::uint64_t rx_bytes = 0, rx_pkts = 0, rx_errs = 0, rx_drop = 0;
            std::uint64_t rx_fifo = 0, rx_frame = 0, rx_comp = 0, rx_mcast = 0;
            std::uint64_t tx_bytes = 0, tx_pkts = 0, tx_errs = 0, tx_drop = 0;
            if (iss >> rx_bytes >> rx_pkts >> rx_errs >> rx_drop >> rx_fifo >> rx_frame >> rx_comp >> rx_mcast
                    >> tx_bytes >> tx_pkts >> tx_errs >> tx_drop) {
                auto& c = find_or_add(name);
                c.rx = rx_bytes;
                c.tx = tx_bytes;
                c.rx_err = rx_errs;
                c.tx_err = tx_errs;
                c.rx_drop = rx_drop;
                c.tx_drop = tx_drop;

                std::ifstream mtu_in("/sys/class/net/" + name + "/mtu");
                unsigned int mtu_val = 1500;
                if (mtu_in.is_open() && (mtu_in >> mtu_val) && mtu_val > 0 && mtu_val <= 65535) {
                    c.mtu = static_cast<std::uint16_t>(mtu_val);
                }

                if (name.starts_with("bond")) {
                    std::ifstream bond_in("/proc/net/bonding/" + name);
                    if (bond_in.is_open()) {
                        std::string bline;
                        int up_slaves = 0;
                        int total_slaves = 0;
                        bool in_slave = false;
                        while (std::getline(bond_in, bline)) {
                            if (bline.starts_with("Slave Interface:")) {
                                in_slave = true;
                                ++total_slaves;
                            } else if (in_slave && bline.starts_with("MII Status:")) {
                                if (bline.find("up") != std::string::npos) {
                                    ++up_slaves;
                                }
                            }
                        }
                        if (total_slaves > 0) {
                            c.bond_info = "LACP " + std::to_string(up_slaves) + "/" +
                                          std::to_string(total_slaves) +
                                          ((up_slaves == total_slaves) ? " UP" : " DEGRADED");
                        }
                    }
                }
            }
        }
    }
#endif

    for (const auto& [name, raw] : counters) {
        const bool is_dc_iface =
            name.starts_with("bond") || name.starts_with("team") ||
            name.starts_with("br")   || name.starts_with("vmbr") ||
            name.starts_with("docker") || name.starts_with("cni") ||
            name.starts_with("vxlan");

        // 1. Hide phantom / internal macOS & Linux tunnel interfaces without an assigned IPv4 address
        // (macOS automatically creates utun0..utun12 for internal daemons like AirDrop, FindMy, etc.)
        if (raw.ipv4.empty() && (name.starts_with("utun") || name.starts_with("tun") || name.starts_with("tap"))) {
            continue;
        }

        // 2. Hide loopback and internal Apple wireless/virtual interfaces
        if (name.starts_with("lo") || name.starts_with("awdl") || name.starts_with("llw") ||
            name.starts_with("anpi") || name.starts_with("ap") || name.starts_with("nan") ||
            name.starts_with("gif") || name.starts_with("stf")) {
            continue;
        }

        // 3. Skip idle interfaces without IPv4 and without traffic (unless Datacenter bridge/bond)
        if (raw.ipv4.empty() && raw.rx == 0 && raw.tx == 0 && !is_dc_iface) {
            continue;
        }

        auto it = std::find_if(net_interfaces.begin(), net_interfaces.end(), [&](const NetInterfaceStats& s) {
            return s.name == name;
        });

        if (it == net_interfaces.end()) {
            NetInterfaceStats st{};
            st.name = name;
            st.ipv4 = raw.ipv4.empty() ? "---" : raw.ipv4;
            st.mtu = raw.mtu;
            st.rx_total = raw.rx;
            st.tx_total = raw.tx;
            st.rx_errors = raw.rx_err;
            st.tx_errors = raw.tx_err;
            st.rx_drops = raw.rx_drop;
            st.tx_drops = raw.tx_drop;
            st.bond_info = raw.bond_info;
            st.rx_top_bps = 4096.0;
            st.tx_top_bps = 4096.0;
            net_interfaces.push_back(std::move(st));
        } else {
            if (!raw.ipv4.empty()) {
                it->ipv4 = raw.ipv4;
            }
            it->mtu = raw.mtu;
            it->rx_errors = raw.rx_err;
            it->tx_errors = raw.tx_err;
            it->rx_drops = raw.rx_drop;
            it->tx_drops = raw.tx_drop;
            it->bond_info = raw.bond_info;

            if (dt_sec >= 0.05 && raw.rx >= it->rx_total && raw.tx >= it->tx_total) {
                const double inst_rx = static_cast<double>(raw.rx - it->rx_total) / dt_sec;
                const double inst_tx = static_cast<double>(raw.tx - it->tx_total) / dt_sec;
                it->rx_speed_bps = (it->rx_speed_bps <= 0.0) ? inst_rx : (it->rx_speed_bps * 0.4 + inst_rx * 0.6);
                it->tx_speed_bps = (it->tx_speed_bps <= 0.0) ? inst_tx : (it->tx_speed_bps * 0.4 + inst_tx * 0.6);
                it->rx_top_bps = std::max(it->rx_top_bps, it->rx_speed_bps);
                it->tx_top_bps = std::max(it->tx_top_bps, it->tx_speed_bps);
                it->rx_history.push(it->rx_speed_bps);
                it->tx_history.push(it->tx_speed_bps);
            }
            it->rx_total = raw.rx;
            it->tx_total = raw.tx;
        }
    }

    // Prioritize physical network adapters with assigned IPv4 (en0, eth0) as the primary displayed interface
    std::stable_sort(net_interfaces.begin(), net_interfaces.end(), [](const NetInterfaceStats& a, const NetInterfaceStats& b) {
        auto rank = [](const NetInterfaceStats& s) -> int {
            const bool has_ip = !s.ipv4.empty() && s.ipv4 != "---";
            if (s.name.starts_with("en") || s.name.starts_with("eth") || s.name.starts_with("wlan")) {
                return has_ip ? 0 : 3;
            }
            if (s.name.starts_with("bond") || s.name.starts_with("team")) {
                return has_ip ? 1 : 4;
            }
            if (s.name.starts_with("br") || s.name.starts_with("vmbr") || s.name.starts_with("docker") || s.name.starts_with("cni")) {
                return has_ip ? 2 : 5;
            }
            if (s.name.starts_with("utun") || s.name.starts_with("tun") || s.name.starts_with("wg") || s.name.starts_with("tailscale")) {
                return has_ip ? 2 : 6;
            }
            return has_ip ? 3 : 7;
        };
        return rank(a) < rank(b);
    });
}

} // namespace pingtop
