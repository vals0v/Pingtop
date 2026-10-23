#include "network_monitor.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <bit>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <poll.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

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

[[nodiscard]] bool is_tailscale_ip(std::string_view ip) noexcept {
    in_addr addr{};
    std::string s(ip);
    if (::inet_pton(AF_INET, s.c_str(), &addr) != 1) {
        return false;
    }
    const std::uint32_t h = net_to_host32(addr.s_addr);
    // Tailscale CGNAT range: 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
    return (h & 0xFFC00000U) == 0x64400000U;
}

[[nodiscard]] HostCategory classify_ip_category(std::string_view ip, HostCategory fallback) noexcept {
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

[[nodiscard]] std::string resolve_short_hostname(const std::string& ip) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    if (::inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) != 1) {
        return {};
    }
    char host[NI_MAXHOST]{};
    if (::getnameinfo(reinterpret_cast<const sockaddr*>(&sa), sizeof(sa),
                      host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0 &&
        host[0] != '\0') {
        std::string name(host);
        // Strip MagicDNS suffix (.ts.net) or .local for compact display
        const auto dot_pos = name.find('.');
        if (dot_pos != std::string::npos && dot_pos > 0) {
            return name.substr(0, dot_pos);
        }
        return name;
    }
    return {};
}

[[nodiscard]] double pick_percentile(const std::vector<double>& sorted, double q) noexcept {
    if (sorted.empty()) {
        return 0.0;
    }
    const double pos = q * static_cast<double>(sorted.size() - 1);
    const auto lower = static_cast<std::size_t>(pos);
    const auto upper = std::min(lower + 1, sorted.size() - 1);
    const double weight = pos - static_cast<double>(lower);
    return sorted[lower] * (1.0 - weight) + sorted[upper] * weight;
}

} // namespace

LatencyPercentiles HostEntry::compute_percentiles() const {
    LatencyPercentiles res{};
    std::vector<double> valid;
    valid.reserve(history.size());
    for (double v : history) {
        if (v >= 0.0) {
            valid.push_back(v);
        }
    }
    if (valid.empty()) {
        return res;
    }

    std::sort(valid.begin(), valid.end());
    res.p50 = pick_percentile(valid, 0.50);
    res.p90 = pick_percentile(valid, 0.90);
    res.p95 = pick_percentile(valid, 0.95);
    res.p99 = pick_percentile(valid, 0.99);

    double mean = 0.0;
    for (double v : valid) {
        mean += v;
    }
    mean /= static_cast<double>(valid.size());

    double sq_sum = 0.0;
    for (double v : valid) {
        const double d = v - mean;
        sq_sum += d * d;
    }
    res.stddev = std::sqrt(sq_sum / static_cast<double>(valid.size()));
    return res;
}

void HostEntry::reset_stats() noexcept {
    if (tcp_fd >= 0) {
        ::close(tcp_fd);
        tcp_fd = -1;
    }
    if (status != HostStatus::DnsError) {
        status = HostStatus::Pending;
    }
    sent_count = 0;
    completed_count = 0;
    received_count = 0;
    lost_count = 0;
    last_ttl = 0;
    in_flight = false;
    last_rtt_ms = 0.0;
    min_rtt_ms = 0.0;
    avg_rtt_ms = 0.0;
    max_rtt_ms = 0.0;
    jitter_ms = 0.0;
    rtt_sum_ms = 0.0;
    prev_rtt_ms = -1.0;
    history.clear();
}

NetworkMonitor::NetworkMonitor(MonitorConfig config)
    : config_(std::move(config)),
      start_time_(std::chrono::steady_clock::now()) {}

NetworkMonitor::~NetworkMonitor() {
    stop_mtr();
    for (HostEntry& h : hosts_) {
        close_tcp_probe(h);
    }
}

bool NetworkMonitor::initialize() {
    start_time_ = std::chrono::steady_clock::now();
    return socket_.open();
}

void NetworkMonitor::close_tcp_probe(HostEntry& host) noexcept {
    if (host.tcp_fd >= 0) {
        ::close(host.tcp_fd);
        host.tcp_fd = -1;
    }
}

bool NetworkMonitor::add_host(
    const std::string& target,
    const std::string& custom_label,
    HostCategory category
) {
    if (target.empty()) {
        return false;
    }

    std::string host_part = target;
    std::uint16_t tcp_port = 0;
    ProbeType probe_type = ProbeType::Icmp;

    const auto colon_pos = target.rfind(':');
    if (colon_pos != std::string::npos && colon_pos > 0 && colon_pos + 1 < target.size()) {
        const std::string port_str = target.substr(colon_pos + 1);
        char* endptr = nullptr;
        const long port_val = std::strtol(port_str.c_str(), &endptr, 10);
        if (endptr != nullptr && *endptr == '\0' && port_val >= 1 && port_val <= 65535) {
            host_part = target.substr(0, colon_pos);
            tcp_port = static_cast<std::uint16_t>(port_val);
            probe_type = ProbeType::Tcp;
        }
    }

    HostEntry entry{};
    entry.hostname = host_part;
    entry.probe_type = probe_type;
    entry.tcp_port = tcp_port;
    if (!custom_label.empty()) {
        entry.display_name = custom_label;
    } else if (probe_type == ProbeType::Tcp) {
        entry.display_name = host_part + ":" + std::to_string(tcp_port);
    } else {
        entry.display_name = host_part;
    }

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = 0;

    addrinfo* result = nullptr;
    const int err = ::getaddrinfo(host_part.c_str(), nullptr, &hints, &result);
    if (err == 0 && result != nullptr) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(result->ai_addr);
        entry.addr = *ipv4;
        entry.addr.sin_port = host_to_net16(tcp_port);

        char ip_buf[INET_ADDRSTRLEN]{};
        if (::inet_ntop(AF_INET, &ipv4->sin_addr, ip_buf, sizeof(ip_buf)) != nullptr) {
            entry.resolved_ip = ip_buf;
        } else {
            entry.resolved_ip = host_part;
        }
        entry.status = HostStatus::Pending;
        ::freeaddrinfo(result);
    } else {
        entry.resolved_ip = "DNS Error";
        entry.status = HostStatus::DnsError;
    }

    if (category == HostCategory::Internet && entry.status != HostStatus::DnsError) {
        entry.category = classify_ip_category(entry.resolved_ip, HostCategory::Internet);
    } else {
        entry.category = category;
    }

    for (auto& existing : hosts_) {
        if (existing.resolved_ip == entry.resolved_ip &&
            existing.probe_type == entry.probe_type &&
            existing.tcp_port == entry.tcp_port &&
            entry.status != HostStatus::DnsError) {
            if (!custom_label.empty()) {
                existing.display_name = custom_label;
            }
            return false;
        }
    }

    hosts_.push_back(std::move(entry));
    return true;
}

std::string NetworkMonitor::default_config_path() {
    const char* home = std::getenv("HOME");
    if (home == nullptr || home[0] == '\0') {
        return "pingtop.conf";
    }
    return std::string(home) + "/.config/pingtop/hosts.conf";
}

std::size_t NetworkMonitor::load_or_create_config_file(const std::string& custom_path) {
    const std::string path = custom_path.empty() ? default_config_path() : custom_path;
    std::error_code ec;
    const std::filesystem::path fs_path(path);

    if (!std::filesystem::exists(fs_path, ec)) {
        if (fs_path.has_parent_path()) {
            std::filesystem::create_directories(fs_path.parent_path(), ec);
        }
        std::ofstream out(path);
        if (out.is_open()) {
            out << "# Pingtop Configuration File (~/.config/pingtop/hosts.conf)\n"
                << "# Syntax: LABEL=HOST, LABEL=HOST:PORT (TCP Ping), or HOST\n"
                << "# Sections: [LAN], [VPN], [WAN]\n\n"
                << "[VPN]\n"
                << "Tailscale Server=100.82.99.23\n"
                << "Tailscale SSH=100.82.99.23:22\n\n"
                << "[WAN]\n"
                << "Cloudflare DNS=1.1.1.1\n"
                << "Google Public DNS=8.8.8.8\n"
                << "Quad9 Security DNS=9.9.9.9\n"
                << "Cloudflare HTTPS=1.1.1.1:443\n"
                << "Google HTTPS=8.8.8.8:443\n";
        }
    }

    std::ifstream in(path);
    if (!in.is_open()) {
        return 0;
    }

    HostCategory current_cat = HostCategory::Internet;
    std::size_t loaded = 0;
    std::string raw_line;

    while (std::getline(in, raw_line)) {
        const auto hash_pos = raw_line.find('#');
        if (hash_pos != std::string::npos) {
            raw_line.erase(hash_pos);
        }
        const std::string line = trim_copy(raw_line);
        if (line.empty()) {
            continue;
        }

        if (line.front() == '[' && line.back() == ']') {
            const std::string sec = trim_copy(std::string_view(line).substr(1, line.size() - 2));
            if (sec == "LAN" || sec == "lan" || sec == "LOCAL") {
                current_cat = HostCategory::LocalLan;
            } else if (sec == "VPN" || sec == "vpn" || sec == "TAILSCALE") {
                current_cat = HostCategory::Vpn;
            } else {
                current_cat = HostCategory::Internet;
            }
            continue;
        }

        const auto eq_pos = line.find('=');
        if (eq_pos != std::string::npos && eq_pos > 0 && eq_pos + 1 < line.size()) {
            const std::string label = trim_copy(std::string_view(line).substr(0, eq_pos));
            const std::string host = trim_copy(std::string_view(line).substr(eq_pos + 1));
            if (add_host(host, label, current_cat)) {
                ++loaded;
            }
        } else {
            if (add_host(line, "", current_cat)) {
                ++loaded;
            }
        }
    }

    return loaded;
}

std::vector<std::string> NetworkMonitor::get_local_ips() {
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

std::optional<std::string> NetworkMonitor::detect_default_gateway() {
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
                        unsigned long gw_val = std::strtoul(gw_hex.c_str(), nullptr, 16);
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

    pipe = ::popen("/sbin/route -n get default 2>/dev/null", "r");
    if (pipe != nullptr) {
        char line[256]{};
        std::string gateway;
        while (std::fgets(line, sizeof(line), pipe) != nullptr) {
            std::string_view sv(line);
            const auto pos = sv.find("gateway:");
            if (pos != std::string_view::npos) {
                sv.remove_prefix(pos + 8);
                gateway = trim_copy(sv);
                if (!gateway.empty()) {
                    break;
                }
            }
        }
        ::pclose(pipe);
        if (!gateway.empty()) {
            return gateway;
        }
    }
#endif
    return std::nullopt;
}

std::vector<DiscoveredTarget> NetworkMonitor::discover_lan_devices() {
    std::vector<DiscoveredTarget> targets;
    const auto local_ips = get_local_ips();
    const auto gw = detect_default_gateway();

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

                const std::string short_name = resolve_short_hostname(ip);
                const std::string label = !short_name.empty()
                    ? ("LAN: " + short_name)
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

                    const std::string short_name = resolve_short_hostname(ip);
                    const std::string label = !short_name.empty()
                        ? ("LAN: " + short_name)
                        : ("LAN Device (" + ip + ")");

                    targets.push_back({ip, label, HostCategory::LocalLan});
                }
            }
        }
    }
#endif
    return targets;
}

std::vector<DiscoveredTarget> NetworkMonitor::discover_vpn_and_tailscale() {
    std::vector<DiscoveredTarget> targets;
    const auto local_ips = get_local_ips();
    bool tailscale_detected = false;

    // 1. Check interfaces for Tailscale CGNAT (100.64.0.0/10) and remote point-to-point gateways
    ifaddrs* ifaddr = nullptr;
    if (::getifaddrs(&ifaddr) == 0 && ifaddr != nullptr) {
        for (const auto* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET) {
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

    // 2. Discover active SSH sessions (port 22) and Tailscale peers via lsof (uses libproc, works unprivileged)
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
                const std::string peer_name = resolve_short_hostname(rem_ip);

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

    // 3. Discover Tailscale peers from macOS routing table (100.x.y.z host routes on utun*)
    {
        FILE* pipe = ::popen("/usr/sbin/netstat -rn -f inet 2>/dev/null", "r");
        if (pipe != nullptr) {
            char line[512]{};
            while (std::fgets(line, sizeof(line), pipe) != nullptr) {
                std::istringstream iss(line);
                std::string dest, gw, flags, netif;
                if (iss >> dest >> gw >> flags >> netif) {
                    if (dest.find('/') != std::string::npos || dest == "100.100.100.100") {
                        continue;
                    }
                    if (is_tailscale_ip(dest) &&
                        std::find(local_ips.begin(), local_ips.end(), dest) == local_ips.end()) {
                        tailscale_detected = true;
                        const std::string peer_name = resolve_short_hostname(dest);
                        const std::string label = !peer_name.empty()
                            ? ("TS: " + peer_name)
                            : "Tailscale Peer";
                        targets.push_back({dest, label, HostCategory::Vpn});
                    }
                }
            }
            ::pclose(pipe);
        }
    }
#elif defined(__linux__)
    // Parse active TCP connections from /proc/net/tcp on Linux
    {
        std::ifstream tcp_file("/proc/net/tcp");
        if (tcp_file.is_open()) {
            std::string line;
            if (std::getline(tcp_file, line)) {
                while (std::getline(tcp_file, line)) {
                    std::istringstream iss(line);
                    std::string sl, local_hex, rem_hex, state_hex;
                    if (iss >> sl >> local_hex >> rem_hex >> state_hex) {
                        if (state_hex != "01") { // 01 = TCP_ESTABLISHED
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
                        const std::string peer_name = resolve_short_hostname(rem_ip);
                        const std::string display_peer = !peer_name.empty() ? peer_name : rem_ip;

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

    // 4. Also check Tailscale CLI if installed
    const std::array<const char*, 3> tailscale_bins = {
        "/opt/homebrew/bin/tailscale",
        "/usr/local/bin/tailscale",
        "tailscale"
    };

    for (const auto* bin : tailscale_bins) {
        if (bin[0] == '/' && ::access(bin, X_OK) != 0) {
            continue;
        }
        std::string cmd = std::string(bin) + " status 2>/dev/null";
        FILE* pipe = ::popen(cmd.c_str(), "r");
        if (pipe != nullptr) {
            char line[512]{};
            bool found_peers = false;
            while (std::fgets(line, sizeof(line), pipe) != nullptr) {
                std::istringstream iss(line);
                std::string ip, name;
                if (iss >> ip >> name) {
                    if (is_tailscale_ip(ip) &&
                        std::find(local_ips.begin(), local_ips.end(), ip) == local_ips.end()) {
                        targets.push_back({ip, "Tailscale: " + name, HostCategory::Vpn});
                        found_peers = true;
                        tailscale_detected = true;
                    }
                }
            }
            ::pclose(pipe);
            if (found_peers) {
                break;
            }
        }
    }

    if (tailscale_detected) {
        targets.push_back({"100.100.100.100", "Tailscale MagicDNS", HostCategory::Vpn});
    }

    return targets;
}

void NetworkMonitor::discover_and_add_network_devices() {
    if (const auto gw = detect_default_gateway(); gw.has_value()) {
        add_host(*gw, "Router / Gateway", HostCategory::LocalLan);
    }

    for (const auto& dev : discover_lan_devices()) {
        add_host(dev.ip, dev.label, dev.category);
    }

    for (const auto& vpn : discover_vpn_and_tailscale()) {
        add_host(vpn.ip, vpn.label, vpn.category);
    }
}

void NetworkMonitor::add_default_hosts() {
    discover_and_add_network_devices();

    (void)load_or_create_config_file(config_.config_file_path);

    add_host("1.1.1.1", "Cloudflare DNS", HostCategory::Internet);
    add_host("8.8.8.8", "Google Public DNS", HostCategory::Internet);
    add_host("9.9.9.9", "Quad9 Security DNS", HostCategory::Internet);
}

void NetworkMonitor::start_mtr(std::size_t host_idx) {
    if (host_idx >= hosts_.size()) {
        return;
    }

    stop_mtr();

    const HostEntry& target = hosts_[host_idx];
    if (target.status == HostStatus::DnsError) {
        return;
    }

    mtr_active_ = true;
    mtr_target_name_ = target.display_name;
    mtr_target_ip_ = target.resolved_ip;
    mtr_hops_.clear();
    mtr_line_buf_.clear();

    if (const auto gw = detect_default_gateway(); gw.has_value()) {
        MtrHop hop1{};
        hop1.hop_index = 1;
        hop1.reachable = true;
        hop1.entry.display_name = "Hop 1 (Gateway)";
        hop1.entry.hostname = *gw;
        hop1.entry.resolved_ip = *gw;
        hop1.entry.addr.sin_family = AF_INET;
        (void)::inet_pton(AF_INET, gw->c_str(), &hop1.entry.addr.sin_addr);
        hop1.entry.status = HostStatus::Pending;
        mtr_hops_.push_back(std::move(hop1));
    }

    std::string cmd = "PATH=/usr/sbin:/sbin:/usr/bin:/bin traceroute -n -q 1 -w 1 -m 20 " + mtr_target_ip_ + " 2>/dev/null";
    mtr_pipe_ = ::popen(cmd.c_str(), "r");
    if (mtr_pipe_ != nullptr) {
        mtr_pipe_fd_ = ::fileno(mtr_pipe_);
        if (mtr_pipe_fd_ >= 0) {
            const int flags = ::fcntl(mtr_pipe_fd_, F_GETFL, 0);
            if (flags >= 0) {
                (void)::fcntl(mtr_pipe_fd_, F_SETFL, flags | O_NONBLOCK);
            }
        }
    }
}

void NetworkMonitor::stop_mtr() noexcept {
    if (mtr_pipe_ != nullptr) {
        ::pclose(mtr_pipe_);
        mtr_pipe_ = nullptr;
        mtr_pipe_fd_ = -1;
    }
    mtr_active_ = false;
    mtr_hops_.clear();
    mtr_line_buf_.clear();
}

void NetworkMonitor::read_mtr_pipe() {
    if (mtr_pipe_ == nullptr || mtr_pipe_fd_ < 0) {
        return;
    }

    char buf[512]{};
    const ssize_t n = ::read(mtr_pipe_fd_, buf, sizeof(buf));
    if (n > 0) {
        mtr_line_buf_.append(buf, static_cast<std::size_t>(n));

        std::size_t nl_pos = 0;
        while ((nl_pos = mtr_line_buf_.find('\n')) != std::string::npos) {
            std::string line = mtr_line_buf_.substr(0, nl_pos);
            mtr_line_buf_.erase(0, nl_pos + 1);

            std::istringstream iss(line);
            int hop_num = 0;
            std::string token;
            if ((iss >> hop_num >> token) && hop_num >= 1 && hop_num <= 64) {
                MtrHop hop{};
                hop.hop_index = hop_num;

                in_addr addr{};
                if (token != "*" && ::inet_pton(AF_INET, token.c_str(), &addr) == 1) {
                    hop.reachable = true;
                    hop.entry.display_name = "Hop " + std::to_string(hop_num);
                    hop.entry.hostname = token;
                    hop.entry.resolved_ip = token;
                    hop.entry.addr.sin_family = AF_INET;
                    hop.entry.addr.sin_addr = addr;
                    hop.entry.status = HostStatus::Pending;
                } else {
                    hop.reachable = false;
                    hop.entry.display_name = "Hop " + std::to_string(hop_num);
                    hop.entry.hostname = "*";
                    hop.entry.resolved_ip = "* (No ICMP Reply)";
                    hop.entry.status = HostStatus::Offline;
                }

                auto it = std::find_if(mtr_hops_.begin(), mtr_hops_.end(), [&](const MtrHop& h) {
                    return h.hop_index == hop_num;
                });
                if (it != mtr_hops_.end()) {
                    if (it->entry.resolved_ip != hop.entry.resolved_ip && hop.reachable) {
                        *it = std::move(hop);
                    }
                } else {
                    mtr_hops_.push_back(std::move(hop));
                    std::sort(mtr_hops_.begin(), mtr_hops_.end(), [](const MtrHop& a, const MtrHop& b) {
                        return a.hop_index < b.hop_index;
                    });
                }
            }
        }
    } else if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
        ::pclose(mtr_pipe_);
        mtr_pipe_ = nullptr;
        mtr_pipe_fd_ = -1;
    }
}

void NetworkMonitor::poll_once(int poll_timeout_ms, const std::function<void(int)>& on_key_pressed) {
    const auto now = std::chrono::steady_clock::now();

    check_timeouts(now);

    if (!paused_) {
        const bool first_run = (last_batch_send_time_.time_since_epoch().count() == 0);
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_batch_send_time_);
        if (first_run || elapsed >= config_.ping_interval) {
            dispatch_pings(now);
            last_batch_send_time_ = now;
            ++completed_rounds_;
        }
    }

    std::vector<pollfd> fds;
    fds.reserve(4 + hosts_.size());

    int icmp_slot = -1;
    if (socket_.is_open()) {
        icmp_slot = static_cast<int>(fds.size());
        fds.push_back(pollfd{socket_.fd(), POLLIN, 0});
    }

    const int stdin_slot = static_cast<int>(fds.size());
    fds.push_back(pollfd{STDIN_FILENO, POLLIN, 0});

    int mtr_slot = -1;
    if (mtr_pipe_fd_ >= 0) {
        mtr_slot = static_cast<int>(fds.size());
        fds.push_back(pollfd{mtr_pipe_fd_, POLLIN, 0});
    }

    struct TcpSlot {
        std::size_t host_idx;
        std::size_t poll_idx;
    };
    std::vector<TcpSlot> tcp_slots;
    for (std::size_t i = 0; i < hosts_.size(); ++i) {
        if (hosts_[i].in_flight && hosts_[i].tcp_fd >= 0) {
            tcp_slots.push_back({i, fds.size()});
            fds.push_back(pollfd{hosts_[i].tcp_fd, POLLOUT, 0});
        }
    }

    const int ready = ::poll(fds.data(), static_cast<nfds_t>(fds.size()), poll_timeout_ms);
    const auto after_poll = std::chrono::steady_clock::now();

    if (ready > 0) {
        if (icmp_slot >= 0 && (fds[static_cast<std::size_t>(icmp_slot)].revents & POLLIN) != 0) {
            drain_replies(after_poll);
        }

        if (mtr_slot >= 0 && (fds[static_cast<std::size_t>(mtr_slot)].revents & (POLLIN | POLLHUP)) != 0) {
            read_mtr_pipe();
        }

        for (const auto& ts : tcp_slots) {
            const short rev = fds[ts.poll_idx].revents;
            if ((rev & (POLLOUT | POLLERR | POLLHUP)) != 0) {
                HostEntry& host = hosts_[ts.host_idx];
                int so_err = 0;
                socklen_t err_len = sizeof(so_err);
                const int rc = ::getsockopt(host.tcp_fd, SOL_SOCKET, SO_ERROR, &so_err, &err_len);
                close_tcp_probe(host);

                if (rc == 0 && (so_err == 0 || so_err == ECONNREFUSED)) {
                    const auto delta_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                        after_poll - host.last_send_time
                    ).count();
                    const double rtt_ms = (delta_ns > 0)
                        ? (static_cast<double>(delta_ns) / 1'000'000.0)
                        : 0.01;
                    record_reply(host, rtt_ms, 64);
                } else {
                    record_timeout(host);
                }
            }
        }

        if ((fds[static_cast<std::size_t>(stdin_slot)].revents & POLLIN) != 0) {
            char key_buf[8]{};
            const ssize_t n = ::read(STDIN_FILENO, key_buf, sizeof(key_buf));
            if (n > 0 && on_key_pressed) {
                if (n >= 3 && key_buf[0] == '\033' && key_buf[1] == '[') {
                    if (key_buf[2] == 'A') {
                        on_key_pressed(kKeyArrowUp);
                    } else if (key_buf[2] == 'B') {
                        on_key_pressed(kKeyArrowDown);
                    }
                } else if (n == 1 && key_buf[0] == '\033') {
                    on_key_pressed(kKeyEscape);
                } else if (key_buf[0] == 127 || key_buf[0] == 8) {
                    on_key_pressed(kKeyBackspace);
                } else {
                    on_key_pressed(static_cast<unsigned char>(key_buf[0]));
                }
            }
        }
    }

    check_timeouts(after_poll);
}

void NetworkMonitor::dispatch_host_probe(
    HostEntry& host,
    std::uint16_t id_tag,
    std::chrono::steady_clock::time_point now
) {
    if (host.status == HostStatus::DnsError) {
        return;
    }

    if (host.in_flight) {
        record_timeout(host);
    }

    const std::uint32_t next_seq = ++host.last_sequence;
    const auto send_timestamp = std::chrono::steady_clock::now();

    ++host.sent_count;
    host.in_flight = true;
    host.in_flight_seq = next_seq;
    host.last_send_time = now;

    if (host.probe_type == ProbeType::Tcp) {
        const int sock = ::socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            record_timeout(host);
            return;
        }
        const int flags = ::fcntl(sock, F_GETFL, 0);
        if (flags < 0 || ::fcntl(sock, F_SETFL, flags | O_NONBLOCK) != 0) {
            ::close(sock);
            record_timeout(host);
            return;
        }

        host.last_send_time = std::chrono::steady_clock::now();
        const int rc = ::connect(sock, reinterpret_cast<const sockaddr*>(&host.addr), sizeof(host.addr));
        if (rc == 0) {
            const auto done_time = std::chrono::steady_clock::now();
            ::close(sock);
            const auto delta_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                done_time - host.last_send_time
            ).count();
            record_reply(host, static_cast<double>(delta_ns) / 1'000'000.0, 64);
        } else if (errno == EINPROGRESS) {
            host.tcp_fd = sock;
        } else {
            ::close(sock);
            record_timeout(host);
        }
    } else {
        const bool sent_ok = socket_.send_echo_request(
            host.addr,
            id_tag,
            next_seq,
            send_timestamp
        );
        if (!sent_ok) {
            record_timeout(host);
        }
    }
}

void NetworkMonitor::dispatch_pings(std::chrono::steady_clock::time_point now) {
    for (std::size_t i = 0; i < hosts_.size(); ++i) {
        dispatch_host_probe(hosts_[i], static_cast<std::uint16_t>(i), now);
    }

    if (mtr_active_) {
        for (std::size_t h = 0; h < mtr_hops_.size(); ++h) {
            if (mtr_hops_[h].reachable) {
                const auto tag = static_cast<std::uint16_t>(kMtrHopFlag | static_cast<std::uint16_t>(h));
                dispatch_host_probe(mtr_hops_[h].entry, tag, now);
            }
        }
    }
}

void NetworkMonitor::check_timeouts(std::chrono::steady_clock::time_point now) {
    for (HostEntry& host : hosts_) {
        if (!host.in_flight) {
            continue;
        }
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - host.last_send_time);
        if (elapsed >= config_.ping_timeout) {
            record_timeout(host);
        }
    }

    if (mtr_active_) {
        for (MtrHop& hop : mtr_hops_) {
            if (!hop.reachable || !hop.entry.in_flight) {
                continue;
            }
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - hop.entry.last_send_time
            );
            if (elapsed >= config_.ping_timeout) {
                record_timeout(hop.entry);
            }
        }
    }
}

void NetworkMonitor::drain_replies(std::chrono::steady_clock::time_point now) {
    while (true) {
        const auto reply_opt = socket_.receive_echo_reply(now);
        if (!reply_opt.has_value()) {
            break;
        }

        const IcmpReply& reply = *reply_opt;
        if ((reply.host_index & kMtrHopFlag) != 0) {
            const std::size_t hop_idx = static_cast<std::size_t>(reply.host_index & ~kMtrHopFlag);
            if (mtr_active_ && hop_idx < mtr_hops_.size()) {
                HostEntry& hop_entry = mtr_hops_[hop_idx].entry;
                if (hop_entry.in_flight && reply.sequence == hop_entry.in_flight_seq) {
                    record_reply(hop_entry, reply.rtt_ms, reply.ttl);
                }
            }
            continue;
        }

        if (reply.host_index < hosts_.size()) {
            HostEntry& host = hosts_[reply.host_index];
            if (host.in_flight && reply.sequence == host.in_flight_seq) {
                record_reply(host, reply.rtt_ms, reply.ttl);
            }
        }
    }
}

void NetworkMonitor::record_reply(HostEntry& host, double rtt, std::uint8_t ttl) noexcept {
    close_tcp_probe(host);
    host.in_flight = false;
    host.status = HostStatus::Online;
    ++host.completed_count;
    ++host.received_count;

    host.last_rtt_ms = rtt;
    host.last_ttl = ttl;
    host.rtt_sum_ms += rtt;
    host.avg_rtt_ms = host.rtt_sum_ms / static_cast<double>(host.received_count);

    if (host.received_count == 1) {
        host.min_rtt_ms = rtt;
        host.max_rtt_ms = rtt;
        host.jitter_ms = 0.0;
    } else {
        host.min_rtt_ms = std::min(host.min_rtt_ms, rtt);
        host.max_rtt_ms = std::max(host.max_rtt_ms, rtt);

        const double diff = std::abs(rtt - host.prev_rtt_ms);
        if (host.received_count == 2) {
            host.jitter_ms = diff;
        } else {
            host.jitter_ms += (diff - host.jitter_ms) / 16.0;
        }
    }

    host.prev_rtt_ms = rtt;
    host.history.push(rtt);
}

void NetworkMonitor::record_timeout(HostEntry& host) noexcept {
    close_tcp_probe(host);
    host.in_flight = false;
    host.status = HostStatus::Offline;
    ++host.completed_count;
    ++host.lost_count;
    host.history.push(-1.0);
}

void NetworkMonitor::reset_all_stats() noexcept {
    for (HostEntry& host : hosts_) {
        host.reset_stats();
    }
    for (MtrHop& hop : mtr_hops_) {
        hop.entry.reset_stats();
    }
    completed_rounds_ = 0;
    start_time_ = std::chrono::steady_clock::now();
}

void NetworkMonitor::adjust_interval(std::chrono::milliseconds delta) noexcept {
    auto next = config_.ping_interval + delta;
    next = std::clamp(next, std::chrono::milliseconds(100), std::chrono::milliseconds(10000));
    config_.ping_interval = next;
    config_.ping_timeout = std::min(
        std::chrono::milliseconds(2000),
        std::chrono::milliseconds(static_cast<long long>(next.count() * 9 / 10))
    );
}

void NetworkMonitor::cycle_sort_column() noexcept {
    switch (sort_column_) {
        case SortColumn::None:       sort_column_ = SortColumn::Latency; break;
        case SortColumn::Latency:    sort_column_ = SortColumn::AvgLatency; break;
        case SortColumn::AvgLatency: sort_column_ = SortColumn::Jitter; break;
        case SortColumn::Jitter:     sort_column_ = SortColumn::PacketLoss; break;
        case SortColumn::PacketLoss: sort_column_ = SortColumn::None; break;
    }
}

std::string_view NetworkMonitor::sort_column_name() const noexcept {
    switch (sort_column_) {
        case SortColumn::None:       return "Category / Default";
        case SortColumn::Latency:    return "Current RTT";
        case SortColumn::AvgLatency: return "Average RTT";
        case SortColumn::Jitter:     return "Jitter";
        case SortColumn::PacketLoss: return "Packet Loss %";
    }
    return "Category / Default";
}

} // namespace pingtop
