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
#include <netdb.h>
#include <poll.h>
#include <sstream>
#include <sys/socket.h>
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

[[nodiscard]] std::string trim_copy(std::string_view sv) {
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front())) != 0) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back())) != 0) {
        sv.remove_suffix(1);
    }
    return std::string(sv);
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

std::size_t build_dns_benchmark_packet(std::uint16_t tx_id, std::uint8_t* buf) noexcept {
    static constexpr std::array<std::uint8_t, 33> kTemplate = {
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x03, 'o', 'n', 'e',
        0x03, 'o', 'n', 'e',
        0x03, 'o', 'n', 'e',
        0x03, 'o', 'n', 'e',
        0x00,
        0x00, 0x01, 0x00, 0x01
    };
    std::memcpy(buf, kTemplate.data(), kTemplate.size());
    buf[0] = static_cast<std::uint8_t>(tx_id >> 8U);
    buf[1] = static_cast<std::uint8_t>(tx_id & 0xFFU);
    return kTemplate.size();
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
    if (scan_thread_.joinable()) {
        scan_thread_.join();
    }
    stop_mtr();
    for (HostEntry& h : hosts_) {
        close_tcp_probe(h);
    }
}

bool NetworkMonitor::initialize() {
    start_time_ = std::chrono::steady_clock::now();
    NetDiscovery::sample_net_interfaces(net_interfaces_, last_net_sample_time_, start_time_);
    return socket_.open();
}

void NetworkMonitor::close_tcp_probe(HostEntry& host) noexcept {
    if (host.tcp_fd >= 0) {
        ::close(host.tcp_fd);
        host.tcp_fd = -1;
    }
}

void NetworkMonitor::run_mtu_discovery(std::size_t host_idx) {
    if (host_idx >= hosts_.size()) {
        return;
    }
    HostEntry& host = hosts_[host_idx];
    if (host.status == HostStatus::DnsError) {
        return;
    }
    if (host.is_ipv6) {
        host.path_mtu = 1280;
    } else {
        host.path_mtu = IcmpSocket::probe_path_mtu(host.addr);
    }
    status_msg_ = "MTU for " + host.display_name + ": " + std::to_string(host.path_mtu) + "B";
    status_expiry_ = std::chrono::steady_clock::now() + std::chrono::seconds(4);
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

    if (host_part.starts_with("dns://")) {
        host_part = host_part.substr(6);
        probe_type = ProbeType::Dns;
        tcp_port = 53;
    } else if (host_part.ends_with(":53/udp") || host_part.ends_with(":53/dns")) {
        const auto colon = host_part.rfind(':');
        host_part = host_part.substr(0, colon);
        probe_type = ProbeType::Dns;
        tcp_port = 53;
    } else if (host_part.front() == '[') {
        const auto close_br = host_part.find(']');
        if (close_br != std::string::npos) {
            const std::string v6_lit = host_part.substr(1, close_br - 1);
            if (close_br + 2 < host_part.size() && host_part[close_br + 1] == ':') {
                const long p = std::strtol(host_part.substr(close_br + 2).c_str(), nullptr, 10);
                if (p > 0 && p <= 65535) {
                    tcp_port = static_cast<std::uint16_t>(p);
                    probe_type = ProbeType::Tcp;
                }
            }
            host_part = v6_lit;
        }
    } else {
        const auto first_colon = host_part.find(':');
        const auto last_colon = host_part.rfind(':');
        if (first_colon != std::string::npos && first_colon == last_colon &&
            last_colon > 0 && last_colon + 1 < host_part.size()) {
            const std::string port_str = host_part.substr(last_colon + 1);
            char* end_ptr = nullptr;
            const long p = std::strtol(port_str.c_str(), &end_ptr, 10);
            if (end_ptr != nullptr && *end_ptr == '\0' && p > 0 && p <= 65535) {
                tcp_port = static_cast<std::uint16_t>(p);
                probe_type = ProbeType::Tcp;
                host_part = host_part.substr(0, last_colon);
            }
        }
    }

    HostEntry entry{};
    entry.hostname = host_part;
    entry.display_name = custom_label.empty() ? target : custom_label;
    entry.probe_type = probe_type;
    entry.tcp_port = tcp_port;

    const std::uint16_t target_port = (probe_type == ProbeType::Dns)
        ? 53
        : ((probe_type == ProbeType::Tcp) ? tcp_port : 0);

    in_addr v4_addr{};
    in6_addr v6_addr{};

    if (::inet_pton(AF_INET, host_part.c_str(), &v4_addr) == 1) {
        entry.addr.sin_family = AF_INET;
        entry.addr.sin_addr = v4_addr;
        entry.addr.sin_port = host_to_net16(target_port);
        entry.is_ipv6 = false;
        entry.resolved_ip = host_part;
        entry.status = HostStatus::Pending;
    } else if (::inet_pton(AF_INET6, host_part.c_str(), &v6_addr) == 1) {
        entry.addr6.sin6_family = AF_INET6;
        entry.addr6.sin6_addr = v6_addr;
        entry.addr6.sin6_port = host_to_net16(target_port);
        entry.is_ipv6 = true;
        entry.resolved_ip = host_part;
        entry.status = HostStatus::Pending;
    } else {
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = (probe_type == ProbeType::Tcp) ? SOCK_STREAM : SOCK_DGRAM;

        addrinfo* result = nullptr;
        const int rc = ::getaddrinfo(host_part.c_str(), nullptr, &hints, &result);
        if (rc == 0 && result != nullptr) {
            const addrinfo* chosen = result;
            for (const addrinfo* p = result; p != nullptr; p = p->ai_next) {
                if (p->ai_family == AF_INET) {
                    chosen = p;
                    break;
                }
            }

            if (chosen->ai_family == AF_INET6) {
                const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(chosen->ai_addr);
                entry.addr6 = *ipv6;
                entry.addr6.sin6_port = host_to_net16(target_port);
                entry.is_ipv6 = true;

                char ip6_buf[INET6_ADDRSTRLEN]{};
                if (::inet_ntop(AF_INET6, &ipv6->sin6_addr, ip6_buf, sizeof(ip6_buf)) != nullptr) {
                    entry.resolved_ip = ip6_buf;
                } else {
                    entry.resolved_ip = host_part;
                }
                entry.status = HostStatus::Pending;
            } else {
                const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(chosen->ai_addr);
                entry.addr = *ipv4;
                entry.addr.sin_port = host_to_net16(target_port);
                entry.is_ipv6 = false;

                char ip_buf[INET_ADDRSTRLEN]{};
                if (::inet_ntop(AF_INET, &ipv4->sin_addr, ip_buf, sizeof(ip_buf)) != nullptr) {
                    entry.resolved_ip = ip_buf;
                } else {
                    entry.resolved_ip = host_part;
                }
                entry.status = HostStatus::Pending;
            }
            ::freeaddrinfo(result);
        } else {
            entry.resolved_ip = "DNS Error";
            entry.status = HostStatus::DnsError;
        }
    }

    if (category == HostCategory::Internet && entry.status != HostStatus::DnsError) {
        entry.category = NetDiscovery::classify_ip_category(entry.resolved_ip, HostCategory::Internet);
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

    if (entry.status != HostStatus::DnsError) {
        entry.asn_info = NetDiscovery::lookup_asn_and_geo(entry.resolved_ip);
        entry.path_mtu = NetDiscovery::detect_route_mtu(entry.resolved_ip, entry.is_ipv6);
    } else {
        entry.asn_info = "---";
        entry.path_mtu = 0;
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

void NetworkMonitor::discover_and_add_network_devices() {
    for (const auto& target : NetDiscovery::discover_all()) {
        add_host(target.ip, target.label, target.category);
    }
}

void NetworkMonitor::trigger_async_scan() {
    if (scan_in_progress_.exchange(true)) {
        return;
    }
    if (scan_thread_.joinable()) {
        scan_thread_.join();
    }

    scan_thread_ = std::thread([this]() {
        auto found = NetDiscovery::discover_all();
        {
            std::lock_guard<std::mutex> lock(scan_mutex_);
            pending_discovered_ = std::move(found);
        }
        scan_results_ready_.store(true, std::memory_order_release);
        scan_in_progress_.store(false, std::memory_order_release);
    });
}

void NetworkMonitor::apply_pending_discoveries() {
    if (!scan_results_ready_.exchange(false, std::memory_order_acquire)) {
        return;
    }

    std::vector<DiscoveredTarget> found;
    {
        std::lock_guard<std::mutex> lock(scan_mutex_);
        found.swap(pending_discovered_);
    }

    std::size_t added = 0;
    for (const auto& t : found) {
        if (add_host(t.ip, t.label, t.category)) {
            ++added;
        }
    }

    status_msg_ = (added > 0)
        ? ("Scan done: +" + std::to_string(added) + " new host(s)")
        : "Scan done: all LAN/VPN hosts up to date";
    status_expiry_ = std::chrono::steady_clock::now() + std::chrono::seconds(4);
}

std::string NetworkMonitor::status_message() const {
    if (scan_in_progress_.load(std::memory_order_relaxed)) {
        return "Scanning LAN, ARP & Tailscale...";
    }
    if (!status_msg_.empty() && std::chrono::steady_clock::now() < status_expiry_) {
        return status_msg_;
    }
    return {};
}

void NetworkMonitor::add_default_hosts() {
    discover_and_add_network_devices();
    (void)load_or_create_config_file(config_.config_file_path);

    add_host("1.1.1.1", "Cloudflare DNS", HostCategory::Internet);
    add_host("8.8.8.8", "Google Public DNS", HostCategory::Internet);
    add_host("9.9.9.9", "Quad9 Security DNS", HostCategory::Internet);
    add_host("dns://1.1.1.1", "Cloudflare DNS53", HostCategory::Internet);
    add_host("dns://8.8.8.8", "Google DNS53", HostCategory::Internet);
    if (socket_.is_v6_open()) {
        add_host("2606:4700:4700::1111", "Cloudflare IPv6", HostCategory::Internet);
    }
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

    if (!target.is_ipv6) {
        if (const auto gw = NetDiscovery::detect_default_gateway(); gw.has_value()) {
            MtrHop hop1{};
            hop1.hop_index = 1;
            hop1.reachable = true;
            hop1.entry.display_name = "Hop 1 (Gateway)";
            hop1.entry.hostname = *gw;
            hop1.entry.resolved_ip = *gw;
            hop1.entry.addr.sin_family = AF_INET;
            (void)::inet_pton(AF_INET, gw->c_str(), &hop1.entry.addr.sin_addr);
            hop1.entry.status = HostStatus::Pending;
            hop1.entry.asn_info = NetDiscovery::lookup_asn_and_geo(*gw);
            hop1.entry.path_mtu = NetDiscovery::detect_route_mtu(*gw, false);
            mtr_hops_.push_back(std::move(hop1));
        }
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
                    hop.entry.asn_info = NetDiscovery::lookup_asn_and_geo(token);
                    hop.entry.path_mtu = NetDiscovery::detect_route_mtu(token, false);
                } else {
                    hop.reachable = false;
                    hop.entry.display_name = "Hop " + std::to_string(hop_num);
                    hop.entry.hostname = "*";
                    hop.entry.resolved_ip = "* (No ICMP Reply)";
                    hop.entry.status = HostStatus::Offline;
                    hop.entry.asn_info = "---";
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

[[nodiscard]] static int normalize_input_key(const char* buf, ssize_t len) noexcept {
    if (len <= 0) {
        return 0;
    }
    if (len == 1) {
        return static_cast<unsigned char>(buf[0]);
    }

    const auto b0 = static_cast<std::uint8_t>(buf[0]);
    const auto b1 = static_cast<std::uint8_t>(buf[1]);
    std::uint32_t cp = 0;

    if ((b0 & 0xE0U) == 0xC0U && len >= 2) {
        cp = ((static_cast<std::uint32_t>(b0) & 0x1FU) << 6U) |
             (static_cast<std::uint32_t>(b1) & 0x3FU);
    } else if ((b0 & 0xF0U) == 0xE0U && len >= 3) {
        const auto b2 = static_cast<std::uint8_t>(buf[2]);
        cp = ((static_cast<std::uint32_t>(b0) & 0x0FU) << 12U) |
             ((static_cast<std::uint32_t>(b1) & 0x3FU) << 6U)  |
             (static_cast<std::uint32_t>(b2) & 0x3FU);
    } else {
        return static_cast<unsigned char>(buf[0]);
    }

    switch (cp) {
        // --- 'd' (Scan) ---
        case 0x0432: case 0x0412: // Cyrillic 'в' / 'В' (physical D)
        case 0x0434: case 0x0414: // Cyrillic 'д' / 'Д' (phonetic D)
        case 0x03B4: case 0x0394: // Greek 'δ' / 'Δ' (Delta)
        case 0x03B3: case 0x0393: // Greek 'γ' / 'Γ' (physical D)
        case 0x05D2: case 0x05D3: // Hebrew 'ג' (physical D) / 'ד' (Dalet)
        case 0x064A: case 0x062F: // Arabic 'ي' (physical D) / 'د' (Dal)
        case 0x10D3:             // Georgian 'დ' (D)
        case 0x0564: case 0x057F: // Armenian 'դ' / 'տ' (physical D)
            return 'd';

        // --- 'q' (Quit) ---
        case 0x0439: case 0x0419: // Cyrillic 'й' / 'Й' (physical Q)
        case 0x05E7:             // Hebrew 'ק' (Qof)
        case 0x0636:             // Arabic 'ض' (physical Q)
        case 0x10E5:             // Georgian 'ქ' (physical Q)
        case 0x0584:             // Armenian 'ք' (physical Q)
            return 'q';

        // --- 't' (MTR) ---
        case 0x0435: case 0x0415: // Cyrillic 'е' / 'Е' (physical T)
        case 0x03C4: case 0x03A4: // Greek 'τ' / 'Τ' (Tau)
        case 0x05D0: case 0x05D8: case 0x05EA: // Hebrew 'א' / 'ט' / 'ת'
        case 0x0641:             // Arabic 'ف' (physical T)
        case 0x10D7: case 0x10E2: // Georgian 'თ' / 'ტ'
        case 0x0569:             // Armenian 'թ'
            return 't';

        // --- 'm' (MTU) ---
        case 0x044C: case 0x042C: // Cyrillic 'ь' / 'Ь' (physical M)
        case 0x03BC: case 0x039C: // Greek 'μ' / 'Μ' (Mu)
        case 0x05E6: case 0x05DE: case 0x05DD: // Hebrew 'צ' / 'מ' / 'ם'
        case 0x0629: case 0x0645: // Arabic 'ة' / 'م'
        case 0x10DB:             // Georgian 'მ' (physical M)
        case 0x0574:             // Armenian 'մ' (physical M)
            return 'm';

        // --- 'g' (Group) ---
        case 0x043F: case 0x041F: // Cyrillic 'п' / 'П' (physical G)
        case 0x0433: case 0x0413: // Cyrillic 'г' / 'Г' (phonetic G)
        case 0x05E2:             // Hebrew 'ע' (physical G)
        case 0x0644: case 0x063A: // Arabic 'ل' / 'غ'
        case 0x10D2:             // Georgian 'გ' (physical G)
        case 0x0563:             // Armenian 'գ' (physical G)
            return 'g';

        // --- 's' (Sort) ---
        case 0x044B: case 0x042B: // Cyrillic 'ы' / 'Ы' (physical S)
        case 0x0456: case 0x0406: // Ukrainian 'і' / 'І' (physical S)
        case 0x0441: case 0x0421: // Cyrillic 'с' / 'С' (phonetic S)
        case 0x03C3: case 0x03A3: case 0x03C2: // Greek 'σ' / 'Σ' / 'ς' (Sigma)
        case 0x05E1: case 0x05E9: // Hebrew 'ס' / 'ש'
        case 0x0633: case 0x0635: // Arabic 'س' / 'ص'
        case 0x10E1:             // Georgian 'ს' (physical S)
        case 0x057D:             // Armenian 'ս' (physical S)
            return 's';

        // --- 'p' (Pause) ---
        case 0x0437: case 0x0417: // Cyrillic 'з' / 'З' (physical P)
        case 0x03C0: case 0x03A0: // Greek 'π' / 'Π' (Pi)
        case 0x05E4: case 0x05E3: // Hebrew 'פ' / 'ף' (Pe)
        case 0x062D:             // Arabic 'ح' (physical P)
        case 0x10DE: case 0x10E4: // Georgian 'პ' / 'ფ'
        case 0x057A: case 0x0583: // Armenian 'պ' / 'փ'
            return 'p';

        // --- 'r' (Reset) ---
        case 0x043A: case 0x041A: // Cyrillic 'к' / 'К' (physical R)
        case 0x0440: case 0x0420: // Cyrillic 'р' / 'Р' (phonetic R)
        case 0x03C1: case 0x03A1: // Greek 'ρ' / 'Ρ' (Rho)
        case 0x05E8:             // Hebrew 'ר' (Resh)
        case 0x0642: case 0x0631: // Arabic 'ق' / 'ر'
        case 0x10E0:             // Georgian 'რ' (physical R)
        case 0x0580: case 0x057C: // Armenian 'ր' / 'ռ'
            return 'r';

        // --- 'z' (Zero peaks) ---
        case 0x044F: case 0x042F: // Cyrillic 'я' / 'Я' (physical Z)
        case 0x03B6: case 0x0396: // Greek 'ζ' / 'Ζ' (Zeta)
        case 0x05D6:             // Hebrew 'ז' (Zayin)
        case 0x0626: case 0x0632: // Arabic 'ئ' / 'ز'
        case 0x10D6:             // Georgian 'ზ' (physical Z)
        case 0x0566:             // Armenian 'զ' (physical Z)
            return 'z';

        // --- 'v' (Detail graph) ---
        case 0x043C: case 0x041C: // Cyrillic 'м' / 'М' (physical V)
        case 0x03C9: case 0x03A9: // Greek 'ω' / 'Ω' (Omega)
        case 0x05D4: case 0x05D5: // Hebrew 'ה' / 'ו'
        case 0x0648:             // Arabic 'و'
        case 0x10D5:             // Georgian 'ვ' (physical V)
        case 0x057E:             // Armenian 'վ' (physical V)
            return 'v';

        // --- 'b' (Back / Iface prev) ---
        case 0x0438: case 0x0418: // Cyrillic 'и' / 'И' (physical B)
        case 0x0431: case 0x0411: // Cyrillic 'б' / 'Б' (phonetic B)
        case 0x03B2: case 0x0392: // Greek 'β' / 'Β' (Beta)
        case 0x05E0: case 0x05D1: // Hebrew 'נ' / 'ב'
        case 0xFEFB: case 0x0628: // Arabic 'لا' / 'ب'
        case 0x10D1:             // Georgian 'ბ' (physical B)
        case 0x0562:             // Armenian 'բ' (physical B)
            return 'b';

        // --- 'n' (Iface next) ---
        case 0x0442: case 0x0422: // Cyrillic 'т' / 'Т' (physical N)
        case 0x043D: case 0x041D: // Cyrillic 'н' / 'Н' (phonetic N)
        case 0x03BD: case 0x039D: // Greek 'ν' / 'Ν' (Nu)
        case 0x0649:             // Arabic 'ى' (physical N)
        case 0x10DC:             // Georgian 'ნ' (physical N)
        case 0x0576:             // Armenian 'ն' (physical N)
            return 'n';

        // --- 'j' (Down) & 'k' (Up) ---
        case 0x043E: case 0x041E: // Cyrillic 'о' / 'О' (physical J)
        case 0x03BE: case 0x039E: // Greek 'ξ' / 'Ξ'
        case 0x05D7:             // Hebrew 'ח' (physical J)
        case 0x062A:             // Arabic 'ت' (physical J)
        case 0x10EF:             // Georgian 'ჯ'
        case 0x0575:             // Armenian 'յ'
            return 'j';

        case 0x043B: case 0x041B: // Cyrillic 'л' / 'Л' (physical K)
        case 0x03BA: case 0x039A: // Greek 'κ' / 'Κ' (Kappa)
        case 0x05DC:             // Hebrew 'ל' (Lamed)
        case 0x0646:             // Arabic 'ن' (physical K)
        case 0x10D9:             // Georgian 'კ'
        case 0x056F:             // Armenian 'կ'
            return 'k';

        // --- '[' & ']' (Iface cycle) ---
        case 0x0445: case 0x0425: // Cyrillic 'х' / 'Х' (physical [)
        case 0x062C:             // Arabic 'ج' (physical [)
            return '[';

        case 0x044A: case 0x042A: // Cyrillic 'ъ' / 'Ъ' (physical ])
        case 0x0457: case 0x0407: // Ukrainian 'ї' / 'Ї' (physical ])
            return ']';

        default:
            return static_cast<int>(cp);
    }
}

void NetworkMonitor::poll_once(int poll_timeout_ms, const std::function<void(int)>& on_key_pressed) {
    const auto now = std::chrono::steady_clock::now();

    apply_pending_discoveries();
    check_timeouts(now);

    const auto net_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_net_sample_time_);
    const long long sample_thresh = (completed_rounds_ <= 1) ? 100 : 300;
    if (last_net_sample_time_.time_since_epoch().count() == 0 || net_elapsed.count() >= sample_thresh) {
        NetDiscovery::sample_net_interfaces(net_interfaces_, last_net_sample_time_, now);
    }

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
    fds.reserve(5 + hosts_.size());

    int icmp_slot = -1;
    if (socket_.is_open()) {
        icmp_slot = static_cast<int>(fds.size());
        fds.push_back(pollfd{socket_.fd(), POLLIN, 0});
    }

    int icmp6_slot = -1;
    if (socket_.is_v6_open()) {
        icmp6_slot = static_cast<int>(fds.size());
        fds.push_back(pollfd{socket_.fd6(), POLLIN, 0});
    }

    const int stdin_slot = static_cast<int>(fds.size());
    fds.push_back(pollfd{STDIN_FILENO, POLLIN, 0});

    int mtr_slot = -1;
    if (mtr_pipe_fd_ >= 0) {
        mtr_slot = static_cast<int>(fds.size());
        fds.push_back(pollfd{mtr_pipe_fd_, POLLIN, 0});
    }

    struct ProbeSlot {
        std::size_t host_idx;
        std::size_t poll_idx;
    };
    std::vector<ProbeSlot> probe_slots;
    for (std::size_t i = 0; i < hosts_.size(); ++i) {
        if (hosts_[i].in_flight && hosts_[i].tcp_fd >= 0) {
            probe_slots.push_back({i, fds.size()});
            const short ev = (hosts_[i].probe_type == ProbeType::Dns) ? POLLIN : POLLOUT;
            fds.push_back(pollfd{hosts_[i].tcp_fd, ev, 0});
        }
    }

    const int ready = ::poll(fds.data(), static_cast<nfds_t>(fds.size()), poll_timeout_ms);
    const auto after_poll = std::chrono::steady_clock::now();

    if (ready > 0) {
        if ((icmp_slot >= 0 && (fds[static_cast<std::size_t>(icmp_slot)].revents & POLLIN) != 0) ||
            (icmp6_slot >= 0 && (fds[static_cast<std::size_t>(icmp6_slot)].revents & POLLIN) != 0)) {
            drain_replies(after_poll);
        }

        if (mtr_slot >= 0 && (fds[static_cast<std::size_t>(mtr_slot)].revents & (POLLIN | POLLHUP)) != 0) {
            read_mtr_pipe();
        }

        for (const auto& ps : probe_slots) {
            const short rev = fds[ps.poll_idx].revents;
            HostEntry& host = hosts_[ps.host_idx];

            if (host.probe_type == ProbeType::Dns) {
                if ((rev & (POLLIN | POLLERR | POLLHUP)) != 0) {
                    std::uint8_t rbuf[512]{};
                    const ssize_t n = ::recvfrom(host.tcp_fd, rbuf, sizeof(rbuf), 0, nullptr, nullptr);
                    close_tcp_probe(host);
                    if (n >= 12 && (rbuf[2] & 0x80U) != 0) {
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
            } else if ((rev & (POLLOUT | POLLERR | POLLHUP)) != 0) {
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
                    } else if (key_buf[2] == 'D') {
                        on_key_pressed(kKeyArrowLeft);
                    } else if (key_buf[2] == 'C') {
                        on_key_pressed(kKeyArrowRight);
                    }
                } else if (n == 1 && key_buf[0] == '\033') {
                    on_key_pressed(kKeyEscape);
                } else if (key_buf[0] == 127 || key_buf[0] == 8) {
                    on_key_pressed(kKeyBackspace);
                } else {
                    on_key_pressed(normalize_input_key(key_buf, n));
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

    if (host.probe_type == ProbeType::Dns) {
        const int domain = host.is_ipv6 ? AF_INET6 : AF_INET;
        const int sock = ::socket(domain, SOCK_DGRAM, IPPROTO_UDP);
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

        std::uint8_t dns_pkt[36]{};
        const auto tx_id = static_cast<std::uint16_t>((next_seq ^ (static_cast<std::uint32_t>(id_tag) << 8U) ^ 0xA5A5U) & 0xFFFFU);
        const std::size_t pkt_len = build_dns_benchmark_packet(tx_id, dns_pkt);

        host.last_send_time = std::chrono::steady_clock::now();
        const sockaddr* dst_sa = host.is_ipv6
            ? reinterpret_cast<const sockaddr*>(&host.addr6)
            : reinterpret_cast<const sockaddr*>(&host.addr);
        const socklen_t dst_len = host.is_ipv6 ? sizeof(host.addr6) : sizeof(host.addr);

        const ssize_t sent = ::sendto(sock, dns_pkt, pkt_len, 0, dst_sa, dst_len);
        if (sent == static_cast<ssize_t>(pkt_len)) {
            host.tcp_fd = sock;
        } else {
            ::close(sock);
            record_timeout(host);
        }
    } else if (host.probe_type == ProbeType::Tcp) {
        const int domain = host.is_ipv6 ? AF_INET6 : AF_INET;
        const int sock = ::socket(domain, SOCK_STREAM, 0);
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
        const sockaddr* dst_sa = host.is_ipv6
            ? reinterpret_cast<const sockaddr*>(&host.addr6)
            : reinterpret_cast<const sockaddr*>(&host.addr);
        const socklen_t dst_len = host.is_ipv6 ? sizeof(host.addr6) : sizeof(host.addr);

        const int rc = ::connect(sock, dst_sa, dst_len);
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
        const bool sent_ok = host.is_ipv6
            ? socket_.send_echo_request_v6(host.addr6, id_tag, next_seq, send_timestamp)
            : socket_.send_echo_request(host.addr, id_tag, next_seq, send_timestamp);
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
    auto process_reply = [&](const IcmpReply& reply) {
        if ((reply.host_index & kMtrHopFlag) != 0) {
            const std::size_t hop_idx = static_cast<std::size_t>(reply.host_index & ~kMtrHopFlag);
            if (mtr_active_ && hop_idx < mtr_hops_.size()) {
                HostEntry& hop_entry = mtr_hops_[hop_idx].entry;
                if (hop_entry.in_flight && reply.sequence == hop_entry.in_flight_seq) {
                    record_reply(hop_entry, reply.rtt_ms, reply.ttl);
                }
            }
            return;
        }

        if (reply.host_index < hosts_.size()) {
            HostEntry& host = hosts_[reply.host_index];
            if (host.in_flight && reply.sequence == host.in_flight_seq) {
                record_reply(host, reply.rtt_ms, reply.ttl);
            }
        }
    };

    while (true) {
        const auto reply_opt = socket_.receive_echo_reply(now);
        if (!reply_opt.has_value()) {
            break;
        }
        process_reply(*reply_opt);
    }

    while (true) {
        const auto reply6_opt = socket_.receive_echo_reply_v6(now);
        if (!reply6_opt.has_value()) {
            break;
        }
        process_reply(*reply6_opt);
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

void NetworkMonitor::cycle_net_interface(int delta) noexcept {
    if (net_interfaces_.empty()) {
        active_net_idx_ = 0;
        return;
    }
    const long long count = static_cast<long long>(net_interfaces_.size());
    const long long cur = static_cast<long long>(std::min(active_net_idx_, net_interfaces_.size() - 1));
    long long next = (cur + delta) % count;
    if (next < 0) {
        next += count;
    }
    active_net_idx_ = static_cast<std::size_t>(next);
}

void NetworkMonitor::reset_net_peaks() noexcept {
    for (auto& iface : net_interfaces_) {
        iface.rx_top_bps = iface.rx_speed_bps;
        iface.tx_top_bps = iface.tx_speed_bps;
        iface.rx_history.clear();
        iface.tx_history.clear();
    }
}

} // namespace pingtop
