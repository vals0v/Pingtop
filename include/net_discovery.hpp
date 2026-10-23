#pragma once

#include "ring_buffer.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace pingtop {

enum class HostCategory {
    LocalLan,
    Vpn,
    Internet
};

struct DiscoveredTarget {
    std::string  ip;
    std::string  label;
    HostCategory category{HostCategory::LocalLan};
};

struct NetInterfaceStats {
    static constexpr std::size_t kGraphCapacity = 80;

    std::string   name;
    std::string   ipv4;
    std::uint64_t rx_total{0};
    std::uint64_t tx_total{0};
    double        rx_speed_bps{0.0};
    double        tx_speed_bps{0.0};
    double        rx_top_bps{0.0};
    double        tx_top_bps{0.0};

    RingBuffer<double, kGraphCapacity> rx_history;
    RingBuffer<double, kGraphCapacity> tx_history;
};

// Dedicated service for OS network topology discovery, GeoIP/ASN, MTU & interface counters
class NetDiscovery {
public:
    [[nodiscard]] static bool is_tailscale_ip(std::string_view ip) noexcept;
    [[nodiscard]] static HostCategory classify_ip_category(std::string_view ip, HostCategory fallback) noexcept;

    [[nodiscard]] static std::string lookup_asn_and_geo(const std::string& ip);
    [[nodiscard]] static std::uint16_t detect_route_mtu(const std::string& ip, bool is_ipv6) noexcept;

    [[nodiscard]] static std::optional<std::string> detect_default_gateway();
    [[nodiscard]] static std::vector<std::string> get_local_ips();
    [[nodiscard]] static std::vector<DiscoveredTarget> discover_lan_devices();
    [[nodiscard]] static std::vector<DiscoveredTarget> discover_vpn_and_tailscale();
    [[nodiscard]] static std::vector<DiscoveredTarget> discover_all();

    static void sample_net_interfaces(
        std::vector<NetInterfaceStats>& interfaces,
        std::chrono::steady_clock::time_point& last_sample_time,
        std::chrono::steady_clock::time_point now
    );
};

} // namespace pingtop
