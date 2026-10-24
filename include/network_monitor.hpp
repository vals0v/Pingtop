#pragma once

#include "icmp_socket.hpp"
#include "net_discovery.hpp"
#include "ring_buffer.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace pingtop {

enum class HostStatus {
    Pending,
    Online,
    Offline,
    DnsError
};

enum class ProbeType {
    Icmp,
    Tcp,
    Dns
};

enum class SortColumn {
    None,
    Latency,
    AvgLatency,
    Jitter,
    PacketLoss
};

struct LatencyPercentiles {
    double p50{0.0};
    double p90{0.0};
    double p95{0.0};
    double p99{0.0};
    double stddev{0.0};
};

struct HostEntry {
    static constexpr std::size_t kHistoryCapacity = 60;

    std::string   display_name;
    std::string   hostname;
    std::string   resolved_ip;
    sockaddr_in   addr{};
    sockaddr_in6  addr6{};
    bool          is_ipv6{false};
    HostStatus    status{HostStatus::Pending};
    ProbeType     probe_type{ProbeType::Icmp};
    std::uint16_t tcp_port{0};
    HostCategory  category{HostCategory::Internet};
    std::string   asn_info;
    std::uint16_t path_mtu{1500};
    bool          is_dynamic{false};

    std::uint64_t sent_count{0};
    std::uint64_t completed_count{0};
    std::uint64_t received_count{0};
    std::uint64_t lost_count{0};
    std::uint32_t last_sequence{0};
    std::uint8_t  last_ttl{0};

    bool                                  in_flight{false};
    std::uint32_t                         in_flight_seq{0};
    int                                   tcp_fd{-1};
    std::chrono::steady_clock::time_point last_send_time{};

    double last_rtt_ms{0.0};
    double min_rtt_ms{0.0};
    double avg_rtt_ms{0.0};
    double max_rtt_ms{0.0};
    double jitter_ms{0.0};
    double rtt_sum_ms{0.0};
    double prev_rtt_ms{-1.0};

    RingBuffer<double, kHistoryCapacity> history;

    [[nodiscard]] double packet_loss_percent() const noexcept {
        if (completed_count == 0) {
            return 0.0;
        }
        return (static_cast<double>(lost_count) * 100.0) / static_cast<double>(completed_count);
    }

    [[nodiscard]] LatencyPercentiles compute_percentiles() const;
    void reset_stats() noexcept;
};

struct MtrHop {
    int       hop_index{1};
    bool      reachable{false};
    HostEntry entry{};
};

struct MonitorConfig {
    std::chrono::milliseconds ping_interval{1000};
    std::chrono::milliseconds ping_timeout{900};
    std::uint64_t             max_cycles{0};
    std::string               config_file_path;
};

class NetworkMonitor {
public:
    static constexpr std::uint16_t kMtrHopFlag = 0x8000U;

    explicit NetworkMonitor(MonitorConfig config = {});
    ~NetworkMonitor();

    NetworkMonitor(const NetworkMonitor&) = delete;
    NetworkMonitor& operator=(const NetworkMonitor&) = delete;

    [[nodiscard]] bool initialize();

    bool add_host(
        const std::string& target,
        const std::string& custom_label = "",
        HostCategory category = HostCategory::Internet,
        bool is_dynamic = false
    );

    void add_default_hosts();

    [[nodiscard]] static std::string default_config_path();
    std::size_t load_or_create_config_file(const std::string& path = "");

    // Non-blocking background discovery of LAN, ARP & Tailscale/VPN targets
    void discover_and_add_network_devices();
    void trigger_async_scan();
    [[nodiscard]] bool is_scanning() const noexcept { return scan_in_progress_.load(std::memory_order_relaxed); }
    [[nodiscard]] std::string status_message() const;

    void run_mtu_discovery(std::size_t host_idx);

    // MTR / Traceroute engine
    void start_mtr(std::size_t host_idx);
    void stop_mtr() noexcept;
    [[nodiscard]] bool is_mtr_active() const noexcept { return mtr_active_; }
    [[nodiscard]] bool is_mtr_discovering() const noexcept { return mtr_pipe_ != nullptr; }
    [[nodiscard]] const std::string& mtr_target_name() const noexcept { return mtr_target_name_; }
    [[nodiscard]] const std::string& mtr_target_ip() const noexcept { return mtr_target_ip_; }
    [[nodiscard]] const std::vector<MtrHop>& mtr_hops() const noexcept { return mtr_hops_; }

    void poll_once(int poll_timeout_ms, const std::function<void(int)>& on_key_pressed);
    void reset_all_stats() noexcept;

    void toggle_pause() noexcept { paused_ = !paused_; }
    [[nodiscard]] bool is_paused() const noexcept { return paused_; }

    void adjust_interval(std::chrono::milliseconds delta) noexcept;
    void cycle_sort_column() noexcept;

    void cycle_net_interface(int delta) noexcept;
    void reset_net_peaks() noexcept;
    [[nodiscard]] const std::vector<NetInterfaceStats>& net_interfaces() const noexcept { return net_interfaces_; }
    [[nodiscard]] std::size_t active_net_index() const noexcept { return active_net_idx_; }

    [[nodiscard]] SortColumn sort_column() const noexcept { return sort_column_; }
    [[nodiscard]] std::string_view sort_column_name() const noexcept;
    [[nodiscard]] const std::vector<HostEntry>& hosts() const noexcept { return hosts_; }
    [[nodiscard]] const MonitorConfig& config() const noexcept { return config_; }
    [[nodiscard]] const IcmpSocket& socket() const noexcept { return socket_; }
    [[nodiscard]] std::uint64_t completed_rounds() const noexcept { return completed_rounds_; }
    [[nodiscard]] std::chrono::steady_clock::time_point start_time() const noexcept { return start_time_; }

    static constexpr int kKeyArrowUp    = -101;
    static constexpr int kKeyArrowDown  = -102;
    static constexpr int kKeyBackspace  = -103;
    static constexpr int kKeyEscape     = -104;
    static constexpr int kKeyArrowLeft  = -105;
    static constexpr int kKeyArrowRight = -106;

private:
    void apply_pending_discoveries();
    void dispatch_pings(std::chrono::steady_clock::time_point now);
    void dispatch_host_probe(HostEntry& host, std::uint16_t id_tag, std::chrono::steady_clock::time_point now);
    void check_timeouts(std::chrono::steady_clock::time_point now);
    void drain_replies(std::chrono::steady_clock::time_point now);
    void read_mtr_pipe();
    static void record_reply(HostEntry& host, double rtt_ms, std::uint8_t ttl) noexcept;
    static void record_timeout(HostEntry& host) noexcept;
    static void close_tcp_probe(HostEntry& host) noexcept;

    MonitorConfig                         config_;
    IcmpSocket                            socket_;
    std::vector<HostEntry>                hosts_;
    std::chrono::steady_clock::time_point start_time_;
    std::chrono::steady_clock::time_point last_batch_send_time_{};
    std::chrono::steady_clock::time_point last_net_sample_time_{};
    std::uint64_t                         completed_rounds_{0};
    bool                                  paused_{false};
    SortColumn                            sort_column_{SortColumn::None};
    std::vector<NetInterfaceStats>        net_interfaces_;
    std::size_t                           active_net_idx_{0};

    // Background scan state
    std::atomic<bool>                     scan_in_progress_{false};
    std::atomic<bool>                     scan_results_ready_{false};
    std::mutex                            scan_mutex_;
    std::vector<DiscoveredTarget>         pending_discovered_;
    std::thread                           scan_thread_;
    std::string                           status_msg_;
    std::chrono::steady_clock::time_point status_expiry_{};

    // MTR state
    bool                 mtr_active_{false};
    std::string          mtr_target_name_;
    std::string          mtr_target_ip_;
    std::vector<MtrHop>  mtr_hops_;
    FILE*                mtr_pipe_{nullptr};
    int                  mtr_pipe_fd_{-1};
    std::string          mtr_line_buf_;
};

} // namespace pingtop
