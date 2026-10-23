#include "tui_renderer.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <numeric>
#include <sys/ioctl.h>
#include <unistd.h>
#include <vector>

namespace pingtop {

namespace {

volatile std::sig_atomic_t g_terminate_requested = 0;
volatile std::sig_atomic_t g_window_resized = 1;

extern "C" void signal_handler(int sig) noexcept {
    if (sig == SIGINT || sig == SIGTERM) {
        g_terminate_requested = 1;
    } else if (sig == SIGWINCH) {
        g_window_resized = 1;
    }
}

constexpr const char* kAltScreenEnter = "\033[?1049h";
constexpr const char* kAltScreenExit  = "\033[?1049l";
constexpr const char* kCursorHide     = "\033[?25l";
constexpr const char* kCursorShow     = "\033[?25h";
constexpr const char* kCursorHome     = "\033[H";
constexpr const char* kClearScreen    = "\033[2J";
constexpr const char* kClearLineEnd   = "\033[K";
constexpr const char* kClearToBottom  = "\033[J";

constexpr const char* kReset          = "\033[0m";
constexpr const char* kBold           = "\033[1m";
constexpr const char* kFgWhite        = "\033[97m";
constexpr const char* kFgCyan         = "\033[96m";
constexpr const char* kFgGreen        = "\033[92m";
constexpr const char* kFgYellowGreen  = "\033[38;5;154m";
constexpr const char* kFgYellow       = "\033[93m";
constexpr const char* kFgOrange       = "\033[38;5;208m";
constexpr const char* kFgRed          = "\033[91m";
constexpr const char* kFgGray         = "\033[90m";
constexpr const char* kFgMagenta      = "\033[95m";
constexpr const char* kBgHeader       = "\033[48;5;236m";
constexpr const char* kBgSection      = "\033[48;5;235m";
constexpr const char* kBgSelected     = "\033[48;5;237m";
constexpr const char* kBgTitle        = "\033[48;5;24m";
constexpr const char* kBgKey          = "\033[48;5;238m";
constexpr const char* kBgSearch       = "\033[48;5;23m";

constexpr std::array<const char*, 8> kSparkBlocks = {
    " ", "▂", "▃", "▄", "▅", "▆", "▇", "█"
};

[[nodiscard]] std::string fit_string(std::string_view sv, std::size_t width, bool align_right = false) {
    if (sv.size() > width) {
        if (width > 2) {
            return std::string(sv.substr(0, width - 2)) + "..";
        }
        return std::string(sv.substr(0, width));
    }
    const std::size_t pad = width - sv.size();
    if (align_right) {
        return std::string(pad, ' ') + std::string(sv);
    }
    return std::string(sv) + std::string(pad, ' ');
}

[[nodiscard]] std::string format_metric(double val, bool valid, std::size_t width) {
    if (!valid) {
        return fit_string("---", width, true);
    }
    char buf[32]{};
    if (val < 10.0) {
        std::snprintf(buf, sizeof(buf), "%.2f", val);
    } else if (val < 100.0) {
        std::snprintf(buf, sizeof(buf), "%.1f", val);
    } else {
        std::snprintf(buf, sizeof(buf), "%.0f", val);
    }
    return fit_string(buf, width, true);
}

[[nodiscard]] std::string format_uptime(std::chrono::steady_clock::time_point start) {
    const auto now = std::chrono::steady_clock::now();
    const auto total_sec = std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
    const long long hrs = total_sec / 3600;
    const long long mins = (total_sec % 3600) / 60;
    const long long secs = total_sec % 60;
    char buf[32]{};
    std::snprintf(buf, sizeof(buf), "%02lld:%02lld:%02lld", hrs, mins, secs);
    return std::string(buf);
}

[[nodiscard]] bool icontains(std::string_view haystack, std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        }
    );
    return it != haystack.end();
}

[[nodiscard]] const char* category_header_title(HostCategory cat) noexcept {
    switch (cat) {
        case HostCategory::LocalLan:
            return " ▼ [ LOCAL GATEWAY & LAN ] ";
        case HostCategory::Vpn:
            return " ▼ [ VPN & TAILSCALE ] ";
        case HostCategory::Internet:
        default:
            return " ▼ [ INTERNET & WAN ] ";
    }
}

[[nodiscard]] std::string format_probe_badge(const HostEntry& h) {
    if (h.probe_type == ProbeType::Dns) {
        return "DNS:53";
    }
    if (h.probe_type == ProbeType::Tcp) {
        return "TCP:" + std::to_string(h.tcp_port);
    }
    return h.is_ipv6 ? "ICMPv6" : "ICMP";
}

} // namespace

TuiRenderer::TuiRenderer() noexcept {
    frame_buffer_.reserve(65536);
}

TuiRenderer::~TuiRenderer() noexcept {
    shutdown();
}

bool TuiRenderer::initialize() noexcept {
    if (initialized_) {
        return true;
    }

    struct sigaction sa{};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    (void)::sigaction(SIGINT, &sa, nullptr);
    (void)::sigaction(SIGTERM, &sa, nullptr);
    (void)::sigaction(SIGWINCH, &sa, nullptr);

    if (::isatty(STDIN_FILENO) != 0) {
        if (::tcgetattr(STDIN_FILENO, &orig_termios_) == 0) {
            termios_saved_ = true;
            termios raw = orig_termios_;
            raw.c_lflag &= ~static_cast<tcflag_t>(ICANON | ECHO);
            raw.c_cc[VMIN] = 0;
            raw.c_cc[VTIME] = 0;
            (void)::tcsetattr(STDIN_FILENO, TCSANOW, &raw);
        }
    }

    std::string init_seq;
    init_seq.append(kAltScreenEnter)
            .append(kCursorHide)
            .append(kClearScreen)
            .append(kCursorHome);
    (void)::write(STDOUT_FILENO, init_seq.data(), init_seq.size());

    update_terminal_size();
    initialized_ = true;
    return true;
}

void TuiRenderer::shutdown() noexcept {
    if (!initialized_) {
        return;
    }

    std::string exit_seq;
    exit_seq.append(kReset)
            .append(kCursorShow)
            .append(kAltScreenExit);
    (void)::write(STDOUT_FILENO, exit_seq.data(), exit_seq.size());

    if (termios_saved_) {
        (void)::tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios_);
        termios_saved_ = false;
    }

    initialized_ = false;
}

bool TuiRenderer::should_quit() noexcept {
    return g_terminate_requested != 0;
}

void TuiRenderer::request_quit() noexcept {
    g_terminate_requested = 1;
}

void TuiRenderer::stop_search(bool clear_filter) noexcept {
    search_active_ = false;
    if (clear_filter) {
        filter_query_.clear();
        selected_row_ = 0;
    }
}

void TuiRenderer::append_search_char(char c) {
    if (filter_query_.size() < 40 && std::isprint(static_cast<unsigned char>(c)) != 0) {
        filter_query_.push_back(c);
        selected_row_ = 0;
    }
}

void TuiRenderer::pop_search_char() noexcept {
    if (!filter_query_.empty()) {
        filter_query_.pop_back();
        selected_row_ = 0;
    }
}

bool TuiRenderer::matches_filter(const HostEntry& host) const noexcept {
    if (filter_query_.empty()) {
        return true;
    }
    return icontains(host.display_name, filter_query_) ||
           icontains(host.hostname, filter_query_) ||
           icontains(host.resolved_ip, filter_query_) ||
           icontains(host.asn_info, filter_query_) ||
           (host.probe_type == ProbeType::Dns && icontains("dns", filter_query_)) ||
           (host.probe_type == ProbeType::Tcp && icontains("tcp", filter_query_)) ||
           (host.probe_type == ProbeType::Icmp && icontains("icmp", filter_query_)) ||
           (host.is_ipv6 && icontains("ipv6", filter_query_));
}

std::vector<std::size_t> TuiRenderer::build_visible_order(const NetworkMonitor& monitor) const {
    const auto& hosts = monitor.hosts();
    std::vector<std::size_t> order;
    order.reserve(hosts.size());

    for (std::size_t i = 0; i < hosts.size(); ++i) {
        if (matches_filter(hosts[i])) {
            order.push_back(i);
        }
    }

    const SortColumn sort_col = monitor.sort_column();
    std::stable_sort(order.begin(), order.end(), [&](std::size_t a, std::size_t b) {
        const HostEntry& ha = hosts[a];
        const HostEntry& hb = hosts[b];

        if (group_by_category_ && ha.category != hb.category) {
            return static_cast<int>(ha.category) < static_cast<int>(hb.category);
        }

        switch (sort_col) {
            case SortColumn::Latency:    return ha.last_rtt_ms > hb.last_rtt_ms;
            case SortColumn::AvgLatency: return ha.avg_rtt_ms > hb.avg_rtt_ms;
            case SortColumn::Jitter:     return ha.jitter_ms > hb.jitter_ms;
            case SortColumn::PacketLoss: return ha.packet_loss_percent() > hb.packet_loss_percent();
            case SortColumn::None:
            default:                     return a < b;
        }
    });

    return order;
}

void TuiRenderer::move_selection(int delta, const NetworkMonitor& monitor) noexcept {
    const auto order = build_visible_order(monitor);
    if (order.empty()) {
        selected_row_ = 0;
        return;
    }
    const long long current = static_cast<long long>(std::min(selected_row_, order.size() - 1));
    const long long count = static_cast<long long>(order.size());
    long long next = (current + delta) % count;
    if (next < 0) {
        next += count;
    }
    selected_row_ = static_cast<std::size_t>(next);
}

std::size_t TuiRenderer::selected_host_index(const NetworkMonitor& monitor) const {
    const auto order = build_visible_order(monitor);
    if (order.empty()) {
        return 0;
    }
    const std::size_t clamped = std::min(selected_row_, order.size() - 1);
    return order[clamped];
}

void TuiRenderer::update_terminal_size() noexcept {
    winsize ws{};
    if (::ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
        term_width_ = std::max(84, static_cast<int>(ws.ws_col));
        term_height_ = std::max(20, static_cast<int>(ws.ws_row));
    } else {
        term_width_ = 120;
        term_height_ = 32;
    }
}

const char* TuiRenderer::latency_color(double rtt_ms) noexcept {
    if (rtt_ms < 0.0)   return kFgRed;
    if (rtt_ms < 25.0)  return kFgGreen;
    if (rtt_ms < 60.0)  return kFgYellowGreen;
    if (rtt_ms < 120.0) return kFgYellow;
    if (rtt_ms < 220.0) return kFgOrange;
    return kFgRed;
}

const char* TuiRenderer::loss_color(double loss_pct) noexcept {
    if (loss_pct <= 0.01) return kFgGreen;
    if (loss_pct < 5.0)   return kFgYellow;
    if (loss_pct < 20.0)  return kFgOrange;
    return kFgRed;
}

const char* TuiRenderer::jitter_color(double jitter_ms) noexcept {
    if (jitter_ms < 5.0)  return kFgGreen;
    if (jitter_ms < 15.0) return kFgYellowGreen;
    if (jitter_ms < 30.0) return kFgYellow;
    return kFgRed;
}

std::string TuiRenderer::build_sparkline(
    const RingBuffer<double, HostEntry::kHistoryCapacity>& history,
    std::size_t width
) {
    if (width == 0) {
        return {};
    }

    std::string out;
    out.reserve(width * 20);

    const std::size_t hist_size = history.size();
    const std::size_t visible_count = std::min(hist_size, width);
    const std::size_t start_idx = hist_size - visible_count;

    double min_val = 1e9;
    double max_val = 0.0;
    bool has_valid = false;

    for (std::size_t i = start_idx; i < hist_size; ++i) {
        const double v = history[i];
        if (v >= 0.0) {
            min_val = std::min(min_val, v);
            max_val = std::max(max_val, v);
            has_valid = true;
        }
    }

    if (!has_valid) {
        min_val = 0.0;
        max_val = 100.0;
    }

    const double span = std::max(10.0, max_val - min_val * 0.7);
    const double base = min_val * 0.7;

    for (std::size_t i = 0; i < visible_count; ++i) {
        const double sample = history[start_idx + i];
        if (sample < 0.0) {
            out.append(kFgRed).append("×");
        } else {
            const double normalized = std::clamp((sample - base) / span, 0.0, 1.0);
            const auto level = std::clamp(
                static_cast<std::size_t>(std::llround(normalized * 6.0) + 1),
                std::size_t{1},
                std::size_t{7}
            );
            out.append(latency_color(sample)).append(kSparkBlocks[level]);
        }
    }

    if (visible_count < width) {
        out.append(kFgGray);
        for (std::size_t i = visible_count; i < width; ++i) {
            out.append("·");
        }
    }

    out.append(kReset);
    return out;
}

void TuiRenderer::render(const NetworkMonitor& monitor) {
    if (g_window_resized != 0) {
        g_window_resized = 0;
        update_terminal_size();
        frame_buffer_.assign(kClearScreen);
    } else {
        frame_buffer_.clear();
    }

    frame_buffer_.append(kCursorHome);

    const auto order = build_visible_order(monitor);
    if (selected_row_ >= order.size() && !order.empty()) {
        selected_row_ = order.size() - 1;
    }

    append_header(monitor);

    switch (view_mode_) {
        case ViewMode::Table:
            append_table_view(monitor, order);
            break;
        case ViewMode::Detail:
            append_detail_view(monitor, order);
            break;
        case ViewMode::Mtr:
            append_mtr_view(monitor);
            break;
    }

    append_footer(monitor, order);
    frame_buffer_.append(kClearToBottom);

    (void)::write(STDOUT_FILENO, frame_buffer_.data(), frame_buffer_.size());
}

void TuiRenderer::append_header(const NetworkMonitor& monitor) {
    const auto& hosts = monitor.hosts();
    std::size_t online_count = 0;
    std::size_t offline_count = 0;
    double global_rtt_sum = 0.0;
    std::size_t rtt_hosts = 0;
    std::uint64_t total_completed = 0;
    std::uint64_t total_lost = 0;

    for (const auto& h : hosts) {
        if (h.status == HostStatus::Online) {
            ++online_count;
        } else if (h.status == HostStatus::Offline || h.status == HostStatus::DnsError) {
            ++offline_count;
        }
        if (h.received_count > 0) {
            global_rtt_sum += h.last_rtt_ms;
            ++rtt_hosts;
        }
        total_completed += h.completed_count;
        total_lost += h.lost_count;
    }

    const double mean_rtt = (rtt_hosts > 0) ? (global_rtt_sum / static_cast<double>(rtt_hosts)) : 0.0;
    const double global_loss = (total_completed > 0)
        ? (static_cast<double>(total_lost) * 100.0 / static_cast<double>(total_completed))
        : 0.0;

    const char* mode_badge = "[VIEW: TABLE]";
    if (view_mode_ == ViewMode::Detail) {
        mode_badge = "[VIEW: 2D GRAPH & PERCENTILES]";
    } else if (view_mode_ == ViewMode::Mtr) {
        mode_badge = "[VIEW: MTR / TRACEROUTE]";
    }

    frame_buffer_.append(kBgTitle).append(kBold).append(kFgWhite);
    frame_buffer_.append(" ⚡ PINGTOP v1.2 — Network Latency, MTR & Quality Monitor ");
    frame_buffer_.append(kFgCyan).append(" ").append(mode_badge).append(" ");
    frame_buffer_.append(kFgWhite).append(" [ICMP: ").append(monitor.socket().mode_string()).append("] ");
    if (monitor.is_paused()) {
        frame_buffer_.append(kFgYellow).append(kBold).append(" [PAUSED] ");
    }
    frame_buffer_.append(kClearLineEnd).append(kReset).append("\n");

    char summary_buf[256]{};
    std::snprintf(
        summary_buf,
        sizeof(summary_buf),
        " Hosts: %zu (%zu up / %zu down) │ Mean RTT: %.1f ms │ Loss: %.1f%% │ Int: %lld ms │ Sort: %.*s │ Group: %s │ Uptime: %s",
        hosts.size(),
        online_count,
        offline_count,
        mean_rtt,
        global_loss,
        static_cast<long long>(monitor.config().ping_interval.count()),
        static_cast<int>(monitor.sort_column_name().size()),
        monitor.sort_column_name().data(),
        group_by_category_ ? "ON" : "OFF",
        format_uptime(monitor.start_time()).c_str()
    );

    frame_buffer_.append(kBold).append(kFgWhite).append(summary_buf).append(kReset).append(kClearLineEnd).append("\n");

    frame_buffer_.append(kFgGray);
    for (int i = 0; i < term_width_; ++i) {
        frame_buffer_.append("─");
    }
    frame_buffer_.append(kReset).append(kClearLineEnd).append("\n");
}

void TuiRenderer::append_host_row(const HostEntry& h, bool is_selected, std::size_t spark_width) {
    if (is_selected) {
        frame_buffer_.append(kBgSelected).append(kBold);
    }

    frame_buffer_.append(is_selected ? "\033[96m▸" : " ");
    frame_buffer_.append(kFgWhite).append(fit_string(h.display_name, 18)).append(" ");
    frame_buffer_.append(kFgGray).append(fit_string(h.resolved_ip, 15)).append(" ");

    const char* proto_color = kFgCyan;
    if (h.probe_type == ProbeType::Tcp) {
        proto_color = kFgMagenta;
    } else if (h.probe_type == ProbeType::Dns) {
        proto_color = kFgYellow;
    } else if (h.is_ipv6) {
        proto_color = kFgYellowGreen;
    }
    frame_buffer_.append(proto_color)
                 .append(fit_string(format_probe_badge(h), 7))
                 .append(" ");

    switch (h.status) {
        case HostStatus::Online:   frame_buffer_.append(kFgGreen).append(fit_string("● ONLINE", 8)); break;
        case HostStatus::Offline:  frame_buffer_.append(kFgRed).append(fit_string("✖ DOWN  ", 8)); break;
        case HostStatus::Pending:  frame_buffer_.append(kFgYellow).append(fit_string("◌ WAIT  ", 8)); break;
        case HostStatus::DnsError: frame_buffer_.append(kFgRed).append(fit_string("! DNSERR", 8)); break;
    }
    frame_buffer_.append(" ");

    const double loss = h.packet_loss_percent();
    char loss_buf[16]{};
    std::snprintf(loss_buf, sizeof(loss_buf), "%.1f%%", loss);
    frame_buffer_.append(loss_color(loss)).append(fit_string(loss_buf, 6, true)).append(" ");

    const bool has_samples = (h.received_count > 0);
    const bool last_valid = (h.status == HostStatus::Online && has_samples);

    frame_buffer_.append(last_valid ? latency_color(h.last_rtt_ms) : kFgRed)
                 .append(format_metric(h.last_rtt_ms, last_valid, 6))
                 .append(" ");

    frame_buffer_.append(has_samples ? latency_color(h.min_rtt_ms) : kFgGray)
                 .append(format_metric(h.min_rtt_ms, has_samples, 6))
                 .append(" ");

    frame_buffer_.append(has_samples ? latency_color(h.avg_rtt_ms) : kFgGray)
                 .append(format_metric(h.avg_rtt_ms, has_samples, 6))
                 .append(" ");

    frame_buffer_.append(has_samples ? latency_color(h.max_rtt_ms) : kFgGray)
                 .append(format_metric(h.max_rtt_ms, has_samples, 6))
                 .append(" ");

    frame_buffer_.append(has_samples ? jitter_color(h.jitter_ms) : kFgGray)
                 .append(format_metric(h.jitter_ms, has_samples, 6))
                 .append("  ");

    frame_buffer_.append(build_sparkline(h.history, spark_width));
    frame_buffer_.append(kClearLineEnd).append(kReset).append("\n");
}

void TuiRenderer::append_table_view(const NetworkMonitor& monitor, const std::vector<std::size_t>& order) {
    const auto& hosts = monitor.hosts();

    constexpr int kFixedColsWidth = 91;
    const std::size_t spark_width = static_cast<std::size_t>(
        std::clamp(term_width_ - kFixedColsWidth, 10, static_cast<int>(HostEntry::kHistoryCapacity))
    );

    frame_buffer_.append(kBgHeader).append(kBold).append(kFgCyan);
    frame_buffer_.append(" ")
                 .append(fit_string("TARGET", 18))
                 .append(" ")
                 .append(fit_string("IP ADDRESS", 15))
                 .append(" ")
                 .append(fit_string("PROTO", 7))
                 .append(" ")
                 .append(fit_string("STATUS", 8))
                 .append(" ")
                 .append(fit_string("LOSS%", 6, true))
                 .append(" ")
                 .append(fit_string("LAST", 6, true))
                 .append(" ")
                 .append(fit_string("MIN", 6, true))
                 .append(" ")
                 .append(fit_string("AVG", 6, true))
                 .append(" ")
                 .append(fit_string("MAX", 6, true))
                 .append(" ")
                 .append(fit_string("JITTER", 6, true))
                 .append("  ")
                 .append(fit_string("LATENCY SPARKLINE (ms)", spark_width))
                 .append(kClearLineEnd)
                 .append(kReset)
                 .append("\n");

    const std::size_t max_body_lines = static_cast<std::size_t>(std::max(5, term_height_ - 9));
    std::size_t lines_used = 0;

    if (order.empty()) {
        frame_buffer_.append(kFgYellow)
                     .append("   No hosts match filter '")
                     .append(filter_query_)
                     .append("'. Press Esc to clear filter.")
                     .append(kReset)
                     .append(kClearLineEnd)
                     .append("\n");
        ++lines_used;
    } else {
        std::optional<HostCategory> prev_cat;
        for (std::size_t row = 0; row < order.size(); ++row) {
            if (lines_used >= max_body_lines) {
                break;
            }
            const HostEntry& h = hosts[order[row]];

            if (group_by_category_ && (!prev_cat.has_value() || *prev_cat != h.category)) {
                prev_cat = h.category;
                frame_buffer_.append(kBgSection).append(kBold).append(kFgYellow)
                             .append(category_header_title(h.category))
                             .append(kClearLineEnd).append(kReset).append("\n");
                ++lines_used;
                if (lines_used >= max_body_lines) {
                    break;
                }
            }

            append_host_row(h, row == selected_row_, spark_width);
            ++lines_used;
        }
    }

    while (lines_used < std::min<std::size_t>(hosts.size() + 4, max_body_lines)) {
        frame_buffer_.append(kClearLineEnd).append("\n");
        ++lines_used;
    }
}

void TuiRenderer::append_detail_view(const NetworkMonitor& monitor, const std::vector<std::size_t>& order) {
    const auto& hosts = monitor.hosts();
    if (order.empty()) {
        frame_buffer_.append(" No host selected.\n");
        return;
    }

    const HostEntry& h = hosts[order[std::min(selected_row_, order.size() - 1)]];
    const LatencyPercentiles pct = h.compute_percentiles();

    // 1. Target banner & Percentile cards
    frame_buffer_.append(kBgHeader).append(kBold).append(kFgCyan)
                 .append(" 📊 DETAILED ANALYTICS: ").append(kFgWhite).append(h.display_name)
                 .append(" (").append(h.resolved_ip).append(") ")
                 .append(kFgMagenta).append("[").append(format_probe_badge(h)).append("]")
                 .append(kFgGray).append("  — Press Enter or b to return to Table")
                 .append(kClearLineEnd).append(kReset).append("\n");

    char diag_buf[256]{};
    std::snprintf(
        diag_buf,
        sizeof(diag_buf),
        " GeoIP / ASN: %s  │  Path MTU: %u B (press 'm' to probe DF MTU)  │  Stack: %s  │  Last TTL: %u",
        h.asn_info.empty() ? "---" : h.asn_info.c_str(),
        static_cast<unsigned int>(h.path_mtu),
        h.is_ipv6 ? "IPv6" : "IPv4",
        static_cast<unsigned int>(h.last_ttl)
    );
    frame_buffer_.append(kBold).append(kFgCyan).append(diag_buf).append(kReset).append(kClearLineEnd).append("\n");

    char p_buf[256]{};
    std::snprintf(
        p_buf,
        sizeof(p_buf),
        " Percentiles:  p50 (Median): %.2f ms  │  p90: %.2f ms  │  p95: %.2f ms  │  p99: %.2f ms  │  StdDev (σ): %.2f ms  │  Jitter: %.2f ms",
        pct.p50, pct.p90, pct.p95, pct.p99, pct.stddev, h.jitter_ms
    );
    frame_buffer_.append(kBold).append(kFgYellow).append(p_buf).append(kReset).append(kClearLineEnd).append("\n\n");

    // 2. 2D Multi-line Latency Chart (8 rows tall)
    constexpr int kChartHeight = 8;
    const std::size_t chart_width = static_cast<std::size_t>(
        std::clamp(term_width_ - 16, 20, static_cast<int>(HostEntry::kHistoryCapacity))
    );
    const std::size_t hist_size = h.history.size();
    const std::size_t visible = std::min(hist_size, chart_width);
    const std::size_t start_idx = hist_size - visible;

    double max_rtt = 10.0;
    for (std::size_t i = start_idx; i < hist_size; ++i) {
        if (h.history[i] > max_rtt) {
            max_rtt = h.history[i];
        }
    }
    max_rtt = std::ceil(max_rtt * 1.15);

    frame_buffer_.append(kBold).append(kFgCyan)
                 .append(" 2D Latency History Graph (last ").append(std::to_string(visible)).append(" samples):")
                 .append(kReset).append(kClearLineEnd).append("\n");

    for (int row = kChartHeight - 1; row >= 0; --row) {
        const double row_threshold = (static_cast<double>(row) / static_cast<double>(kChartHeight)) * max_rtt;
        const double row_top = (static_cast<double>(row + 1) / static_cast<double>(kChartHeight)) * max_rtt;

        char y_label[16]{};
        std::snprintf(y_label, sizeof(y_label), "%7.1f ms │ ", row_top);
        frame_buffer_.append(kFgGray).append(y_label);

        for (std::size_t i = 0; i < visible; ++i) {
            const double val = h.history[start_idx + i];
            if (val < 0.0) {
                frame_buffer_.append(row == 0 ? "\033[91m×" : " ");
            } else if (val >= row_top) {
                frame_buffer_.append(latency_color(val)).append("█");
            } else if (val > row_threshold) {
                const double frac = (val - row_threshold) / (row_top - row_threshold);
                const auto sub = std::clamp(static_cast<std::size_t>(std::llround(frac * 7.0)), std::size_t{1}, std::size_t{7});
                frame_buffer_.append(latency_color(val)).append(kSparkBlocks[sub]);
            } else {
                frame_buffer_.append(" ");
            }
        }
        frame_buffer_.append(kReset).append(kClearLineEnd).append("\n");
    }

    frame_buffer_.append(kFgGray).append("    0.0 ms └");
    for (std::size_t i = 0; i < visible + 1; ++i) {
        frame_buffer_.append("─");
    }
    frame_buffer_.append(kReset).append(kClearLineEnd).append("\n\n");

    // 3. Latency Distribution Histogram
    frame_buffer_.append(kBold).append(kFgCyan)
                 .append(" Latency Distribution Histogram:")
                 .append(kReset).append(kClearLineEnd).append("\n");

    struct Bucket {
        const char* label;
        double low;
        double high;
        const char* color;
        std::size_t count{0};
    };

    std::array<Bucket, 5> buckets = {{
        {"  0 -  25 ms", 0.0,   25.0,  kFgGreen,       0},
        {" 25 -  60 ms", 25.0,  60.0,  kFgYellowGreen, 0},
        {" 60 - 120 ms", 60.0,  120.0, kFgYellow,      0},
        {"120 - 220 ms", 120.0, 220.0, kFgOrange,      0},
        {"  >= 220 ms ", 220.0, 1e9,   kFgRed,         0}
    }};

    std::size_t valid_total = 0;
    for (double v : h.history) {
        if (v >= 0.0) {
            ++valid_total;
            for (auto& b : buckets) {
                if (v >= b.low && v < b.high) {
                    ++b.count;
                    break;
                }
            }
        }
    }

    for (const auto& b : buckets) {
        const double ratio = (valid_total > 0)
            ? (static_cast<double>(b.count) / static_cast<double>(valid_total))
            : 0.0;
        const int bar_cells = static_cast<int>(std::llround(ratio * 30.0));

        frame_buffer_.append("  ").append(kFgWhite).append(b.label).append(" │ ").append(b.color);
        for (int c = 0; c < 30; ++c) {
            frame_buffer_.append(c < bar_cells ? "█" : "\033[90m░");
        }
        char stat_buf[48]{};
        std::snprintf(stat_buf, sizeof(stat_buf), " %5.1f%% (%zu)", ratio * 100.0, b.count);
        frame_buffer_.append(kReset).append(kFgWhite).append(stat_buf).append(kReset).append(kClearLineEnd).append("\n");
    }
}

void TuiRenderer::append_mtr_view(const NetworkMonitor& monitor) {
    frame_buffer_.append(kBgHeader).append(kBold).append(kFgCyan)
                 .append(" 🛰️  MTR / TRACEROUTE HOP-BY-HOP MONITOR: ")
                 .append(kFgWhite).append(monitor.mtr_target_name())
                 .append(" (").append(monitor.mtr_target_ip()).append(") ")
                 .append(monitor.is_mtr_discovering() ? "\033[93m[Scanning Hops...]" : "\033[92m[Route Ready]")
                 .append(kFgGray).append("  — Press t or b to return")
                 .append(kClearLineEnd).append(kReset).append("\n");

    constexpr int kFixedColsWidth = 88;
    const std::size_t spark_width = static_cast<std::size_t>(
        std::clamp(term_width_ - kFixedColsWidth, 10, static_cast<int>(HostEntry::kHistoryCapacity))
    );

    frame_buffer_.append(kBgSection).append(kBold).append(kFgCyan);
    frame_buffer_.append(" ")
                 .append(fit_string("HOP", 14))
                 .append(" ")
                 .append(fit_string("HOP IP", 15))
                 .append(" ")
                 .append(fit_string("GEO / ASN / ISP", 20))
                 .append(" ")
                 .append(fit_string("STATUS", 8))
                 .append(" ")
                 .append(fit_string("LOSS%", 6, true))
                 .append(" ")
                 .append(fit_string("LAST", 6, true))
                 .append(" ")
                 .append(fit_string("AVG", 6, true))
                 .append(" ")
                 .append(fit_string("JITTER", 6, true))
                 .append("  ")
                 .append(fit_string("HOP SPARKLINE", spark_width))
                 .append(kClearLineEnd).append(kReset).append("\n");

    const auto& hops = monitor.mtr_hops();
    if (hops.empty()) {
        frame_buffer_.append(kFgYellow)
                     .append("   Probing intermediate route hops to ")
                     .append(monitor.mtr_target_ip())
                     .append("...")
                     .append(kReset).append(kClearLineEnd).append("\n");
    } else {
        for (const auto& hop : hops) {
            const HostEntry& h = hop.entry;
            frame_buffer_.append(" ")
                         .append(kFgWhite).append(fit_string(h.display_name, 14)).append(" ")
                         .append(kFgGray).append(fit_string(h.resolved_ip, 15)).append(" ")
                         .append(kFgYellow).append(fit_string(h.asn_info.empty() ? "---" : h.asn_info, 20)).append(" ");

            switch (h.status) {
                case HostStatus::Online:   frame_buffer_.append(kFgGreen).append(fit_string("● ONLINE", 8)); break;
                case HostStatus::Offline:  frame_buffer_.append(kFgRed).append(fit_string("✖ DOWN  ", 8)); break;
                case HostStatus::Pending:  frame_buffer_.append(kFgYellow).append(fit_string("◌ WAIT  ", 8)); break;
                case HostStatus::DnsError: frame_buffer_.append(kFgRed).append(fit_string("! DNSERR", 8)); break;
            }
            frame_buffer_.append(" ");

            const double loss = h.packet_loss_percent();
            char loss_buf[16]{};
            std::snprintf(loss_buf, sizeof(loss_buf), "%.1f%%", loss);
            frame_buffer_.append(loss_color(loss)).append(fit_string(loss_buf, 6, true)).append(" ");

            const bool has_samples = (h.received_count > 0);
            const bool last_valid = (h.status == HostStatus::Online && has_samples);

            frame_buffer_.append(last_valid ? latency_color(h.last_rtt_ms) : kFgRed)
                         .append(format_metric(h.last_rtt_ms, last_valid, 6)).append(" ");
            frame_buffer_.append(has_samples ? latency_color(h.avg_rtt_ms) : kFgGray)
                         .append(format_metric(h.avg_rtt_ms, has_samples, 6)).append(" ");
            frame_buffer_.append(has_samples ? jitter_color(h.jitter_ms) : kFgGray)
                         .append(format_metric(h.jitter_ms, has_samples, 6)).append("  ");

            frame_buffer_.append(build_sparkline(h.history, spark_width));
            frame_buffer_.append(kClearLineEnd).append(kReset).append("\n");
        }
    }
}

void TuiRenderer::append_footer(const NetworkMonitor& monitor, const std::vector<std::size_t>& order) {
    frame_buffer_.append(kFgGray);
    for (int i = 0; i < term_width_; ++i) {
        frame_buffer_.append("─");
    }
    frame_buffer_.append(kReset).append(kClearLineEnd).append("\n");

    if (search_active_ || !filter_query_.empty()) {
        frame_buffer_.append(kBgSearch).append(kBold).append(kFgWhite)
                     .append(" 🔍 Filter: ").append(kFgYellow).append(filter_query_);
        if (search_active_) {
            frame_buffer_.append("█  (Type to filter, Enter to lock, Esc to clear)");
        } else {
            frame_buffer_.append("   (Press '/' to edit filter, Esc to clear)");
        }
        frame_buffer_.append(kClearLineEnd).append(kReset).append("\n");
    } else if (!order.empty()) {
        const HostEntry& sel = monitor.hosts()[order[std::min(selected_row_, order.size() - 1)]];
        const LatencyPercentiles pct = sel.compute_percentiles();

        char detail_buf[320]{};
        std::snprintf(
            detail_buf,
            sizeof(detail_buf),
            " Selected: %s (%s) │ ASN: %s │ MTU: %uB │ p50: %.1fms  p95: %.1fms  p99: %.1fms │ TTL: %u",
            sel.display_name.c_str(),
            sel.resolved_ip.c_str(),
            sel.asn_info.empty() ? "---" : sel.asn_info.c_str(),
            static_cast<unsigned int>(sel.path_mtu),
            pct.p50,
            pct.p95,
            pct.p99,
            static_cast<unsigned int>(sel.last_ttl)
        );
        frame_buffer_.append(kFgCyan).append(detail_buf).append(kReset).append(kClearLineEnd).append("\n");
    } else {
        frame_buffer_.append(kClearLineEnd).append("\n");
    }

    frame_buffer_.append(" Sparkline: ")
                 .append(kFgGreen).append("▂▃ <25ms ")
                 .append(kFgYellowGreen).append("▄ <60ms ")
                 .append(kFgYellow).append("▅▆ <120ms ")
                 .append(kFgOrange).append("▇ <220ms ")
                 .append(kFgRed).append("█ >=220ms × Loss")
                 .append(kFgGray).append("  │ Config: ~/.config/pingtop/hosts.conf")
                 .append(kReset).append(kClearLineEnd).append("\n");

    frame_buffer_.append(kBgKey).append(kBold)
                 .append(kFgCyan).append(" q ").append(kFgWhite).append("Quit ")
                 .append(kFgCyan).append(" Enter ").append(kFgWhite).append("2D Graph/p99 ")
                 .append(kFgCyan).append(" t ").append(kFgWhite).append("MTR Trace ")
                 .append(kFgCyan).append(" m ").append(kFgWhite).append("MTU Test ")
                 .append(kFgCyan).append(" / ").append(kFgWhite).append("Search ")
                 .append(kFgCyan).append(" g ").append(kFgWhite).append("Group ")
                 .append(kFgCyan).append(" d ").append(kFgWhite).append("Scan LAN/VPN ")
                 .append(kFgCyan).append(" s ").append(kFgWhite).append("Sort ")
                 .append(kFgCyan).append(" r ").append(kFgWhite).append("Reset ")
                 .append(kFgCyan).append(" p ").append(kFgWhite).append("Pause ")
                 .append(kFgCyan).append(" +/- ").append(kFgWhite).append("Int ")
                 .append(kClearLineEnd).append(kReset);
}

} // namespace pingtop
