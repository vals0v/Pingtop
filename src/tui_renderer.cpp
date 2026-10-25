#include "tui_renderer.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string_view>
#include <sys/ioctl.h>
#include <unistd.h>

namespace pingtop {

namespace {

volatile std::sig_atomic_t g_terminate_requested = 0;
volatile std::sig_atomic_t g_window_resized = 0;

extern "C" void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        g_terminate_requested = 1;
    } else if (sig == SIGWINCH) {
        g_window_resized = 1;
    }
}

constexpr const char* kAltScreenEnter = "\033[?1049h";
constexpr const char* kAltScreenExit  = "\033[?1049l";
constexpr const char* kLineWrapOff    = "\033[?7l";
constexpr const char* kLineWrapOn     = "\033[?7h";
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
constexpr const char* kFgMagenta      = "\033[95m";
constexpr const char* kFgGray         = "\033[90m";
constexpr const char* kBgHeader       = "\033[48;5;236m";
constexpr const char* kBgSection      = "\033[48;5;235m";
constexpr const char* kBgSelected     = "\033[48;5;237m";
constexpr const char* kBgTitle        = "\033[48;5;24m";

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

[[nodiscard]] std::string format_byte_rate(double bps) {
    char buf[32]{};
    const double kib = bps / 1024.0;
    if (kib < 1000.0) {
        std::snprintf(buf, sizeof(buf), "%.1f KiB/s", kib);
    } else if (kib < 1024.0 * 1000.0) {
        std::snprintf(buf, sizeof(buf), "%.2f MiB/s", kib / 1024.0);
    } else {
        std::snprintf(buf, sizeof(buf), "%.2f GiB/s", kib / (1024.0 * 1024.0));
    }
    return std::string(buf);
}

[[nodiscard]] std::string format_bit_rate_parens(double bps) {
    char buf[32]{};
    const double kibit = (bps * 8.0) / 1024.0;
    if (kibit < 1000.0) {
        std::snprintf(buf, sizeof(buf), "(%.0f Kibps)", kibit);
    } else if (kibit < 1024.0 * 1000.0) {
        std::snprintf(buf, sizeof(buf), "(%.1f Mibps)", kibit / 1024.0);
    } else {
        std::snprintf(buf, sizeof(buf), "(%.2f Gibps)", kibit / (1024.0 * 1024.0));
    }
    return std::string(buf);
}

[[nodiscard]] std::string format_total_bytes(std::uint64_t bytes) {
    char buf[32]{};
    const double kib = static_cast<double>(bytes) / 1024.0;
    if (kib < 1024.0) {
        std::snprintf(buf, sizeof(buf), "%.0f KiB", kib);
    } else if (kib < 1024.0 * 1024.0) {
        std::snprintf(buf, sizeof(buf), "%.1f MiB", kib / 1024.0);
    } else if (kib < 1024.0 * 1024.0 * 1024.0) {
        std::snprintf(buf, sizeof(buf), "%.1f GiB", kib / (1024.0 * 1024.0));
    } else {
        std::snprintf(buf, sizeof(buf), "%.2f TiB", kib / (1024.0 * 1024.0 * 1024.0));
    }
    return std::string(buf);
}

[[nodiscard]] std::string format_scale_label(double max_bps) {
    char buf[16]{};
    const double kib = std::max(1.0, max_bps / 1024.0);
    if (kib < 1000.0) {
        std::snprintf(buf, sizeof(buf), "%.0fK", kib);
    } else if (kib < 1024.0 * 100.0) {
        std::snprintf(buf, sizeof(buf), "%.1fM", kib / 1024.0);
    } else {
        std::snprintf(buf, sizeof(buf), "%.0fM", kib / 1024.0);
    }
    return fit_string(buf, 5, true);
}

void append_block_graph_row(
    std::string& out,
    const RingBuffer<double, NetInterfaceStats::kGraphCapacity>& history,
    std::size_t width_cols,
    int row_idx,
    int total_rows,
    double max_scale,
    const char* color_ansi
) {
    out.append(color_ansi);
    const std::size_t total_samples = history.size();
    const double row_base = static_cast<double>(row_idx);
    const double row_ceil = static_cast<double>(row_idx + 1);

    for (std::size_t c = 0; c < width_cols; ++c) {
        double val = 0.0;
        if (width_cols > total_samples) {
            const std::size_t pad = width_cols - total_samples;
            if (c >= pad) {
                val = std::max(0.0, history[c - pad]);
            }
        } else {
            const std::size_t offset = total_samples - width_cols;
            val = std::max(0.0, history[offset + c]);
        }

        const double norm = (max_scale > 0.0)
            ? (val / max_scale) * static_cast<double>(total_rows)
            : 0.0;

        if (norm >= row_ceil) {
            out.append("█");
        } else if (norm > row_base) {
            const double frac = norm - row_base;
            const auto level = std::clamp(static_cast<std::size_t>(std::llround(frac * 7.0)), std::size_t{1}, std::size_t{7});
            out.append(kSparkBlocks[level]);
        } else {
            out.append(" ");
        }
    }
}

void append_status_cell(std::string& out, HostStatus status) {
    switch (status) {
        case HostStatus::Online:   out.append(kFgGreen).append("● ONLINE"); break;
        case HostStatus::Offline:  out.append(kFgRed).append("✖ DOWN  "); break;
        case HostStatus::Pending:  out.append(kFgYellow).append("◌ WAIT  "); break;
        case HostStatus::DnsError: out.append(kFgRed).append("! DNSERR"); break;
    }
}

} // namespace

TuiRenderer::TuiRenderer() noexcept {
    frame_buffer_.reserve(65536);
}

TuiRenderer::~TuiRenderer() noexcept {
    shutdown();
}

void TuiRenderer::install_signal_handlers() noexcept {
    struct sigaction sa{};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    (void)::sigaction(SIGINT, &sa, nullptr);
    (void)::sigaction(SIGTERM, &sa, nullptr);
    (void)::sigaction(SIGWINCH, &sa, nullptr);
}

bool TuiRenderer::initialize() noexcept {
    if (initialized_) {
        return true;
    }

    install_signal_handlers();

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
            .append(kLineWrapOff)
            .append(kCursorHide)
            .append(kClearScreen)
            .append(kCursorHome);
    (void)::write(STDOUT_FILENO, init_seq.data(), init_seq.size());

    (void)update_terminal_size();
    initialized_ = true;
    return true;
}

void TuiRenderer::shutdown() noexcept {
    if (!initialized_) {
        return;
    }

    std::string exit_seq;
    exit_seq.append(kReset)
            .append(kLineWrapOn)
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

bool TuiRenderer::update_terminal_size() noexcept {
    winsize ws{};
    if (::ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
        const int new_w = static_cast<int>(ws.ws_col);
        const int new_h = static_cast<int>(ws.ws_row);
        const bool changed = (new_w != term_width_ || new_h != term_height_);
        term_width_ = new_w;
        term_height_ = new_h;
        return changed;
    }
    return false;
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

// btop-style warning screen when terminal window is resized smaller than minimum dimensions
void TuiRenderer::append_too_small_warning() {
    const int pad_top = std::max(0, (term_height_ - 7) / 2);
    for (int r = 0; r < pad_top; ++r) {
        frame_buffer_.append(kClearLineEnd).append("\n");
    }

    auto center_pad = [&](int content_len) {
        const int left = std::max(1, (term_width_ - content_len) / 2);
        frame_buffer_.append(static_cast<std::size_t>(left), ' ');
    };

    const char* w_color = (term_width_ < kMinTermWidth) ? kFgRed : kFgGreen;
    const char* h_color = (term_height_ < kMinTermHeight) ? kFgRed : kFgGreen;

    center_pad(34);
    frame_buffer_.append(kBold).append(kFgRed).append("⚠  Terminal size too small!").append(kReset).append(kClearLineEnd).append("\n\n");

    char cur_buf[64]{};
    std::snprintf(cur_buf, sizeof(cur_buf), "Current size : %s%d%s cols x %s%d%s rows",
                  w_color, term_width_, kFgWhite, h_color, term_height_, kFgWhite);
    center_pad(32);
    frame_buffer_.append(kBold).append(kFgWhite).append(cur_buf).append(kReset).append(kClearLineEnd).append("\n");

    char min_buf[64]{};
    std::snprintf(min_buf, sizeof(min_buf), "Minimum size : %s%d%s cols x %s%d%s rows",
                  kFgCyan, kMinTermWidth, kFgWhite, kFgCyan, kMinTermHeight, kFgWhite);
    center_pad(32);
    frame_buffer_.append(kBold).append(kFgWhite).append(min_buf).append(kReset).append(kClearLineEnd).append("\n\n");

    center_pad(38);
    frame_buffer_.append(kFgGray).append("Resize window to resume (press q to quit)").append(kReset).append(kClearLineEnd);
}

void TuiRenderer::render(const NetworkMonitor& monitor) {
    const bool size_changed = update_terminal_size();
    if (g_window_resized != 0 || size_changed) {
        g_window_resized = 0;
        frame_buffer_.assign(kClearScreen);
    } else {
        frame_buffer_.clear();
    }

    frame_buffer_.append(kCursorHome);

    if (term_width_ < kMinTermWidth || term_height_ < kMinTermHeight) {
        append_too_small_warning();
        frame_buffer_.append(kClearToBottom);
        (void)::write(STDOUT_FILENO, frame_buffer_.data(), frame_buffer_.size());
        return;
    }

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

    const char* mode_badge = "[TABLE]";
    if (view_mode_ == ViewMode::Detail) {
        mode_badge = "[2D GRAPH]";
    } else if (view_mode_ == ViewMode::Mtr) {
        mode_badge = "[MTR]";
    }

    const std::string status_msg = monitor.status_message();

    frame_buffer_.append(kBgTitle).append(kBold).append(kFgWhite);
    if (term_width_ >= 96 && status_msg.empty()) {
        frame_buffer_.append(" ⚡ PINGTOP v1.4 — Network Latency, MTR & Quality Monitor ");
    } else {
        frame_buffer_.append(" ⚡ PINGTOP v1.4 ");
    }
    frame_buffer_.append(kFgCyan).append(" ").append(mode_badge).append(" ");
    if (term_width_ >= 80) {
        frame_buffer_.append(kFgWhite).append(" [ICMP: ").append(monitor.socket().mode_string()).append("] ");
    }
    if (monitor.is_exporter_active()) {
        frame_buffer_.append(kFgGreen).append(kBold)
                     .append(" [PROM :").append(std::to_string(monitor.exporter_port())).append("] ");
    }
    if (monitor.is_paused()) {
        frame_buffer_.append(kFgYellow).append(kBold).append(" [PAUSED] ");
    }
    if (!status_msg.empty()) {
        frame_buffer_.append(kFgYellow).append(kBold).append(" [").append(status_msg).append("] ");
    }
    frame_buffer_.append(kClearLineEnd).append(kReset).append("\n");

    char summary_buf[256]{};
    if (term_width_ >= 96) {
        std::snprintf(
            summary_buf,
            sizeof(summary_buf),
            " Hosts: %zu (%zu up/%zu down) │ Mean: %.1f ms │ Loss: %.1f%% │ Int: %lld ms │ Sort: %.*s │ Uptime: %s",
            hosts.size(),
            online_count,
            offline_count,
            mean_rtt,
            global_loss,
            static_cast<long long>(monitor.config().ping_interval.count()),
            static_cast<int>(monitor.sort_column_name().size()),
            monitor.sort_column_name().data(),
            format_uptime(monitor.start_time()).c_str()
        );
    } else {
        std::snprintf(
            summary_buf,
            sizeof(summary_buf),
            " Hosts: %zu (%zu/%zu) │ Mean: %.1fms │ Loss: %.1f%% │ Int: %lldms │ Up: %s",
            hosts.size(),
            online_count,
            offline_count,
            mean_rtt,
            global_loss,
            static_cast<long long>(monitor.config().ping_interval.count()),
            format_uptime(monitor.start_time()).c_str()
        );
    }

    frame_buffer_.append(kBold).append(kFgWhite).append(summary_buf).append(kReset).append(kClearLineEnd).append("\n");

    frame_buffer_.append(kFgGray);
    for (int i = 0; i < term_width_; ++i) {
        frame_buffer_.append("─");
    }
    frame_buffer_.append(kReset).append(kClearLineEnd).append("\n");
}

void TuiRenderer::append_host_row(const HostEntry& h, bool is_selected, std::size_t spark_width) {
    const bool wide_layout   = (term_width_ >= 104);
    const bool medium_layout = (term_width_ >= 82 && term_width_ < 104);
    const std::size_t name_w = wide_layout ? 18 : 15;

    if (is_selected) {
        frame_buffer_.append(kBgSelected).append(kBold);
    }

    frame_buffer_.append(is_selected ? "\033[96m▸" : " ");
    frame_buffer_.append(kFgWhite).append(fit_string(h.display_name, name_w)).append(" ");

    if (wide_layout || medium_layout) {
        frame_buffer_.append(kFgGray).append(fit_string(h.resolved_ip, 15)).append(" ");
    }

    const char* proto_color = kFgCyan;
    if (h.probe_type == ProbeType::Tcp) {
        proto_color = kFgMagenta;
    } else if (h.probe_type == ProbeType::Dns) {
        proto_color = kFgYellow;
    } else if (h.is_ipv6) {
        proto_color = kFgYellowGreen;
    }
    frame_buffer_.append(proto_color).append(fit_string(format_probe_badge(h), 7)).append(" ");

    append_status_cell(frame_buffer_, h.status);
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

    if (wide_layout) {
        frame_buffer_.append(has_samples ? latency_color(h.min_rtt_ms) : kFgGray)
                     .append(format_metric(h.min_rtt_ms, has_samples, 6))
                     .append(" ");
    }

    frame_buffer_.append(has_samples ? latency_color(h.avg_rtt_ms) : kFgGray)
                 .append(format_metric(h.avg_rtt_ms, has_samples, 6));

    if (wide_layout) {
        frame_buffer_.append(" ")
                     .append(has_samples ? latency_color(h.max_rtt_ms) : kFgGray)
                     .append(format_metric(h.max_rtt_ms, has_samples, 6));
    }

    if (wide_layout || medium_layout) {
        frame_buffer_.append(" ")
                     .append(has_samples ? jitter_color(h.jitter_ms) : kFgGray)
                     .append(format_metric(h.jitter_ms, has_samples, 6));
    }

    frame_buffer_.append("  ");
    frame_buffer_.append(build_sparkline(h.history, spark_width));
    frame_buffer_.append(kClearLineEnd).append(kReset).append("\n");
}

void TuiRenderer::append_table_view(const NetworkMonitor& monitor, const std::vector<std::size_t>& order) {
    const auto& hosts = monitor.hosts();

    const bool wide_layout   = (term_width_ >= 104);
    const bool medium_layout = (term_width_ >= 82 && term_width_ < 104);
    const std::size_t name_w = wide_layout ? 18 : 15;
    const int fixed_cols     = wide_layout ? 91 : (medium_layout ? 74 : 51);

    const std::size_t spark_width = static_cast<std::size_t>(
        std::clamp(term_width_ - fixed_cols, 6, static_cast<int>(HostEntry::kHistoryCapacity))
    );

    frame_buffer_.append(kBgHeader).append(kBold).append(kFgCyan).append(" ");
    frame_buffer_.append(fit_string("TARGET", name_w)).append(" ");
    if (wide_layout || medium_layout) {
        frame_buffer_.append(fit_string("IP ADDRESS", 15)).append(" ");
    }
    frame_buffer_.append(fit_string("PROTO", 7)).append(" ")
                 .append(fit_string("STATUS", 8)).append(" ")
                 .append(fit_string("LOSS%", 6, true)).append(" ")
                 .append(fit_string("LAST", 6, true)).append(" ");
    if (wide_layout) {
        frame_buffer_.append(fit_string("MIN", 6, true)).append(" ");
    }
    frame_buffer_.append(fit_string("AVG", 6, true));
    if (wide_layout) {
        frame_buffer_.append(" ").append(fit_string("MAX", 6, true));
    }
    if (wide_layout || medium_layout) {
        frame_buffer_.append(" ").append(fit_string("JITTER", 6, true));
    }
    frame_buffer_.append("  ")
                 .append(fit_string("SPARKLINE", spark_width))
                 .append(kClearLineEnd)
                 .append(kReset)
                 .append("\n");

    // Strict height budget: 4 header lines + footer_lines (12 when height>=24, 4 when compact)
    const int footer_lines = (term_height_ >= 24) ? 12 : 4;
    const std::size_t max_body_lines = static_cast<std::size_t>(std::max(4, term_height_ - 4 - footer_lines));
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
        const std::size_t approx_rows_per_screen = (max_body_lines > 3) ? (max_body_lines - 3) : max_body_lines;
        std::size_t start_row = 0;
        if (selected_row_ >= approx_rows_per_screen) {
            start_row = selected_row_ - approx_rows_per_screen + 1;
        }

        std::optional<HostCategory> prev_cat;
        for (std::size_t row = start_row; row < order.size(); ++row) {
            if (lines_used >= max_body_lines) {
                break;
            }
            const HostEntry& h = hosts[order[row]];

            if (group_by_category_ && (!prev_cat.has_value() || *prev_cat != h.category)) {
                if (lines_used + 1 >= max_body_lines) {
                    break;
                }
                prev_cat = h.category;
                frame_buffer_.append(kBgSection).append(kBold).append(kFgYellow)
                             .append(category_header_title(h.category))
                             .append(kClearLineEnd).append(kReset).append("\n");
                ++lines_used;
            }

            append_host_row(h, row == selected_row_, spark_width);
            ++lines_used;
        }
    }

    while (lines_used < max_body_lines) {
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

    const HostEntry& h = hosts[selected_host_index(monitor)];
    const LatencyPercentiles pct = h.compute_percentiles();

    frame_buffer_.append(kBgSection).append(kBold).append(kFgCyan)
                 .append(" 📊 DETAILED TELEMETRY: ")
                 .append(kFgWhite).append(h.display_name)
                 .append(" (").append(h.resolved_ip).append(") ")
                 .append(kFgYellow).append("[").append(format_probe_badge(h)).append("]")
                 .append(kFgGray).append("  — Press Enter or b to return")
                 .append(kClearLineEnd).append(kReset).append("\n");

    char meta_buf[256]{};
    std::snprintf(
        meta_buf,
        sizeof(meta_buf),
        " Geo / ASN: %-24s │ Path MTU: %u bytes │ Last TTL: %u │ Sent: %llu  Recv: %llu  Loss: %.1f%%",
        h.asn_info.empty() ? "---" : h.asn_info.c_str(),
        static_cast<unsigned int>(h.path_mtu),
        static_cast<unsigned int>(h.last_ttl),
        static_cast<unsigned long long>(h.sent_count),
        static_cast<unsigned long long>(h.received_count),
        h.packet_loss_percent()
    );
    frame_buffer_.append(kFgWhite).append(meta_buf).append(kReset).append(kClearLineEnd).append("\n");

    char pct_buf[256]{};
    std::snprintf(
        pct_buf,
        sizeof(pct_buf),
        " Percentiles:  p50 (Median): %.2f ms │ p90: %.2f ms │ p95: %.2f ms │ p99: %.2f ms │ StdDev (σ): %.2f ms",
        pct.p50, pct.p90, pct.p95, pct.p99, pct.stddev
    );
    frame_buffer_.append(kBold).append(kFgCyan).append(pct_buf).append(kReset).append(kClearLineEnd).append("\n\n");

    const int chart_height = (term_height_ >= 30) ? 7 : 4;
    const std::size_t chart_width = static_cast<std::size_t>(std::clamp(term_width_ - 16, 20, 60));
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

    for (int row = chart_height - 1; row >= 0; --row) {
        const double row_threshold = (static_cast<double>(row) / static_cast<double>(chart_height)) * max_rtt;
        const double row_top = (static_cast<double>(row + 1) / static_cast<double>(chart_height)) * max_rtt;

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
    frame_buffer_.append(kReset).append(kClearLineEnd).append("\n");
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
        std::clamp(term_width_ - kFixedColsWidth, 8, static_cast<int>(HostEntry::kHistoryCapacity))
    );

    frame_buffer_.append(kBgSection).append(kBold).append(kFgCyan)
                 .append(" ")
                 .append(fit_string("HOP", 14)).append(" ")
                 .append(fit_string("HOP IP", 15)).append(" ")
                 .append(fit_string("GEO / ASN / ISP", 20)).append(" ")
                 .append(fit_string("STATUS", 8)).append(" ")
                 .append(fit_string("LOSS%", 6, true)).append(" ")
                 .append(fit_string("LAST", 6, true)).append(" ")
                 .append(fit_string("AVG", 6, true)).append(" ")
                 .append(fit_string("JITTER", 6, true)).append("  ")
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

            append_status_cell(frame_buffer_, h.status);
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
    constexpr const char* kBorderColor = "\033[38;5;239m";
    constexpr const char* kBgKeyBar    = "\033[48;5;238m";
    const std::size_t W = static_cast<std::size_t>(std::max(kMinTermWidth, term_width_));

    // 1. Selected Host Telemetry Bar / Search Input
    if (search_active_ || !filter_query_.empty()) {
        frame_buffer_.append("\033[48;5;23m").append(kBold).append(kFgWhite)
                     .append(" 🔍 Filter: ").append(kFgYellow).append(filter_query_);
        if (search_active_) {
            frame_buffer_.append("█  (Enter to lock, Esc to clear)");
        } else {
            frame_buffer_.append("   ('/' to edit, Esc to clear)");
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
        frame_buffer_.append(kFgCyan).append(fit_string(detail_buf, W)).append(kReset).append(kClearLineEnd).append("\n");
    } else {
        frame_buffer_.append(kFgGray).append(" No host selected").append(kReset).append(kClearLineEnd).append("\n");
    }

    // 2. Active network interface stats
    NetInterfaceStats fallback_net{};
    fallback_net.name = "en0";
    fallback_net.ipv4 = "0.0.0.0";
    const auto& net_list = monitor.net_interfaces();
    const NetInterfaceStats& net = net_list.empty()
        ? fallback_net
        : net_list[std::min(monitor.active_net_index(), net_list.size() - 1)];

    const std::string rx_rate_str  = format_byte_rate(net.rx_speed_bps);
    const std::string rx_bits_str  = format_bit_rate_parens(net.rx_speed_bps);
    const std::string rx_top_str   = format_byte_rate(net.rx_top_bps);
    const std::string rx_total_str = format_total_bytes(net.rx_total);

    const std::string tx_rate_str  = format_byte_rate(net.tx_speed_bps);
    const std::string tx_bits_str  = format_bit_rate_parens(net.tx_speed_bps);
    const std::string tx_top_str   = format_byte_rate(net.tx_top_bps);
    const std::string tx_total_str = format_total_bytes(net.tx_total);

    // Compact vertical fallback when terminal height < 24 rows
    if (term_height_ < 24) {
        const std::string compact_hdr = " ▼ [ NET: " + net.name + " (" + net.ipv4 + ") " +
                                        std::to_string(net.mtu) + "B ] ";
        frame_buffer_.append(kBgSection).append(kBold).append(kFgYellow).append(compact_hdr)
                     .append(kFgCyan).append(" ▼ DL: ").append(rx_rate_str).append(" (Tot: ").append(rx_total_str).append(") ")
                     .append(kFgOrange).append(" ▲ UL: ").append(tx_rate_str).append(" (Tot: ").append(tx_total_str).append(")")
                     .append(kClearLineEnd).append(kReset).append("\n");
    } else {
        std::string iface_meta = net.name + " (" + net.ipv4 + ") MTU:" + std::to_string(net.mtu) + "B";
        if (!net.bond_info.empty()) {
            iface_meta += " " + net.bond_info;
        }
        const std::string iface_banner = " ▼ [ NETWORK TRAFFIC & INTERFACE: " + iface_meta + " ] ";
        const std::string iface_nav    = " [ < / > Switch Iface │ z Reset ] ";
        frame_buffer_.append(kBgSection).append(kBold).append(kFgYellow).append(iface_banner).append(kReset);

        const std::size_t banner_cols = iface_banner.size() - 2; // ▼ is 3 UTF-8 bytes, 1 col
        const std::size_t nav_cols    = iface_nav.size() - 2;    // │ is 3 UTF-8 bytes, 1 col
        if (W > banner_cols + nav_cols) {
            frame_buffer_.append(kFgGray);
            for (std::size_t i = 0; i < (W - banner_cols - nav_cols); ++i) {
                frame_buffer_.append("─");
            }
            frame_buffer_.append(kFgCyan).append(iface_nav).append(kReset);
        }
        frame_buffer_.append(kClearLineEnd).append("\n");

        const bool show_side_box = (W >= 82);
        constexpr std::size_t kInfoWidth = 34;
        const std::size_t left_width = show_side_box ? (W - kInfoWidth - 3) : (W - 2);
        const std::size_t graph_cols = (left_width > 7) ? (left_width - 7) : 10;

        double rx_max = 32.0 * 1024.0;
        for (double v : net.rx_history) {
            rx_max = std::max(rx_max, v * 1.15);
        }
        double tx_max = 32.0 * 1024.0;
        for (double v : net.tx_history) {
            tx_max = std::max(tx_max, v * 1.15);
        }

        const std::string rx_scale_top = format_scale_label(rx_max);
        const std::string rx_scale_mid = format_scale_label(rx_max * 0.5);
        const std::string tx_scale_top = format_scale_label(tx_max);
        const std::string tx_scale_mid = format_scale_label(tx_max * 0.5);

        auto format_side_cell = [](const char* label, const std::string& val) {
            char buf[64]{};
            std::snprintf(buf, sizeof(buf), "%-14s %18s", label, val.c_str());
            return std::string(buf);
        };

        // Top Border
        frame_buffer_.append(kBorderColor).append("┌");
        for (std::size_t i = 0; i < left_width; ++i) frame_buffer_.append("─");
        if (show_side_box) {
            frame_buffer_.append("┬");
            for (std::size_t i = 0; i < kInfoWidth; ++i) frame_buffer_.append("─");
        }
        frame_buffer_.append("┐").append(kReset).append(kClearLineEnd).append("\n");

        // Row 1: Download Header
        {
            frame_buffer_.append(kBorderColor).append("│ ").append(kReset);
            std::string dl_hdr = "DOWNLOAD: " + rx_rate_str + " " + rx_bits_str;
            if (left_width >= 56) {
                dl_hdr += "   Peak: " + rx_top_str;
            }
            const std::size_t dl_avail = (left_width > 3) ? (left_width - 3) : 10;
            frame_buffer_.append(kFgCyan).append("▼ ").append(fit_string(dl_hdr, dl_avail)).append(kReset);
            if (show_side_box) {
                frame_buffer_.append(kBorderColor).append("│ ").append(kReset);
                frame_buffer_.append(kBold).append(kFgWhite).append(format_side_cell("Total Recv:", rx_total_str)).append(kReset);
            }
            frame_buffer_.append(kBorderColor).append("│").append(kReset).append(kClearLineEnd).append("\n");
        }

        // Row 2: Download Graph Top
        {
            frame_buffer_.append(kBorderColor).append("│").append(kReset);
            frame_buffer_.append(kFgGray).append(fit_string(rx_scale_top, 5)).append(" │").append(kReset);
            append_block_graph_row(frame_buffer_, net.rx_history, graph_cols, 1, 2, rx_max, kFgCyan);
            if (show_side_box) {
                frame_buffer_.append(kReset).append(kBorderColor).append("│ ").append(kReset);
                frame_buffer_.append(kFgCyan).append(format_side_cell("Current Rate:", rx_rate_str)).append(kReset);
            }
            frame_buffer_.append(kReset).append(kBorderColor).append("│").append(kReset).append(kClearLineEnd).append("\n");
        }

        // Row 3: Download Graph Bottom
        {
            frame_buffer_.append(kBorderColor).append("│").append(kReset);
            frame_buffer_.append(kFgGray).append(fit_string(rx_scale_mid, 5)).append(" │").append(kReset);
            append_block_graph_row(frame_buffer_, net.rx_history, graph_cols, 0, 2, rx_max, kFgCyan);
            if (show_side_box) {
                frame_buffer_.append(kReset).append(kBorderColor).append("│ ").append(kReset);
                const std::uint64_t rx_faults = net.rx_drops + net.rx_errors;
                if (rx_faults > 0) {
                    const std::string fault_str = std::to_string(net.rx_drops) + "d / " + std::to_string(net.rx_errors) + "e";
                    frame_buffer_.append(kFgYellow).append(format_side_cell("RX Drop/Err:", fault_str)).append(kReset);
                } else {
                    frame_buffer_.append(kFgGray).append(format_side_cell("Peak Rate:", rx_top_str)).append(kReset);
                }
            }
            frame_buffer_.append(kReset).append(kBorderColor).append("│").append(kReset).append(kClearLineEnd).append("\n");
        }

        // Row 4: Middle Divider
        {
            frame_buffer_.append(kBorderColor).append("├").append(kFgGray).append("   0B └");
            for (std::size_t i = 0; i < graph_cols; ++i) frame_buffer_.append("─");
            if (show_side_box) {
                frame_buffer_.append(kBorderColor).append("┼");
                for (std::size_t i = 0; i < kInfoWidth; ++i) frame_buffer_.append("─");
            }
            frame_buffer_.append(kBorderColor).append("┤").append(kReset).append(kClearLineEnd).append("\n");
        }

        // Row 5: Upload Header
        {
            frame_buffer_.append(kBorderColor).append("│ ").append(kReset);
            std::string ul_hdr = "UPLOAD:   " + tx_rate_str + " " + tx_bits_str;
            if (left_width >= 56) {
                ul_hdr += "   Peak: " + tx_top_str;
            }
            const std::size_t ul_avail = (left_width > 3) ? (left_width - 3) : 10;
            frame_buffer_.append(kFgOrange).append("▲ ").append(fit_string(ul_hdr, ul_avail)).append(kReset);
            if (show_side_box) {
                frame_buffer_.append(kBorderColor).append("│ ").append(kReset);
                frame_buffer_.append(kBold).append(kFgWhite).append(format_side_cell("Total Sent:", tx_total_str)).append(kReset);
            }
            frame_buffer_.append(kBorderColor).append("│").append(kReset).append(kClearLineEnd).append("\n");
        }

        // Row 6: Upload Graph Top
        {
            frame_buffer_.append(kBorderColor).append("│").append(kReset);
            frame_buffer_.append(kFgGray).append(fit_string(tx_scale_top, 5)).append(" │").append(kReset);
            append_block_graph_row(frame_buffer_, net.tx_history, graph_cols, 1, 2, tx_max, kFgOrange);
            if (show_side_box) {
                frame_buffer_.append(kReset).append(kBorderColor).append("│ ").append(kReset);
                frame_buffer_.append(kFgOrange).append(format_side_cell("Current Rate:", tx_rate_str)).append(kReset);
            }
            frame_buffer_.append(kReset).append(kBorderColor).append("│").append(kReset).append(kClearLineEnd).append("\n");
        }

        // Row 7: Upload Graph Bottom
        {
            frame_buffer_.append(kBorderColor).append("│").append(kReset);
            frame_buffer_.append(kFgGray).append(fit_string(tx_scale_mid, 5)).append(" │").append(kReset);
            append_block_graph_row(frame_buffer_, net.tx_history, graph_cols, 0, 2, tx_max, kFgOrange);
            if (show_side_box) {
                frame_buffer_.append(kReset).append(kBorderColor).append("│ ").append(kReset);
                const std::uint64_t all_faults = net.rx_drops + net.tx_drops + net.rx_errors + net.tx_errors;
                const std::string fault_str = std::to_string(net.rx_drops + net.tx_drops) + "d / " +
                                              std::to_string(net.rx_errors + net.tx_errors) + "e";
                frame_buffer_.append((all_faults > 0) ? kFgRed : kFgGray)
                             .append(format_side_cell("Drops / Errs:", fault_str)).append(kReset);
            }
            frame_buffer_.append(kReset).append(kBorderColor).append("│").append(kReset).append(kClearLineEnd).append("\n");
        }

        // Row 8: Bottom Border
        {
            frame_buffer_.append(kBorderColor).append("└").append(kFgGray).append("   0B └");
            for (std::size_t i = 0; i < graph_cols; ++i) frame_buffer_.append("─");
            if (show_side_box) {
                frame_buffer_.append(kBorderColor).append("┴");
                for (std::size_t i = 0; i < kInfoWidth; ++i) frame_buffer_.append("─");
            }
            frame_buffer_.append(kBorderColor).append("┘").append(kReset).append(kClearLineEnd).append("\n");
        }
    }

    // 4. Responsive Pingtop Interactive Hotkeys Bar
    frame_buffer_.append(kBgKeyBar).append(kBold)
                 .append(kFgCyan).append(" q ").append(kFgWhite).append("Quit ")
                 .append(kFgCyan).append(" Enter ").append(kFgWhite).append("Graph ")
                 .append(kFgCyan).append(" t ").append(kFgWhite).append("MTR ")
                 .append(kFgCyan).append(" m ").append(kFgWhite).append("MTU ")
                 .append(kFgCyan).append(" </> ").append(kFgWhite).append("Iface ")
                 .append(kFgCyan).append(" z ").append(kFgWhite).append("Zero ")
                 .append(kFgCyan).append(" / ").append(kFgWhite).append("Find ");
    if (monitor.is_scanning()) {
        frame_buffer_.append(kBold).append("\033[93m").append(" d ").append(kFgWhite).append("Scanning... ").append(kReset).append(kBgKeyBar);
    } else {
        frame_buffer_.append(kFgCyan).append(" d ").append(kFgWhite).append("Scan ");
    }
    if (W >= 90) {
        frame_buffer_.append(kFgCyan).append(" g ").append(kFgWhite).append("Group ")
                     .append(kFgCyan).append(" s ").append(kFgWhite).append("Sort ")
                     .append(kFgCyan).append(" r ").append(kFgWhite).append("Reset ")
                     .append(kFgCyan).append(" p ").append(kFgWhite).append("Pause ");
    }
    frame_buffer_.append(kClearLineEnd).append(kReset);
}

} // namespace pingtop
