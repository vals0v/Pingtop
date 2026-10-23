#pragma once

#include "network_monitor.hpp"

#include <csignal>
#include <cstddef>
#include <string>
#include <termios.h>
#include <vector>

namespace pingtop {

enum class ViewMode {
    Table,  // Main host table grouped by category
    Detail, // 2D chart, percentiles (p50/p90/p95/p99), and histogram
    Mtr     // Live hop-by-hop MTR / Traceroute view
};

// RAII ANSI/VT100 terminal renderer
class TuiRenderer {
public:
    TuiRenderer() noexcept;
    ~TuiRenderer() noexcept;

    TuiRenderer(const TuiRenderer&) = delete;
    TuiRenderer& operator=(const TuiRenderer&) = delete;

    [[nodiscard]] bool initialize() noexcept;
    void shutdown() noexcept;

    [[nodiscard]] static bool should_quit() noexcept;
    static void request_quit() noexcept;

    // Navigation & View controls
    void move_selection(int delta, const NetworkMonitor& monitor) noexcept;
    [[nodiscard]] std::size_t selected_host_index(const NetworkMonitor& monitor) const;

    void set_view_mode(ViewMode mode) noexcept { view_mode_ = mode; }
    [[nodiscard]] ViewMode view_mode() const noexcept { return view_mode_; }

    void toggle_grouping() noexcept { group_by_category_ = !group_by_category_; }
    [[nodiscard]] bool group_by_category() const noexcept { return group_by_category_; }

    // Live filter ('/' search mode)
    void start_search() noexcept { search_active_ = true; }
    void stop_search(bool clear_filter) noexcept;
    [[nodiscard]] bool is_search_active() const noexcept { return search_active_; }
    void append_search_char(char c);
    void pop_search_char() noexcept;
    [[nodiscard]] const std::string& filter_query() const noexcept { return filter_query_; }

    void render(const NetworkMonitor& monitor);

private:
    void update_terminal_size() noexcept;
    [[nodiscard]] std::vector<std::size_t> build_visible_order(const NetworkMonitor& monitor) const;
    [[nodiscard]] bool matches_filter(const HostEntry& host) const noexcept;

    void append_header(const NetworkMonitor& monitor);
    void append_table_view(const NetworkMonitor& monitor, const std::vector<std::size_t>& order);
    void append_detail_view(const NetworkMonitor& monitor, const std::vector<std::size_t>& order);
    void append_mtr_view(const NetworkMonitor& monitor);
    void append_footer(const NetworkMonitor& monitor, const std::vector<std::size_t>& order);
    void append_host_row(const HostEntry& h, bool is_selected, std::size_t spark_width);

    [[nodiscard]] static std::string build_sparkline(
        const RingBuffer<double, HostEntry::kHistoryCapacity>& history,
        std::size_t width
    );

    [[nodiscard]] static const char* latency_color(double rtt_ms) noexcept;
    [[nodiscard]] static const char* loss_color(double loss_pct) noexcept;
    [[nodiscard]] static const char* jitter_color(double jitter_ms) noexcept;

    termios     orig_termios_{};
    bool        termios_saved_{false};
    bool        initialized_{false};
    int         term_width_{120};
    int         term_height_{32};
    std::size_t selected_row_{0};
    ViewMode    view_mode_{ViewMode::Table};
    bool        group_by_category_{true};
    bool        search_active_{false};
    std::string filter_query_;
    std::string frame_buffer_;
};

} // namespace pingtop
