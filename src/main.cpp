#include "network_monitor.hpp"
#include "tui_renderer.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

void print_help(std::string_view prog_name) {
    std::cout
        << "Pingtop v1.3.0 — Interactive TUI Network Latency, MTR & Quality Monitor (C++20)\n\n"
        << "Usage:\n"
        << "  " << prog_name << " [OPTIONS] [HOST... | HOST:PORT... | dns://HOST... | LABEL=TARGET...]\n\n"
        << "Options:\n"
        << "  -i, --interval <ms>   Ping interval in milliseconds (100..10000, default: 1000)\n"
        << "  -c, --count <num>     Exit automatically after <num> ping rounds (default: 0 = infinite)\n"
        << "  -f, --config <path>   Path to config file (default: ~/.config/pingtop/hosts.conf)\n"
        << "  -h, --help            Show this help message and exit\n\n"
        << "Examples:\n"
        << "  " << prog_name << "                                      # Auto-discover LAN, VPN, Tailscale & config\n"
        << "  " << prog_name << " 1.1.1.1 github.com:443 dns://8.8.8.8 # ICMP + TCP SYN + UDP:53 DNS Benchmark\n"
        << "  " << prog_name << " 2606:4700:4700::1111                 # IPv6 ICMPv6 Ping\n\n"
        << "Interactive TUI Hotkeys:\n"
        << "  Enter / v   Open 2D Latency Graph, Percentiles (p50/p90/p95/p99), ASN & Histogram\n"
        << "  t           Open live Hop-by-Hop MTR / Traceroute view with GeoIP/ASN per hop\n"
        << "  m           Run active Path MTU Discovery (Don't Fragment binary search) on selected host\n"
        << "  /           Live search & filter hosts (by name, IP, ASN, or protocol)\n"
        << "  g           Toggle category grouping ([LAN], [VPN & Tailscale], [WAN])\n"
        << "  d           Scan & discover LAN devices (ARP) and VPN/Tailscale peers\n"
        << "  s           Cycle table sorting (Default -> Last RTT -> Avg RTT -> Jitter -> Loss%)\n"
        << "  r           Reset all collected statistics and sparklines\n"
        << "  p / Space   Pause / Resume sending probes\n"
        << "  + / -       Increase / Decrease ping interval by 100 ms\n"
        << "  Up / Down   Select host row in table (also j / k)\n"
        << "  b / Esc     Back to table view / Clear active search filter\n"
        << "  q           Quit and print session summary\n";
}

void print_final_summary(const pingtop::NetworkMonitor& monitor) {
    std::cout << "\n--- Pingtop Session Summary ---\n";
    std::printf(
        "%-20s %-15s %-7s %-6s %-20s %5s %5s %7s %7s %7s %7s %7s\n",
        "TARGET", "IP", "PROTO", "MTU", "GEO / ASN", "SENT", "RECV", "LOSS%", "MIN", "AVG", "P99", "JITTER"
    );
    std::cout << std::string(124, '-') << "\n";

    for (const auto& h : monitor.hosts()) {
        const auto pct = h.compute_percentiles();
        std::string proto = h.is_ipv6 ? "ICMPv6" : "ICMP";
        if (h.probe_type == pingtop::ProbeType::Dns) {
            proto = "DNS:53";
        } else if (h.probe_type == pingtop::ProbeType::Tcp) {
            proto = "TCP:" + std::to_string(h.tcp_port);
        }

        std::printf(
            "%-20.20s %-15.15s %-7.7s %5uB %-20.20s %5llu %5llu %6.1f%% %7.2f %7.2f %7.2f %7.2f\n",
            h.display_name.c_str(),
            h.resolved_ip.c_str(),
            proto.c_str(),
            static_cast<unsigned int>(h.path_mtu),
            h.asn_info.empty() ? "---" : h.asn_info.c_str(),
            static_cast<unsigned long long>(h.sent_count),
            static_cast<unsigned long long>(h.received_count),
            h.packet_loss_percent(),
            h.min_rtt_ms,
            h.avg_rtt_ms,
            pct.p99,
            h.jitter_ms
        );
    }
}

} // namespace

int main(int argc, char* argv[]) {
    pingtop::MonitorConfig config{};
    std::vector<std::pair<std::string, std::string>> custom_targets;

    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (arg == "-h" || arg == "--help") {
            print_help(argv[0]);
            return EXIT_SUCCESS;
        }
        if (arg == "-i" || arg == "--interval") {
            if (i + 1 >= argc) {
                std::cerr << "Error: Missing value for " << arg << "\n";
                return EXIT_FAILURE;
            }
            const long val = std::strtol(argv[++i], nullptr, 10);
            if (val < 100 || val > 10000) {
                std::cerr << "Error: Interval must be between 100 and 10000 ms.\n";
                return EXIT_FAILURE;
            }
            config.ping_interval = std::chrono::milliseconds(val);
            config.ping_timeout = std::min(
                std::chrono::milliseconds(2000),
                std::chrono::milliseconds(val * 9 / 10)
            );
            continue;
        }
        if (arg == "-c" || arg == "--count") {
            if (i + 1 >= argc) {
                std::cerr << "Error: Missing value for " << arg << "\n";
                return EXIT_FAILURE;
            }
            const long long val = std::strtoll(argv[++i], nullptr, 10);
            if (val < 0) {
                std::cerr << "Error: Count must be non-negative.\n";
                return EXIT_FAILURE;
            }
            config.max_cycles = static_cast<std::uint64_t>(val);
            continue;
        }
        if (arg == "-f" || arg == "--config") {
            if (i + 1 >= argc) {
                std::cerr << "Error: Missing file path for " << arg << "\n";
                return EXIT_FAILURE;
            }
            config.config_file_path = argv[++i];
            continue;
        }

        const auto eq_pos = arg.find('=');
        if (eq_pos != std::string_view::npos && eq_pos > 0 && eq_pos + 1 < arg.size()) {
            std::string label(arg.substr(0, eq_pos));
            std::string host(arg.substr(eq_pos + 1));
            custom_targets.emplace_back(std::move(host), std::move(label));
        } else {
            custom_targets.emplace_back(std::string(arg), "");
        }
    }

    pingtop::NetworkMonitor monitor(config);
    if (!monitor.initialize()) {
        std::cerr << "Error: " << monitor.socket().last_error() << "\n";
        return EXIT_FAILURE;
    }

    if (custom_targets.empty()) {
        monitor.add_default_hosts();
    } else {
        for (const auto& [host, label] : custom_targets) {
            monitor.add_host(host, label);
        }
    }

    pingtop::TuiRenderer renderer;
    (void)renderer.initialize();

    auto last_render_time = std::chrono::steady_clock::time_point{};
    constexpr std::chrono::milliseconds kRenderInterval(50);

    while (!pingtop::TuiRenderer::should_quit()) {
        bool force_redraw = false;

        monitor.poll_once(25, [&](int key) {
            force_redraw = true;

            // Handle live search input mode
            if (renderer.is_search_active()) {
                if (key == '\n' || key == '\r') {
                    renderer.stop_search(false);
                } else if (key == pingtop::NetworkMonitor::kKeyEscape) {
                    renderer.stop_search(true);
                } else if (key == pingtop::NetworkMonitor::kKeyBackspace) {
                    renderer.pop_search_char();
                } else if (key == pingtop::NetworkMonitor::kKeyArrowUp) {
                    renderer.move_selection(-1, monitor);
                } else if (key == pingtop::NetworkMonitor::kKeyArrowDown) {
                    renderer.move_selection(1, monitor);
                } else if (key >= 32 && key <= 126) {
                    renderer.append_search_char(static_cast<char>(key));
                }
                return;
            }

            switch (key) {
                case 'q':
                case 'Q':
                    pingtop::TuiRenderer::request_quit();
                    break;
                case pingtop::NetworkMonitor::kKeyEscape:
                    if (renderer.view_mode() != pingtop::ViewMode::Table) {
                        monitor.stop_mtr();
                        renderer.set_view_mode(pingtop::ViewMode::Table);
                    } else if (!renderer.filter_query().empty()) {
                        renderer.stop_search(true);
                    } else {
                        pingtop::TuiRenderer::request_quit();
                    }
                    break;
                case 'b':
                case 'B':
                    if (renderer.view_mode() != pingtop::ViewMode::Table) {
                        monitor.stop_mtr();
                        renderer.set_view_mode(pingtop::ViewMode::Table);
                    } else {
                        monitor.cycle_net_interface(-1);
                    }
                    break;
                case '[':
                case ',':
                case '<':
                case pingtop::NetworkMonitor::kKeyArrowLeft:
                    monitor.cycle_net_interface(-1);
                    break;
                case 'n':
                case 'N':
                case ']':
                case '.':
                case '>':
                case pingtop::NetworkMonitor::kKeyArrowRight:
                    monitor.cycle_net_interface(1);
                    break;
                case 'z':
                case 'Z':
                    monitor.reset_net_peaks();
                    break;
                case '\n':
                case '\r':
                case 'v':
                case 'V':
                    if (renderer.view_mode() == pingtop::ViewMode::Detail) {
                        renderer.set_view_mode(pingtop::ViewMode::Table);
                    } else {
                        monitor.stop_mtr();
                        renderer.set_view_mode(pingtop::ViewMode::Detail);
                    }
                    break;
                case 't':
                case 'T':
                    if (renderer.view_mode() == pingtop::ViewMode::Mtr) {
                        monitor.stop_mtr();
                        renderer.set_view_mode(pingtop::ViewMode::Table);
                    } else {
                        monitor.start_mtr(renderer.selected_host_index(monitor));
                        renderer.set_view_mode(pingtop::ViewMode::Mtr);
                    }
                    break;
                case 'm':
                case 'M':
                    monitor.run_mtu_discovery(renderer.selected_host_index(monitor));
                    break;
                case '/':
                    renderer.start_search();
                    break;
                case 'g':
                case 'G':
                    renderer.toggle_grouping();
                    break;
                case 'r':
                case 'R':
                    monitor.reset_all_stats();
                    break;
                case 'd':
                case 'D':
                    monitor.discover_and_add_network_devices();
                    break;
                case 's':
                case 'S':
                    monitor.cycle_sort_column();
                    break;
                case 'p':
                case 'P':
                case ' ':
                    monitor.toggle_pause();
                    break;
                case '+':
                case '=':
                    monitor.adjust_interval(std::chrono::milliseconds(100));
                    break;
                case '-':
                case '_':
                    monitor.adjust_interval(std::chrono::milliseconds(-100));
                    break;
                case 'j':
                case 'J':
                case pingtop::NetworkMonitor::kKeyArrowDown:
                    renderer.move_selection(1, monitor);
                    if (renderer.view_mode() == pingtop::ViewMode::Mtr) {
                        monitor.start_mtr(renderer.selected_host_index(monitor));
                    }
                    break;
                case 'k':
                case 'K':
                case pingtop::NetworkMonitor::kKeyArrowUp:
                    renderer.move_selection(-1, monitor);
                    if (renderer.view_mode() == pingtop::ViewMode::Mtr) {
                        monitor.start_mtr(renderer.selected_host_index(monitor));
                    }
                    break;
                default:
                    break;
            }
        });

        const auto now = std::chrono::steady_clock::now();
        if (force_redraw || (now - last_render_time) >= kRenderInterval) {
            renderer.render(monitor);
            last_render_time = now;
        }

        if (config.max_cycles > 0 && monitor.completed_rounds() >= config.max_cycles) {
            const auto wait_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(250);
            while (std::chrono::steady_clock::now() < wait_deadline && !pingtop::TuiRenderer::should_quit()) {
                monitor.poll_once(20, nullptr);
                renderer.render(monitor);
            }
            break;
        }
    }

    renderer.shutdown();
    print_final_summary(monitor);

    return EXIT_SUCCESS;
}
