# ⚡ Pingtop

[Русская версия (Russian version)](README_RU.md)

**Pingtop** is a lightweight, cross-platform (Linux & macOS) interactive TUI network latency, MTR, and quality monitor (`ping`, `TCP ping`, `jitter`, `packet loss`, `percentiles`), written in modern **C++20** with **Zero External Dependencies**.

---

## Features

- **Direct ICMP & Non-blocking TCP Ping Engine**:
  - Constructs and parses `ICMP Echo Request` / `Echo Reply` (RFC 792) with RFC 1071 checksums directly in userspace.
  - Supports **Non-blocking TCP SYN Ping** (`host:port`, e.g., `1.1.1.1:443`, `github.com:443`) for hosts behind firewalls that block ICMP.
- **Rootless Operation**: Uses unprivileged ICMP datagram sockets (`SOCK_DGRAM` / `IPPROTO_ICMP`) on macOS and modern Linux, with automatic fallback to `SOCK_RAW`.
- **Built-in Live MTR / Traceroute (`t` key)**: Hop-by-hop route discovery and real-time latency/loss/sparkline monitoring for every intermediate hop along the network path.
- **2D Latency Graph, Percentiles & Histogram (`Enter` key)**:
  - Detailed analytics view with **$p_{50}$ (Median), $p_{90}$, $p_{95}$, $p_{99}$**, standard deviation ($\sigma$), and **RFC 3550 Jitter**;
  - Multi-line 2D UTF-8 latency chart and latency distribution histogram.
- **Auto-Discovery & Category Grouping (`g` & `d` keys)**:
  - Automatically discovers your **Router / Default Gateway**, **LAN devices** (ARP cache with reverse DNS), and **VPN / Tailscale** tunnels (`utun`, `wg`);
  - Automatically tracks **Active SSH sessions** (Termius, OpenSSH, VS Code) and remote server peers over Tailscale/VPN, measuring both host ICMP ping and direct TCP connect latency to port 22;
  - Groups targets into visual sections: `[LOCAL GATEWAY & LAN]`, `[VPN & TAILSCALE]`, and `[INTERNET & WAN]`.
- **Live Search & Filter (`/` key)**: Vim/fzf-style instant substring filtering by host name, IP address, or protocol (`ICMP` / `TCP`).
- **Configuration File (`~/.config/pingtop/hosts.conf`)**: Automatically generates and loads a persistent configuration file with custom hosts, labels, TCP ports, and category sections.

---

## Project Structure

```text
pingtop/
├── CMakeLists.txt
├── LICENSE
├── README.md
├── README_RU.md
├── .gitignore
├── include/
│   ├── icmp_socket.hpp
│   ├── network_monitor.hpp
│   ├── ring_buffer.hpp
│   └── tui_renderer.hpp
└── src/
    ├── icmp_socket.cpp
    ├── main.cpp
    ├── network_monitor.cpp
    └── tui_renderer.cpp
```

---

## Build and Run

### macOS (Clang / AppleClang)

```bash
# Build via CMake
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

# Or compile directly
clang++ -std=c++20 -O2 -Wall -Wextra -Wpedantic -Iinclude \
    src/main.cpp src/icmp_socket.cpp src/network_monitor.cpp src/tui_renderer.cpp \
    -o pingtop

# Optional: make 'pingtop' available globally in Terminal
ln -sf "$(pwd)/pingtop" /opt/homebrew/bin/pingtop

# Run
pingtop
```

### Linux (GCC 10+ / Clang 12+)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

If unprivileged ping is restricted by system policy:
```bash
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
# or
sudo setcap cap_net_raw+ep ./build/pingtop
```

---

## Usage Examples

```bash
# Auto-discover LAN, VPN/Tailscale & load ~/.config/pingtop/hosts.conf
pingtop

# Monitor specific ICMP and TCP (host:port) targets
pingtop 1.1.1.1 github.com:443 8.8.8.8:53

# Custom host labels and 500 ms ping interval
pingtop -i 500 Router=192.168.1.1 Web=google.com:443
```

---

## Interactive Hotkeys

| Key | Action |
| :--- | :--- |
| `Enter` / `v` | Open **2D Latency Graph, Percentiles ($p_{50}$–$p_{99}$) & Histogram** for selected host |
| `t` | Open live **Hop-by-Hop MTR / Traceroute** view for selected host |
| `/` | Live **Search & Filter** hosts by name, IP, or protocol |
| `g` | Toggle **Category Grouping** (`[LAN]`, `[VPN & Tailscale]`, `[WAN]`) |
| `d` | Rescan & discover active **LAN (ARP)** and **VPN / Tailscale** devices |
| `s` | Cycle sort column (`Category/Default` → `Last RTT` → `Avg RTT` → `Jitter` → `Loss%`) |
| `r` | Reset collected statistics and sparklines |
| `p` / `Space` | Pause / resume sending probes |
| `+` / `-` | Increase / decrease ping interval (±100 ms) |
| `↑` / `↓` (`k` / `j`) | Select host row |
| `b` / `Esc` | Return to main table view / Clear active search filter |
| `q` | Quit and print session summary |
