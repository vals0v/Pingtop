#include "icmp_socket.hpp"

#include <arpa/inet.h>
#include <bit>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netinet/ip.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace pingtop {

namespace {

[[nodiscard]] constexpr std::uint16_t to_network_u16(std::uint16_t value) noexcept {
    if constexpr (std::endian::native == std::endian::little) {
        return static_cast<std::uint16_t>((value >> 8U) | (value << 8U));
    } else {
        return value;
    }
}

[[nodiscard]] bool set_nonblocking(int fd) noexcept {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

} // namespace

IcmpSocket::IcmpSocket() noexcept
    : client_id_(static_cast<std::uint16_t>(::getpid() & 0xFFFF)) {}

IcmpSocket::~IcmpSocket() noexcept {
    close();
}

IcmpSocket::IcmpSocket(IcmpSocket&& other) noexcept
    : fd_(other.fd_),
      fd6_(other.fd6_),
      mode_(other.mode_),
      client_id_(other.client_id_),
      last_error_(std::move(other.last_error_)) {
    other.fd_ = -1;
    other.fd6_ = -1;
    other.mode_ = SocketMode::None;
}

IcmpSocket& IcmpSocket::operator=(IcmpSocket&& other) noexcept {
    if (this != &other) {
        close();
        fd_ = other.fd_;
        fd6_ = other.fd6_;
        mode_ = other.mode_;
        client_id_ = other.client_id_;
        last_error_ = std::move(other.last_error_);
        other.fd_ = -1;
        other.fd6_ = -1;
        other.mode_ = SocketMode::None;
    }
    return *this;
}

bool IcmpSocket::open() {
    close();
    last_error_.clear();

    // 1. Try unprivileged datagram ICMP socket (macOS default, Linux ping_group_range)
    int sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sock >= 0) {
        mode_ = SocketMode::Datagram;
    } else {
        const int dgram_errno = errno;

        // 2. Fallback to privileged raw ICMP socket (root / CAP_NET_RAW)
        sock = ::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock >= 0) {
            mode_ = SocketMode::Raw;
        } else {
            const int raw_errno = errno;
            last_error_ = "Failed to open ICMP socket (SOCK_DGRAM: '" +
                          std::string(std::strerror(dgram_errno)) +
                          "', SOCK_RAW: '" +
                          std::string(std::strerror(raw_errno)) +
                          "'). On Linux run with sudo, or enable ping_group_range.";
            return false;
        }
    }

    if (!set_nonblocking(sock)) {
        last_error_ = "Failed to set O_NONBLOCK: " + std::string(std::strerror(errno));
        ::close(sock);
        mode_ = SocketMode::None;
        return false;
    }

    const int ttl = 64;
    (void)::setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

    const int rcvbuf_size = 256 * 1024;
    (void)::setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size));

    fd_ = sock;

    // 3. Also open non-blocking IPv6 ICMPv6 socket (best-effort)
    int sock6 = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    if (sock6 < 0) {
        sock6 = ::socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    }
    if (sock6 >= 0) {
        if (set_nonblocking(sock6)) {
            const int hops = 64;
            (void)::setsockopt(sock6, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops));
            (void)::setsockopt(sock6, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size));
            fd6_ = sock6;
        } else {
            ::close(sock6);
        }
    }

    return true;
}

void IcmpSocket::close() noexcept {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    if (fd6_ >= 0) {
        ::close(fd6_);
        fd6_ = -1;
    }
    mode_ = SocketMode::None;
}

std::string_view IcmpSocket::mode_string() const noexcept {
    switch (mode_) {
        case SocketMode::Datagram:
            return "DGRAM (unprivileged)";
        case SocketMode::Raw:
            return "RAW (privileged)";
        case SocketMode::None:
        default:
            return "CLOSED";
    }
}

// RFC 1071 internet checksum
std::uint16_t IcmpSocket::compute_checksum(const void* data, std::size_t length) noexcept {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::uint32_t sum = 0;

    std::size_t i = 0;
    while (i + 1 < length) {
        std::uint16_t word = 0;
        std::memcpy(&word, bytes + i, sizeof(std::uint16_t));
        sum += word;
        i += 2;
    }

    if (i < length) {
        std::uint16_t last_byte = 0;
        std::memcpy(&last_byte, bytes + i, 1);
        sum += last_byte;
    }

    while ((sum >> 16U) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }

    return static_cast<std::uint16_t>(~sum);
}

bool IcmpSocket::send_echo_request(
    const sockaddr_in& dest_addr,
    std::uint16_t host_index,
    std::uint32_t sequence,
    std::chrono::steady_clock::time_point send_time
) noexcept {
    if (fd_ < 0) {
        return false;
    }

    const auto send_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        send_time.time_since_epoch()
    ).count();

    IcmpPacket packet{};
    packet.header.type = kIcmpEchoRequest;
    packet.header.code = 0;
    packet.header.checksum = 0;
    packet.header.identifier = to_network_u16(client_id_);
    packet.header.sequence = to_network_u16(static_cast<std::uint16_t>(sequence & 0xFFFFU));

    packet.payload.magic = kPayloadMagic;
    packet.payload.client_id = client_id_;
    packet.payload.host_index = host_index;
    packet.payload.sequence = sequence;
    packet.payload.send_time_ns = static_cast<std::int64_t>(send_ns);

    packet.header.checksum = compute_checksum(&packet, sizeof(packet));

    const ssize_t sent = ::sendto(
        fd_,
        &packet,
        sizeof(packet),
        0,
        reinterpret_cast<const sockaddr*>(&dest_addr),
        sizeof(dest_addr)
    );

    return sent == static_cast<ssize_t>(sizeof(packet));
}

std::optional<IcmpReply> IcmpSocket::receive_echo_reply(
    std::chrono::steady_clock::time_point receive_time
) noexcept {
    if (fd_ < 0) {
        return std::nullopt;
    }

    std::uint8_t buffer[1024];
    sockaddr_in from_addr{};
    socklen_t from_len = sizeof(from_addr);

    const ssize_t bytes_received = ::recvfrom(
        fd_,
        buffer,
        sizeof(buffer),
        0,
        reinterpret_cast<sockaddr*>(&from_addr),
        &from_len
    );

    if (bytes_received <= 0) {
        return std::nullopt;
    }

    const auto total_len = static_cast<std::size_t>(bytes_received);
    std::size_t icmp_offset = 0;
    std::uint8_t ttl = 0;

    // Check if IPv4 header is included (macOS DGRAM/RAW and Linux RAW)
    if (total_len >= 20 && ((buffer[0] >> 4U) == 4U) && buffer[9] == IPPROTO_ICMP) {
        const std::size_t ip_header_len = static_cast<std::size_t>(buffer[0] & 0x0FU) * 4U;
        if (ip_header_len < 20 || total_len < ip_header_len + sizeof(IcmpPacket)) {
            return std::nullopt;
        }
        ttl = buffer[8];
        icmp_offset = ip_header_len;
    } else {
        if (total_len < sizeof(IcmpPacket)) {
            return std::nullopt;
        }
    }

    IcmpPacket reply_packet{};
    std::memcpy(&reply_packet, buffer + icmp_offset, sizeof(IcmpPacket));

    if (reply_packet.header.type != kIcmpEchoReply || reply_packet.header.code != 0) {
        return std::nullopt;
    }

    if (reply_packet.payload.magic != kPayloadMagic ||
        reply_packet.payload.client_id != client_id_) {
        return std::nullopt;
    }

    const auto recv_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        receive_time.time_since_epoch()
    ).count();

    const std::int64_t delta_ns = static_cast<std::int64_t>(recv_ns) - reply_packet.payload.send_time_ns;
    const double rtt_ms = (delta_ns > 0) ? (static_cast<double>(delta_ns) / 1'000'000.0) : 0.01;

    char ip_str[INET_ADDRSTRLEN]{};
    (void)::inet_ntop(AF_INET, &from_addr.sin_addr, ip_str, sizeof(ip_str));

    IcmpReply result{};
    result.host_index = reply_packet.payload.host_index;
    result.sequence = reply_packet.payload.sequence;
    result.rtt_ms = rtt_ms;
    result.ttl = ttl;
    result.source_ip = ip_str;

    return result;
}

bool IcmpSocket::send_echo_request_v6(
    const sockaddr_in6& dest_addr,
    std::uint16_t host_index,
    std::uint32_t sequence,
    std::chrono::steady_clock::time_point send_time
) noexcept {
    if (fd6_ < 0) {
        return false;
    }

    const auto send_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        send_time.time_since_epoch()
    ).count();

    IcmpPacket packet{};
    packet.header.type = kIcmpv6EchoRequest;
    packet.header.code = 0;
    packet.header.checksum = 0;
    packet.header.identifier = to_network_u16(client_id_);
    packet.header.sequence = to_network_u16(static_cast<std::uint16_t>(sequence & 0xFFFFU));

    packet.payload.magic = kPayloadMagic;
    packet.payload.client_id = client_id_;
    packet.payload.host_index = host_index;
    packet.payload.sequence = sequence;
    packet.payload.send_time_ns = static_cast<std::int64_t>(send_ns);

    packet.header.checksum = compute_checksum(&packet, sizeof(packet));

    const ssize_t sent = ::sendto(
        fd6_,
        &packet,
        sizeof(packet),
        0,
        reinterpret_cast<const sockaddr*>(&dest_addr),
        sizeof(dest_addr)
    );

    return sent == static_cast<ssize_t>(sizeof(packet));
}

std::optional<IcmpReply> IcmpSocket::receive_echo_reply_v6(
    std::chrono::steady_clock::time_point receive_time
) noexcept {
    if (fd6_ < 0) {
        return std::nullopt;
    }

    std::uint8_t buffer[1024];
    sockaddr_in6 from_addr{};
    socklen_t from_len = sizeof(from_addr);

    const ssize_t bytes_received = ::recvfrom(
        fd6_,
        buffer,
        sizeof(buffer),
        0,
        reinterpret_cast<sockaddr*>(&from_addr),
        &from_len
    );

    if (bytes_received <= 0) {
        return std::nullopt;
    }

    const auto total_len = static_cast<std::size_t>(bytes_received);
    std::size_t icmp_offset = 0;

    if (total_len >= 40 + sizeof(IcmpPacket) && ((buffer[0] >> 4U) == 6U)) {
        icmp_offset = 40;
    } else if (total_len < sizeof(IcmpPacket)) {
        return std::nullopt;
    }

    IcmpPacket reply_packet{};
    std::memcpy(&reply_packet, buffer + icmp_offset, sizeof(IcmpPacket));

    if (reply_packet.header.type != kIcmpv6EchoReply || reply_packet.header.code != 0) {
        return std::nullopt;
    }

    if (reply_packet.payload.magic != kPayloadMagic ||
        reply_packet.payload.client_id != client_id_) {
        return std::nullopt;
    }

    const auto recv_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        receive_time.time_since_epoch()
    ).count();

    const std::int64_t delta_ns = static_cast<std::int64_t>(recv_ns) - reply_packet.payload.send_time_ns;
    const double rtt_ms = (delta_ns > 0) ? (static_cast<double>(delta_ns) / 1'000'000.0) : 0.01;

    char ip_str[INET6_ADDRSTRLEN]{};
    (void)::inet_ntop(AF_INET6, &from_addr.sin6_addr, ip_str, sizeof(ip_str));

    IcmpReply result{};
    result.host_index = reply_packet.payload.host_index;
    result.sequence = reply_packet.payload.sequence;
    result.rtt_ms = rtt_ms;
    result.ttl = 64;
    result.source_ip = ip_str;

    return result;
}

std::uint16_t IcmpSocket::probe_path_mtu(const sockaddr_in& dest_addr) noexcept {
    int sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sock < 0) {
        sock = ::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    }
    if (sock < 0) {
        return 1500;
    }

#if defined(__APPLE__)
    const int df = 1;
    (void)::setsockopt(sock, IPPROTO_IP, IP_DONTFRAG, &df, sizeof(df));
#elif defined(__linux__) && defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)
    const int pmtu = IP_PMTUDISC_DO;
    (void)::setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu));
#endif

    (void)set_nonblocking(sock);

    std::uint16_t low = 576;
    std::uint16_t high = 9000;
    std::uint16_t best_send_mtu = 1280;

    std::vector<std::uint8_t> pkt(9000, 0x42);
    std::vector<std::uint8_t> rbuf(9020, 0);
    const std::uint16_t ident = to_network_u16(static_cast<std::uint16_t>((::getpid() ^ 0x5A5A) & 0xFFFF));

    // Fast-path check: if local interface/route rejects 1501B, cap search range at 1500B
    // Otherwise search full Jumbo Frame range up to 9000B (SAN / Ceph / Datacenter fabrics)
    {
        constexpr std::size_t kJumboProbeLen = 1501U - 20U;
        IcmpHeader hdr{};
        hdr.type = kIcmpEchoRequest;
        hdr.code = 0;
        hdr.checksum = 0;
        hdr.identifier = ident;
        hdr.sequence = to_network_u16(1501U);
        std::memcpy(pkt.data(), &hdr, sizeof(hdr));
        hdr.checksum = compute_checksum(pkt.data(), kJumboProbeLen);
        std::memcpy(pkt.data(), &hdr, sizeof(hdr));

        const ssize_t sent = ::sendto(
            sock,
            pkt.data(),
            kJumboProbeLen,
            0,
            reinterpret_cast<const sockaddr*>(&dest_addr),
            sizeof(dest_addr)
        );
        if (sent < 0 && errno == EMSGSIZE) {
            high = 1500;
        } else if (sent == static_cast<ssize_t>(kJumboProbeLen)) {
            best_send_mtu = 1501;
            low = 1501;
        }
    }

    // Binary search maximum unfragmented frame size accepted by kernel route & remote peer
    while (low <= high) {
        const auto mid = static_cast<std::uint16_t>((low + high) / 2);
        const std::size_t icmp_len = (mid > 20) ? static_cast<std::size_t>(mid - 20) : 8U;

        IcmpHeader hdr{};
        hdr.type = kIcmpEchoRequest;
        hdr.code = 0;
        hdr.checksum = 0;
        hdr.identifier = ident;
        hdr.sequence = to_network_u16(mid);
        std::memcpy(pkt.data(), &hdr, sizeof(hdr));
        hdr.checksum = compute_checksum(pkt.data(), icmp_len);
        std::memcpy(pkt.data(), &hdr, sizeof(hdr));

        const ssize_t sent = ::sendto(
            sock,
            pkt.data(),
            icmp_len,
            0,
            reinterpret_cast<const sockaddr*>(&dest_addr),
            sizeof(dest_addr)
        );

        if (sent < 0 && errno == EMSGSIZE) {
            high = static_cast<std::uint16_t>(mid - 1);
            continue;
        }

        if (sent == static_cast<ssize_t>(icmp_len)) {
            best_send_mtu = mid;
            pollfd pfd{sock, POLLIN, 0};
            if (::poll(&pfd, 1, 25) > 0) {
                (void)::recvfrom(sock, rbuf.data(), rbuf.size(), 0, nullptr, nullptr);
            }
            low = static_cast<std::uint16_t>(mid + 1);
        } else {
            high = static_cast<std::uint16_t>(mid - 1);
        }
    }

    ::close(sock);
    return best_send_mtu;
}

} // namespace pingtop
