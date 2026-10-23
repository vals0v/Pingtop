#pragma once

#include <chrono>
#include <cstdint>
#include <netinet/in.h>
#include <optional>
#include <string>
#include <string_view>

namespace pingtop {

enum class SocketMode {
    None,
    Datagram, // SOCK_DGRAM, IPPROTO_ICMP (unprivileged)
    Raw       // SOCK_RAW, IPPROTO_ICMP (privileged)
};

#pragma pack(push, 1)
// RFC 792 ICMP Echo header
struct IcmpHeader {
    std::uint8_t  type;
    std::uint8_t  code;
    std::uint16_t checksum;
    std::uint16_t identifier;
    std::uint16_t sequence;
};

// Custom payload echoed back by the remote target
struct IcmpPayload {
    std::uint64_t magic;
    std::uint16_t client_id;
    std::uint16_t host_index;
    std::uint32_t sequence;
    std::int64_t  send_time_ns;
};

struct IcmpPacket {
    IcmpHeader  header;
    IcmpPayload payload;
};
#pragma pack(pop)

static_assert(sizeof(IcmpHeader) == 8, "IcmpHeader must be 8 bytes");
static_assert(sizeof(IcmpPayload) == 24, "IcmpPayload must be 24 bytes");
static_assert(sizeof(IcmpPacket) == 32, "IcmpPacket must be 32 bytes");

struct IcmpReply {
    std::uint16_t host_index{0};
    std::uint32_t sequence{0};
    double        rtt_ms{0.0};
    std::uint8_t  ttl{0};
    std::string   source_ip;
};

class IcmpSocket {
public:
    static constexpr std::uint8_t  kIcmpEchoRequest = 8;
    static constexpr std::uint8_t  kIcmpEchoReply   = 0;
    static constexpr std::uint64_t kPayloadMagic    = 0x50494E47544F5031ULL; // "PINGTOP1"

    IcmpSocket() noexcept;
    ~IcmpSocket() noexcept;

    IcmpSocket(const IcmpSocket&) = delete;
    IcmpSocket& operator=(const IcmpSocket&) = delete;
    IcmpSocket(IcmpSocket&& other) noexcept;
    IcmpSocket& operator=(IcmpSocket&& other) noexcept;

    [[nodiscard]] bool open();
    void close() noexcept;

    [[nodiscard]] bool is_open() const noexcept { return fd_ >= 0; }
    [[nodiscard]] int fd() const noexcept { return fd_; }
    [[nodiscard]] SocketMode mode() const noexcept { return mode_; }
    [[nodiscard]] std::string_view mode_string() const noexcept;
    [[nodiscard]] const std::string& last_error() const noexcept { return last_error_; }

    [[nodiscard]] bool send_echo_request(
        const sockaddr_in& dest_addr,
        std::uint16_t host_index,
        std::uint32_t sequence,
        std::chrono::steady_clock::time_point send_time
    ) noexcept;

    [[nodiscard]] std::optional<IcmpReply> receive_echo_reply(
        std::chrono::steady_clock::time_point receive_time
    ) noexcept;

    [[nodiscard]] static std::uint16_t compute_checksum(const void* data, std::size_t length) noexcept;

private:
    int           fd_{-1};
    SocketMode    mode_{SocketMode::None};
    std::uint16_t client_id_{0};
    std::string   last_error_;
};

} // namespace pingtop
