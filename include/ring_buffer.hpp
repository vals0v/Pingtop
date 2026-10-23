#pragma once

#include <array>
#include <cstddef>

namespace pingtop {

// Compact fixed-capacity ring buffer backed by std::array (zero heap allocations)
template <typename T, std::size_t Capacity = 60>
class RingBuffer {
    static_assert(Capacity > 0, "RingBuffer capacity must be greater than 0");

public:
    struct Iterator {
        const RingBuffer* buf;
        std::size_t idx;

        constexpr const T& operator*() const noexcept { return (*buf)[idx]; }
        constexpr Iterator& operator++() noexcept { ++idx; return *this; }
        constexpr bool operator!=(const Iterator& other) const noexcept { return idx != other.idx; }
    };

    constexpr void push(const T& item) noexcept {
        data_[write_pos_] = item;
        write_pos_ = (write_pos_ + 1) % Capacity;
        if (size_ < Capacity) {
            ++size_;
        }
    }

    // 0 is oldest sample, size() - 1 is newest sample
    [[nodiscard]] constexpr const T& operator[](std::size_t logical_idx) const noexcept {
        const std::size_t oldest = (size_ < Capacity) ? 0 : write_pos_;
        return data_[(oldest + logical_idx) % Capacity];
    }

    constexpr void clear() noexcept {
        write_pos_ = 0;
        size_ = 0;
    }

    [[nodiscard]] constexpr std::size_t size() const noexcept { return size_; }
    [[nodiscard]] constexpr bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] constexpr Iterator begin() const noexcept { return {this, 0}; }
    [[nodiscard]] constexpr Iterator end() const noexcept { return {this, size_}; }

private:
    std::array<T, Capacity> data_{};
    std::size_t write_pos_{0};
    std::size_t size_{0};
};

} // namespace pingtop
