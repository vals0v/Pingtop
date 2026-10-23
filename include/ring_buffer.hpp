#pragma once

#include <array>
#include <cstddef>
#include <iterator>
#include <type_traits>
#include <utility>

namespace pingtop {

// Fixed-capacity ring buffer backed by std::array (zero allocations on push)
template <typename T, std::size_t Capacity = 60>
class RingBuffer {
    static_assert(Capacity > 0, "RingBuffer capacity must be greater than 0");

public:
    using value_type = T;
    using size_type = std::size_t;
    using reference = T&;
    using const_reference = const T&;

    class ConstIterator {
    public:
        using iterator_category = std::random_access_iterator_tag;
        using value_type = T;
        using difference_type = std::ptrdiff_t;
        using pointer = const T*;
        using reference = const T&;

        constexpr ConstIterator(const RingBuffer* buffer, size_type logical_index) noexcept
            : buffer_(buffer), index_(logical_index) {}

        constexpr reference operator*() const noexcept {
            return (*buffer_)[index_];
        }

        constexpr pointer operator->() const noexcept {
            return &((*buffer_)[index_]);
        }

        constexpr ConstIterator& operator++() noexcept {
            ++index_;
            return *this;
        }

        constexpr ConstIterator operator++(int) noexcept {
            ConstIterator tmp = *this;
            ++index_;
            return tmp;
        }

        constexpr ConstIterator& operator--() noexcept {
            --index_;
            return *this;
        }

        constexpr ConstIterator operator--(int) noexcept {
            ConstIterator tmp = *this;
            --index_;
            return *this;
        }

        constexpr ConstIterator& operator+=(difference_type n) noexcept {
            index_ = static_cast<size_type>(static_cast<difference_type>(index_) + n);
            return *this;
        }

        constexpr ConstIterator& operator-=(difference_type n) noexcept {
            index_ = static_cast<size_type>(static_cast<difference_type>(index_) - n);
            return *this;
        }

        friend constexpr ConstIterator operator+(ConstIterator it, difference_type n) noexcept {
            it += n;
            return it;
        }

        friend constexpr ConstIterator operator-(ConstIterator it, difference_type n) noexcept {
            it -= n;
            return it;
        }

        friend constexpr difference_type operator-(const ConstIterator& a, const ConstIterator& b) noexcept {
            return static_cast<difference_type>(a.index_) - static_cast<difference_type>(b.index_);
        }

        friend constexpr bool operator==(const ConstIterator& a, const ConstIterator& b) noexcept {
            return a.buffer_ == b.buffer_ && a.index_ == b.index_;
        }

        friend constexpr bool operator!=(const ConstIterator& a, const ConstIterator& b) noexcept {
            return !(a == b);
        }

        friend constexpr bool operator<(const ConstIterator& a, const ConstIterator& b) noexcept {
            return a.index_ < b.index_;
        }

    private:
        const RingBuffer* buffer_;
        size_type index_;
    };

    constexpr RingBuffer() noexcept = default;

    constexpr void push(const T& item) noexcept(std::is_nothrow_copy_assignable_v<T>) {
        data_[write_pos_] = item;
        write_pos_ = (write_pos_ + 1) % Capacity;
        if (size_ < Capacity) {
            ++size_;
        }
    }

    constexpr void push(T&& item) noexcept(std::is_nothrow_move_assignable_v<T>) {
        data_[write_pos_] = std::move(item);
        write_pos_ = (write_pos_ + 1) % Capacity;
        if (size_ < Capacity) {
            ++size_;
        }
    }

    // 0 is oldest element, size() - 1 is newest
    [[nodiscard]] constexpr const_reference operator[](size_type logical_index) const noexcept {
        const size_type oldest_pos = (size_ < Capacity) ? 0 : write_pos_;
        const size_type physical_pos = (oldest_pos + logical_index) % Capacity;
        return data_[physical_pos];
    }

    [[nodiscard]] constexpr reference operator[](size_type logical_index) noexcept {
        const size_type oldest_pos = (size_ < Capacity) ? 0 : write_pos_;
        const size_type physical_pos = (oldest_pos + logical_index) % Capacity;
        return data_[physical_pos];
    }

    [[nodiscard]] constexpr const_reference back() const noexcept {
        return (*this)[size_ - 1];
    }

    [[nodiscard]] constexpr reference back() noexcept {
        return (*this)[size_ - 1];
    }

    [[nodiscard]] constexpr const_reference front() const noexcept {
        return (*this)[0];
    }

    constexpr void clear() noexcept {
        write_pos_ = 0;
        size_ = 0;
    }

    [[nodiscard]] constexpr size_type size() const noexcept {
        return size_;
    }

    [[nodiscard]] static constexpr size_type capacity() noexcept {
        return Capacity;
    }

    [[nodiscard]] constexpr bool empty() const noexcept {
        return size_ == 0;
    }

    [[nodiscard]] constexpr bool full() const noexcept {
        return size_ == Capacity;
    }

    [[nodiscard]] constexpr ConstIterator begin() const noexcept {
        return ConstIterator(this, 0);
    }

    [[nodiscard]] constexpr ConstIterator end() const noexcept {
        return ConstIterator(this, size_);
    }

    [[nodiscard]] constexpr ConstIterator cbegin() const noexcept {
        return ConstIterator(this, 0);
    }

    [[nodiscard]] constexpr ConstIterator cend() const noexcept {
        return ConstIterator(this, size_);
    }

private:
    std::array<T, Capacity> data_{};
    size_type write_pos_{0};
    size_type size_{0};
};

} // namespace pingtop
