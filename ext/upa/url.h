// Copyright 2016-2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//
// This file contains portions of modified code from:
// https://cs.chromium.org/chromium/src/url/url_canon_etc.cc
// Copyright 2013 The Chromium Authors. All rights reserved.
//

// URL Standard
// https://url.spec.whatwg.org/
//
// Infra Standard - fundamental concepts upon which standards are built
// https://infra.spec.whatwg.org/
//

#ifndef UPA_URL_H
#define UPA_URL_H

// #include "buffer.h"
// Copyright 2016-2024 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//
// This file contains portions of modified code from:
// https://cs.chromium.org/chromium/src/url/url_canon.h
// Copyright 2013 The Chromium Authors. All rights reserved.
//

#ifndef UPA_BUFFER_H
#define UPA_BUFFER_H

#include <array>
#include <cstddef>
#include <memory>
#include <stdexcept>
#include <string>

namespace upa {

template <
    class T,
    std::size_t fixed_capacity = 1024,
    class Traits = std::char_traits<T>,
    class Allocator = std::allocator<T>
>
class simple_buffer {
public:
    using value_type = T ;
    using traits_type = Traits;
    using allocator_type = Allocator;
    using allocator_traits = std::allocator_traits<allocator_type>;
    using size_type = std::size_t;
    // iterator
    using const_iterator = const value_type*;

    // default
    simple_buffer() = default; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
    explicit simple_buffer(const Allocator& alloc)
        : allocator_(alloc)
    {}

    // with initial capacity
    explicit simple_buffer(size_type new_cap, const Allocator& alloc = Allocator())
        : allocator_(alloc)
    {
        if (new_cap > fixed_capacity)
            init_capacity(new_cap);
    }

    // disable copy/move
    simple_buffer(const simple_buffer&) = delete;
    simple_buffer(simple_buffer&&) = delete;
    simple_buffer& operator=(const simple_buffer&) = delete;
    simple_buffer& operator=(simple_buffer&&) = delete;

    ~simple_buffer() {
        if (data_ != fixed_buffer())
            allocator_traits::deallocate(allocator_, data_, capacity_);
    }

    allocator_type get_allocator() const noexcept {
        return allocator_;
    }

    value_type* data() noexcept {
        return data_;
    }
    const value_type* data() const noexcept {
        return data_;
    }

    const_iterator begin() const noexcept {
        return data_;
    }
    const_iterator end() const noexcept {
        return data_ + size_;
    }

    // Capacity
    bool empty() const noexcept {
        return size_ == 0;
    }
    size_type size() const noexcept {
        return size_;
    }
    size_type max_size() const noexcept {
        return allocator_traits::max_size(allocator_);
    }
    size_type capacity() const noexcept {
        return capacity_;
    }

    void reserve(size_type new_cap) {
        if (new_cap > capacity_)
            grow_capacity(new_cap);
    }

    // Modifiers
    void clear() noexcept {
        size_ = 0;
    }

    void append(const value_type* first, const value_type* last) {
        const auto ncopy = std::distance(first, last);
        const size_type new_size = add_sizes(size_, ncopy);
        if (new_size > capacity_)
            grow(new_size);
        // copy
        traits_type::copy(data_ + size_, first, ncopy);
        // new size
        size_ = new_size;
    }

    void push_back(const value_type& value) {
        if (size_ < capacity_) {
            data_[size_] = value;
            ++size_;
            return;
        }
        // grow buffer capacity
        grow(add_sizes(size_, 1));
        data_[size_] = value;
        ++size_;
    }
    void pop_back() {
        --size_;
    }
    void resize(size_type count) {
        reserve(count);
        size_ = count;
    }

#ifdef DOCTEST_LIBRARY_INCLUDED
    void internal_test() {
        // https://en.cppreference.com/w/cpp/memory/allocator
        // default allocator is stateless, i.e. instances compare equal:
        CHECK(get_allocator() == allocator_);
        CHECK_THROWS(grow(max_size() + 1));
        CHECK_THROWS(add_sizes(max_size() - 1, 2));
    }
#endif

protected:
    void init_capacity(size_type new_cap) {
        data_ = allocator_traits::allocate(allocator_, new_cap);
        capacity_ = new_cap;
    }
    void grow_capacity(size_type new_cap) {
        value_type* new_data = allocator_traits::allocate(allocator_, new_cap);
        // copy data
        traits_type::copy(new_data, data(), size());
        // deallocate old data & assign new
        if (data_ != fixed_buffer())
            allocator_traits::deallocate(allocator_, data_, capacity_);
        data_ = new_data;
        capacity_ = new_cap;
    }

    // https://cs.chromium.org/chromium/src/url/url_canon.h
    // Grows the given buffer so that it can fit at least |min_cap|
    // characters. Throws std::length_error() if min_cap is too big.
    void grow(size_type min_cap) {
        static const size_type kMinBufferLen = 16;
        size_type new_cap = (capacity_ == 0) ? kMinBufferLen : capacity_;
        do {
            if (new_cap > (max_size() >> 1))  // Prevent overflow below.
                throw std::length_error("too big size");
            new_cap *= 2;
        } while (new_cap < min_cap);
        reserve(new_cap);
    }

    // add without overflow
    size_type add_sizes(size_type n1, size_type n2) const {
        if (max_size() - n1 >= n2)
            return n1 + n2;
        throw std::length_error("too big size");
    }

private:
    value_type* fixed_buffer() noexcept {
        return fixed_buffer_.data();
    }

private:
    allocator_type allocator_;
    value_type* data_ = fixed_buffer();
    size_type size_ = 0;
    size_type capacity_ = fixed_capacity;

    // fixed size buffer
    std::array<value_type, fixed_capacity> fixed_buffer_;
};

} // namespace upa

#endif // UPA_BUFFER_H

// #include "config.h"
// Copyright 2016-2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//

#ifndef UPA_CONFIG_H
#define UPA_CONFIG_H

#if __has_include(<version>)
# include <version> // IWYU pragma: export
#endif

// Macros for compilers that support the C++20 or later standard
// https://devblogs.microsoft.com/cppblog/msvc-now-correctly-reports-__cplusplus/
#if defined(_MSVC_LANG) ? (_MSVC_LANG >= 202002) : (__cplusplus >= 202002)
# define UPA_CPP_20
# define UPA_CONSTEXPR_20 constexpr
#else
# define UPA_CONSTEXPR_20 inline
#endif

// Define UPA_API macro to mark symbols for export/import
// when compiling as shared library
#if defined (UPA_LIB_EXPORT) || defined (UPA_LIB_IMPORT)
# ifdef _MSC_VER
#  ifdef UPA_LIB_EXPORT
#   define UPA_API __declspec(dllexport)
#  else
#   define UPA_API __declspec(dllimport)
#  endif
# elif defined(__clang__) || defined(__GNUC__)
#  define UPA_API __attribute__((visibility ("default")))
# endif
#endif
#ifndef UPA_API
# define UPA_API
#endif

// Barrier for pointer anti-aliasing optimizations even across function boundaries.
// This is a slightly modified U_ALIASING_BARRIER macro from the char16ptr.h file
// of the ICU 75.1 library.
// Discussion: https://github.com/sg16-unicode/sg16/issues/67
#ifndef UPA_ALIASING_BARRIER
# if defined(__clang__) || defined(__GNUC__)
#  define UPA_ALIASING_BARRIER(ptr) asm volatile("" : : "rm"(ptr) : "memory");  // NOLINT(*-macro-*,hicpp-no-assembler)
# else
#  define UPA_ALIASING_BARRIER(ptr)
# endif
#endif

#endif // UPA_CONFIG_H
             // IWYU pragma: export
// #include "str_arg.h"
// Copyright 2016-2024 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//

/**************************************************************
// Usage example:

template <class StrT, enable_if_str_arg_t<StrT> = 0>
inline void procfn(StrT&& str) {
    const auto inp = make_str_arg(std::forward<StrT>(str));
    const auto* first = inp.begin();
    const auto* last = inp.end();
    // do something with first ... last
}

**************************************************************/
#ifndef UPA_STR_ARG_H
#define UPA_STR_ARG_H

// #include "config.h"

// #include "url_utf.h"
// Copyright 2016-2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//
// This file contains portions of modified code from the ICU project.
// Copyright (c) 2016-2023 Unicode, Inc.
//

#ifndef UPA_URL_UTF_H
#define UPA_URL_UTF_H

// #include "config.h"
 // IWYU pragma: export
// #include "url_result.h"
// Copyright 2016-2023 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//

#ifndef UPA_URL_RESULT_H
#define UPA_URL_RESULT_H

#include <stdexcept>

namespace upa {

/// @brief URL validation and other error codes
///
/// See: https://url.spec.whatwg.org/#validation-error
enum class validation_errc {
    // Success:
    ok = 0,                         ///< Success
    // Ignored input (for internal use):
    ignored,                        ///< Setter ignored the value (internal)
    scheme_invalid_code_point,      ///< The scheme contains invalid code point (internal,
                                    ///< relevant to the protocol setter)

    // Standard validation error codes
    // https://url.spec.whatwg.org/#validation-error

    // Non-failure (only ipv4_out_of_range_part indicates failure in some cases,
    // see: https://url.spec.whatwg.org/#ipv4-out-of-range-part):
    // IDNA
    domain_to_unicode,              ///< Unicode ToUnicode records an error
    // Host parsing
    ipv4_empty_part,                ///< An IPv4 address ends with a U+002E (.)
    ipv4_non_decimal_part,          ///< The IPv4 address contains numbers expressed using hexadecimal or octal digits
    ipv4_out_of_range_part,         ///< An IPv4 address part exceeds 255
    // URL parsing
    invalid_url_unit,               ///< A code point is found that is not a URL unit
    special_scheme_missing_following_solidus, ///< The input’s scheme is not followed by "//"
    invalid_reverse_solidus,        ///< The URL has a special scheme and it uses U+005C (\) instead of U+002F (/)
    invalid_credentials,            ///< The input includes credentials
    file_invalid_windows_drive_letter, ///< The input is a relative-URL string that starts with a Windows drive letter
                                       ///< and the base URL’s scheme is "file"
    file_invalid_windows_drive_letter_host, ///< A file: URL’s host is a Windows drive letter

    // Failure:
    // IDNA
    domain_to_ascii,                ///< Unicode ToASCII records an error or returns the empty string
    // Host parsing
    domain_invalid_code_point,      ///< The input’s host contains a forbidden domain code point
    host_invalid_code_point,        ///< An opaque host contains a forbidden host code point
    ipv4_too_many_parts,            ///< An IPv4 address does not consist of exactly 4 parts
    ipv4_non_numeric_part,          ///< An IPv4 address part is not numeric
    ipv6_unclosed,                  ///< An IPv6 address is missing the closing U+005D (])
    ipv6_invalid_compression,       ///< An IPv6 address begins with improper compression
    ipv6_too_many_pieces,           ///< An IPv6 address contains more than 8 pieces
    ipv6_multiple_compression,      ///< An IPv6 address is compressed in more than one spot
    ipv6_invalid_code_point,        ///< An IPv6 address contains a code point that is neither an ASCII hex digit nor
                                    ///< a U+003A (:). Or it unexpectedly ends
    ipv6_too_few_pieces,            ///< An uncompressed IPv6 address contains fewer than 8 pieces
    ipv4_in_ipv6_too_many_pieces,   ///< An IPv6 address with IPv4 address syntax: the IPv6 address has more than 6 pieces
    ipv4_in_ipv6_invalid_code_point, ///< An IPv6 address with IPv4 address syntax:
                                     ///< * An IPv4 part is empty or contains a non-ASCII digit
                                     ///< * An IPv4 part contains a leading 0
                                     ///< * There are too many IPv4 parts
    ipv4_in_ipv6_out_of_range_part, ///< An IPv6 address with IPv4 address syntax: an IPv4 part exceeds 255
    ipv4_in_ipv6_too_few_parts,     ///< An IPv6 address with IPv4 address syntax: an IPv4 address contains too few parts
    // URL parsing
    missing_scheme_non_relative_url, ///< The input is missing a scheme, because it does not begin with an ASCII alpha, and
                                     ///< either no base URL was provided or the base URL cannot be used as a base URL
                                     ///< because it has an opaque path
    host_missing,                   ///< The input has a special scheme, but does not contain a host
    port_out_of_range,              ///< The input’s port is too big
    port_invalid,                   ///< The input’s port is invalid

    // Non-standard error codes (indicates failure)

    overflow,                       ///< URL is too long
    invalid_base,                   ///< Invalid base
    // url_from_file_path errors
    file_empty_path,                ///< Path cannot be empty
    file_unsupported_path,          ///< Unsupported file path (e.g. non-absolute)
    // path_from_file_url errors
    not_file_url,                   ///< Not a file URL
    file_url_cannot_have_host,      ///< POSIX path cannot have host
    file_url_unsupported_host,      ///< UNC path cannot have "." hostname
    file_url_invalid_unc,           ///< Invalid UNC path in file URL
    file_url_not_windows_path,      ///< Not a Windows path in file URL
    null_character,                 ///< Path contains null character
};

/// @brief Check validation error code indicates success
/// @return `true` if validation error code is validation_errc::ok, `false` otherwise
[[nodiscard]] constexpr bool success(validation_errc res) noexcept {
    return res == validation_errc::ok;
}

/// @brief URL exception class

class url_error : public std::runtime_error {
public:
    /// constructs a new url_error object with the given result code and error message
    ///
    /// @param[in] res validation error code
    /// @param[in] what_arg error message
    explicit url_error(validation_errc res, const char* what_arg)
        : std::runtime_error(what_arg)
        , res_(res)
    {}

    /// @return validation error code
    [[nodiscard]] validation_errc result() const noexcept {
        return res_;
    }
private:
    validation_errc res_;
};

namespace detail {

/// @brief Result/value pair

template<typename T, typename R = bool>
struct result_value {
    T value{};
    R result{};

    constexpr result_value(R res) noexcept
        : result(res) {}
    constexpr result_value(R res, T val) noexcept
        : value(val), result(res) {}
    [[nodiscard]] constexpr operator R() const noexcept {
        return result;
    }
};

} // namespace detail
} // namespace upa

#endif // UPA_URL_RESULT_H

#include <cstdint> // uint8_t, uint32_t
#include <string>
#include <string_view>


namespace upa {

class url_utf {
public:
    template <typename CharT>
    static constexpr detail::result_value<uint32_t> read_utf_char(const CharT*& first, const CharT* last) noexcept;

    template <typename CharT>
    static void read_char_append_utf8(const CharT*& it, const CharT* last, std::string& output);
    static void read_char_append_utf8(const char*& it, const char* last, std::string& output);

    template <class Output, void appendByte(unsigned char, Output&)>
    static void append_utf8(uint32_t code_point, Output& output);

    template <class Output>
    static void append_utf16(uint32_t code_point, Output& output);

    // Convert to utf-8 string
    static UPA_API std::string to_utf8_string(const char16_t* first, const char16_t* last);
    static UPA_API std::string to_utf8_string(const char32_t* first, const char32_t* last);

    // Invalid utf-8 bytes sequences are replaced with 0xFFFD character.
    static UPA_API void check_fix_utf8(std::string& str);

    static UPA_API int compare_by_code_units(const char* first1, const char* last1, const char* first2, const char* last2) noexcept;
protected:
    // low level
    static constexpr bool read_code_point(const char*& first, const char* last, uint32_t& code_point) noexcept;
    static constexpr bool read_code_point(const char16_t*& first, const char16_t* last, uint32_t& code_point) noexcept;
    static constexpr bool read_code_point(const char32_t*& first, const char32_t* last, uint32_t& code_point) noexcept;
private:
    // Replacement character (U+FFFD)
    static constexpr std::string_view kReplacementCharUtf8{ "\xEF\xBF\xBD" };

    // Following two arrays have values from corresponding macros in ICU 74.1 library's
    // include\unicode\utf8.h file.

    // Internal bit vector for 3-byte UTF-8 validity check, for use in U8_IS_VALID_LEAD3_AND_T1.
    // Each bit indicates whether one lead byte + first trail byte pair starts a valid sequence.
    // Lead byte E0..EF bits 3..0 are used as byte index,
    // first trail byte bits 7..5 are used as bit index into that byte.
    static constexpr uint8_t k_U8_LEAD3_T1_BITS[16] = {
        0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x10, 0x30, 0x30
    };
    // Internal bit vector for 4-byte UTF-8 validity check, for use in U8_IS_VALID_LEAD4_AND_T1.
    // Each bit indicates whether one lead byte + first trail byte pair starts a valid sequence.
    // First trail byte bits 7..4 are used as byte index,
    // lead byte F0..F4 bits 2..0 are used as bit index into that byte.
    static constexpr uint8_t k_U8_LEAD4_T1_BITS[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1E, 0x0F, 0x0F, 0x0F, 0x00, 0x00, 0x00, 0x00
    };
};


// The URL class (https://url.spec.whatwg.org/#url-class) in URL Standard uses
// USVString for text data. The USVString is sequence of Unicode scalar values
// (https://heycam.github.io/webidl/#idl-USVString). The Infra Standard defines
// how to convert into it: "To convert a JavaScript string into a scalar value
// string, replace any surrogates with U+FFFD"
// (https://infra.spec.whatwg.org/#javascript-string-convert).
//
// The url_utf::read_utf_char(..) function follows this conversion when reads UTF-16
// text (CharT = char16_t). When it reads UTF-32 text (CharT = char32_t) it additionally
// replaces code units > 0x10FFFF with U+FFFD.
//
// When it reads UTF-8 text (CharT = char) it replaces bytes in invalid UTF-8 sequences
// with U+FFFD. This corresponds to UTF-8 decode without BOM
// (https://encoding.spec.whatwg.org/#utf-8-decode-without-bom).
//
// This function reads one character from [first, last), places it's value to `code_point`
// and advances `first` to point to the next character.

template <typename CharT>
constexpr detail::result_value<uint32_t> url_utf::read_utf_char(const CharT*& first, const CharT* last) noexcept {
    // read_code_point always initializes code_point
    uint32_t code_point{};
    if (read_code_point(first, last, code_point))
        return { true, code_point };
    return { false, 0xFFFD }; // REPLACEMENT CHARACTER
}

namespace detail {
    template <typename CharT>
    inline void append_to_string(uint8_t c, std::basic_string<CharT>& str) {
        str.push_back(static_cast<CharT>(c));
    };
} // namespace detail

template <typename CharT>
inline void url_utf::read_char_append_utf8(const CharT*& it, const CharT* last, std::string& output) {
    const uint32_t code_point = read_utf_char(it, last).value;
    append_utf8<std::string, detail::append_to_string>(code_point, output);
}

inline void url_utf::read_char_append_utf8(const char*& it, const char* last, std::string& output) {
    uint32_t code_point; // NOLINT(cppcoreguidelines-init-variables)
    const char* start = it;
    if (read_code_point(it, last, code_point))
        output.append(start, it);
    else
        output.append(kReplacementCharUtf8);
}

// ------------------------------------------------------------------------
// The code bellow is based on the ICU 74.1 library's UTF macros in
// utf8.h, utf16.h and utf.h files.
//
// (c) 2016 and later: Unicode, Inc. and others.
// License & terms of use: https://www.unicode.org/copyright.html
//

// Decoding UTF-8, UTF-16, UTF-32

// Modified version of the U8_INTERNAL_NEXT_OR_SUB macro in utf8.h from ICU

constexpr bool url_utf::read_code_point(const char*& first, const char* last, uint32_t& c) noexcept {
    c = static_cast<uint8_t>(*first++);
    if (c & 0x80) {
        uint8_t tmp = 0;
        // NOLINTBEGIN(bugprone-assignment-in-if-condition)
        if (first != last &&
            // fetch/validate/assemble all but last trail byte
            (c >= 0xE0 ?
                (c < 0xF0 ? // U+0800..U+FFFF except surrogates
                    k_U8_LEAD3_T1_BITS[c &= 0xF] & (1 << ((tmp = static_cast<uint8_t>(*first)) >> 5)) &&
                    (tmp &= 0x3F, 1)
                    : // U+10000..U+10FFFF
                    (c -= 0xF0) <= 4 &&
                    k_U8_LEAD4_T1_BITS[(tmp = static_cast<uint8_t>(*first)) >> 4] & (1 << c) &&
                    (c = (c << 6) | (tmp & 0x3F), ++first != last) &&
                    (tmp = static_cast<uint8_t>(static_cast<uint8_t>(*first) - 0x80)) <= 0x3F) &&
                // valid second-to-last trail byte
                (c = (c << 6) | tmp, ++first != last)
                : // U+0080..U+07FF
                c >= 0xC2 && (c &= 0x1F, 1)) &&
            // last trail byte
            (tmp = static_cast<uint8_t>(static_cast<uint8_t>(*first) - 0x80)) <= 0x3F &&
            (c = (c << 6) | tmp, ++first, 1)) {
            // valid utf-8
        } else {
            // ill-formed
            // c = 0xfffd;
            return false;
        }
        // NOLINTEND(bugprone-assignment-in-if-condition)
    }
    return true;
}

namespace detail {
    // UTF-16

    // Is this code unit/point a surrogate (U+d800..U+dfff)?
    // Based on U_IS_SURROGATE in utf.h from ICU
    template <typename T>
    constexpr bool u16_is_surrogate(T c) noexcept {
        return (c & 0xfffff800) == 0xd800;
    }

    // Assuming c is a surrogate code point (u16_is_surrogate(c)),
    // is it a lead surrogate?
    // Based on U16_IS_SURROGATE_LEAD in utf16.h from ICU
    template <typename T>
    constexpr bool u16_is_surrogate_lead(T c) noexcept {
        return (c & 0x400) == 0;
    }

    // Is this code unit a lead surrogate (U+d800..U+dbff)?
    // Based on U16_IS_LEAD in utf16.h from ICU
    template <typename T>
    constexpr bool u16_is_lead(T c) noexcept {
        return (c & 0xfffffc00) == 0xd800;
    }

    // Is this code unit a trail surrogate (U+dc00..U+dfff)?
    // Based on U16_IS_TRAIL in utf16.h from ICU
    template <typename T>
    constexpr bool u16_is_trail(T c) noexcept {
        return (c & 0xfffffc00) == 0xdc00;
    }

    // Get a supplementary code point value (U+10000..U+10ffff)
    // from its lead and trail surrogates.
    // Based on U16_GET_SUPPLEMENTARY in utf16.h from ICU
    constexpr uint32_t u16_get_supplementary(uint32_t lead, uint32_t trail) noexcept {
        constexpr uint32_t u16_surrogate_offset = (0xd800 << 10UL) + 0xdc00 - 0x10000;
        return (lead << 10UL) + trail - u16_surrogate_offset;
    }
} // namespace detail

// Modified version of the U16_NEXT_OR_FFFD macro in utf16.h from ICU

constexpr bool url_utf::read_code_point(const char16_t*& first, const char16_t* last, uint32_t& c) noexcept {
    c = *first++;
    if (detail::u16_is_surrogate(c)) {
        if (detail::u16_is_surrogate_lead(c) && first != last && detail::u16_is_trail(*first)) {
            c = detail::u16_get_supplementary(c, *first);
            ++first;
        } else {
            // c = 0xfffd;
            return false;
        }
    }
    return true;
}

constexpr bool url_utf::read_code_point(const char32_t*& first, const char32_t*, uint32_t& c) noexcept {
    // no conversion
    c = *first++;
    // don't allow surogates (U+D800..U+DFFF) and too high values
    return c < 0xD800u || (c > 0xDFFFu && c <= 0x10FFFFu);
}


// Encoding to UTF-8, UTF-16

// Modified version of the U8_APPEND_UNSAFE macro in utf8.h from ICU
//
// It converts code_point to UTF-8 bytes sequence and calls appendByte function for each byte.
// It assumes a valid code point (https://infra.spec.whatwg.org/#scalar-value).

template <class Output, void appendByte(uint8_t, Output&)>
inline void url_utf::append_utf8(uint32_t code_point, Output& output) {
    if (code_point <= 0x7f) {
        appendByte(static_cast<uint8_t>(code_point), output);
    } else {
        if (code_point <= 0x7ff) {
            appendByte(static_cast<uint8_t>((code_point >> 6) | 0xc0), output);
        } else {
            if (code_point <= 0xffff) {
                appendByte(static_cast<uint8_t>((code_point >> 12) | 0xe0), output);
            } else {
                appendByte(static_cast<uint8_t>((code_point >> 18) | 0xf0), output);
                appendByte(static_cast<uint8_t>(((code_point >> 12) & 0x3f) | 0x80), output);
            }
            appendByte(static_cast<uint8_t>(((code_point >> 6) & 0x3f) | 0x80), output);
        }
        appendByte(static_cast<uint8_t>((code_point & 0x3f) | 0x80), output);
    }
}

// Modified version of the U16_APPEND_UNSAFE macro in utf16.h from ICU
//
// It converts code_point to UTF-16 code units sequence and appends to output.
// It assumes a valid code point (https://infra.spec.whatwg.org/#scalar-value).

template <class Output>
inline void url_utf::append_utf16(uint32_t code_point, Output& output) {
    if (code_point <= 0xffff) {
        output.push_back(static_cast<char16_t>(code_point));
    } else {
        output.push_back(static_cast<char16_t>((code_point >> 10) + 0xd7c0));
        output.push_back(static_cast<char16_t>((code_point & 0x3ff) | 0xdc00));
    }
}


} // namespace upa

#endif // UPA_URL_UTF_H

#include <cassert>
#include <cstddef>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace upa {

// String view type

using string_view = std::string_view;

// Supported char and size types

template<class CharT>
constexpr bool is_char_type_v =
    std::is_same_v<CharT, char> ||
#ifdef __cpp_char8_t
    std::is_same_v<CharT, char8_t> ||
#endif
    std::is_same_v<CharT, char16_t> ||
    std::is_same_v<CharT, char32_t> ||
    std::is_same_v<CharT, wchar_t>;

template<class SizeT>
constexpr bool is_size_type_v =
    std::is_convertible_v<SizeT, std::size_t> ||
    std::is_convertible_v<SizeT, std::ptrdiff_t>;

// See: https://en.cppreference.com/w/cpp/concepts/derived_from
template<class Derived, class Base>
constexpr bool is_derived_from_v =
    std::is_base_of_v<Base, Derived> &&
    std::is_convertible_v<const volatile Derived*, const volatile Base*>;


// string args helper class

template <typename CharT>
class str_arg {
public:
    using input_type = CharT;
    using traits_type = std::char_traits<input_type>;
    // output value type
    using value_type =
        // wchar_t type will be converted to char16_t or char32_t type equivalent by size
        std::conditional_t<std::is_same_v<CharT, wchar_t>, std::conditional_t<sizeof(wchar_t) == sizeof(char16_t), char16_t, char32_t>,
#ifdef __cpp_char8_t
        // char8_t type will be converted to char type
        std::conditional_t<std::is_same_v<CharT, char8_t>, char, input_type>
#else
        input_type
#endif
        >;

    // constructors
    constexpr str_arg(const str_arg&) noexcept = default;

    constexpr str_arg(const CharT* s)
        : first_(s)
        , last_(s + traits_type::length(s))
    {}

    template <typename SizeT, std::enable_if_t<is_size_type_v<SizeT>, int> = 0>
    constexpr str_arg(const CharT* s, SizeT length)
        : first_(s)
        , last_(s + length)
    { assert(length >= 0); }

    constexpr str_arg(const CharT* first, const CharT* last)
        : first_(first)
        , last_(last)
    { assert(first <= last); }

    // destructor
    UPA_CONSTEXPR_20 ~str_arg() noexcept = default;

    // assignment is not used
    str_arg& operator=(const str_arg&) = delete;

    // output
    constexpr const value_type* begin() const noexcept {
        return reinterpret_cast<const value_type*>(first_);
    }
    constexpr const value_type* end() const noexcept {
        return reinterpret_cast<const value_type*>(last_);
    }
    constexpr const value_type* data() const noexcept {
        return begin();
    }
    constexpr std::size_t length() const noexcept {
        return end() - begin();
    }
    constexpr std::size_t size() const noexcept {
        return length();
    }

private:
    const input_type* first_;
    const input_type* last_;
};


// String type helpers

template<class T>
using remove_cvptr_t = std::remove_cv_t<std::remove_pointer_t<T>>;

template<class T>
using remove_cvref_t = std::remove_cv_t<std::remove_reference_t<T>>;

namespace detail {

// See: https://stackoverflow.com/a/9154394

// test class T has data() member
template<class T>
auto test_data(int) -> decltype(std::declval<T>().data());
template<class>
auto test_data(long) -> void;

// test class T has size() member
template<class T>
auto test_size(int) -> decltype(std::declval<T>().size());
template<class>
auto test_size(long) -> void;

// T::data() return type (void - if no such member)
template<class T>
using data_member_t = decltype(detail::test_data<T>(0));

// T::size() return type (void - if no such member)
template<class T>
using size_member_t = decltype(detail::test_size<T>(0));

// Check that StrT has data() and size() members of supported types

template<class StrT>
constexpr bool has_data_and_size_v =
    std::is_pointer_v<detail::data_member_t<StrT>> &&
    is_char_type_v<remove_cvptr_t<detail::data_member_t<StrT>>> &&
    is_size_type_v<detail::size_member_t<StrT>>;

// Check StrT is convertible to std::basic_string_view

template<class StrT, typename CharT>
constexpr bool convertible_to_string_view_v =
    std::is_convertible_v<StrT, std::basic_string_view<CharT>> &&
    !has_data_and_size_v<StrT> &&
    !std::is_same_v<StrT, std::nullptr_t>;

// Common class for converting input to str_arg

template<typename CharT, class ArgT>
struct str_arg_char_common {
    using type = CharT;
    static constexpr str_arg<CharT> to_str_arg(ArgT str) {
        return { str.data(), str.size() };
    }
};

// Default str_arg_char implementation

template<class StrT, typename = void>
struct str_arg_char_default {};

// StrT has data() and size() members
template<class StrT>
struct str_arg_char_default<StrT, std::enable_if_t<
    has_data_and_size_v<StrT>>>
    : str_arg_char_common<
    remove_cvptr_t<detail::data_member_t<StrT>>,
    remove_cvref_t<StrT> const&> {};

// StrT is convertible to std::basic_string_view
template<class StrT>
struct str_arg_char_default<StrT, std::enable_if_t<
    convertible_to_string_view_v<StrT, char>>>
    : str_arg_char_common<char, std::basic_string_view<char>> {};

#ifdef __cpp_char8_t
template<class StrT>
struct str_arg_char_default<StrT, std::enable_if_t<
    convertible_to_string_view_v<StrT, char8_t>>>
    : str_arg_char_common<char8_t, std::basic_string_view<char8_t>> {};
#endif

template<class StrT>
struct str_arg_char_default<StrT, std::enable_if_t<
    convertible_to_string_view_v<StrT, char16_t>>>
    : str_arg_char_common<char16_t, std::basic_string_view<char16_t>> {};

template<class StrT>
struct str_arg_char_default<StrT, std::enable_if_t<
    convertible_to_string_view_v<StrT, char32_t>>>
    : str_arg_char_common<char32_t, std::basic_string_view<char32_t>> {};

template<class StrT>
struct str_arg_char_default<StrT, std::enable_if_t<
    convertible_to_string_view_v<StrT, wchar_t>>>
    : str_arg_char_common<wchar_t, std::basic_string_view<wchar_t>> {};

} // namespace detail


// Requirements for string arguments

template<class StrT, typename = void>
struct str_arg_char : detail::str_arg_char_default<StrT> {};

// Null terminated string
template<class CharT>
struct str_arg_char<CharT*, std::enable_if_t<is_char_type_v<remove_cvref_t<CharT>>>> {
    using type = remove_cvref_t<CharT>;
    static constexpr str_arg<type> to_str_arg(const type* s) {
        return s;
    }
};

// str_arg input
template<class CharT>
struct str_arg_char<str_arg<CharT>> {
    using type = CharT;
    static constexpr str_arg<type> to_str_arg(str_arg<type> s) {
        return s;
    }
};


// String arguments helper types

template<class StrT>
using str_arg_char_s = str_arg_char<std::decay_t<StrT>>;

template<class StrT>
using str_arg_char_t = typename str_arg_char_s<StrT>::type;


template<class StrT>
using enable_if_str_arg_t = std::enable_if_t<
    is_char_type_v<str_arg_char_t<StrT>>,
    int>;


// String arguments helper function

template <class StrT>
constexpr auto make_str_arg(StrT&& str) -> str_arg<str_arg_char_t<StrT>> {
    return str_arg_char_s<StrT>::to_str_arg(std::forward<StrT>(str));
}


// Convert to std::string or string_view

template<class CharT>
constexpr bool is_char8_type_v =
    std::is_same_v<CharT, char>
#ifdef __cpp_char8_t
    || std::is_same_v<CharT, char8_t>
#endif
;

template<class StrT>
using enable_if_str_arg_to_char8_t = std::enable_if_t<
    is_char8_type_v<str_arg_char_t<StrT>>,
    int>;

template<class CharT>
constexpr bool is_charW_type_v =
    std::is_same_v<CharT, char16_t> ||
    std::is_same_v<CharT, char32_t> ||
    std::is_same_v<CharT, wchar_t>;

template<class StrT>
using enable_if_str_arg_to_charW_t = std::enable_if_t<
    is_charW_type_v<str_arg_char_t<StrT>>,
    int>;


inline std::string&& make_string(std::string&& str) {
    return std::move(str);
}

template <class StrT, enable_if_str_arg_to_char8_t<StrT> = 0>
constexpr string_view make_string(StrT&& str) {
    const auto inp = make_str_arg(std::forward<StrT>(str));
    return { inp.data(), inp.length() };
}

template <class StrT, enable_if_str_arg_to_charW_t<StrT> = 0>
inline std::string make_string(StrT&& str) {
    const auto inp = make_str_arg(std::forward<StrT>(str));
    return url_utf::to_utf8_string(inp.begin(), inp.end());
}


} // namespace upa

#endif // UPA_STR_ARG_H
            // IWYU pragma: export
// #include "url_host.h"
// Copyright 2016-2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//

#ifndef UPA_URL_HOST_H
#define UPA_URL_HOST_H

// #include "buffer.h"

// #include "config.h"

// #include "idna.h"
// Copyright 2017-2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//
#ifndef UPA_IDNA_H
#define UPA_IDNA_H

// #include "idna/idna.h"
// Copyright 2017-2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//
#ifndef UPA_IDNA_IDNA_H
#define UPA_IDNA_IDNA_H

// #include "bitmask_operators.hpp"
#ifndef UPA_IDNA_BITMASK_OPERATORS_HPP
#define UPA_IDNA_BITMASK_OPERATORS_HPP

// (C) Copyright 2015 Just Software Solutions Ltd
//
// Distributed under the Boost Software License, Version 1.0.
//
// Boost Software License - Version 1.0 - August 17th, 2003
//
// Permission is hereby granted, free of charge, to any person or
// organization obtaining a copy of the software and accompanying
// documentation covered by this license (the "Software") to use,
// reproduce, display, distribute, execute, and transmit the
// Software, and to prepare derivative works of the Software, and
// to permit third-parties to whom the Software is furnished to
// do so, all subject to the following:
//
// The copyright notices in the Software and this entire
// statement, including the above license grant, this restriction
// and the following disclaimer, must be included in all copies
// of the Software, in whole or in part, and all derivative works
// of the Software, unless such copies or derivative works are
// solely in the form of machine-executable object code generated
// by a source language processor.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
// KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
// COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE
// LIABLE FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN
// CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#include<type_traits>

namespace upa::idna {

template<typename E>
struct enable_bitmask_operators : public std::false_type {};

template<typename E>
constexpr bool enable_bitmask_operators_v = enable_bitmask_operators<E>::value;

} // namespace upa::idna

template<typename E>
constexpr std::enable_if_t<upa::idna::enable_bitmask_operators_v<E>, E>
operator|(E lhs, E rhs) noexcept {
    using underlying = std::underlying_type_t<E>;
    return static_cast<E>(
        static_cast<underlying>(lhs) | static_cast<underlying>(rhs));
}

template<typename E>
constexpr std::enable_if_t<upa::idna::enable_bitmask_operators_v<E>, E>
operator&(E lhs, E rhs) noexcept {
    using underlying = std::underlying_type_t<E>;
    return static_cast<E>(
        static_cast<underlying>(lhs) & static_cast<underlying>(rhs));
}

template<typename E>
constexpr std::enable_if_t<upa::idna::enable_bitmask_operators_v<E>, E>
operator^(E lhs, E rhs) noexcept {
    using underlying = std::underlying_type_t<E>;
    return static_cast<E>(
        static_cast<underlying>(lhs) ^ static_cast<underlying>(rhs));
}

template<typename E>
constexpr std::enable_if_t<upa::idna::enable_bitmask_operators_v<E>, E>
operator~(E lhs) noexcept {
    using underlying = std::underlying_type_t<E>;
    return static_cast<E>(
        ~static_cast<underlying>(lhs));
}

template<typename E>
constexpr std::enable_if_t<upa::idna::enable_bitmask_operators_v<E>, E&>
operator|=(E& lhs, E rhs) noexcept {
    using underlying = std::underlying_type_t<E>;
    lhs = static_cast<E>(
        static_cast<underlying>(lhs) | static_cast<underlying>(rhs));
    return lhs;
}

template<typename E>
constexpr std::enable_if_t<upa::idna::enable_bitmask_operators_v<E>, E&>
operator&=(E& lhs, E rhs) noexcept {
    using underlying = std::underlying_type_t<E>;
    lhs = static_cast<E>(
        static_cast<underlying>(lhs) & static_cast<underlying>(rhs));
    return lhs;
}

template<typename E>
constexpr std::enable_if_t<upa::idna::enable_bitmask_operators_v<E>, E&>
operator^=(E& lhs, E rhs) noexcept {
    using underlying = std::underlying_type_t<E>;
    lhs = static_cast<E>(
        static_cast<underlying>(lhs) ^ static_cast<underlying>(rhs));
    return lhs;
}

#endif // UPA_IDNA_BITMASK_OPERATORS_HPP

// #include "config.h"
// Copyright 2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//
#ifndef UPA_IDNA_CONFIG_H
#define UPA_IDNA_CONFIG_H

// Define UPA_IDNA_API macro to mark symbols for export/import
// when compiling as shared library
#if defined (UPA_LIB_EXPORT) || defined (UPA_LIB_IMPORT)
# ifdef _MSC_VER
#  ifdef UPA_LIB_EXPORT
#   define UPA_IDNA_API __declspec(dllexport)
#  else
#   define UPA_IDNA_API __declspec(dllimport)
#  endif
# elif defined(__clang__) || defined(__GNUC__)
#  define UPA_IDNA_API __attribute__((visibility ("default")))
# endif
#endif
#ifndef UPA_IDNA_API
# define UPA_IDNA_API
#endif

#endif // UPA_IDNA_CONFIG_H
 // IWYU pragma: export
// #include "idna_version.h"
// Copyright 2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//
#ifndef UPA_IDNA_IDNA_VERSION_H
#define UPA_IDNA_IDNA_VERSION_H

// NOLINTBEGIN(*-macro-*)

#define UPA_IDNA_VERSION_MAJOR 2
#define UPA_IDNA_VERSION_MINOR 3
#define UPA_IDNA_VERSION_PATCH 0

#define UPA_IDNA_VERSION "2.3.0"

// NOLINTEND(*-macro-*)

#endif // UPA_IDNA_IDNA_VERSION_H
 // IWYU pragma: export
#include <string>

namespace upa::idna {

enum class Option {
    Default           = 0,
    UseSTD3ASCIIRules = 0x0001,
    Transitional      = 0x0002,
    VerifyDnsLength   = 0x0004,
    CheckHyphens      = 0x0008,
    CheckBidi         = 0x0010,
    CheckJoiners      = 0x0020,
    // ASCII optimization
    InputASCII        = 0x1000,
};

template<>
struct enable_bitmask_operators<Option> : public std::true_type {};


namespace detail {

// Bit flags
constexpr bool has(Option option, const Option value) noexcept {
    return (option & value) == value;
}

constexpr Option domain_options(bool be_strict, bool is_input_ascii) noexcept {
    // https://url.spec.whatwg.org/#concept-domain-to-ascii
    // https://url.spec.whatwg.org/#concept-domain-to-unicode
    // Note. The to_unicode ignores Option::VerifyDnsLength
    auto options = Option::CheckBidi | Option::CheckJoiners;
    if (be_strict)
        options |= Option::CheckHyphens | Option::UseSTD3ASCIIRules | Option::VerifyDnsLength;
    if (is_input_ascii)
        options |= Option::InputASCII;
    return options;
}

// IDNA map and normalize to NFC

template <typename CharT>
bool map(std::u32string& mapped, const CharT* input, const CharT* input_end, Option options, bool is_to_ascii);

extern template UPA_IDNA_API bool map(std::u32string&, const char*, const char*, Option, bool);
extern template UPA_IDNA_API bool map(std::u32string&, const char16_t*, const char16_t*, Option, bool);
extern template UPA_IDNA_API bool map(std::u32string&, const char32_t*, const char32_t*, Option, bool);

// Performs ToASCII on IDNA-mapped and normalized to NFC input
UPA_IDNA_API bool to_ascii_mapped(std::string& domain, const std::u32string& mapped, Option options);

// Performs ToUnicode on IDNA-mapped and normalized to NFC input
UPA_IDNA_API bool to_unicode_mapped(std::u32string& domain, const std::u32string& mapped, Option options);

} // namespace detail


/// @brief Implements the Unicode IDNA ToASCII
///
/// See: https://www.unicode.org/reports/tr46/#ToASCII
///
/// @param[out] domain buffer to store result string
/// @param[in]  input source domain string
/// @param[in]  input_end the end of source domain string
/// @param[in]  options
/// @return `true` on success, or `false` on failure
template <typename CharT>
inline bool to_ascii(std::string& domain, const CharT* input, const CharT* input_end, Option options) {
    // P1 - Map and further processing
    std::u32string mapped;
    domain.clear();
    return
        detail::map(mapped, input, input_end, options, true) &&
        detail::to_ascii_mapped(domain, mapped, options);
}

/// @brief Implements the Unicode IDNA ToUnicode
///
/// See: https://www.unicode.org/reports/tr46/#ToUnicode
///
/// @param[out] domain buffer to store result string
/// @param[in]  input source domain string
/// @param[in]  input_end the end of source domain string
/// @param[in]  options
/// @return `true` on success, or `false` on errors
template <typename CharT>
inline bool to_unicode(std::u32string& domain, const CharT* input, const CharT* input_end, Option options) {
    // P1 - Map and further processing
    std::u32string mapped;
    detail::map(mapped, input, input_end, options, false);
    return detail::to_unicode_mapped(domain, mapped, options);
}

/// @brief Implements the domain to ASCII algorithm
///
/// See: https://url.spec.whatwg.org/#concept-domain-to-ascii
///
/// @param[out] domain buffer to store result string
/// @param[in]  input source domain string
/// @param[in]  input_end the end of source domain string
/// @param[in]  be_strict
/// @param[in]  is_input_ascii
/// @return `true` on success, or `false` on failure
template <typename CharT>
inline bool domain_to_ascii(std::string& domain, const CharT* input, const CharT* input_end,
    bool be_strict = false, bool is_input_ascii = false)
{
    const bool res = to_ascii(domain, input, input_end, detail::domain_options(be_strict, is_input_ascii));

    // 3. If result is the empty string, domain-to-ASCII validation error, return failure.
    //
    // Note. Result of to_ascii can be the empty string if input consists entirely of
    // IDNA ignored code points.
    return res && !domain.empty();
}

/// @brief Implements the domain to Unicode algorithm
///
/// See: https://url.spec.whatwg.org/#concept-domain-to-unicode
///
/// @param[out] domain buffer to store result string
/// @param[in]  input source domain string
/// @param[in]  input_end the end of source domain string
/// @param[in]  be_strict
/// @param[in]  is_input_ascii
/// @return `true` on success, or `false` on errors
template <typename CharT>
inline bool domain_to_unicode(std::u32string& domain, const CharT* input, const CharT* input_end,
    bool be_strict = false, bool is_input_ascii = false)
{
    return to_unicode(domain, input, input_end, detail::domain_options(be_strict, is_input_ascii));
}

/// @brief Encodes Unicode version
///
/// The version is encoded as follows: <version 1st number> * 0x1000000 +
/// <version 2nd number> * 0x10000 + <version 3rd number> * 0x100 + <version 4th number>
///
/// For example for Unicode version 15.1.0 it returns 0x0F010000
///
/// @param[in] n1 version 1st number
/// @param[in] n2 version 2nd number
/// @param[in] n3 version 3rd number
/// @param[in] n4 version 4th number
/// @return encoded Unicode version
[[nodiscard]] constexpr unsigned make_unicode_version(unsigned n1, unsigned n2 = 0,
    unsigned n3 = 0, unsigned n4 = 0) noexcept {
    return n1 << 24 | n2 << 16 | n3 << 8 | n4;
}

/// @brief Gets Unicode version that IDNA library conforms to
///
/// @return encoded Unicode version
/// @see make_unicode_version
[[nodiscard]] inline unsigned unicode_version() {
    return make_unicode_version(16);
}


} // namespace upa::idna

#endif // UPA_IDNA_IDNA_H
 // IWYU pragma: export
// #include "idna/nfc.h"
// Copyright 2024-2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//
#ifndef UPA_IDNA_NFC_H
#define UPA_IDNA_NFC_H

// #include "config.h"
 // IWYU pragma: export
// #include <string>

namespace upa::idna {


UPA_IDNA_API void compose(std::u32string& str);
UPA_IDNA_API void canonical_decompose(std::u32string& str);

UPA_IDNA_API void normalize_nfc(std::u32string& str);
[[nodiscard]] UPA_IDNA_API bool is_normalized_nfc(const char32_t* first, const char32_t* last);


} // namespace upa::idna

#endif // UPA_IDNA_NFC_H

// #include "idna/punycode.h"
// Copyright 2017-2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//
#ifndef UPA_IDNA_PUNYCODE_H
#define UPA_IDNA_PUNYCODE_H

// #include "config.h"
 // IWYU pragma: export
// #include <string>

namespace upa::idna::punycode {

enum class status {
    success = 0,
    bad_input = 1,  // Input is invalid.
    big_output = 2, // Output would exceed the space provided.
    overflow = 3    // Wider integers needed to process input.
};

UPA_IDNA_API status encode(std::string& output, const char32_t* first, const char32_t* last);
UPA_IDNA_API status decode(std::u32string& output, const char32_t* first, const char32_t* last);

} // namespace upa::idna::punycode

#endif // UPA_IDNA_PUNYCODE_H


#endif // UPA_IDNA_H

// #include "str_arg.h"

// #include "url_ip.h"
// Copyright 2016-2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//

#ifndef UPA_URL_IP_H
#define UPA_URL_IP_H

// #include "config.h"
 // IWYU pragma: export
// #include "url_percent_encode.h"
// Copyright 2016-2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//
// This file contains portions of modified code from:
// https://cs.chromium.org/chromium/src/url/url_canon_internal.h
// Copyright 2013 The Chromium Authors. All rights reserved.
//

#ifndef UPA_URL_PERCENT_ENCODE_H
#define UPA_URL_PERCENT_ENCODE_H

// #include "config.h"
 // IWYU pragma: export
// #include "str_arg.h"

// #include "url_utf.h"

// #include "util.h"
// Copyright 2016-2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//

#ifndef UPA_UTIL_H
#define UPA_UTIL_H

// #include "config.h"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <stdexcept>
#include <string>
#include <type_traits>

namespace upa::util {

// For use in static_assert, workaround before CWG2518/P2593R1

template<class>
constexpr bool false_v = false;

// Integers

// Some functions here use unsigned arithmetics with unsigned overflow intentionally.
// So unsigned-integer-overflow checks are disabled for these functions in the Clang
// UndefinedBehaviorSanitizer (UBSan) with
// __attribute__((no_sanitize("unsigned-integer-overflow"))).

// Utility class to get unsigned (abs) max, min values of (signed) integer type
template <typename T, typename UT = std::make_unsigned_t<T>>
struct unsigned_limit {
    static constexpr UT max() noexcept {
        return static_cast<UT>(std::numeric_limits<T>::max());
    }

#if defined(__clang__)
    __attribute__((no_sanitize("unsigned-integer-overflow")))
#endif
    static constexpr UT min() noexcept {
        // http://en.cppreference.com/w/cpp/language/implicit_conversion
        // Integral conversions: If the destination type is unsigned, the resulting
        // value is the smallest unsigned value equal to the source value modulo 2^n
        // where n is the number of bits used to represent the destination type.
        // https://en.wikipedia.org/wiki/Modular_arithmetic#Congruence
        return static_cast<UT>(0) - static_cast<UT>(std::numeric_limits<T>::min());
    }
};

// Returns difference between a and b (a - b), if result is not representable
// by the type Out - throws exception.
template <typename Out, typename T,
    typename UT = std::make_unsigned_t<T>,
    std::enable_if_t<std::is_integral_v<T>, int> = 0>
#if defined(__clang__)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#endif
constexpr Out checked_diff(T a, T b) {
    if (a >= b) {
        const UT diff = static_cast<UT>(static_cast<UT>(a) - static_cast<UT>(b));
        if (diff <= unsigned_limit<Out>::max())
            return static_cast<Out>(diff);
    } else if constexpr (std::is_signed_v<Out>) {
        // b > a ==> diff >= 1
        const UT diff = static_cast<UT>(static_cast<UT>(b) - static_cast<UT>(a));
        if (diff <= unsigned_limit<Out>::min())
            return static_cast<Out>(0) - static_cast<Out>(diff - 1) - 1;
    }
    throw std::length_error("too big difference");
}

// Cast integer value to corresponding unsigned type

template <typename T, typename UT = std::make_unsigned_t<T>>
constexpr auto to_unsigned(T n) noexcept -> UT {
    return static_cast<UT>(n);
}

// Append unsigned integer to string

template <typename UIntT>
inline void unsigned_to_str(UIntT num, std::string& output, UIntT base) {
    static const char digit[] = "0123456789abcdef";

    // count digits
    std::size_t count = output.length() + 1;
    // one division is needed to prevent the multiplication overflow
    const UIntT num0 = num / base;
    for (UIntT divider = 1; divider <= num0; divider *= base)
        ++count;
    output.resize(count);

    // convert
    do {
        output[--count] = digit[num % base];
        num /= base;
    } while (num);
}

// Append data to string

constexpr std::size_t add_sizes(std::size_t size1, std::size_t size2, std::size_t max_size) {
    if (max_size - size1 < size2)
        throw std::length_error("too big size");
    // now it is safe to add sizes
    return size1 + size2;
}

template <class CharT, class StrT>
inline void append(std::basic_string<CharT>& dest, const StrT& src) {
#ifdef _MSC_VER
    if constexpr (!std::is_same_v<typename StrT::value_type, CharT>) {
        // the value_type of dest and src are different
        dest.reserve(add_sizes(dest.size(), src.size(), dest.max_size()));
        for (const auto c : src)
            dest.push_back(static_cast<CharT>(c));
    } else
#endif
    dest.append(src.begin(), src.end());
}

template <class CharT, class UnaryOperation>
inline void append_tr(std::string& dest, const CharT* first, const CharT* last, UnaryOperation unary_op) {
    const std::size_t old_size = dest.size();
    const std::size_t src_size = last - first;
    const std::size_t new_size = add_sizes(old_size, src_size, dest.max_size());

#ifdef __cpp_lib_string_resize_and_overwrite
    dest.resize_and_overwrite(new_size, [&](char* buff, std::size_t) {
        std::transform(first, last, buff + old_size, unary_op);
        return new_size;
    });
#else
    dest.resize(new_size);
    std::transform(first, last, dest.data() + old_size, unary_op);
#endif
}

template <typename CharT>
constexpr char ascii_to_lower_char(CharT c) noexcept {
    return static_cast<char>((c <= 'Z' && c >= 'A') ? (c | 0x20) : c);
}

template <class CharT>
inline void append_ascii_lowercase(std::string& dest, const CharT* first, const CharT* last) {
    util::append_tr(dest, first, last, ascii_to_lower_char<CharT>);
}

// Finders

template <class InputIt>
inline bool contains_null(InputIt first, InputIt last) {
    return std::find(first, last, '\0') != last;
}

template <class CharT>
constexpr bool has_xn_label(const CharT* first, const CharT* last) {
    if (last - first >= 4) {
        // search for labels starting with "xn--"
        const auto end = last - 4;
        for (auto p = first; ; ++p) { // skip '.'
            // "XN--", "xn--", ...
            if ((p[0] | 0x20) == 'x' && (p[1] | 0x20) == 'n' && p[2] == '-' && p[3] == '-')
                return true;
            p = std::char_traits<CharT>::find(p, end - p, '.');
            if (p == nullptr) break;
        }
    }
    return false;
}


} // namespace upa::util

#endif // UPA_UTIL_H

#include <array>
#include <cstdint> // uint8_t
#include <initializer_list>
#include <string>
#include <type_traits>
#include <utility>


namespace upa {


/// @brief Represents code point set
///
/// Is used to define percent encode sets, forbidden host code points, and
/// other code point sets.
///
class code_point_set {
public:
    /// @brief constructor for code point set initialization
    ///
    /// Function @a fun must iniatialize @a self object by using code_point_set
    /// member functions: copy(), exclude(), and include().
    ///
    /// @param[in] fun constexpr function to initialize code point set elements
    constexpr explicit code_point_set(void (*fun)(code_point_set& self)) {
        fun(*this);
    }

    /// @brief copy code points from @a other set
    /// @param[in] other code point set to copy from
    constexpr void copy(const code_point_set& other) {
        arr_ = other.arr_;
    }

    /// @brief exclude @a c code point from set
    /// @param[in] c code point to exclude
    constexpr void exclude(uint8_t c) {
        arr_[c >> 3] &= ~(1u << (c & 0x07));
    }

    /// @brief include @a c code point to set
    /// @param[in] c code point to include
    constexpr void include(uint8_t c) {
        arr_[c >> 3] |= (1u << (c & 0x07));
    }

    /// @brief exclude list of code points from set
    /// @param[in] clist list of code points to exclude
    constexpr void exclude(std::initializer_list<uint8_t> clist) {
        for (auto c : clist)
            exclude(c);
    }

    /// @brief include code points from list
    /// @param[in] clist list of code points to include
    constexpr void include(std::initializer_list<uint8_t> clist) {
        for (auto c : clist)
            include(c);
    }

    /// @brief include range of code points to set
    /// @param[in] from,to range of code points to include
    constexpr void include(uint8_t from, uint8_t to) {
        for (auto c = from; c <= to; ++c)
            include(c);
    }

    /// @brief test code point set contains code point @a c
    /// @param[in] c code point to test
    template <typename CharT>
    [[nodiscard]] constexpr bool operator[](CharT c) const {
        const auto uc = util::to_unsigned(c);
        return is_8bit(uc) && (arr_[uc >> 3] & (1u << (uc & 0x07))) != 0;
    }

private:
    // Check code point value is 8 bit (<=0xFF)
    static constexpr bool is_8bit(unsigned char) noexcept {
        return true;
    }

    template <typename CharT>
    static constexpr bool is_8bit(CharT c) noexcept {
        return c <= 0xFF;
    }

    // Data
    std::array<uint8_t, 32> arr_{};
};


// Percent encode sets

// fragment percent-encode set
// https://url.spec.whatwg.org/#fragment-percent-encode-set
inline constexpr code_point_set fragment_no_encode_set{ [](code_point_set& self) constexpr {
    self.include(0x20, 0x7E); // C0 control percent-encode set
    self.exclude({ 0x20, 0x22, 0x3C, 0x3E, 0x60 });
    } };

// query percent-encode set
// https://url.spec.whatwg.org/#query-percent-encode-set
inline constexpr code_point_set query_no_encode_set{ [](code_point_set& self) constexpr {
    self.include(0x20, 0x7E); // C0 control percent-encode set
    self.exclude({ 0x20, 0x22, 0x23, 0x3C, 0x3E });
    } };

// special query percent-encode set
// https://url.spec.whatwg.org/#special-query-percent-encode-set
inline constexpr code_point_set special_query_no_encode_set{ [](code_point_set& self) constexpr {
    self.copy(query_no_encode_set);
    self.exclude(0x27);
    } };

// path percent-encode set
// https://url.spec.whatwg.org/#path-percent-encode-set
inline constexpr code_point_set path_no_encode_set{ [](code_point_set& self) constexpr {
    self.copy(query_no_encode_set);
    self.exclude({ 0x3F, 0x5E, 0x60, 0x7B, 0x7D });
    } };

// path percent-encode set with '%' (0x25)
inline constexpr code_point_set raw_path_no_encode_set{ [](code_point_set& self) constexpr {
    self.copy(path_no_encode_set);
    self.exclude(0x25);
    } };

// POSIX path percent-encode set
// Additionally encode ':', '|' and '\' to prevent windows drive letter detection and interpretation of the
// '\' as directory separator in POSIX paths (for example "/c:\end" will be encoded to "/c%3A%5Cend").
inline constexpr code_point_set posix_path_no_encode_set{ [](code_point_set& self) constexpr {
    self.copy(raw_path_no_encode_set);
    self.exclude({ 0x3A, 0x5C, 0x7C }); // ':' (0x3A), '\' (0x5C), '|' (0x7C)
    } };

// userinfo percent-encode set
// https://url.spec.whatwg.org/#userinfo-percent-encode-set
inline constexpr code_point_set userinfo_no_encode_set{ [](code_point_set& self) constexpr {
    self.copy(path_no_encode_set);
    self.exclude({ 0x2F, 0x3A, 0x3B, 0x3D, 0x40, 0x5B, 0x5C, 0x5D, 0x7C });
    } };

// component percent-encode set
// https://url.spec.whatwg.org/#component-percent-encode-set
inline constexpr code_point_set component_no_encode_set{ [](code_point_set& self) constexpr {
    self.copy(userinfo_no_encode_set);
    self.exclude({ 0x24, 0x25, 0x26, 0x2B, 0x2C });
    } };


namespace detail {

// Code point sets in one bytes array

enum CP_SET : std::uint8_t {
    ASCII_DOMAIN_SET = 0x01,
    DOMAIN_FORBIDDEN_SET = 0x02,
    HOST_FORBIDDEN_SET = 0x04,
    HEX_DIGIT_SET = 0x08,
    IPV4_CHAR_SET = 0x10,
    SCHEME_SET = 0x20,
};

class code_points_multiset {
public:
    constexpr code_points_multiset() {
        // Forbidden host code points: U+0000 NULL, U+0009 TAB, U+000A LF, U+000D CR,
        // U+0020 SPACE, U+0023 (#), U+002F (/), U+003A (:), U+003C (<), U+003E (>),
        // U+003F (?), U+0040 (@), U+005B ([), U+005C (\), U+005D (]), U+005E (^) and
        // U+007C (|).
        // https://url.spec.whatwg.org/#forbidden-host-code-point
        include(static_cast<CP_SET>(HOST_FORBIDDEN_SET | DOMAIN_FORBIDDEN_SET), {
            0x00, 0x09, 0x0A, 0x0D, 0x20, 0x23, 0x2F, 0x3A, 0x3C, 0x3E, 0x3F, 0x40, 0x5B,
            0x5C, 0x5D, 0x5E, 0x7C });

        // Forbidden domain code points: forbidden host code points, C0 controls, U+0025 (%)
        // and U+007F DELETE.
        // https://url.spec.whatwg.org/#forbidden-domain-code-point
        include(DOMAIN_FORBIDDEN_SET, 0x00, 0x1F); // C0 controls
        include(DOMAIN_FORBIDDEN_SET, { 0x25, 0x7F });

        // ASCII domain code points

        // All ASCII excluding C0 controls (forbidden in domains)
        include(ASCII_DOMAIN_SET, 0x20, 0x7F);
        // exclude forbidden host code points
        exclude(ASCII_DOMAIN_SET, {
            0x00, 0x09, 0x0A, 0x0D, 0x20, 0x23, 0x2F, 0x3A, 0x3C, 0x3E, 0x3F, 0x40, 0x5B,
            0x5C, 0x5D, 0x5E, 0x7C });
        // exclude forbidden domain code points
        exclude(ASCII_DOMAIN_SET, { 0x25, 0x7F });

        // Hex digits
        include(static_cast<CP_SET>(HEX_DIGIT_SET | IPV4_CHAR_SET), '0', '9');
        include(static_cast<CP_SET>(HEX_DIGIT_SET | IPV4_CHAR_SET), 'A', 'F');
        include(static_cast<CP_SET>(HEX_DIGIT_SET | IPV4_CHAR_SET), 'a', 'f');

        // Characters allowed in IPv4
        include(IPV4_CHAR_SET, { '.', 'X', 'x' });

        // Scheme code points
        // ASCII alphanumeric, U+002B (+), U+002D (-), or U+002E (.)
        // https://url.spec.whatwg.org/#scheme-state
        include(SCHEME_SET, '0', '9');
        include(SCHEME_SET, 'A', 'Z');
        include(SCHEME_SET, 'a', 'z');
        include(SCHEME_SET, { 0x2B, 0x2D, 0x2E });
    }

    /// @brief test the @a cps code points set contains code point @a c
    /// @param[in] c code point to test
    /// @param[in] cps code point set
    template <typename CharT>
    [[nodiscard]] constexpr bool char_in_set(CharT c, CP_SET cps) const {
        const auto uc = util::to_unsigned(c);
        return is_8bit(uc) && (arr_[uc] & cps);
    }

private:
    /// @brief include @a c code point to @a cpsbits sets
    /// @param[in] cpsbits code points sets
    /// @param[in] c code point to include
    constexpr void include(CP_SET cpsbits, uint8_t c) {
        arr_[c] |= cpsbits;
    }

    /// @brief include code points from list
    /// @param[in] cpsbits code points sets
    /// @param[in] clist list of code points to include
    constexpr void include(CP_SET cpsbits, std::initializer_list<uint8_t> clist) {
        for (auto c : clist)
            include(cpsbits, c);
    }

    /// @brief include range of code points to set
    /// @param[in] cpsbits code points sets
    /// @param[in] from,to range of code points to include
    constexpr void include(CP_SET cpsbits, uint8_t from, uint8_t to) {
        for (auto c = from; c <= to; ++c)
            include(cpsbits, c);
    }

    /// @brief exclude @a c code point from set
    /// @param[in] cpsbits code points sets
    /// @param[in] c code point to exclude
    constexpr void exclude(CP_SET cpsbits, uint8_t c) {
        arr_[c] &= ~cpsbits;
    }

    /// @brief exclude list of code points from set
    /// @param[in] cpsbits code points sets
    /// @param[in] clist list of code points to exclude
    constexpr void exclude(CP_SET cpsbits, std::initializer_list<uint8_t> clist) {
        for (auto c : clist)
            exclude(cpsbits, c);
    }

    // Check code point value is 8 bit (<=0xFF)
    static constexpr bool is_8bit(unsigned char) noexcept {
        return true;
    }

    template <typename CharT>
    static constexpr bool is_8bit(CharT c) noexcept {
        return c <= 0xFF;
    }

    // Data
    std::array<uint8_t, 256> arr_{};
};

inline constexpr code_points_multiset code_points;

// ----------------------------------------------------------------------------
// Check char is in predefined set

template <typename CharT>
constexpr bool is_char_in_set(CharT c, const code_point_set& cpset) {
    return cpset[c];
}

template <typename CharT>
constexpr bool is_ipv4_char(CharT c) {
    return code_points.char_in_set(c, IPV4_CHAR_SET);
}

template <typename CharT>
constexpr bool is_hex_char(CharT c) {
    return code_points.char_in_set(c, HEX_DIGIT_SET);
}

template <typename CharT>
constexpr bool is_scheme_char(CharT c) {
    return code_points.char_in_set(c, SCHEME_SET);
}

template <typename CharT>
constexpr bool is_forbidden_domain_char(CharT c) {
    return code_points.char_in_set(c, DOMAIN_FORBIDDEN_SET);
}

template <typename CharT>
constexpr bool is_forbidden_host_char(CharT c) {
    return code_points.char_in_set(c, HOST_FORBIDDEN_SET);
}

template <typename CharT>
constexpr bool is_ascii_domain_char(CharT c) {
    return code_points.char_in_set(c, ASCII_DOMAIN_SET);
}

// Char classification

template <typename CharT>
constexpr bool is_ascii_digit(CharT ch) noexcept {
    return ch <= '9' && ch >= '0';
}

template <typename CharT>
constexpr bool is_ascii_alpha(CharT ch) noexcept {
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
}

// ----------------------------------------------------------------------------
// Hex digit conversion tables and functions

// Maps the hex numerical values 0x0 to 0xf to the corresponding ASCII digit
// that will be used to represent it.
inline constexpr char kHexCharLookup[0x10] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
};

// This lookup table allows fast conversion between ASCII hex letters and their
// corresponding numerical value. The 8-bit range is divided up into 8
// regions of 0x20 characters each. Each of the three character types (numbers,
// uppercase, lowercase) falls into different regions of this range. The table
// contains the amount to subtract from characters in that range to get at
// the corresponding numerical value.
//
// See hex_char_to_num for the lookup.
inline constexpr char kCharToHexLookup[8] = {
    0,         // 0x00 - 0x1f
    '0',       // 0x20 - 0x3f: digits 0 - 9 are 0x30 - 0x39
    'A' - 10,  // 0x40 - 0x5f: letters A - F are 0x41 - 0x46
    'a' - 10,  // 0x60 - 0x7f: letters a - f are 0x61 - 0x66
    0,         // 0x80 - 0x9F
    0,         // 0xA0 - 0xBF
    0,         // 0xC0 - 0xDF
    0,         // 0xE0 - 0xFF
};

// Assumes the input is a valid hex digit! Call is_hex_char before using this.
inline unsigned char hex_char_to_num(unsigned char c) noexcept {
    return c - kCharToHexLookup[c / 0x20];
}

// ----------------------------------------------------------------------------
// Percent decode

// Given a character after '%' at |*first| in the string, this will decode
// the escaped value and put it into |*unescaped_value| on success (returns
// true). On failure, this will return false, and will not write into
// |*unescaped_value|.
//
// |*first| will be updated to point after the last character of the escape
// sequence. On failure, |*first| will be unchanged.

template <typename CharT>
inline bool decode_hex_to_byte(const CharT*& first, const CharT* last, unsigned char& unescaped_value) {
    if (last - first < 2 ||
        !is_hex_char(first[0]) || !is_hex_char(first[1])) {
        // not enough or invalid hex digits
        return false;
    }

    // Valid escape sequence.
    const auto uc1 = static_cast<unsigned char>(first[0]);
    const auto uc2 = static_cast<unsigned char>(first[1]);
    unescaped_value = (hex_char_to_num(uc1) << 4) + hex_char_to_num(uc2);
    first += 2;
    return true;
}

// ----------------------------------------------------------------------------
// Percent encode

// Percent-encodes byte and appends to string
// See: https://url.spec.whatwg.org/#percent-encode

inline void append_percent_encoded_byte(unsigned char uc, std::string& output) {
    output.push_back('%');
    output.push_back(kHexCharLookup[uc >> 4]);
    output.push_back(kHexCharLookup[uc & 0xf]);
}

// Reads one character from string (first, last), converts to UTF-8, then
// percent-encodes, and appends to `output`. Replaces invalid UTF-8, UTF-16 or UTF-32
// sequences in input with Unicode replacement characters (U+FFFD) if present.

template <typename CharT>
inline bool append_utf8_percent_encoded_char(const CharT*& first, const CharT* last, std::string& output) {
    // url_util::read_utf_char(..) will handle invalid characters for us and give
    // us the kUnicodeReplacementCharacter, so we don't have to do special
    // checking after failure, just pass through the failure to the caller.
    const auto cp_res = url_utf::read_utf_char(first, last);
    // convert cp_res.value code point to UTF-8, then percent encode and append to `output`
    url_utf::append_utf8<std::string, append_percent_encoded_byte>(cp_res.value, output);
    return cp_res.result;
}

// Converts input string (first, last) to UTF-8, then percent encodes bytes not
// in `cpset`, and appends to `output`. Replaces invalid UTF-8, UTF-16 or UTF-32
// sequences in input with Unicode replacement characters (U+FFFD) if present.

template<typename CharT>
inline void append_utf8_percent_encoded(const CharT* first, const CharT* last, const code_point_set& cpset, std::string& output) {
    using UCharT = std::make_unsigned_t<CharT>;

    for (auto it = first; it < last; ) {
        const auto uch = static_cast<UCharT>(*it);
        if (uch >= 0x80) {
            // invalid utf-8/16/32 sequences will be replaced with kUnicodeReplacementCharacter
            append_utf8_percent_encoded_char(it, last, output);
        } else {
            // Just append the 7-bit character, possibly percent encoding it
            const auto uc = static_cast<unsigned char>(uch);
            if (is_char_in_set(uc, cpset)) {
                output.push_back(uc);
            } else {
                // other characters are percent encoded
                append_percent_encoded_byte(uc, output);
            }
            ++it;
        }
    }
}

/// @brief Percent decode input string and append to output string
///
/// Invalid code points are replaced with U+FFFD characters.
///
/// More info:
/// https://url.spec.whatwg.org/#string-percent-decode
///
/// @param[in] str string input
/// @param[out] output string output
template <class StrT, enable_if_str_arg_t<StrT> = 0>
inline void append_percent_decoded(StrT&& str, std::string& output) {
    const auto inp = make_str_arg(std::forward<StrT>(str));
    const auto* first = inp.begin();
    const auto* last = inp.end();

    for (auto it = first; it != last;) {
        const auto uch = util::to_unsigned(*it); ++it;
        if (uch < 0x80) {
            if (uch != '%') {
                output.push_back(static_cast<char>(uch));
                continue;
            }
            // uch == '%'
            unsigned char uc8; // NOLINT(cppcoreguidelines-init-variables)
            if (decode_hex_to_byte(it, last, uc8)) {
                if (uc8 < 0x80) {
                    output.push_back(static_cast<char>(uc8));
                    continue;
                }
                // percent encoded utf-8 sequence
                std::string buff_utf8;
                buff_utf8.push_back(static_cast<char>(uc8));
                while (it != last && *it == '%') {
                    ++it; // skip '%'
                    if (!decode_hex_to_byte(it, last, uc8))
                        uc8 = '%';
                    buff_utf8.push_back(static_cast<char>(uc8));
                }
                url_utf::check_fix_utf8(buff_utf8);
                output += buff_utf8;
                continue;
            }
            // detected invalid percent encoding
            output.push_back('%');
        } else { // uch >= 0x80
            --it;
            url_utf::read_char_append_utf8(it, last, output);
        }
    }
}


} // namespace detail


/// @brief Percent decode input string.
///
/// Invalid code points are replaced with U+FFFD characters.
///
/// More info:
/// https://url.spec.whatwg.org/#string-percent-decode
///
/// @param[in] str string input
/// @return percent decoded string
template <class StrT, enable_if_str_arg_t<StrT> = 0>
[[nodiscard]] inline std::string percent_decode(StrT&& str) {
    std::string out;
    detail::append_percent_decoded(std::forward<StrT>(str), out);
    return out;
}

/// @brief UTF-8 percent encode input string using specified percent encode set.
///
/// Invalid code points are replaced with UTF-8 percent encoded U+FFFD characters.
///
/// More info:
/// https://url.spec.whatwg.org/#string-utf-8-percent-encode
///
/// @param[in] str string input
/// @param[in] no_encode_set percent no encode set, contains code points which
///            must not be percent encoded
/// @return percent encoded string
template <class StrT, enable_if_str_arg_t<StrT> = 0>
[[nodiscard]] inline std::string percent_encode(StrT&& str, const code_point_set& no_encode_set) {
    const auto inp = make_str_arg(std::forward<StrT>(str));

    std::string out;
    detail::append_utf8_percent_encoded(inp.begin(), inp.end(), no_encode_set, out);
    return out;
}

/// @brief UTF-8 percent encode input string using component percent encode set.
///
/// Invalid code points are replaced with UTF-8 percent encoded U+FFFD characters.
///
/// More info:
/// * https://url.spec.whatwg.org/#string-utf-8-percent-encode
/// * https://url.spec.whatwg.org/#component-percent-encode-set
///
/// @param[in] str string input
/// @return percent encoded string
template <class StrT, enable_if_str_arg_t<StrT> = 0>
[[nodiscard]] inline std::string encode_url_component(StrT&& str) {
    return percent_encode(std::forward<StrT>(str), component_no_encode_set);
}


} // namespace upa

#endif // UPA_URL_PERCENT_ENCODE_H

// #include "url_result.h"

#include <algorithm>
#include <cstddef>
#include <cstdint> // uint16_t, uint32_t, uint64_t
#include <limits>
#include <string>
#include <type_traits>

namespace upa {

// The hostname ends in a number checker
// https://url.spec.whatwg.org/#ends-in-a-number-checker
// Optimized version
//
template <typename CharT>
inline bool hostname_ends_in_a_number(const CharT* first, const CharT* last) {
    if (first != last) {
        // if the last label is empty string, then skip it
        if (*(last - 1) == '.')
            --last;
        // find start of the label
        const CharT* start_of_label = last;
        while (start_of_label != first && *(start_of_label - 1) != '.')
            --start_of_label;
        // check for a number
        const auto len = last - start_of_label;
        if (len) {
            if (len >= 2 && start_of_label[0] == '0' && (start_of_label[1] == 'X' || start_of_label[1] == 'x')) {
                // "0x" is valid IPv4 number (std::all_of returns true if the range is empty)
                return std::all_of(start_of_label + 2, last, detail::is_hex_char<CharT>);
            }
            // decimal or octal number?
            return std::all_of(start_of_label, last, detail::is_ascii_digit<CharT>);
        }
    }
    return false;
}

// IPv4 number parser
// https://url.spec.whatwg.org/#ipv4-number-parser
//
// - on success sets number value and returns validation_errc::ok
// - if resulting number can not be represented by uint32_t value, then returns
//   validation_errc::ipv4_non_numeric_part
//
// TODO-WARN: validationError
//
template <typename CharT>
inline validation_errc ipv4_parse_number(const CharT* first, const CharT* last, uint32_t& number) {
    // If input is the empty string, then return failure
    if (first == last)
        return validation_errc::ipv4_non_numeric_part;

    // Figure out the base
    uint32_t radix = 10;
    if (first[0] == '0') {
        const std::size_t len = last - first;
        if (len == 1) {
            number = 0;
            return validation_errc::ok;
        }
        // len >= 2
        if (first[1] == 'X' || first[1] == 'x') {
            radix = 16;
            first += 2;
        } else {
            radix = 8;
            first += 1;
        }
        // Skip leading zeros (*)
        while (first < last && first[0] == '0')
            ++first;
    }
    // if all characters '0' (*) OR
    // if input is the empty string, then return zero
    if (first == last) {
        number = 0;
        return validation_errc::ok;
    }

    // Check length - max 32-bit value is
    // HEX: FFFFFFFF    (8 digits)
    // DEC: 4294967295  (10 digits)
    // OCT: 37777777777 (11 digits)
    if (last - first > 11)
        return validation_errc::ipv4_out_of_range_part; // int overflow

    // Check chars are valid digits and convert its sequence to number.
    // Use the 64-bit to get a big number (no hex, decimal, or octal
    // number can overflow a 64-bit number in <= 16 characters).
    uint64_t num = 0;
    if (radix <= 10) {
        const auto chmax = static_cast<CharT>('0' - 1 + radix);
        for (auto it = first; it != last; ++it) {
            const auto ch = *it;
            if (ch > chmax || ch < '0')
                return validation_errc::ipv4_non_numeric_part;
            num = num * radix + (ch - '0');
        }
    } else {
        // radix == 16
        for (auto it = first; it != last; ++it) {
            // This cast is safe because chars are ASCII
            const auto uch = static_cast<unsigned char>(*it);
            if (!detail::is_hex_char(uch))
                return validation_errc::ipv4_non_numeric_part;
            num = num * radix + detail::hex_char_to_num(uch);
        }
    }

    // Check for 32-bit overflow.
    if (num > std::numeric_limits<uint32_t>::max())
        return validation_errc::ipv4_out_of_range_part; // int overflow

    number = static_cast<uint32_t>(num);
    return validation_errc::ok;
}

// IPv4 parser
// https://url.spec.whatwg.org/#concept-ipv4-parser
//
// - on success sets ipv4 value and returns validation_errc::ok
// - on failure returns validation error code
//
template <typename CharT>
inline validation_errc ipv4_parse(const CharT* first, const CharT* last, uint32_t& ipv4) {
    using UCharT = std::make_unsigned_t<CharT>;

    // 2. If the last item in parts is the empty string, then
    //    1. IPv4-empty-part validation error. (TODO-WARN)
    //
    // Failure comes from: 5.2 & "IPv4 number parser":
    // 1. If input is the empty string, then return failure.
    if (first == last)
        return validation_errc::ipv4_non_numeric_part;

    // <1>.<2>.<3>.<4>.<->
    const CharT* part[6];
    int dot_count = 0;

    // split on "."
    part[0] = first;
    for (auto it = first; it != last; ++it) {
        const auto uc = static_cast<UCharT>(*it);
        if (uc == '.') {
            if (dot_count == 4)
                // 3. If parts’s size is greater than 4, IPv4-too-many-parts validation error, return failure
                return validation_errc::ipv4_too_many_parts;
            if (part[dot_count] == it)
                // 5.2 & "IPv4 number parser":
                // 1. If input is the empty string, then return failure.
                return validation_errc::ipv4_non_numeric_part;
            part[++dot_count] = it + 1; // skip '.'
        } else if (!detail::is_ipv4_char(uc)) {
            // non IPv4 character
            return validation_errc::ipv4_non_numeric_part;
        }
    }

    // 2. If the last item in parts is the empty string, then:
    //    1. IPv4-empty-part validation error. (TODO-WARN)
    //    2. If parts’s size is greater than 1, then remove the last item from parts.
    int part_count = dot_count + 1;
    if (dot_count > 0 && part[dot_count] == last) {
        --part_count;
    } else {
        // the part[part_count] - 1 must point to the end of last part:
        part[part_count] = last + 1;
    }
    // 3. If parts’s size is greater than 4, IPv4-too-many-parts validation error, return failure
    if (part_count > 4)
        return validation_errc::ipv4_too_many_parts;

    // IPv4 numbers
    uint32_t number[4];
    for (int ind = 0; ind < part_count; ++ind) {
        const auto res = ipv4_parse_number(part[ind], part[ind + 1] - 1, number[ind]);
        // 5.2. If result is failure, IPv4-non-numeric-part validation error, return failure.
        if (res != validation_errc::ok) return res;
        // TODO-WARN: 5.3. If result[1] is true, IPv4-non-decimal-part validation error.
    }
    // TODO-WARN:
    // 6. If any item in numbers is greater than 255, IPv4-out-of-range-part validation error.

    // 7. If any but the last item in numbers is greater than 255, then return failure.
    for (int ind = 0; ind < part_count - 1; ++ind) {
        if (number[ind] > 255) return validation_errc::ipv4_out_of_range_part;
    }
    // 8. If the last item in numbers is greater than or equal to 256(5 − numbers’s size),
    // then return failure.
    ipv4 = number[part_count - 1];
    if (ipv4 > (std::numeric_limits<uint32_t>::max() >> (8 * (part_count - 1))))
        return validation_errc::ipv4_out_of_range_part;

    // 14.1. Increment ipv4 by n * 256**(3 - counter).
    for (int counter = 0; counter < part_count - 1; ++counter) {
        ipv4 += number[counter] << (8 * (3 - counter));
    }

    return validation_errc::ok;
}

// IPv4 serializer
// https://url.spec.whatwg.org/#concept-ipv4-serializer

UPA_API void ipv4_serialize(uint32_t ipv4, std::string& output);


// IPv6

namespace detail {

template <typename IntT, typename CharT>
inline IntT get_hex_number(const CharT*& pointer, const CharT* last) {
    IntT value = 0;
    while (pointer != last && detail::is_hex_char(*pointer)) {
        const auto uc = static_cast<unsigned char>(*pointer);
        value = value * 0x10 + detail::hex_char_to_num(uc);
        ++pointer;
    }
    return value;
}

} // namespace detail

// IPv6 parser
// https://url.spec.whatwg.org/#concept-ipv6-parser
//
// - on success sets address value and returns true
// - on failure returns false
//
template <typename CharT>
inline validation_errc ipv6_parse(const CharT* first, const CharT* last, uint16_t(&address)[8]) {
    std::fill(std::begin(address), std::end(address), static_cast<uint16_t>(0));
    int piece_index = 0;    // zero
    int compress = 0;       // null
    bool is_ipv4 = false;

    const std::size_t len = last - first;
    // the shortest valid IPv6 address is "::"
    if (len < 2) {
        if (len == 0)
            return validation_errc::ipv6_too_few_pieces; // (8)
        switch (first[0]) {
        case ':':
            return validation_errc::ipv6_invalid_compression; // (5-1)
        case '.':
            return validation_errc::ipv4_in_ipv6_invalid_code_point; // (6-5-1)
        default:
            return detail::is_hex_char(first[0])
                ? validation_errc::ipv6_too_few_pieces // (8)
                : validation_errc::ipv6_invalid_code_point; // (6-7)
        }
    }

    const CharT* pointer = first;
    // 5. If c is U+003A (:), then:
    if (pointer[0] == ':') {
        if (pointer[1] != ':') {
            // 5.1. If remaining does not start with U+003A (:), IPv6-invalid-compression
            // validation error, return failure.
            return validation_errc::ipv6_invalid_compression;
        }
        pointer += 2;
        compress = ++piece_index;
    }

    // Main
    while (pointer < last) {
        if (piece_index == 8) {
            // 6.1. If pieceIndex is 8, IPv6-too-many-pieces validation error, return failure.
            return validation_errc::ipv6_too_many_pieces;
        }
        if (pointer[0] == ':') {
            if (compress) {
                // 6.2.1. If compress is non-null, IPv6-multiple-compression validation error,
                // return failure.
                return validation_errc::ipv6_multiple_compression;
            }
            ++pointer;
            compress = ++piece_index;
            continue;
        }

        // HEX
        auto pointer0 = pointer;
        const auto value = detail::get_hex_number<uint16_t>(pointer, (last - pointer <= 4 ? last : pointer + 4));
        if (pointer != last) {
            const CharT ch = *pointer;
            if (ch == '.') {
                if (pointer == pointer0) {
                    // 6.5.1. If length is 0, IPv4-in-IPv6-invalid-code-point
                    // validation error, return failure.
                    return validation_errc::ipv4_in_ipv6_invalid_code_point;
                }
                pointer = pointer0;
                is_ipv4 = true;
                break;
            }
            if (ch == ':') {
                if (++pointer == last) {
                    // 6.6.2. If c is the EOF code point, IPv6-invalid-code-point
                    // validation error, return failure.
                    return validation_errc::ipv6_invalid_code_point;
                }
            } else {
                // 6.7. Otherwise, if c is not the EOF code point, IPv6-invalid-code-point
                // validation error, return failure.
                return validation_errc::ipv6_invalid_code_point;
            }
        }
        address[piece_index++] = value;
    }

    if (is_ipv4) {
        if (piece_index > 6) {
            // 6.5.3. If pieceIndex is greater than 6, IPv4-in-IPv6-too-many-pieces
            // validation error, return failure.
            return validation_errc::ipv4_in_ipv6_too_many_pieces;
        }
        int numbers_seen = 0;
        while (pointer < last) {
            if (numbers_seen > 0) {
                if (*pointer == '.' && numbers_seen < 4) {
                    ++pointer;
                } else {
                    // 6.5.5.2.2. Otherwise, IPv4-in-IPv6-invalid-code-point
                    // validation error, return failure.
                    return validation_errc::ipv4_in_ipv6_invalid_code_point;
                }
            }
            if (pointer == last || !detail::is_ascii_digit(*pointer)) {
                // 6.5.5.3. If c is not an ASCII digit, IPv4-in-IPv6-invalid-code-point
                // validation error, return failure.
                return validation_errc::ipv4_in_ipv6_invalid_code_point;
            }
            // While c is an ASCII digit, run these subsubsteps
            unsigned ipv4Piece = *(pointer++) - '0';
            while (pointer != last && detail::is_ascii_digit(*pointer)) {
                // 6.5.5.4.2. Otherwise, if ipv4Piece is 0, IPv4-in-IPv6-invalid-code-point
                // validation error, return failure.
                if (ipv4Piece == 0) // leading zero
                    return validation_errc::ipv4_in_ipv6_invalid_code_point;
                ipv4Piece = ipv4Piece * 10 + (*pointer - '0');
                // 6.5.5.4.3. If ipv4Piece is greater than 255, IPv4-in-IPv6-out-of-range-part
                // validation error, return failure.
                if (ipv4Piece > 255)
                    return validation_errc::ipv4_in_ipv6_out_of_range_part;
                ++pointer;
            }
            address[piece_index] = static_cast<uint16_t>(address[piece_index] * 0x100 + ipv4Piece);
            ++numbers_seen;
            if (!(numbers_seen & 1)) // 2 or 4
                ++piece_index;
        }
        // 6.5.6. If numbersSeen is not 4, IPv4-in-IPv6-too-few-parts
        // validation error, return failure.
        if (numbers_seen != 4)
            return validation_errc::ipv4_in_ipv6_too_few_parts;
    }

    // Finale
    if (compress) {
        if (const int diff = 8 - piece_index) {
            for (int ind = piece_index - 1; ind >= compress; --ind) {
                address[ind + diff] = address[ind];
                address[ind] = 0;
            }
        }
    } else if (piece_index != 8) {
        // Otherwise, if compress is null and pieceIndex is not 8, IPv6-too-few-pieces
        // validation error, return failure.
        return validation_errc::ipv6_too_few_pieces;
    }
    return validation_errc::ok;
}

// IPv6 serializer
// https://url.spec.whatwg.org/#concept-ipv6-serializer

UPA_API void ipv6_serialize(const uint16_t(&address)[8], std::string& output);


} // namespace upa

#endif // UPA_URL_IP_H

// #include "url_percent_encode.h"

// #include "url_result.h"

// #include "url_utf.h"

// #include "util.h"

#include <algorithm> // any_of
#include <cassert>
#include <cstdint> // uint16_t, uint32_t
#include <string>
#include <type_traits>

namespace upa {

/// @brief Host representation
///
/// See: https://url.spec.whatwg.org/#host-representation
enum class HostType {
    Empty = 0, ///< **empty host** is the empty string
    Opaque,    ///< **opaque host** is a non-empty ASCII string used in a not special URL
    Domain,    ///< **domain** is a non-empty ASCII string that identifies a realm within a network
               ///< (it is usually the host of a special URL)
    IPv4,      ///< host is an **IPv4 address**
    IPv6       ///< host is an **IPv6 address**
};


class host_output {
protected:
    host_output() = default;
    host_output(bool need_save)
        : need_save_{ need_save } {}
public:
    host_output(const host_output&) = delete;
    host_output& operator=(const host_output&) = delete;
    virtual ~host_output() = default;

    virtual std::string& hostStart() = 0;
    virtual void hostDone(HostType /*ht*/) = 0;
    bool need_save() const noexcept { return need_save_; }
private:
    bool need_save_ = true;
};

class host_parser {
public:
    template <typename CharT>
    static validation_errc parse_host(const CharT* first, const CharT* last, bool is_opaque, host_output& dest);

    template <typename CharT>
    static validation_errc parse_opaque_host(const CharT* first, const CharT* last, host_output& dest);

    template <typename CharT>
    static validation_errc parse_ipv4(const CharT* first, const CharT* last, host_output& dest);

    template <typename CharT>
    static validation_errc parse_ipv6(const CharT* first, const CharT* last, host_output& dest);
};


// url_host class
// https://github.com/whatwg/url/pull/288
// https://whatpr.org/url/288.html#urlhost-class

class url_host {
public:
    url_host() = delete;
    url_host(const url_host&) = default;
    url_host(url_host&&) noexcept = default;
    url_host& operator=(const url_host&) = default;
    url_host& operator=(url_host&&) noexcept = default;

    /// Parsing constructor
    ///
    /// Throws @a url_error exception on parse error.
    ///
    /// @param[in] str Host string to parse
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    explicit url_host(StrT&& str) {
        host_out out(*this);

        const auto inp = make_str_arg(std::forward<StrT>(str));
        const auto res = host_parser::parse_host(inp.begin(), inp.end(), false, out);
        if (res != validation_errc::ok)
            throw url_error(res, "Host parse error");
    }

    /// destructor
    ~url_host() = default;

    /// Host type getter
    ///
    /// @return host type, the one of: Domain, IPv4, IPv6
    [[nodiscard]] HostType type() const {
        return type_;
    }

    /// Hostname view
    ///
    /// @return serialized host as string_view
    [[nodiscard]] string_view name() const {
        return host_str_;
    }

    /// Hostname stringifier
    ///
    /// @return host serialized to string
    [[nodiscard]] std::string to_string() const {
        return host_str_;
    }

private:
    class host_out : public host_output {
    public:
        explicit host_out(url_host& host)
            : host_(host)
        {}
        std::string& hostStart() override {
            return host_.host_str_;
        }
        void hostDone(HostType ht) override {
            host_.type_ = ht;
        }
    private:
        url_host& host_; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)
    };

    // members
    std::string host_str_;
    HostType type_ = HostType::Empty;
};


// Helper functions

namespace detail {

template <typename CharT>
inline bool contains_forbidden_domain_char(const CharT* first, const CharT* last) {
    return std::any_of(first, last, detail::is_forbidden_domain_char<CharT>);
}

template <typename CharT>
inline bool contains_forbidden_host_char(const CharT* first, const CharT* last) {
    return std::any_of(first, last, detail::is_forbidden_host_char<CharT>);
}

} // namespace detail


// IDNA
// https://url.spec.whatwg.org/#idna

/// @brief Implements the domain to Unicode algorithm
///
/// See: https://url.spec.whatwg.org/#concept-domain-to-unicode
/// The domain to Unicode result is appended to the @a output, even if the
/// function returns `false`.
///
/// @param[out] output string to store result
/// @param[in]  input source domain string
/// @param[in]  be_strict
/// @param[in]  is_input_ascii
/// @return `true` on success, or `false` on errors
template <class CharT, class StrT, enable_if_str_arg_t<StrT> = 0>
inline bool domain_to_unicode(std::basic_string<CharT>& output, StrT&& input,
    bool be_strict = false, bool is_input_ascii = false)
{
    const auto inp = make_str_arg(std::forward<StrT>(input));
    if constexpr (std::is_same_v<CharT, char32_t>) {
        return idna::domain_to_unicode(output, inp.begin(), inp.end(), be_strict, is_input_ascii);
    } else {
        std::u32string domain;
        const bool res = idna::domain_to_unicode(domain, inp.begin(), inp.end(), be_strict, is_input_ascii);
        if constexpr (sizeof(CharT) == sizeof(char)) {
            // CharT is char8_t, or char
            for (auto cp : domain)
                url_utf::append_utf8<std::basic_string<CharT>, detail::append_to_string>(cp, output);
        } else if constexpr (sizeof(CharT) == sizeof(char16_t)) {
            // CharT is char16_t, or wchar_t (Windows)
            for (auto cp : domain)
                url_utf::append_utf16(cp, output);
        } else if constexpr (sizeof(CharT) == sizeof(char32_t)) {
            // CharT is wchar_t (non Windows)
            util::append(output, domain);
        } else {
            static_assert(util::false_v<CharT>, "unsupported output character type");
        }
        return res;
    }
}

// The host parser
// https://url.spec.whatwg.org/#concept-host-parser

template <typename CharT>
inline validation_errc host_parser::parse_host(const CharT* first, const CharT* last, bool is_opaque, host_output& dest) {
    using UCharT = std::make_unsigned_t<CharT>;

    // 1. Non-"file" special URL's cannot have an empty host.
    // 2. For "file" URL's empty host is set in the file_host_state 1.2
    //    https://url.spec.whatwg.org/#file-host-state
    // 3. Non-special URLs can have empty host and it will be set here.
    if (first == last) {
        // https://github.com/whatwg/url/issues/79
        // https://github.com/whatwg/url/pull/189
        // set empty host
        dest.hostStart();
        dest.hostDone(HostType::Empty);
        return is_opaque ? validation_errc::ok : validation_errc::host_missing;
    }
    assert(first < last);

    if (*first == '[') {
        if (*(last - 1) == ']') {
            return parse_ipv6(first + 1, last - 1, dest);
        }
        // 1.1. If input does not end with U+005D (]), IPv6-unclosed
        // validation error, return failure.
        return validation_errc::ipv6_unclosed;
    }

    if (is_opaque)
        return parse_opaque_host(first, last, dest);

    // Is ASCII domain?
    const auto ptr = std::find_if_not(first, last, detail::is_ascii_domain_char<CharT>);
    if (ptr == last) {
        if (!util::has_xn_label(first, last)) {
            // Fast path for ASCII domain

            // If asciiDomain ends in a number, return the result of IPv4 parsing asciiDomain
            if (hostname_ends_in_a_number(first, last))
                return parse_ipv4(first, last, dest);

            if (dest.need_save()) {
                // Return asciiDomain lower cased
                std::string& str_host = dest.hostStart();
                util::append_ascii_lowercase(str_host, first, last);
                dest.hostDone(HostType::Domain);
            }
            return validation_errc::ok;
        }
    } else if (static_cast<UCharT>(*ptr) < 0x80 && *ptr != '%') {
        // NFC normalizes U+003C (<), U+003D (=), U+003E (>) characters if they precede
        // U+0338. Therefore, no errors are reported here for forbidden < and > characters
        // if there is a possibility to normalize them.
        if (!(*ptr >= 0x3C && *ptr <= 0x3E && ptr + 1 < last && static_cast<UCharT>(ptr[1]) >= 0x80))
            // 7. If asciiDomain contains a forbidden domain code point, domain-invalid-code-point
            // validation error, return failure.
            return validation_errc::domain_invalid_code_point;
    }

    std::string buff_ascii;

    const auto pes = std::find(ptr, last, '%');
    if (pes == last) {
        // Input is ASCII if ptr == last
        if (!idna::domain_to_ascii(buff_ascii, first, last, false, ptr == last))
            return validation_errc::domain_to_ascii;
    } else {
        // Input for domain_to_ascii
        simple_buffer<char32_t> buff_uc;

        // copy ASCII chars
        for (auto it = first; it != ptr; ++it) {
            const auto uch = static_cast<UCharT>(*it);
            buff_uc.push_back(static_cast<char32_t>(uch));
        }

        // Let buff_uc be the result of running UTF-8 decode (to UTF-16) without BOM
        // on the percent decoding of UTF-8 encode on input
        for (auto it = ptr; it != last;) {
            const auto uch = static_cast<UCharT>(*it++);
            if (uch < 0x80) {
                if (uch != '%') {
                    buff_uc.push_back(static_cast<char32_t>(uch));
                    continue;
                }
                // uch == '%'
                unsigned char uc8; // NOLINT(cppcoreguidelines-init-variables)
                if (detail::decode_hex_to_byte(it, last, uc8)) {
                    if (uc8 < 0x80) {
                        buff_uc.push_back(static_cast<char32_t>(uc8));
                        continue;
                    }
                    // percent encoded utf-8 sequence
                    // TODO: gal po vieną code_point, tuomet užtektų utf-8 buferio vienam simboliui
                    simple_buffer<char> buff_utf8;
                    buff_utf8.push_back(static_cast<char>(uc8));
                    while (it != last && *it == '%') {
                        ++it; // skip '%'
                        if (!detail::decode_hex_to_byte(it, last, uc8))
                            uc8 = '%';
                        buff_utf8.push_back(static_cast<char>(uc8));
                    }
                    // utf-8 to utf-32
                    const auto* last_utf8 = buff_utf8.data() + buff_utf8.size();
                    for (const auto* it_utf8 = buff_utf8.data(); it_utf8 < last_utf8;)
                        buff_uc.push_back(url_utf::read_utf_char(it_utf8, last_utf8).value);
                    //buff_utf8.clear();
                    continue;
                }
                // detected an invalid percent-encoding sequence
                buff_uc.push_back('%');
            } else { // uch >= 0x80
                --it;
                buff_uc.push_back(url_utf::read_utf_char(it, last).value);
            }
        }
        if (!idna::domain_to_ascii(buff_ascii, buff_uc.begin(), buff_uc.end()))
            return validation_errc::domain_to_ascii;
    }

    if (detail::contains_forbidden_domain_char(buff_ascii.data(), buff_ascii.data() + buff_ascii.size())) {
        // 7. If asciiDomain contains a forbidden domain code point, domain-invalid-code-point
        // validation error, return failure.
        return validation_errc::domain_invalid_code_point;
    }

    // If asciiDomain ends in a number, return the result of IPv4 parsing asciiDomain
    if (hostname_ends_in_a_number(buff_ascii.data(), buff_ascii.data() + buff_ascii.size()))
        return parse_ipv4(buff_ascii.data(), buff_ascii.data() + buff_ascii.size(), dest);

    if (dest.need_save()) {
        // Return asciiDomain
        std::string& str_host = dest.hostStart();
        str_host.append(buff_ascii);
        dest.hostDone(HostType::Domain);
    }
    return validation_errc::ok;
}

// The opaque-host parser
// https://url.spec.whatwg.org/#concept-opaque-host-parser

template <typename CharT>
inline validation_errc host_parser::parse_opaque_host(const CharT* first, const CharT* last, host_output& dest) {
    // 1. If input contains a forbidden host code point, host-invalid-code-point
    // validation error, return failure.
    if (detail::contains_forbidden_host_char(first, last))
        return validation_errc::host_invalid_code_point;

    // TODO-WARN:
    // 2. If input contains a code point that is not a URL code point and not U+0025 (%),
    // invalid-URL-unit validation error.
    // 3. If input contains a U+0025 (%) and the two code points following it are not ASCII hex digits,
    // invalid-URL-unit validation error.

    if (dest.need_save()) {
        std::string& str_host = dest.hostStart();

        //TODO: UTF-8 percent encode it using the C0 control percent-encode set
        //detail::append_utf8_percent_encoded(first, last, detail::CHAR_C0_CTRL, str_host);
        using UCharT = std::make_unsigned_t<CharT>;

        const CharT* pointer = first;
        while (pointer < last) {
            // UTF-8 percent encode c using the C0 control percent-encode set (U+0000 ... U+001F and >U+007E)
            const auto uch = static_cast<UCharT>(*pointer);
            if (uch >= 0x7f) {
                // invalid utf-8/16/32 sequences will be replaced with 0xfffd
                detail::append_utf8_percent_encoded_char(pointer, last, str_host);
            } else {
                // Just append the 7-bit character, percent encoding C0 control chars
                const auto uc = static_cast<unsigned char>(uch);
                if (uc <= 0x1f)
                    detail::append_percent_encoded_byte(uc, str_host);
                else
                    str_host.push_back(uc);
                ++pointer;
            }
        }

        dest.hostDone(str_host.empty() ? HostType::Empty : HostType::Opaque);
    }
    return validation_errc::ok;
}

template <typename CharT>
inline validation_errc host_parser::parse_ipv4(const CharT* first, const CharT* last, host_output& dest) {
    uint32_t ipv4;  // NOLINT(cppcoreguidelines-init-variables)

    const auto res = ipv4_parse(first, last, ipv4);
    if (res == validation_errc::ok && dest.need_save()) {
        std::string& str_ipv4 = dest.hostStart();
        ipv4_serialize(ipv4, str_ipv4);
        dest.hostDone(HostType::IPv4);
    }
    return res;
}

template <typename CharT>
inline validation_errc host_parser::parse_ipv6(const CharT* first, const CharT* last, host_output& dest) {
    uint16_t ipv6addr[8];

    const auto res = ipv6_parse(first, last, ipv6addr);
    if (res == validation_errc::ok && dest.need_save()) {
        std::string& str_ipv6 = dest.hostStart();
        str_ipv6.push_back('[');
        ipv6_serialize(ipv6addr, str_ipv6);
        str_ipv6.push_back(']');
        dest.hostDone(HostType::IPv6);
    }
    return res;
}


} // namespace upa

#endif // UPA_URL_HOST_H
           // IWYU pragma: export
// #include "url_percent_encode.h"
 // IWYU pragma: export
// #include "url_result.h"
         // IWYU pragma: export
// #include "url_search_params.h"
// Copyright 2016-2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//

#ifndef UPA_URL_SEARCH_PARAMS_H
#define UPA_URL_SEARCH_PARAMS_H

// #include "config.h"
 // IWYU pragma: export
// #include "str_arg.h"

// #include "url_percent_encode.h"

// #include "url_utf.h"

#include <cassert>
#include <list>
#include <memory>
#include <ostream>
#include <string>
#include <type_traits>
#include <utility>

namespace upa {


namespace detail {

// is key value pair
template <typename>
struct is_pair : std::false_type {};

template<class T1, class T2>
struct is_pair<std::pair<T1, T2>> : std::true_type {};

// Get iterable's value type
// https://stackoverflow.com/a/29634934
template <typename T>
auto iterable_value(int) -> decltype(
    std::begin(std::declval<T&>()) != std::end(std::declval<T&>()), // begin/end and operator !=
    ++std::declval<decltype(std::begin(std::declval<T&>()))&>(), // operator ++
    *std::begin(std::declval<T&>()) // operator *
);
template <typename T>
auto iterable_value(long) -> void;

template<class T>
using iterable_value_t = std::remove_cv_t<std::remove_reference_t<
    decltype(iterable_value<T>(0))
>>;

// is iterable over the std::pair values
template<class T>
constexpr bool is_iterable_pairs_v = is_pair<iterable_value_t<T>>::value;

// enable if `Base` is not the base class of `T`
template<class Base, class T>
using enable_if_not_base_of_t = std::enable_if_t<
    !std::is_base_of_v<Base, std::decay_t<T>>, int
>;

} // namespace detail


// forward declarations

class url;
namespace detail {
    class url_search_params_ptr;
} // namespace detail

/// @brief URLSearchParams class
///
/// Follows specification in
/// https://url.spec.whatwg.org/#interface-urlsearchparams
///
class url_search_params
{
public:
    // types
    using name_value_pair = std::pair<std::string, std::string>;
    using name_value_list = std::list<name_value_pair>;
    using const_iterator = name_value_list::const_iterator;
    using const_reverse_iterator = name_value_list::const_reverse_iterator;
    using iterator = const_iterator;
    using reverse_iterator = const_reverse_iterator;
    using size_type = name_value_list::size_type;
    using value_type = name_value_pair;

    // Constructors

    /// @brief Default constructor.
    ///
    /// Constructs empty @c url_search_params object.
    url_search_params() = default;

    /// @brief Copy constructor.
    ///
    /// @param[in] other @c url_search_params object to copy from
    url_search_params(const url_search_params& other);

    /// @brief Move constructor.
    ///
    /// Constructs the @c url_search_params object with the contents of @a other
    /// using move semantics.
    ///
    /// @param[in,out] other @c url_search_params object to move from
    url_search_params(url_search_params&& other)
        noexcept(std::is_nothrow_move_constructible_v<name_value_list>);

    /// @brief Parsing constructor.
    ///
    /// Initializes name-value pairs list by parsing query string.
    ///
    /// @param[in] query string to parse
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    explicit url_search_params(StrT&& query)
        : params_(do_parse(true, std::forward<StrT>(query)))
    {}

    /// Initializes name-value pairs list by copying pairs fron container.
    ///
    /// @param[in] cont name-value pairs container
    template<class ConT,
        // do not hide the copy and move constructors:
        detail::enable_if_not_base_of_t<url_search_params, ConT> = 0,
        std::enable_if_t<detail::is_iterable_pairs_v<ConT>, int> = 0
    >
    explicit url_search_params(ConT&& cont) {
        for (const auto& p : cont) {
            params_.emplace_back(make_string(p.first), make_string(p.second));
        }
    }

    /// destructor
    ~url_search_params() = default;

    // Assignment

    /// @brief Copy assignment.
    ///
    /// Replaces the contents with those of @a other using copy semantics.
    ///
    /// Updates linked URL object if any. So this operator can be used to assign
    /// a value to the reference returned by url::search_params().
    ///
    /// @param[in] other  url_search_params to copy from
    /// @return *this
    url_search_params& operator=(const url_search_params& other);

    /// @brief Move assignment.
    ///
    /// Replaces the contents with those of @a other using move semantics.
    ///
    /// NOTE: It is undefined behavior to use this operator to assign a value to
    /// the reference returned by url::search_params(). Use safe_assign instead.
    ///
    /// @param[in,out] other url_search_params to move to this object
    /// @return *this
    url_search_params& operator=(url_search_params&& other) noexcept;

    /// @brief Safe move assignment.
    ///
    /// Replaces the contents with those of @a other using move semantics.
    ///
    /// Updates linked URL object if any. So this function can be used to assign
    /// a value to the reference returned by url::search_params().
    ///
    /// @param[in,out] other  URL to move to this object
    /// @return *this
    url_search_params& safe_assign(url_search_params&& other);

    // Operations

    /// @brief Clears parameters
    void clear();

    /// @brief Swaps the contents of two url_search_params
    ///
    /// NOTE: It is undefined behavior to use this function to swap the
    /// contents of references returned by url::search_params().
    ///
    /// @param[in,out] other url_search_params to exchange the contents with
    void swap(url_search_params& other) noexcept;

    /// Initializes name-value pairs list by parsing query string.
    ///
    /// @param[in] query string to parse
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    void parse(StrT&& query);

    /// Appends given name-value pair to list
    ///
    /// More info: https://url.spec.whatwg.org/#dom-urlsearchparams-append
    ///
    /// @param[in] name
    /// @param[in] value
    template <class TN, class TV>
    void append(TN&& name, TV&& value);

    /// Remove all name-value pairs whose name is @a name from list.
    ///
    /// More info: https://url.spec.whatwg.org/#dom-urlsearchparams-delete
    ///
    /// @param[in] name
    template <class TN>
    void del(const TN& name);

    /// Remove all name-value pairs whose name is @a name and value is @a value from list.
    ///
    /// More info: https://url.spec.whatwg.org/#dom-urlsearchparams-delete
    ///
    /// @param[in] name
    /// @param[in] value
    template <class TN, class TV>
    void del(const TN& name, const TV& value);

    /// Remove all name-value pairs whose name is @a name from list.
    ///
    /// It updates connected URL only if something is removed.
    ///
    /// @param[in] name
    /// @return the number of pairs removed
    template <class TN>
    size_type remove(const TN& name);

    /// Remove all name-value pairs whose name is @a name and value is @a value from list.
    ///
    /// It updates connected URL only if something is removed.
    ///
    /// @param[in] name
    /// @param[in] value
    /// @return the number of pairs removed
    template <class TN, class TV>
    size_type remove(const TN& name, const TV& value);

    /// Remove all name-value pairs for which predicate @a p returns `true`.
    ///
    /// It updates connected URL only if something is removed.
    ///
    /// @param[in] p unary predicate which returns value of `bool` type and has
    ///   `const value_type&` parameter
    /// @return the number of pairs removed
    template <class UnaryPredicate>
    size_type remove_if(UnaryPredicate p);

    /// Returns value of the first name-value pair whose name is @a name, or `nullptr`,
    /// if there isn't such pair.
    ///
    /// More info: https://url.spec.whatwg.org/#dom-urlsearchparams-get
    ///
    /// @param[in] name
    /// @return pair value, or `nullptr`
    template <class TN>
    [[nodiscard]] const std::string* get(const TN& name) const;

    /// Return the values of all name-value pairs whose name is @a name.
    ///
    /// More info: https://url.spec.whatwg.org/#dom-urlsearchparams-getall
    ///
    /// @param[in] name
    /// @return list of values as `std::string`
    template <class TN>
    [[nodiscard]] std::list<std::string> get_all(const TN& name) const;

    /// Tests if list contains a name-value pair whose name is @a name.
    ///
    /// More info: https://url.spec.whatwg.org/#dom-urlsearchparams-has
    ///
    /// @param[in] name
    /// @return `true`, if list contains such pair, `false` otherwise
    template <class TN>
    [[nodiscard]] bool has(const TN& name) const;

    /// Tests if list contains a name-value pair whose name is @a name and value is @a value.
    ///
    /// More info: https://url.spec.whatwg.org/#dom-urlsearchparams-has
    ///
    /// @param[in] name
    /// @param[in] value
    /// @return `true`, if list contains such pair, `false` otherwise
    template <class TN, class TV>
    [[nodiscard]] bool has(const TN& name, const TV& value) const;

    /// Sets search parameter value
    ///
    /// More info: https://url.spec.whatwg.org/#dom-urlsearchparams-set
    ///
    /// @param[in] name
    /// @param[in] value
    template <class TN, class TV>
    void set(TN&& name, TV&& value);

    /// Sort all name-value pairs, by their names.
    ///
    /// Sorting is done by comparison of code units. The relative order between
    /// name-value pairs with equal names is preserved.
    ///
    /// More info: https://url.spec.whatwg.org/#dom-urlsearchparams-sort
    void sort();

    /// Serializes name-value pairs to string and appends it to @a query.
    ///
    /// @param[in,out] query
    void serialize(std::string& query) const;

    /// Serializes name-value pairs to string.
    ///
    /// More info: https://url.spec.whatwg.org/#urlsearchparams-stringification-behavior
    ///
    /// @return serialized name-value pairs
    [[nodiscard]] std::string to_string() const;

    // Iterators

    /// @return an iterator to the beginning of name-value list
    [[nodiscard]] const_iterator begin() const noexcept { return params_.begin(); }

    /// @return an iterator to the beginning of name-value list
    [[nodiscard]] const_iterator cbegin() const noexcept { return params_.cbegin(); }

    /// @return an iterator to the end of name-value list
    [[nodiscard]] const_iterator end() const noexcept { return params_.end(); }

    /// @return an iterator to the end of name-value list
    [[nodiscard]] const_iterator cend() const noexcept { return params_.cend(); }

    /// @return a reverse iterator to the beginning of name-value list
    [[nodiscard]] const_reverse_iterator rbegin() const noexcept { return params_.rbegin(); }

    /// @return a reverse iterator to the beginning of name-value list
    [[nodiscard]] const_reverse_iterator crbegin() const noexcept { return params_.crbegin(); }

    /// @return a reverse iterator to the end of name-value list
    [[nodiscard]] const_reverse_iterator rend() const noexcept { return params_.rend(); }

    /// @return a reverse iterator to the end of name-value list
    [[nodiscard]] const_reverse_iterator crend() const noexcept { return params_.crend(); }

    // Capacity

    /// Checks whether the name-value list is empty
    ///
    /// @return `true` if the container is empty, `false` otherwise
    [[nodiscard]] bool empty() const noexcept { return params_.empty(); }

    /// @return the number of elements in the name-value list
    [[nodiscard]] size_type size() const noexcept { return params_.size(); }

    // Utils

    /// Initializes and returns name-value pairs list by parsing query string.
    ///
    /// @param[in] rem_qmark if it is `true` and the @a query starts with U+003F (?),
    ///   then skips first code point in @a query
    /// @param[in] query string to parse
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    [[nodiscard]] static name_value_list do_parse(bool rem_qmark, StrT&& query);

    /// Percent encodes the @a value using application/x-www-form-urlencoded percent-encode set,
    /// and replacing 0x20 (SP) with U+002B (+). Appends result to the @a encoded string.
    ///
    /// @param[in,out] encoded string to append percent encoded value
    /// @param[in] value string value to percent encode
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    static void urlencode(std::string& encoded, StrT&& value);

private:
    explicit url_search_params(url* url_ptr);

    void clear_params() noexcept;
    void copy_params(const url_search_params& other);
    void move_params(url_search_params&& other) noexcept;
    void parse_params(string_view query);

    void update();

    static UPA_API void urlencode_sv(std::string& encoded, string_view value);

    friend class url;
    friend class detail::url_search_params_ptr;
    friend std::ostream& operator<<(std::ostream& os, const url_search_params& usp);

private:
    name_value_list params_;
    bool is_sorted_ = false;
    url* url_ptr_ = nullptr;
};


namespace detail {

class url_search_params_ptr
{
public:
    url_search_params_ptr() noexcept = default;

    // copy constructor initializes to nullptr
    url_search_params_ptr(const url_search_params_ptr&) noexcept {}
    url_search_params_ptr& operator=(const url_search_params_ptr& other);

    // move constructor/assignment
    url_search_params_ptr(url_search_params_ptr&& other) noexcept = default;
    url_search_params_ptr& operator=(url_search_params_ptr&& other) noexcept = default;

    // destructor
    ~url_search_params_ptr() = default;

    void init(url* url_ptr) {
        ptr_.reset(new url_search_params(url_ptr)); // NOLINT(cppcoreguidelines-owning-memory)
    }

    void set_url_ptr(url* url_ptr) noexcept {
        if (ptr_)
            ptr_->url_ptr_ = url_ptr;
    }

    void clear_params() noexcept {
        assert(ptr_);
        ptr_->clear_params();
    }
    void parse_params(string_view query) {
        assert(ptr_);
        ptr_->parse_params(query);
    }

    explicit operator bool() const noexcept {
        return static_cast<bool>(ptr_);
    }
    url_search_params& operator*() const {
        return *ptr_;
    }
    url_search_params* operator->() const noexcept {
        return ptr_.get();
    }
private:
    std::unique_ptr<url_search_params> ptr_;
};

} // namespace detail


// url_search_params inline

// Copy constructor

inline url_search_params::url_search_params(const url_search_params& other)
    : params_(other.params_)
    , is_sorted_(other.is_sorted_)
{}

// Move constructor

inline url_search_params::url_search_params(url_search_params&& other)
    noexcept(std::is_nothrow_move_constructible_v<name_value_list>)
    : params_(std::move(other.params_))
    , is_sorted_(other.is_sorted_)
{}

// Assignment

inline url_search_params& url_search_params::operator=(const url_search_params& other) {
    if (this != std::addressof(other)) {
        copy_params(other);
        update();
    }
    return *this;
}

inline url_search_params& url_search_params::operator=(url_search_params&& other) noexcept {
    assert(url_ptr_ == nullptr);
    move_params(std::move(other));
    return *this;
}

inline url_search_params& url_search_params::safe_assign(url_search_params&& other) {
    move_params(std::move(other));
    update();
    return *this;
}

// Operations

inline void url_search_params::clear() {
    params_.clear();
    is_sorted_ = true;
    update();
}

inline void url_search_params::swap(url_search_params& other) noexcept {
    assert(url_ptr_ == nullptr && other.url_ptr_ == nullptr);

    using std::swap;

    swap(params_, other.params_);
    swap(is_sorted_, other.is_sorted_);
}

inline void url_search_params::clear_params() noexcept {
    params_.clear();
    is_sorted_ = true;
}

inline void url_search_params::copy_params(const url_search_params& other) {
    params_ = other.params_;
    is_sorted_ = other.is_sorted_;
}

inline void url_search_params::move_params(url_search_params&& other) noexcept {
    params_ = std::move(other.params_);
    is_sorted_ = other.is_sorted_;
}

inline void url_search_params::parse_params(string_view query) {
    params_ = do_parse(false, query);
    is_sorted_ = false;
}

template <class StrT, enable_if_str_arg_t<StrT>>
inline void url_search_params::parse(StrT&& query) {
    params_ = do_parse(true, std::forward<StrT>(query));
    is_sorted_ = false;
    update();
}

template <class TN, class TV>
inline void url_search_params::append(TN&& name, TV&& value) {
    params_.emplace_back(
        make_string(std::forward<TN>(name)),
        make_string(std::forward<TV>(value))
    );
    is_sorted_ = false;
    update();
}

template <class TN>
inline void url_search_params::del(const TN& name) {
    const auto str_name = make_string(name);

    params_.remove_if([&](const value_type& item) {
        return item.first == str_name;
    });
    update();
}

template <class TN, class TV>
inline void url_search_params::del(const TN& name, const TV& value) {
    const auto str_name = make_string(name);
    const auto str_value = make_string(value);

    params_.remove_if([&](const value_type& item) {
        return item.first == str_name && item.second == str_value;
    });
    update();
}

template <class TN>
inline url_search_params::size_type url_search_params::remove(const TN& name) {
    const auto str_name = make_string(name);

    return remove_if([&](const value_type& item) {
        return item.first == str_name;
    });
}

template <class TN, class TV>
inline url_search_params::size_type url_search_params::remove(const TN& name, const TV& value) {
    const auto str_name = make_string(name);
    const auto str_value = make_string(value);

    return remove_if([&](const value_type& item) {
        return item.first == str_name && item.second == str_value;
    });
}

template <class UnaryPredicate>
inline url_search_params::size_type url_search_params::remove_if(UnaryPredicate p) {
#ifdef __cpp_lib_list_remove_return_type
    const size_type count = params_.remove_if(p);
#else
    const size_type old_size = params_.size();
    params_.remove_if(p);
    const size_type count = old_size - params_.size();
#endif
    if (count) update();
    return count;
}

template <class TN>
inline const std::string* url_search_params::get(const TN& name) const {
    const auto str_name = make_string(name);
    for (const auto& p : params_) {
        if (p.first == str_name)
            return &p.second;
    }
    return nullptr;
}

template <class TN>
inline std::list<std::string> url_search_params::get_all(const TN& name) const {
    std::list<std::string> lst;
    const auto str_name = make_string(name);
    for (const auto& p : params_) {
        if (p.first == str_name)
            lst.push_back(p.second);
    }
    return lst;
}

template <class TN>
inline bool url_search_params::has(const TN& name) const {
    const auto str_name = make_string(name);
    for (const auto& p : params_) {
        if (p.first == str_name)
            return true;
    }
    return false;
}

template <class TN, class TV>
inline bool url_search_params::has(const TN& name, const TV& value) const {
    const auto str_name = make_string(name);
    const auto str_value = make_string(value);

    for (const auto& p : params_) {
        if (p.first == str_name && p.second == str_value)
            return true;
    }
    return false;
}

template <class TN, class TV>
inline void url_search_params::set(TN&& name, TV&& value) {
    auto str_name = make_string(std::forward<TN>(name));
    auto str_value = make_string(std::forward<TV>(value));

    bool is_match = false;
    for (auto it = params_.begin(); it != params_.end(); ) {
        if (it->first == str_name) {
            if (is_match) {
                it = params_.erase(it);
                continue;
            }
            it->second = std::move(str_value);
            is_match = true;
        }
        ++it;
    }
    if (!is_match)
        append(std::move(str_name), std::move(str_value));
    else
        update();
}

inline void url_search_params::sort() {
    // https://url.spec.whatwg.org/#dom-urlsearchparams-sort
    // Sorting must be done by comparison of code units. The relative order
    // between name-value pairs with equal names must be preserved.
    if (!is_sorted_) {
        // https://en.cppreference.com/w/cpp/container/list/sort
        // std::list::sort preserves the order of equal elements.
        params_.sort([](const name_value_pair& a, const name_value_pair& b) {
            //return a.first < b.first;
            return url_utf::compare_by_code_units(
                a.first.data(), a.first.data() + a.first.size(),
                b.first.data(), b.first.data() + b.first.size()) < 0;
        });
        is_sorted_ = true;
    }
    update();
}

template <class StrT, enable_if_str_arg_t<StrT>>
inline url_search_params::name_value_list url_search_params::do_parse(bool rem_qmark, StrT&& query) {
    name_value_list lst;

    const auto str_query = make_string(std::forward<StrT>(query));
    auto b = str_query.begin();
    const auto e = str_query.end();

    // remove leading question-mark?
    if (rem_qmark && b != e && *b == '?')
        ++b;

    std::string name;
    std::string value;
    std::string* pval = &name;
    auto start = b;
    for (auto it = b; it != e; ++it) {
        switch (*it) {
        case '=':
            if (pval != &value)
                pval = &value;
            else
                pval->push_back(*it);
            break;
        case '&':
            if (start != it) {
                url_utf::check_fix_utf8(name);
                url_utf::check_fix_utf8(value);
                lst.emplace_back(std::move(name), std::move(value));
                // clear after move
                name.clear();
                value.clear();
            }
            pval = &name;
            start = it + 1; // skip '&'
            break;
        case '+':
            pval->push_back(' ');
            break;
        case '%':
            if (std::distance(it, e) > 2) {
                auto itc = it;
                const auto uc1 = static_cast<unsigned char>(*(++itc));
                const auto uc2 = static_cast<unsigned char>(*(++itc));
                if (detail::is_hex_char(uc1) && detail::is_hex_char(uc2)) {
                    const char c = static_cast<char>((detail::hex_char_to_num(uc1) << 4) + detail::hex_char_to_num(uc2));
                    pval->push_back(c);
                    it = itc;
                    break;
                }
            }
            [[fallthrough]];
        default:
            pval->push_back(*it);
            break;
        }
    }
    if (start != e) {
        url_utf::check_fix_utf8(name);
        url_utf::check_fix_utf8(value);
        lst.emplace_back(std::move(name), std::move(value));
    }
    return lst;
}

template <class StrT, enable_if_str_arg_t<StrT>>
inline void url_search_params::urlencode(std::string& encoded, StrT&& value) {
    const auto str_value = make_string(std::forward<StrT>(value));
    urlencode_sv(encoded, str_value);
}

inline void url_search_params::serialize(std::string& query) const {
    auto it = params_.begin();
    if (it != params_.end()) {
        while (true) {
            urlencode_sv(query, it->first); // name
            query.push_back('=');
            urlencode_sv(query, it->second); // value
            if (++it == params_.end())
                break;
            query.push_back('&');
        }
    }
}

inline std::string url_search_params::to_string() const {
    std::string query;
    serialize(query);
    return query;
}

// Non-member functions

/// @brief Performs stream output on URL search parameters
///
/// Outputs URL search parameters serialized to application/x-www-form-urlencoded
///
/// @param[in] os the output stream to write to
/// @param[in] usp the url_search_params object to serialize and output
/// @return a reference to the output stream
/// @see https://url.spec.whatwg.org/#urlencoded-serializing
inline std::ostream& operator<<(std::ostream& os, const url_search_params& usp) {
    return os << usp.to_string();
}

/// @brief Swaps the contents of two url_search_params
///
/// Swaps the contents of the @a lhs and @a rhs url_search_params
///
/// NOTE: It is undefined behavior to use this function to swap the
/// contents of references returned by url::search_params().
///
/// @param[in,out] lhs
/// @param[in,out] rhs
inline void swap(url_search_params& lhs, url_search_params& rhs) noexcept {
    lhs.swap(rhs);
}


} // namespace upa

#endif // UPA_URL_SEARCH_PARAMS_H
  // IWYU pragma: export
// #include "url_version.h"
// Copyright 2023-2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//

#ifndef UPA_URL_VERSION_H
#define UPA_URL_VERSION_H

// NOLINTBEGIN(*-macro-*)

#define UPA_URL_VERSION_MAJOR 2
#define UPA_URL_VERSION_MINOR 2
#define UPA_URL_VERSION_PATCH 0

#define UPA_URL_VERSION "2.2.0"

/// @brief Encode version to one number
#define UPA_MAKE_VERSION_NUM(n1, n2, n3) ((n1) << 16 | (n2) << 8 | (n3))

/// @brief Version encoded to one number
#define UPA_URL_VERSION_NUM UPA_MAKE_VERSION_NUM( \
    UPA_URL_VERSION_MAJOR, \
    UPA_URL_VERSION_MINOR, \
    UPA_URL_VERSION_PATCH)

// NOLINTEND(*-macro-*)

#endif // UPA_URL_VERSION_H
        // IWYU pragma: export
// #include "util.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint> // uint8_t
#include <filesystem>
#include <functional> // std::hash
#include <iterator>
#include <ostream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

// not yet
// #define UPA_URL_USE_ENCODING

namespace upa {
namespace detail {

// Forward declarations
class url_serializer;
class url_setter;
class url_parser;

// Scheme info

struct alignas(32) scheme_info {
    string_view scheme;
    int default_port;           // -1 if none
    unsigned is_special : 1;    // "ftp", "file", "http", "https", "ws", "wss"
    unsigned is_file : 1;       // "file"
    unsigned is_http : 1;       // "http", "https"
    unsigned is_ws : 1;         // "ws", "wss"
};

UPA_API const scheme_info* get_scheme_info(string_view src);

// Values of the what() function of url_error exception
inline constexpr const char* kURLParseError = "URL parse error";
inline constexpr const char* kBaseURLParseError = "Base URL parse error";

} // namespace detail

/// @brief URL class
///
/// Follows specification in
/// https://url.spec.whatwg.org/#url-class
///
class url {
public:
    /// Enumeration to identify URL's parts (URL record members) defined here:
    /// https://url.spec.whatwg.org/#url-representation
    enum PartType {
        SCHEME = 0,
        SCHEME_SEP,
        USERNAME,
        PASSWORD,
        HOST_START,
        HOST,
        PORT,
        PATH_PREFIX,    // "/."
        PATH,
        QUERY,
        FRAGMENT,
        PART_COUNT
    };

    /// @brief Default constructor.
    ///
    /// Constructs empty URL.
    url() = default;

    /// @brief Copy constructor.
    ///
    /// @param[in] other  URL to copy from
    url(const url& other) = default;

    /// @brief Move constructor.
    ///
    /// Constructs the URL with the contents of @a other using move semantics.
    ///
    /// @param[in,out] other  URL to move to this object
    url(url&& other) noexcept;

    /// @brief Copy assignment.
    ///
    /// @param[in] other  URL to copy from
    /// @return *this
    url& operator=(const url& other) = default;

    /// @brief Move assignment.
    ///
    /// Replaces the contents with those of @a other using move semantics.
    ///
    /// @param[in,out] other  URL to move to this object
    /// @return *this
    url& operator=(url&& other) noexcept;

    /// @brief Safe move assignment.
    ///
    /// Replaces the contents with those of @a other using move semantics.
    /// Preserves original url_search_params object.
    ///
    /// @param[in,out] other  URL to move to this object
    /// @return *this
    url& safe_assign(url&& other);

    /// @brief Parsing constructor.
    ///
    /// Throws url_error exception on parse error.
    ///
    /// @param[in] str_url URL string to parse
    /// @param[in] pbase   pointer to base URL, may be `nullptr`
    template <class T, enable_if_str_arg_t<T> = 0>
    explicit url(T&& str_url, const url* pbase = nullptr)
        : url(std::forward<T>(str_url), pbase, detail::kURLParseError)
    {}

    /// @brief Parsing constructor.
    ///
    /// Throws url_error exception on parse error.
    ///
    /// @param[in] str_url URL string to parse
    /// @param[in] base    base URL
    template <class T, enable_if_str_arg_t<T> = 0>
    explicit url(T&& str_url, const url& base)
        : url(std::forward<T>(str_url), &base, detail::kURLParseError)
    {}

    /// @brief Parsing constructor.
    ///
    /// Throws url_error exception on parse error.
    ///
    /// @param[in] str_url  URL string to parse
    /// @param[in] str_base base URL string
    template <class T, class TB, enable_if_str_arg_t<T> = 0, enable_if_str_arg_t<TB> = 0>
    explicit url(T&& str_url, TB&& str_base)
        : url(std::forward<T>(str_url), url(std::forward<TB>(str_base), nullptr, detail::kBaseURLParseError))
    {}

    /// destructor
    ~url() = default;

    // Operations

    /// @brief Clears URL
    ///
    /// Makes URL empty.
    void clear();

    /// @brief Swaps the contents of two URLs
    ///
    /// @param[in,out] other URL to exchange the contents with
    void swap(url& other) noexcept;

    // Parser

    /// @brief Parses given URL string against base URL.
    ///
    /// @param[in] str_url URL string to parse
    /// @param[in] base    pointer to base URL, may be nullptr
    /// @return error code (@a validation_errc::ok on success)
    template <class T, enable_if_str_arg_t<T> = 0>
    validation_errc parse(T&& str_url, const url* base = nullptr) {
        const auto inp = make_str_arg(std::forward<T>(str_url));
        return do_parse(inp.begin(), inp.end(), base);
    }

    /// @brief Parses given URL string against base URL.
    ///
    /// @param[in] str_url URL string to parse
    /// @param[in] base    base URL
    /// @return error code (@a validation_errc::ok on success)
    template <class T, enable_if_str_arg_t<T> = 0>
    validation_errc parse(T&& str_url, const url& base) {
        return parse(std::forward<T>(str_url), &base);
    }

    /// @brief Parses given URL string against base URL.
    ///
    /// @param[in] str_url  URL string to parse
    /// @param[in] str_base base URL string
    /// @return error code (@a validation_errc::ok on success)
    template <class T, class TB, enable_if_str_arg_t<T> = 0, enable_if_str_arg_t<TB> = 0>
    validation_errc parse(T&& str_url, TB&& str_base) {
        upa::url base;
        const auto res = base.parse(std::forward<TB>(str_base), nullptr);
        return res == validation_errc::ok
            ? parse(std::forward<T>(str_url), &base)
            : res;
    }

    /// @brief Checks if a given URL string can be successfully parsed
    ///
    /// If @a pbase is not nullptr, then try to parse against *pbase URL.
    /// More info: https://url.spec.whatwg.org/#dom-url-canparse
    ///
    /// @param[in] str_url URL string to parse
    /// @param[in] pbase   pointer to base URL, may be `nullptr`
    /// @return true if given @a str_url can be parsed against @a *pbase
    template <class T, enable_if_str_arg_t<T> = 0>
    [[nodiscard]] static bool can_parse(T&& str_url, const url* pbase = nullptr) {
        upa::url url;
        return url.for_can_parse(std::forward<T>(str_url), pbase) == validation_errc::ok;
    }

    /// @brief Checks if a given URL string can be successfully parsed
    ///
    /// Try to parse against base URL.
    /// More info: https://url.spec.whatwg.org/#dom-url-canparse
    ///
    /// @param[in] str_url URL string to parse
    /// @param[in] base    base URL
    /// @return true if given @a str_url can be parsed against base URL
    template <class T, enable_if_str_arg_t<T> = 0>
    [[nodiscard]] static bool can_parse(T&& str_url, const url& base) {
        return can_parse(std::forward<T>(str_url), &base);
    }

    /// @brief Checks if a given URL string can be successfully parsed
    ///
    /// First try to parse @a str_base URL string, if it succeed, then
    /// try to parse @a str_url against base URL.
    /// More info: https://url.spec.whatwg.org/#dom-url-canparse
    ///
    /// @param[in] str_url  URL string to parse
    /// @param[in] str_base base URL string
    /// @return true if given @a str_url can be parsed against @a str_base URL string
    template <class T, class TB, enable_if_str_arg_t<T> = 0, enable_if_str_arg_t<TB> = 0>
    [[nodiscard]] static bool can_parse(T&& str_url, TB&& str_base) {
        upa::url base;
        return
            base.for_can_parse(std::forward<TB>(str_base), nullptr) == validation_errc::ok &&
            can_parse(std::forward<T>(str_url), &base);
    }

    // Setters

    /// @brief The href setter
    ///
    /// Parses given URL string, and in the case of success assigns parsed URL value.
    /// On parse failure leaves URL value unchanged.
    ///
    /// @param[in] str URL string to parse
    /// @return `true` - on success; `false` - on failure
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    bool href(StrT&& str);
    /// Equivalent to @link href(StrT&& str) @endlink
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    bool set_href(StrT&& str) { return href(std::forward<StrT>(str)); }

    /// @brief The protocol setter
    ///
    /// Parses given string and on succes sets the URL's protocol.
    /// More info: https://url.spec.whatwg.org/#dom-url-protocol
    ///
    /// @param[in] str string to parse
    /// @return `true` - on success; `false` - on failure (URL protocol unchanged)
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    bool protocol(StrT&& str);
    /// Equivalent to @link protocol(StrT&& str) @endlink
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    bool set_protocol(StrT&& str) { return protocol(std::forward<StrT>(str)); }

    /// @brief The username setter
    ///
    /// Parses given string and on succes sets the URL's username.
    /// More info: https://url.spec.whatwg.org/#dom-url-username
    ///
    /// @param[in] str string to parse
    /// @return `true` - on success; `false` - if username can not be set
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    bool username(StrT&& str);
    /// Equivalent to @link username(StrT&& str) @endlink
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    bool set_username(StrT&& str) { return username(std::forward<StrT>(str)); }

    /// @brief The password setter
    ///
    /// Parses given string and on succes sets the URL's password.
    /// More info: https://url.spec.whatwg.org/#dom-url-password
    ///
    /// @param[in] str string to parse
    /// @return `true` - on success; `false` - if password can not be set
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    bool password(StrT&& str);
    /// Equivalent to @link password(StrT&& str) @endlink
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    bool set_password(StrT&& str) { return password(std::forward<StrT>(str)); }

    /// @brief The host setter
    ///
    /// Parses given string and on succes sets the URL's host and port.
    /// More info: https://url.spec.whatwg.org/#dom-url-host
    ///
    /// @param[in] str string to parse
    /// @return `true` - on success; `false` - on failure (URL's host and port unchanged)
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    bool host(StrT&& str);
    /// Equivalent to @link host(StrT&& str) @endlink
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    bool set_host(StrT&& str) { return host(std::forward<StrT>(str)); }

    /// @brief The hostname setter
    ///
    /// Parses given string and on succes sets the URL's host.
    /// More info: https://url.spec.whatwg.org/#dom-url-hostname
    ///
    /// @param[in] str string to parse
    /// @return `true` - on success; `false` - on failure (URL's host unchanged)
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    bool hostname(StrT&& str);
    /// Equivalent to @link hostname(StrT&& str) @endlink
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    bool set_hostname(StrT&& str) { return hostname(std::forward<StrT>(str)); }

    /// @brief The port setter
    ///
    /// Parses given string and on succes sets the URL's port.
    /// More info: https://url.spec.whatwg.org/#dom-url-port
    ///
    /// @param[in] str string to parse
    /// @return `true` - on success; `false` - on failure (URL's port unchanged)
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    bool port(StrT&& str);
    /// Equivalent to @link port(StrT&& str) @endlink
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    bool set_port(StrT&& str) { return port(std::forward<StrT>(str)); }

    /// @brief The pathname setter
    ///
    /// Parses given string and on succes sets the URL's path.
    /// More info: https://url.spec.whatwg.org/#dom-url-pathname
    ///
    /// @param[in] str string to parse
    /// @return `true` - on success; `false` - on failure (URL's path unchanged)
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    bool pathname(StrT&& str);
    /// Equivalent to @link pathname(StrT&& str) @endlink
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    bool set_pathname(StrT&& str) { return pathname(std::forward<StrT>(str)); }

    /// @brief The search setter
    ///
    /// Parses given string and on succes sets the URL's query.
    /// More info: https://url.spec.whatwg.org/#dom-url-search
    ///
    /// @param[in] str string to parse
    /// @return `true` - on success; `false` - on failure (URL's query unchanged)
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    bool search(StrT&& str);
    /// Equivalent to @link search(StrT&& str) @endlink
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    bool set_search(StrT&& str) { return search(std::forward<StrT>(str)); }

    /// @brief The hash setter
    ///
    /// Parses given string and on succes sets the URL's fragment.
    /// More info: https://url.spec.whatwg.org/#dom-url-hash
    ///
    /// @param[in] str string to parse
    /// @return `true` - on success; `false` - on failure (URL's fragment unchanged)
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    bool hash(StrT&& str);
    /// Equivalent to @link hash(StrT&& str) @endlink
    template <class StrT, enable_if_str_arg_t<StrT> = 0>
    bool set_hash(StrT&& str) { return hash(std::forward<StrT>(str)); }

    // Getters

    /// @brief The href getter
    ///
    /// More info: https://url.spec.whatwg.org/#dom-url-href
    ///
    /// @return serialized URL
    [[nodiscard]] string_view href() const;
    /// Equivalent to @link href() const @endlink
    [[nodiscard]] string_view get_href() const { return href(); }

    /// @brief The origin getter
    ///
    /// More info: https://url.spec.whatwg.org/#dom-url-origin
    ///
    /// Note: For file URLs, this implementation returns a serialized opaque
    /// origin (null).
    ///
    /// @return ASCII serialized URL's origin
    [[nodiscard]] std::string origin() const;

    /// @brief The protocol getter
    ///
    /// More info: https://url.spec.whatwg.org/#dom-url-protocol
    ///
    /// @return URL's scheme, followed by U+003A (:)
    [[nodiscard]] string_view protocol() const;
    /// Equivalent to @link protocol() const @endlink
    [[nodiscard]] string_view get_protocol() const { return protocol(); }

    /// @brief The username getter
    ///
    /// More info: https://url.spec.whatwg.org/#dom-url-username
    ///
    /// @return URL’s username
    [[nodiscard]] string_view username() const;
    /// Equivalent to @link username() const @endlink
    [[nodiscard]] string_view get_username() const { return username(); }

    /// @brief The password getter
    ///
    /// More info: https://url.spec.whatwg.org/#dom-url-password
    ///
    /// @return URL’s password
    [[nodiscard]] string_view password() const;
    /// Equivalent to @link password() const @endlink
    [[nodiscard]] string_view get_password() const { return password(); }

    /// @brief The host getter
    ///
    /// More info: https://url.spec.whatwg.org/#dom-url-host
    ///
    /// @return URL’s host, serialized, followed by U+003A (:) and URL’s port, serialized
    [[nodiscard]] string_view host() const;
    /// Equivalent to @link host() const @endlink
    [[nodiscard]] string_view get_host() const { return host(); }

    /// @brief The hostname getter
    ///
    /// More info: https://url.spec.whatwg.org/#dom-url-hostname
    ///
    /// @return URL’s host, serialized
    [[nodiscard]] string_view hostname() const;
    /// Equivalent to @link hostname() const @endlink
    [[nodiscard]] string_view get_hostname() const { return hostname(); }

    /// @brief The host_type getter
    ///
    /// @return URL’s host type as HostType enumeration value
    [[nodiscard]] HostType host_type() const noexcept;

    /// @brief The port getter
    ///
    /// More info: https://url.spec.whatwg.org/#dom-url-port
    ///
    /// @return URL’s port, serialized, if URL’s port is not null, otherwise empty string
    [[nodiscard]] string_view port() const;
    /// Equivalent to @link port() const @endlink
    [[nodiscard]] string_view get_port() const { return port(); }

    /// @return URL’s port, converted to `int` value, if URL’s port is not null,
    ///   otherwise `-1`
    [[nodiscard]] int port_int() const;

    /// @return URL’s port, converted to `int` value, if URL’s port is not null,
    ///   otherwise default port, if URL's scheme has default port,
    ///   otherwise `-1`
    [[nodiscard]] int real_port_int() const;

    /// @brief The path getter
    ///
    /// @return URL's path, serialized, followed by U+003F (?) and URL’s query
    [[nodiscard]] string_view path() const;
    /// Equivalent to @link path() const @endlink
    [[nodiscard]] string_view get_path() const { return path(); }

    /// @brief The pathname getter
    ///
    /// More info: https://url.spec.whatwg.org/#dom-url-pathname
    ///
    /// @return URL’s path, serialized
    [[nodiscard]] string_view pathname() const;
    /// Equivalent to @link pathname() const @endlink
    [[nodiscard]] string_view get_pathname() const { return pathname(); }

    /// @brief The search getter
    ///
    /// More info: https://url.spec.whatwg.org/#dom-url-search
    ///
    /// @return empty string or U+003F (?), followed by URL’s query
    [[nodiscard]] string_view search() const;
    /// Equivalent to @link search() const @endlink
    [[nodiscard]] string_view get_search() const { return search(); }

    /// @brief The hash getter
    ///
    /// More info: https://url.spec.whatwg.org/#dom-url-hash
    ///
    /// @return empty string or U+0023 (#), followed by URL’s fragment
    [[nodiscard]] string_view hash() const;
    /// Equivalent to @link hash() const @endlink
    [[nodiscard]] string_view get_hash() const { return hash(); }

    /// @brief The searchParams getter
    ///
    /// More info: https://url.spec.whatwg.org/#dom-url-searchparams
    ///
    /// Returned reference is valid thru lifetime of url, or until url's move assignment
    /// operation (except @c safe_assign, which preserves reference validity).
    ///
    /// @return reference to this’s query object (url_search_params class)
    url_search_params& search_params()&;

    /// @brief The searchParams getter for rvalue url
    ///
    /// @return the move constructed copy of this’s query object (url_search_params class)
    /// @see search_params()&
    [[nodiscard]] url_search_params search_params()&&;

    /// @brief URL serializer
    ///
    /// Returns serialized URL in a string_view as defined here:
    /// https://url.spec.whatwg.org/#concept-url-serializer
    ///
    /// @param[in] exclude_fragment exclude fragment when serializing
    /// @return serialized URL as string_view
    [[nodiscard]] string_view serialize(bool exclude_fragment = false) const;

    // Get url info

    /// @brief Checks whether the URL is empty
    ///
    /// @return `true` if URL is empty, `false` otherwise
    [[nodiscard]] bool empty() const noexcept;

    /// @brief Returns whether the URL is valid
    ///
    /// URL is valid if it is not empty, and contains a successfully parsed URL.
    ///
    /// @return `true` if URL is valid, `false` otherwise
    [[nodiscard]] bool is_valid() const noexcept;

    /// @brief Gets the start and end position of the specified URL part
    ///
    /// Returns the start and end position of the part (as defined in
    /// https://url.spec.whatwg.org/#url-representation) in the string returned by the
    /// `get_href()`, `href()` or `to_string()` functions.
    ///
    /// * `get_part_pos(upa::url::SCHEME)` - get a URL's **scheme** position
    /// * `get_part_pos(upa::url::USERNAME)` - get a URL's **username** position
    /// * `get_part_pos(upa::url::PASSWORD)` - get a URL's **password** position
    /// * `get_part_pos(upa::url::HOST)` - get a URL's **host** position
    /// * `get_part_pos(upa::url::PORT)` - get a URL's **port** position
    /// * `get_part_pos(upa::url::PATH)` - get a URL's **path** position
    /// * `get_part_pos(upa::url::QUERY)` - get a URL's **query** position
    /// * `get_part_pos(upa::url::FRAGMENT)` - get a URL's **fragment** position
    ///
    /// If @a with_sep is `true`, then:
    ///
    /// * `get_part_pos(upa::url::SCHEME, true)` - gets position of URL's **scheme** along with `:`
    ///   (corresponds to the return value of `protocol()`)
    /// * `get_part_pos(upa::url::QUERY, true)` - gets position of URL's **query** along with `?`
    ///   (corresponds to the return value of `search()`)
    /// * `get_part_pos(upa::url::FRAGMENT, true)` - gets position of URL's **fragment** along
    ///   with `#` (corresponds to the return value of `hash()`)
    ///
    /// For other @a t values, the @a with_sep has no effect.
    ///
    /// @param[in] t URL's part
    /// @param[in] with_sep
    /// @return the start and end position of the specified URL part
    [[nodiscard]] UPA_API std::pair<std::size_t, std::size_t> get_part_pos(PartType t,
        bool with_sep = false) const;

    /// @brief Gets URL's part (URL record member) as string
    ///
    /// Function to get ASCII string of any URL's part (URL record member) defined here:
    /// https://url.spec.whatwg.org/#url-representation
    ///
    /// * `get_part_view(upa::url::SCHEME)` - get a URL's **scheme** string
    /// * `get_part_view(upa::url::USERNAME)` - get a URL's **username** string
    /// * `get_part_view(upa::url::PASSWORD)` - get a URL's **password** string
    /// * `get_part_view(upa::url::HOST)` - get a URL's **host** serialized to string
    /// * `get_part_view(upa::url::PORT)` - get a URL's **port** serialized to string
    /// * `get_part_view(upa::url::PATH)` - get a URL's **path** serialized to string
    /// * `get_part_view(upa::url::QUERY)` - get a URL's **query** string
    /// * `get_part_view(upa::url::FRAGMENT)` - get a URL's **fragment** string
    ///
    /// @param[in] t URL's part
    /// @return URL's part string; it is empty if part is empty or null
    [[nodiscard]] string_view get_part_view(PartType t) const;

    /// @brief Checks whether the URL's part (URL record member) is empty or null
    ///
    /// @param[in] t URL's part
    /// @return `true` if URL's part @a t is empty or null, `false` otherwise
    [[nodiscard]] bool is_empty(PartType t) const;

    /// @brief Checks whether the URL's part (URL record member) is null
    ///
    /// Only the following [URL record members](https://url.spec.whatwg.org/#concept-url)
    /// can be null:
    /// * **host** - check with `is_null(upa::url::HOST)`
    /// * **port** - check with `is_null(upa::url::PORT)`
    /// * **query** - check with `is_null(upa::url::QUERY)`
    /// * **fragment** - check with `is_null(upa::url::FRAGMENT)`
    ///
    /// @param[in] t URL's part
    /// @return `true` if URL's part @a t is null, `false` otherwise
    [[nodiscard]] bool is_null(PartType t) const noexcept;

    /// @return `true` if URL's scheme is special ("ftp", "file", "http", "https", "ws", or "wss"),
    ///   `false` otherwise; see: https://url.spec.whatwg.org/#special-scheme
    [[nodiscard]] bool is_special_scheme() const noexcept;

    /// @return `true` if URL's scheme is "file", `false` otherwise
    [[nodiscard]] bool is_file_scheme() const noexcept;

    /// @return `true` if URL's scheme is "http" or "https", `false` otherwise
    [[nodiscard]] bool is_http_scheme() const noexcept;

    /// @return `true` if URL includes credentials (username, password), `false` otherwise
    [[nodiscard]] bool has_credentials() const;

    /// see: https://url.spec.whatwg.org/#url-opaque-path
    /// @return `true` if URL's path is a URL path segment, `false` otherwise
    [[nodiscard]] bool has_opaque_path() const noexcept;

    /// @return serialized URL as `std::string`
    [[nodiscard]] std::string to_string() const;

private:
    enum UrlFlag : unsigned {
        // not null flags
        SCHEME_FLAG = (1u << SCHEME),
        USERNAME_FLAG = (1u << USERNAME),
        PASSWORD_FLAG = (1u << PASSWORD),
        HOST_FLAG = (1u << HOST),
        PORT_FLAG = (1u << PORT),
        PATH_FLAG = (1u << PATH),
        QUERY_FLAG = (1u << QUERY),
        FRAGMENT_FLAG = (1u << FRAGMENT),
        // other flags
        OPAQUE_PATH_FLAG = (1u << (PART_COUNT + 0)),
        VALID_FLAG = (1u << (PART_COUNT + 1)),
        // host type
        HOST_TYPE_SHIFT = (PART_COUNT + 2),
        HOST_TYPE_MASK = (7u << HOST_TYPE_SHIFT),

        // initial flags (empty (but not null) parts)
        // https://url.spec.whatwg.org/#url-representation
        INITIAL_FLAGS = SCHEME_FLAG | USERNAME_FLAG | PASSWORD_FLAG | PATH_FLAG,
    };

    // part flag masks
    static constexpr unsigned kPartFlagMask[url::PART_COUNT] = {
        SCHEME_FLAG,
        0,  // SCHEME_SEP
        USERNAME_FLAG,
        PASSWORD_FLAG,
        0,  // HOST_START
        HOST_FLAG | HOST_TYPE_MASK,
        PORT_FLAG,
        0,  // PATH_PREFIX
        PATH_FLAG | OPAQUE_PATH_FLAG,
        QUERY_FLAG,
        FRAGMENT_FLAG
    };

    // parsing constructor
    template <class T, enable_if_str_arg_t<T> = 0>
    explicit url(T&& str_url, const url* base, const char* what_arg);

    // parser
    template <typename CharT>
    validation_errc do_parse(const CharT* first, const CharT* last, const url* base);

    template <class T, enable_if_str_arg_t<T> = 0>
    validation_errc for_can_parse(T&& str_url, const url* base);

    // set scheme
    void set_scheme_str(string_view str);
    void set_scheme(const url& src);
    void set_scheme(string_view str);
    void set_scheme(std::size_t scheme_length);

    // path util
    string_view get_path_first_string(std::size_t len) const;
    // path shortening
    bool get_path_rem_last(std::size_t& path_end, std::size_t& path_segment_count) const;
    bool get_shorten_path(std::size_t& path_end, std::size_t& path_segment_count) const;

    // flags
    void set_flag(UrlFlag flag) noexcept;

    void set_has_opaque_path() noexcept;

    void set_host_type(HostType ht) noexcept;

    // info
    bool canHaveUsernamePasswordPort() const;

    // url record
    void move_record(url& other) noexcept;

    // search params
    void clear_search_params() noexcept;
    void parse_search_params();

private:
    std::string norm_url_;
    std::array<std::size_t, PART_COUNT> part_end_ = {};
    const detail::scheme_info* scheme_inf_ = nullptr;
    unsigned flags_ = INITIAL_FLAGS;
    std::size_t path_segment_count_ = 0;
    detail::url_search_params_ptr search_params_ptr_;

    friend bool operator==(const url& lhs, const url& rhs) noexcept;
    friend std::ostream& operator<<(std::ostream& os, const url& url);
    friend struct std::hash<url>;
    friend class detail::url_serializer;
    friend class detail::url_setter;
    friend class detail::url_parser;
    friend class url_search_params;
};


namespace detail {

class url_serializer : public host_output {
public:
    url_serializer() = delete;
    url_serializer(const url_serializer&) = delete;
    url_serializer& operator=(const url_serializer&) = delete;

    explicit url_serializer(url& dest_url, bool need_save = true)
        : host_output(need_save)
        , url_(dest_url)
        , last_pt_(url::SCHEME)
    {}

    ~url_serializer() override = default;

    void new_url() {
        if (!url_.empty())
            url_.clear();
    }
    virtual void reserve(std::size_t new_cap) { url_.norm_url_.reserve(new_cap); }

    // set data
    void set_scheme(const url& src) { url_.set_scheme(src); }
    void set_scheme(string_view str) { url_.set_scheme(str); }
    void set_scheme(std::size_t scheme_length) { url_.set_scheme(scheme_length); }

    // set scheme
    virtual std::string& start_scheme();
    virtual void save_scheme();

    // set url's part
    void fill_parts_offset(url::PartType t1, url::PartType t2, std::size_t offset);
    virtual std::string& start_part(url::PartType new_pt);
    virtual void save_part();

    virtual void clear_part(url::PartType /*pt*/) {}

    // set empty host
    void set_empty_host();

    // empties not empty host
    virtual void empty_host();

    // host_output overrides
    std::string& hostStart() override;
    void hostDone(HostType ht) override;

    // Path operations

    // append the empty string to url’s path (list)
    void append_empty_path_segment();
    // append string to url's path (list)
    virtual std::string& start_path_segment();
    virtual void save_path_segment();
    virtual void commit_path();
    // if '/' not required:
    std::string& start_path_string();
    void save_path_string();

    virtual void shorten_path();
    //UNUSED// retunrs how many slashes are removed
    //virtual std::size_t remove_leading_path_slashes();

    using PathOpFn = bool (url::*)(std::size_t& path_end, std::size_t& segment_count) const;
    void append_parts(const url& src, url::PartType t1, url::PartType t2, PathOpFn pathOpFn = nullptr);

    // flags
    void set_flag(const url::UrlFlag flag) { url_.set_flag(flag); }
    void set_host_type(const HostType ht) { url_.set_host_type(ht); }
    // IMPORTANT: has-an-opaque-path flag must be set before or just after
    // SCHEME set; because other part's serialization depends on this flag
    void set_has_opaque_path() {
        assert(last_pt_ == url::SCHEME);
        url_.set_has_opaque_path();
    }

    // get info
    string_view get_part_view(url::PartType t) const { return url_.get_part_view(t); }
    bool is_empty(const url::PartType t) const { return url_.is_empty(t); }
    virtual bool is_empty_path() const {
        assert(!url_.has_opaque_path());
        // path_segment_count_ has meaning only if path is a list (path isn't opaque)
        return url_.path_segment_count_ == 0;
    }
    bool is_null(const url::PartType t) const noexcept { return url_.is_null(t); }
    bool is_special_scheme() const noexcept { return url_.is_special_scheme(); }
    bool is_file_scheme() const noexcept { return url_.is_file_scheme(); }
    bool has_credentials() const { return url_.has_credentials(); }
    const detail::scheme_info* scheme_inf() const noexcept { return url_.scheme_inf_; }
    int port_int() const { return url_.port_int(); }

protected:
    void adjust_path_prefix();

    std::size_t get_part_pos(url::PartType pt) const;
    std::size_t get_part_len(url::PartType pt) const;
    void replace_part(url::PartType new_pt, const char* str, std::size_t len);
    void replace_part(url::PartType last_pt, const char* str, std::size_t len,
        url::PartType first_pt, std::size_t len0);

protected:
    url& url_; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)
    // last serialized URL's part
    url::PartType last_pt_;
};


class url_setter : public url_serializer {
public:
    url_setter() = delete;
    url_setter(const url_setter&) = delete;
    url_setter& operator=(const url_setter&) = delete;

    explicit url_setter(url& dest_url)
        : url_serializer(dest_url)
        , use_strp_(true)
        , curr_pt_(url::SCHEME)
    {}

    ~url_setter() override = default;

    //???
    void reserve(std::size_t new_cap) override;

    // set scheme
    std::string& start_scheme() override;
    void save_scheme() override;

    // set/clear/empty url's part
    std::string& start_part(url::PartType new_pt) override;
    void save_part() override;

    void clear_part(url::PartType pt) override;
    void empty_part(url::PartType pt); // override

    void empty_host() override;

    // path
    std::string& start_path_segment() override;
    void save_path_segment() override;
    void commit_path() override;

    void shorten_path() override;
    //UNUSED// retunrs how many slashes are removed
    //std::size_t remove_leading_path_slashes() override;
    bool is_empty_path() const override;

protected:
    url::PartType find_last_part(url::PartType pt) const;

private:
    bool use_strp_;
    // buffer for URL's part
    std::string strp_;
    // path segment end positions in the strp_
    std::vector<std::size_t> path_seg_end_;
    // current URL's part
    url::PartType curr_pt_;
};


class url_parser {
public:
    enum State {
        not_set_state = 0,
        scheme_start_state,
        scheme_state,
        no_scheme_state,
        special_relative_or_authority_state,
        path_or_authority_state,
        relative_state,
        relative_slash_state,
        special_authority_slashes_state,
        special_authority_ignore_slashes_state,
        authority_state,
        host_state,
        hostname_state,
        port_state,
        file_state,
        file_slash_state,
        file_host_state,
        path_start_state,
        path_state,
        opaque_path_state,
        query_state,
        fragment_state
    };

    template <typename CharT>
    static validation_errc url_parse(url_serializer& urls, const CharT* first, const CharT* last, const url* base, State state_override = not_set_state);

    template <typename CharT>
    static validation_errc parse_host(url_serializer& urls, const CharT* first, const CharT* last);

    template <typename CharT>
    static void parse_path(url_serializer& urls, const CharT* first, const CharT* last);

private:
    template <typename CharT>
    static void do_path_segment(const CharT* pointer, const CharT* last, std::string& output);

    template <typename CharT>
    static void do_opaque_path(const CharT* pointer, const CharT* last, std::string& output);
};


// Part start
inline constexpr std::uint8_t kPartStart[url::PART_COUNT] = {
    0, 0, 0,
    1,  // ':' PASSWORD
    0, 0,
    1,  // ':' PORT
    0, 0,
    1,  // '?' QUERY
    1   // '#' FRAGMENT
};

constexpr int port_from_str(const char* first, const char* last) noexcept {
    int port = 0;
    for (auto it = first; it != last; ++it) {
        port = port * 10 + (*it - '0');
    }
    return port;
}

// Removable URL chars

// chars to trim (C0 control or space: U+0000 to U+001F or U+0020)
template <typename CharT>
constexpr bool is_trim_char(CharT ch) noexcept {
    return util::to_unsigned(ch) <= ' ';
}

// chars what should be removed from the URL (ASCII tab or newline: U+0009, U+000A, U+000D)
template <typename CharT>
constexpr bool is_removable_char(CharT ch) noexcept {
    return ch == '\r' || ch == '\n' || ch == '\t';
}

template <typename CharT>
constexpr void do_trim(const CharT*& first, const CharT*& last) noexcept {
    // remove leading C0 controls and space
    while (first < last && is_trim_char(*first))
        ++first;
    // remove trailing C0 controls and space
    while (first < last && is_trim_char(*(last-1)))
        --last;
}

// DoRemoveURLWhitespace
// https://cs.chromium.org/chromium/src/url/url_canon_etc.cc
template <typename CharT>
inline void do_remove_whitespace(const CharT*& first, const CharT*& last, simple_buffer<CharT>& buff) {
    // Fast verification that there's nothing that needs removal. This is the 99%
    // case, so we want it to be fast and don't care about impacting the speed
    // when we do find whitespace.
    for (auto it = first; it < last; ++it) {
        if (!is_removable_char(*it))
            continue;
        // copy non whitespace chars into the new buffer and return it
        buff.reserve(last - first);
        buff.append(first, it);
        for (; it < last; ++it) {
            if (!is_removable_char(*it))
                buff.push_back(*it);
        }
        first = buff.data();
        last = buff.data() + buff.size();
        break;
    }
}

// reverse find

template<class InputIt, class T>
constexpr InputIt find_last(InputIt first, InputIt last, const T& value) {
    for (auto it = last; it > first;) {
        --it;
        if (*it == value) return it;
    }
    return last;
}

// special chars

template <typename CharT>
constexpr bool is_slash(CharT ch) noexcept {
    return ch == '/' || ch == '\\';
}

template <typename CharT>
constexpr bool is_posix_slash(CharT ch) noexcept {
    return ch == '/';
}

template <typename CharT>
constexpr bool is_windows_slash(CharT ch) noexcept {
    return ch == '\\' || ch == '/';
}

// Scheme chars

template <typename CharT>
constexpr bool is_first_scheme_char(CharT ch) noexcept {
    return is_ascii_alpha(ch);
}

template <typename CharT>
constexpr bool is_authority_end_char(CharT c) noexcept {
    return c == '/' || c == '?' || c == '#';
}

template <typename CharT>
constexpr bool is_special_authority_end_char(CharT c) noexcept {
    return c == '/' || c == '?' || c == '#' || c == '\\';
}

// Windows drive letter

// https://url.spec.whatwg.org/#windows-drive-letter
template <typename CharT>
constexpr bool is_windows_drive(CharT c1, CharT c2) noexcept {
    return is_ascii_alpha(c1) && (c2 == ':' || c2 == '|');
}

// https://url.spec.whatwg.org/#normalized-windows-drive-letter
template <typename CharT>
constexpr bool is_normalized_windows_drive(CharT c1, CharT c2) noexcept {
    return is_ascii_alpha(c1) && c2 == ':';
}

// https://url.spec.whatwg.org/#start-with-a-windows-drive-letter
template <typename CharT>
constexpr bool starts_with_windows_drive(const CharT* pointer, const CharT* last) noexcept {
    const auto length = last - pointer;
    return
        (length == 2 || (length > 2 && detail::is_special_authority_end_char(pointer[2]))) &&
        detail::is_windows_drive(pointer[0], pointer[1]);
/*** alternative implementation ***
    return
        length >= 2 &&
        detail::is_windows_drive(pointer[0], pointer[1]) &&
        (length == 2 || detail::is_special_authority_end_char(pointer[2]));
***/
}

// Windows drive letter in OS path
//
// NOTE: Windows OS supports only normalized Windows drive letters.

// Check url's pathname has Windows drive, i.e. starts with "/C:/" or is "/C:"
// see also: detail::starts_with_windows_drive
constexpr bool pathname_has_windows_os_drive(string_view pathname) noexcept {
    return
        (pathname.length() == 3 || (pathname.length() > 3 && is_windows_slash(pathname[3]))) &&
        is_windows_slash(pathname[0]) &&
        is_normalized_windows_drive(pathname[1], pathname[2]);
}

/// Check string is absolute Windows drive path (for example: "C:\\path" or "C:/path")
/// @return pointer to the path after first (back)slash, or `nullptr` if path is not
///   absolute Windows drive path
template <typename CharT>
constexpr const CharT* is_windows_os_drive_absolute_path(const CharT* pointer, const CharT* last) noexcept {
    return (last - pointer > 2 &&
        is_normalized_windows_drive(pointer[0], pointer[1]) &&
        is_windows_slash(pointer[2]))
        ? pointer + 3 : nullptr;
}

} // namespace detail


// url class

inline url::url(url&& other) noexcept
    : norm_url_(std::move(other.norm_url_))
    , part_end_(other.part_end_)
    , scheme_inf_(other.scheme_inf_)
    , flags_(other.flags_)
    , path_segment_count_(other.path_segment_count_)
    , search_params_ptr_(std::move(other.search_params_ptr_))
{
    search_params_ptr_.set_url_ptr(this);
}

inline url& url::operator=(url&& other) noexcept {
    // move data
    move_record(other);
    search_params_ptr_ = std::move(other.search_params_ptr_);

    // setup search params
    search_params_ptr_.set_url_ptr(this);

    return *this;
}

inline url& url::safe_assign(url&& other) {
    if (search_params_ptr_) {
        if (other.search_params_ptr_) {
            move_record(other);
            search_params_ptr_->move_params(std::move(*other.search_params_ptr_));
        } else {
            // parse search parameters before move assign for strong exception guarantee
            url_search_params params(&other);
            move_record(other);
            search_params_ptr_->move_params(std::move(params));
        }
    } else {
        move_record(other);
    }
    return *this;
}

inline void url::move_record(url& other) noexcept {
    norm_url_ = std::move(other.norm_url_);
    part_end_ = other.part_end_;
    scheme_inf_ = other.scheme_inf_;
    flags_ = other.flags_;
    path_segment_count_ = other.path_segment_count_;
}

// url getters

inline string_view url::href() const {
    return norm_url_;
}

inline std::string url::to_string() const {
    return norm_url_;
}

// Origin
// https://url.spec.whatwg.org/#concept-url-origin

// ASCII serialization of an origin
// https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin
inline std::string url::origin() const {
    if (is_special_scheme()) {
        if (is_file_scheme())
            return "null"; // opaque origin
        // "scheme://"
        std::string str_origin(norm_url_, 0, part_end_[SCHEME_SEP]);
        // "host:port"
        str_origin.append(norm_url_.data() + part_end_[HOST_START], norm_url_.data() + part_end_[PORT]);
        return str_origin;
    }
    if (get_part_view(SCHEME) == string_view{ "blob", 4 }) {
        // Note: this library does not support blob URL store, so it allways assumes
        // URL's blob URL entry is null and retrieves origin from the URL's path.
        url path_url;
        if (path_url.parse(get_part_view(PATH)) == validation_errc::ok &&
            path_url.is_http_scheme())
            return path_url.origin();
    }
    return "null"; // opaque origin
}

inline string_view url::protocol() const {
    // "scheme:"
    return { norm_url_.data(), part_end_[SCHEME] ? part_end_[SCHEME] + 1 : 0 };
}

inline string_view url::username() const {
    return get_part_view(USERNAME);
}

inline string_view url::password() const {
    return get_part_view(PASSWORD);
}

inline string_view url::host() const {
    if (is_null(HOST))
        return {};
    // "hostname:port"
    const std::size_t b = part_end_[HOST_START];
    const std::size_t e = is_null(PORT) ? part_end_[HOST] : part_end_[PORT];
    return { norm_url_.data() + b, e - b };
}

inline string_view url::hostname() const {
    return get_part_view(HOST);
}

inline HostType url::host_type() const noexcept {
    return static_cast<HostType>((flags_ & HOST_TYPE_MASK) >> HOST_TYPE_SHIFT);
}

inline string_view url::port() const {
    return get_part_view(PORT);
}

inline int url::port_int() const {
    const auto vport = get_part_view(PORT);
    return vport.length() ? detail::port_from_str(vport.data(), vport.data() + vport.length()) : -1;
}

inline int url::real_port_int() const {
    const auto vport = get_part_view(PORT);
    if (vport.length())
        return detail::port_from_str(vport.data(), vport.data() + vport.length());
    return scheme_inf_ ? scheme_inf_->default_port : -1;
}

// pathname + search
inline string_view url::path() const {
    // "pathname?query"
    const std::size_t b = part_end_[PATH - 1];
    const std::size_t e = part_end_[QUERY] ? part_end_[QUERY] : part_end_[PATH];
    return { norm_url_.data() + b, e ? e - b : 0 };
}

inline string_view url::pathname() const {
    // https://url.spec.whatwg.org/#dom-url-pathname
    // already serialized as needed
    return get_part_view(PATH);
}

inline string_view url::search() const {
    const std::size_t b = part_end_[QUERY - 1];
    const std::size_t e = part_end_[QUERY];
    // is empty?
    if (b + 1 >= e)
        return {};
    // return with '?'
    return { norm_url_.data() + b, e - b };
}

inline string_view url::hash() const {
    const std::size_t b = part_end_[FRAGMENT - 1];
    const std::size_t e = part_end_[FRAGMENT];
    // is empty?
    if (b + 1 >= e)
        return {};
    // return with '#'
    return { norm_url_.data() + b, e - b };
}

inline url_search_params& url::search_params()& {
    if (!search_params_ptr_)
        search_params_ptr_.init(this);
    return *search_params_ptr_;
}

inline url_search_params url::search_params()&& {
    if (search_params_ptr_)
        return std::move(*search_params_ptr_);
    return url_search_params{ search() };
}

inline void url::clear_search_params() noexcept {
    if (search_params_ptr_)
        search_params_ptr_.clear_params();
}

inline void url::parse_search_params() {
    if (search_params_ptr_)
        search_params_ptr_.parse_params(get_part_view(QUERY));
}

inline string_view url::serialize(bool exclude_fragment) const {
    if (exclude_fragment && part_end_[FRAGMENT])
        return { norm_url_.data(), part_end_[QUERY] };
    return norm_url_;
}

// Get url info

inline bool url::empty() const noexcept {
    return norm_url_.empty();
}

inline bool url::is_valid() const noexcept {
    return !!(flags_ & VALID_FLAG);
}

inline string_view url::get_part_view(PartType t) const {
    if (t == SCHEME)
        return { norm_url_.data(), part_end_[SCHEME] };
    // begin & end offsets
    const std::size_t b = part_end_[t - 1] + detail::kPartStart[t];
    const std::size_t e = part_end_[t];
    return { norm_url_.data() + b, e > b ? e - b : 0 };
}

inline bool url::is_empty(const PartType t) const {
    if (t == SCHEME)
        return part_end_[SCHEME] == 0;
    // begin & end offsets
    const std::size_t b = part_end_[t - 1] + detail::kPartStart[t];
    const std::size_t e = part_end_[t];
    return b >= e;
}

inline bool url::is_null(const PartType t) const noexcept {
    return !(flags_ & (1u << t));
}

inline bool url::is_special_scheme() const noexcept {
    return scheme_inf_ && scheme_inf_->is_special;
}

inline bool url::is_file_scheme() const noexcept {
    return scheme_inf_ && scheme_inf_->is_file;
}

inline bool url::is_http_scheme() const noexcept {
    return scheme_inf_ && scheme_inf_->is_http;
}

inline bool url::has_credentials() const {
    return !is_empty(USERNAME) || !is_empty(PASSWORD);
}

// set scheme

inline void url::set_scheme_str(string_view str) {
    norm_url_.clear(); // clear all
    part_end_[SCHEME] = str.length();
    norm_url_.append(str);
    norm_url_ += ':';
}

inline void url::set_scheme(const url& src) {
    set_scheme_str(src.get_part_view(SCHEME));
    scheme_inf_ = src.scheme_inf_;
}

inline void url::set_scheme(string_view str) {
    set_scheme_str(str);
    scheme_inf_ = detail::get_scheme_info(str);
}

inline void url::set_scheme(std::size_t scheme_length) {
    part_end_[SCHEME] = scheme_length;
    scheme_inf_ = detail::get_scheme_info(get_part_view(SCHEME));
}

// flags

inline void url::set_flag(const UrlFlag flag) noexcept {
    flags_ |= flag;
}

inline bool url::has_opaque_path() const noexcept {
    return !!(flags_ & OPAQUE_PATH_FLAG);
}

inline void url::set_has_opaque_path() noexcept {
    set_flag(OPAQUE_PATH_FLAG);
}

inline void url::set_host_type(const HostType ht) noexcept {
    flags_ = (flags_ & ~HOST_TYPE_MASK) | HOST_FLAG | (static_cast<unsigned int>(ht) << HOST_TYPE_SHIFT);
}

inline bool url::canHaveUsernamePasswordPort() const {
    return is_valid() && !(is_empty(url::HOST) || is_file_scheme());
}

// Private parsing constructor

template <class T, enable_if_str_arg_t<T>>
inline url::url(T&& str_url, const url* base, const char* what_arg) {
    const auto inp = make_str_arg(std::forward<T>(str_url));
    const auto res = do_parse(inp.begin(), inp.end(), base);
    if (res != validation_errc::ok)
        throw url_error(res, what_arg);
}

// Operations

inline void url::clear() {
    norm_url_.clear();
    part_end_.fill(0);
    scheme_inf_ = nullptr;
    flags_ = INITIAL_FLAGS;
    path_segment_count_ = 0;
    clear_search_params();
}

inline void url::swap(url& other) noexcept {
    url tmp{ std::move(*this) };
    *this = std::move(other);
    other = std::move(tmp);
}

// Parser

// Implements "basic URL parser" https://url.spec.whatwg.org/#concept-basic-url-parser
// without encoding, url and state override parameters. It resets this url object to
// an empty value and then parses the input and modifies this url object.
// Returns validation_errc::ok on success, or an error value on parsing failure.
template <typename CharT>
inline validation_errc url::do_parse(const CharT* first, const CharT* last, const url* base) {
    const validation_errc res = [&]() {
        detail::url_serializer urls(*this);

        // reset URL
        urls.new_url();

        // is base URL valid?
        if (base && !base->is_valid())
            return validation_errc::invalid_base;

        // remove any leading and trailing C0 control or space:
        detail::do_trim(first, last);
        //TODO-WARN: validation error if trimmed

        return detail::url_parser::url_parse(urls, first, last, base);
    }();
    if (res == validation_errc::ok) {
        set_flag(VALID_FLAG);
        parse_search_params();
    }
    return res;
}

template <class T, enable_if_str_arg_t<T>>
validation_errc url::for_can_parse(T&& str_url, const url* base) {
    const auto inp = make_str_arg(std::forward<T>(str_url));
    const auto* first = inp.begin();
    const auto* last = inp.end();
    const validation_errc res = [&]() {
        detail::url_serializer urls(*this, false);

        // reset URL
        urls.new_url();

        // is base URL valid?
        if (base && !base->is_valid())
            return validation_errc::invalid_base;

        // remove any leading and trailing C0 control or space:
        detail::do_trim(first, last);
        //TODO-WARN: validation error if trimmed

        return detail::url_parser::url_parse(urls, first, last, base);
    }();
    if (res == validation_errc::ok)
        set_flag(VALID_FLAG);
    return res;
}

// Setters

template <class StrT, enable_if_str_arg_t<StrT>>
inline bool url::href(StrT&& str) {
    url u; // parsedURL

    const auto inp = make_str_arg(std::forward<StrT>(str));
    if (u.do_parse(inp.begin(), inp.end(), nullptr) == validation_errc::ok) {
        safe_assign(std::move(u));
        return true;
    }
    return false;
}

template <class StrT, enable_if_str_arg_t<StrT>>
inline bool url::protocol(StrT&& str) {
    if (is_valid()) {
        detail::url_setter urls(*this);

        const auto inp = make_str_arg(std::forward<StrT>(str));
        return detail::url_parser::url_parse(urls, inp.begin(), inp.end(), nullptr, detail::url_parser::scheme_start_state) == validation_errc::ok;
    }
    return false;
}

template <class StrT, enable_if_str_arg_t<StrT>>
inline bool url::username(StrT&& str) {
    if (canHaveUsernamePasswordPort()) {
        detail::url_setter urls(*this);

        const auto inp = make_str_arg(std::forward<StrT>(str));

        std::string& str_username = urls.start_part(url::USERNAME);
        // UTF-8 percent encode it using the userinfo encode set
        detail::append_utf8_percent_encoded(inp.begin(), inp.end(), userinfo_no_encode_set, str_username);
        urls.save_part();
        return true;
    }
    return false;
}

template <class StrT, enable_if_str_arg_t<StrT>>
inline bool url::password(StrT&& str) {
    if (canHaveUsernamePasswordPort()) {
        detail::url_setter urls(*this);

        const auto inp = make_str_arg(std::forward<StrT>(str));

        std::string& str_password = urls.start_part(url::PASSWORD);
        // UTF-8 percent encode it using the userinfo encode set
        detail::append_utf8_percent_encoded(inp.begin(), inp.end(), userinfo_no_encode_set, str_password);
        urls.save_part();
        return true;
    }
    return false;
}

template <class StrT, enable_if_str_arg_t<StrT>>
inline bool url::host(StrT&& str) {
    if (!has_opaque_path() && is_valid()) {
        detail::url_setter urls(*this);

        const auto inp = make_str_arg(std::forward<StrT>(str));
        return detail::url_parser::url_parse(urls, inp.begin(), inp.end(), nullptr, detail::url_parser::host_state) == validation_errc::ok;
    }
    return false;
}

template <class StrT, enable_if_str_arg_t<StrT>>
inline bool url::hostname(StrT&& str) {
    if (!has_opaque_path() && is_valid()) {
        detail::url_setter urls(*this);

        const auto inp = make_str_arg(std::forward<StrT>(str));
        return detail::url_parser::url_parse(urls, inp.begin(), inp.end(), nullptr, detail::url_parser::hostname_state) == validation_errc::ok;
    }
    return false;
}

template <class StrT, enable_if_str_arg_t<StrT>>
inline bool url::port(StrT&& str) {
    if (canHaveUsernamePasswordPort()) {
        detail::url_setter urls(*this);

        const auto inp = make_str_arg(std::forward<StrT>(str));
        const auto* first = inp.begin();
        const auto* last = inp.end();

        if (first == last) {
            urls.clear_part(url::PORT);
            return true;
        }
        return detail::url_parser::url_parse(urls, first, last, nullptr, detail::url_parser::port_state) == validation_errc::ok;
    }
    return false;
}

template <class StrT, enable_if_str_arg_t<StrT>>
inline bool url::pathname(StrT&& str) {
    if (!has_opaque_path() && is_valid()) {
        detail::url_setter urls(*this);

        const auto inp = make_str_arg(std::forward<StrT>(str));
        return detail::url_parser::url_parse(urls, inp.begin(), inp.end(), nullptr, detail::url_parser::path_start_state) == validation_errc::ok;
    }
    return false;
}

template <class StrT, enable_if_str_arg_t<StrT>>
inline bool url::search(StrT&& str) {
    bool res = false;
    if (is_valid()) {
        {
            detail::url_setter urls(*this);

            const auto inp = make_str_arg(std::forward<StrT>(str));
            const auto* first = inp.begin();
            const auto* last = inp.end();

            if (first == last) {
                urls.clear_part(url::QUERY);
                // empty context object's query object's list
                clear_search_params();
                return true;
            }
            if (*first == '?') ++first;
            res = detail::url_parser::url_parse(urls, first, last, nullptr, detail::url_parser::query_state) == validation_errc::ok;
        }
        // set context object's query object's list to the result of parsing input
        parse_search_params();
    }
    return res;
}

template <class StrT, enable_if_str_arg_t<StrT>>
inline bool url::hash(StrT&& str) {
    if (is_valid()) {
        detail::url_setter urls(*this);

        const auto inp = make_str_arg(std::forward<StrT>(str));
        const auto* first = inp.begin();
        const auto* last = inp.end();

        if (first == last) {
            urls.clear_part(url::FRAGMENT);
            return true;
        }
        if (*first == '#') ++first;
        return detail::url_parser::url_parse(urls, first, last, nullptr, detail::url_parser::fragment_state) == validation_errc::ok;
    }
    return false;
}


namespace detail {

// Implements "basic URL parser" https://url.spec.whatwg.org/#concept-basic-url-parser
// without 1 step. It modifies the URL stored in the urls object.
// Returns validation_errc::ok on success, or an error value on parsing failure.
template <typename CharT>
inline validation_errc url_parser::url_parse(url_serializer& urls, const CharT* first, const CharT* last, const url* base, State state_override)
{
    using UCharT = std::make_unsigned_t<CharT>;

    // remove all ASCII tab or newline from URL
    simple_buffer<CharT> buff_no_ws;
    detail::do_remove_whitespace(first, last, buff_no_ws);
    //TODO-WARN: validation error if removed

    if (urls.need_save()) {
        // reserve size (TODO: But what if `base` is used?)
        const auto length = std::distance(first, last);
        urls.reserve(length + 32);
    }

#ifdef UPA_URL_USE_ENCODING
    const char* encoding = "UTF-8";
    // TODO: If encoding override is given, set encoding to the result of getting an output encoding from encoding override.
#endif

    auto pointer = first;
    State state = state_override ? state_override : scheme_start_state;

    // has scheme?
    if (state == scheme_start_state) {
        if (pointer != last && detail::is_first_scheme_char(*pointer)) {
            state = scheme_state; // this appends first char to buffer
        } else if (!state_override) {
            state = no_scheme_state;
        } else {
            // 3. Otherwise, return failure.
            return validation_errc::scheme_invalid_code_point;
        }
    }

    if (state == scheme_state) {
        // Deviation from URL stdandart's [ 2. ... if c is ":", run ... ] to
        // [ 2. ... if c is ":", or EOF and state override is given, run ... ]
        // This lets protocol setter to pass input without adding ':' to the end.
        // Similiar deviation exists in nodejs, see:
        // https://github.com/nodejs/node/pull/11917#pullrequestreview-28061847

        // first scheme char has been checked in the scheme_start_state, so skip it
        const auto end_of_scheme = std::find_if_not(pointer + 1, last, detail::is_scheme_char<CharT>);
        const bool is_scheme = end_of_scheme != last
            ? *end_of_scheme == ':'
            : state_override != not_set_state;

        if (is_scheme) {
            // start of scheme
            std::string& str_scheme = urls.start_scheme();
            // Append scheme chars: it is safe to set the 0x20 bit on all code points -
            // it lowercases ASCII alphas, while other code points allowed in a scheme
            // (0 - 9, +, -, .) already have this bit set.
            for (auto it = pointer; it != end_of_scheme; ++it)
                str_scheme.push_back(static_cast<char>(*it | 0x20));

            if (state_override) {
                const auto* scheme_inf = detail::get_scheme_info(str_scheme);
                const bool is_special_old = urls.is_special_scheme();
                const bool is_special_new = scheme_inf && scheme_inf->is_special;
                if (is_special_old != is_special_new)
                    return validation_errc::ignored;
                // new URL("http://u:p@host:88/).protocol("file:");
                if (scheme_inf && scheme_inf->is_file && (urls.has_credentials() || !urls.is_null(url::PORT)))
                    return validation_errc::ignored;
                // new URL("file:///path).protocol("http:");
                if (urls.is_file_scheme() && urls.is_empty(url::HOST))
                    return validation_errc::ignored;
                // OR ursl.is_empty(url::HOST) && scheme_inf->no_empty_host

                // set url's scheme
                urls.save_scheme();

                // https://github.com/whatwg/url/pull/328
                // optimization: compare ports if scheme has the default port
                if (scheme_inf && scheme_inf->default_port >= 0 &&
                    urls.port_int() == scheme_inf->default_port) {
                    // set url's port to null
                    urls.clear_part(url::PORT);
                }

                // if state override is given, then return
                return validation_errc::ok;
            }
            urls.save_scheme();

            pointer = end_of_scheme + 1; // skip ':'
            if (urls.is_file_scheme()) {
                // TODO-WARN: if remaining does not start with "//", validation error.
                state = file_state;
            } else {
                if (urls.is_special_scheme()) {
                    if (base && urls.get_part_view(url::SCHEME) == base->get_part_view(url::SCHEME)) {
                        assert(base->is_special_scheme()); // and therefore does not have an opaque path
                        state = special_relative_or_authority_state;
                    } else {
                        state = special_authority_slashes_state;
                    }
                } else if (pointer < last && *pointer == '/') {
                    state = path_or_authority_state;
                    ++pointer;
                } else {
                    // set url’s path to the empty string (so path becomes opaque,
                    // see: https://url.spec.whatwg.org/#url-opaque-path)
                    urls.set_has_opaque_path();
                    // To complete the set url's path to the empty string, following functions must be called:
                    //  urls.start_path_string();
                    //  urls.save_path_string();
                    // but the same functions will be called in the opaque_path_state, so skip them here.
                    state = opaque_path_state;
                }
            }
        } else if (!state_override) {
            state = no_scheme_state;
        } else {
            // 4. Otherwise, return failure.
            return validation_errc::scheme_invalid_code_point;
        }
    }

    if (state == no_scheme_state) {
        if (base) {
            if (base->has_opaque_path()) {
                if (pointer < last && *pointer == '#') {
                    urls.set_scheme(*base);
                    urls.append_parts(*base, url::PATH, url::QUERY);
                    //TODO: url's fragment to the empty string
                    state = fragment_state;
                    ++pointer;
                } else {
                    // 1. If ..., or base has an opaque path and c is not U+0023 (#),
                    // missing-scheme-non-relative-URL validation error, return failure.
                    return validation_errc::missing_scheme_non_relative_url;
                }
            } else {
                state = base->is_file_scheme() ? file_state : relative_state;
            }
        } else {
            // 1. If base is null, ..., missing-scheme-non-relative-URL
            // validation error, return failure
            return validation_errc::missing_scheme_non_relative_url;
        }
    }

    if (state == special_relative_or_authority_state) {
        if (last - pointer > 1 && pointer[0] == '/' && pointer[1] == '/') {
            state = special_authority_ignore_slashes_state;
            pointer += 2; // skip "//"
        } else {
            //TODO-WARN: validation error
            state = relative_state;
        }
    }

    if (state == path_or_authority_state) {
        if (pointer < last && pointer[0] == '/') {
            state = authority_state;
            ++pointer; // skip "/"
        } else {
            state = path_state;
        }
    }

    if (state == relative_state) {
        // std::assert(base != nullptr);
        urls.set_scheme(*base);
        if (pointer == last) {
            // EOF code point
            // Set url's username to base's username, url's password to base's password, url's host to base's host,
            // url's port to base's port, url's path to base's path, and url's query to base's query
            urls.append_parts(*base, url::USERNAME, url::QUERY);
            return validation_errc::ok; // EOF
        }
        const CharT ch = *pointer++;
        switch (ch) {
        case '/':
            state = relative_slash_state;
            break;
        case '?':
            // Set url's username to base's username, url's password to base's password, url's host to base's host,
            // url's port to base's port, url's path to base's path, url's query to the empty string, and state to query state.
            urls.append_parts(*base, url::USERNAME, url::PATH);
            state = query_state;    // sets query to the empty string
            break;
        case '#':
            // Set url's username to base's username, url's password to base's password, url's host to base's host,
            // url's port to base's port, url's path to base's path, url's query to base's query, url's fragment to the empty string
            urls.append_parts(*base, url::USERNAME, url::QUERY);
            state = fragment_state; // sets fragment to the empty string
            break;
        case '\\':
            if (urls.is_special_scheme()) {
                //TODO-WARN: validation error
                state = relative_slash_state;
                break;
            }
            [[fallthrough]];
        default:
            // Set url's username to base's username, url's password to base's password, url's host to base's host,
            // url's port to base's port, url's path to base's path, and then remove url's path's last entry, if any
            urls.append_parts(*base, url::USERNAME, url::PATH, &url::get_path_rem_last);
            state = path_state;
            --pointer;
        }
    }

    if (state == relative_slash_state) {
        // EOF ==> 0 ==> default:
        switch (pointer != last ? *pointer : 0) {
        case '/':
            if (urls.is_special_scheme())
                state = special_authority_ignore_slashes_state;
            else
                state = authority_state;
            ++pointer;
            break;
        case '\\':
            if (urls.is_special_scheme()) {
                // TODO-WARN: validation error
                state = special_authority_ignore_slashes_state;
                ++pointer;
                break;
            }
            [[fallthrough]];
        default:
            // set url's username to base's username, url's password to base's password, url's host to base's host,
            // url's port to base's port
            urls.append_parts(*base, url::USERNAME, url::PORT);
            state = path_state;
        }
    }

    if (state == special_authority_slashes_state) {
        if (last - pointer > 1 && pointer[0] == '/' && pointer[1] == '/') {
            state = special_authority_ignore_slashes_state;
            pointer += 2; // skip "//"
        } else {
            //TODO-WARN: validation error
            state = special_authority_ignore_slashes_state;
        }
    }

    if (state == special_authority_ignore_slashes_state) {
        auto it = pointer;
        while (it < last && detail::is_slash(*it)) ++it;
        // if (it != pointer) // TODO-WARN: validation error
        pointer = it;
        state = authority_state;
    }

    // TODO?: credentials serialization do after host parsing, because
    // if host is null, then no credentials serialization
    if (state == authority_state) {
        // TODO: saugoti end_of_authority ir naudoti kituose state
        const auto end_of_authority = urls.is_special_scheme() ?
            std::find_if(pointer, last, detail::is_special_authority_end_char<CharT>) :
            std::find_if(pointer, last, detail::is_authority_end_char<CharT>);

        const auto it_eta = detail::find_last(pointer, end_of_authority, static_cast<CharT>('@'));
        if (it_eta != end_of_authority) {
            if (std::distance(it_eta, end_of_authority) == 1) {
                // 2.1. If atSignSeen is true and buffer is the empty string, host-missing
                // validation error, return failure.
                // Example: "http://u:p@/"
                return validation_errc::host_missing;
            }
            //TODO-WARN: validation error
            if (urls.need_save()) {
                const auto it_colon = std::find(pointer, it_eta, ':');
                // url includes credentials?
                const bool not_empty_password = std::distance(it_colon, it_eta) > 1;
                if (not_empty_password || std::distance(pointer, it_colon) > 0 /*not empty username*/) {
                    // username
                    std::string& str_username = urls.start_part(url::USERNAME);
                    detail::append_utf8_percent_encoded(pointer, it_colon, userinfo_no_encode_set, str_username); // UTF-8 percent encode, @ -> %40
                    urls.save_part();
                    // password
                    if (not_empty_password) {
                        std::string& str_password = urls.start_part(url::PASSWORD);
                        detail::append_utf8_percent_encoded(it_colon + 1, it_eta, userinfo_no_encode_set, str_password); // UTF-8 percent encode, @ -> %40
                        urls.save_part();
                    }
                }
            }
            // after '@'
            pointer = it_eta + 1;
        }
        state = host_state;
    }

    if (state == host_state || state == hostname_state) {
        if (state_override && urls.is_file_scheme()) {
            state = file_host_state;
        } else {
            const auto end_of_authority = urls.is_special_scheme() ?
                std::find_if(pointer, last, detail::is_special_authority_end_char<CharT>) :
                std::find_if(pointer, last, detail::is_authority_end_char<CharT>);

            bool in_square_brackets = false; // [] flag
            bool is_port = false;
            auto it_host_end = pointer;
            for (; it_host_end < end_of_authority; ++it_host_end) {
                const CharT ch = *it_host_end;
                if (ch == ':') {
                    if (!in_square_brackets) {
                        is_port = true;
                        break;
                    }
                } else if (ch == '[') {
                    in_square_brackets = true;
                } else if (ch == ']') {
                    in_square_brackets = false;
                }
            }

            // if buffer is the empty string
            if (pointer == it_host_end) {
                // make sure that if port is present or scheme is special, host is non-empty
                if (is_port || urls.is_special_scheme()) {
                    // host-missing validation error, return failure
                    return validation_errc::host_missing;
                }
                // 3.2. if state override is given, buffer is the empty string, and either
                // url includes credentials or url’s port is non-null, return.
                if (state_override && (urls.has_credentials() || !urls.is_null(url::PORT))) {
                    return validation_errc::ignored; // can not make host empty
                }
            }

            // 2.2. If state override is given and state override is hostname state, then return
            if (is_port && state_override == hostname_state)
                return validation_errc::ignored; // host with port not accepted

            // parse and set host:
            const auto res = parse_host(urls, pointer, it_host_end);
            // 2.4, 3.4. If host is failure, then return failure.
            if (res != validation_errc::ok)
                return res;

            if (is_port) {
                pointer = it_host_end + 1; // skip ':'
                state = port_state;
            } else {
                pointer = it_host_end;
                state = path_start_state;
                if (state_override)
                    return validation_errc::ok;
            }
        }
    }

    if (state == port_state) {
        const auto end_of_digits = std::find_if_not(pointer, last, detail::is_ascii_digit<CharT>);

        const bool is_end_of_authority =
            end_of_digits == last || // EOF
            detail::is_authority_end_char(end_of_digits[0]) ||
            (end_of_digits[0] == '\\' && urls.is_special_scheme());

        if (is_end_of_authority || state_override) {
            if (pointer < end_of_digits) {
                // url string contains port
                // skip the leading zeros except the last
                pointer = std::find_if(pointer, end_of_digits - 1, [](CharT c) { return c != '0'; });
                // check port <= 65535 (0xFFFF)
                if (std::distance(pointer, end_of_digits) > 5)
                    return validation_errc::port_out_of_range;
                // port length <= 5
                int port = 0;
                for (auto it = pointer; it < end_of_digits; ++it)
                    port = port * 10 + (*it - '0');
                // 2.1.2. If port is greater than 2^16 − 1, port-out-of-range
                // validation error, return failure
                if (port > 0xFFFF)
                    return validation_errc::port_out_of_range;
                if (urls.need_save()) {
                    // set port if not default
                    if (urls.scheme_inf() == nullptr || urls.scheme_inf()->default_port != port) {
                        util::append(urls.start_part(url::PORT), str_arg<CharT>{ pointer, end_of_digits });
                        urls.save_part();
                        urls.set_flag(url::PORT_FLAG);
                    } else {
                        // (2-1-3) Set url's port to null
                        urls.clear_part(url::PORT);
                    }
                }
                // 2.2. If state override is given, then return
                if (state_override)
                    return validation_errc::ok;
            } else if (state_override)
                return validation_errc::ignored;
            state = path_start_state;
            pointer = end_of_digits;
        } else {
            // 3. Otherwise, port-invalid validation error, return failure (contains non-digit)
            return validation_errc::port_invalid;
        }
    }

    if (state == file_state) {
        if (!urls.is_file_scheme())
            urls.set_scheme(string_view{ "file", 4 });
        // ensure file URL's host is not null
        urls.set_empty_host();
        // EOF ==> 0 ==> default:
        switch (pointer != last ? *pointer : 0) {
        case '\\':
            // TODO-WARN: validation error
        case '/':
            state = file_slash_state;
            ++pointer;
            break;

        default:
            if (base && base->is_file_scheme()) {
                if (pointer == last) {
                    // EOF code point
                    // Set url's host to base's host, url's path to base's path, and url's query to base's query
                    urls.append_parts(*base, url::HOST, url::QUERY);
                    return validation_errc::ok; // EOF
                }
                switch (*pointer) {
                case '?':
                    // Set url's host to base's host, url's path to base's path, url's query to the empty string
                    urls.append_parts(*base, url::HOST, url::PATH);
                    state = query_state; // sets query to the empty string
                    ++pointer;
                    break;
                case '#':
                    // Set url's host to base's host, url's path to base's path, url's query to base's query, url's fragment to the empty string
                    urls.append_parts(*base, url::HOST, url::QUERY);
                    state = fragment_state; // sets fragment to the empty string
                    ++pointer;
                    break;
                default:
                    if (!detail::starts_with_windows_drive(pointer, last)) {
                        // set url's host to base's host, url's path to base's path, and then shorten url's path
                        urls.append_parts(*base, url::HOST, url::PATH, &url::get_shorten_path);
                        // Note: This is a (platform-independent) Windows drive letter quirk.
                    } else {
                        // TODO-WARN: validation error
                        // set url's host to base's host
                        urls.append_parts(*base, url::HOST, url::HOST);
                    }
                    state = path_state;
                }
            } else {
                state = path_state;
            }
        }
    }

    if (state == file_slash_state) {
        // EOF ==> 0 ==> default:
        switch (pointer != last ? *pointer : 0) {
        case '\\':
            // TODO-WARN: validation error
        case '/':
            state = file_host_state;
            ++pointer;
            break;

        default:
            if (base && base->is_file_scheme() && urls.need_save()) {
                // It is important to first set host, then path, otherwise serializer
                // will fail.

                // set url's host to base's host
                urls.append_parts(*base, url::HOST, url::HOST);
                // path
                if (!detail::starts_with_windows_drive(pointer, last)) {
                    const string_view base_path = base->get_path_first_string(2);
                    // if base's path[0] is a normalized Windows drive letter
                    if (base_path.length() == 2 &&
                        detail::is_normalized_windows_drive(base_path[0], base_path[1])) {
                        // append base's path[0] to url's path
                        std::string& str_path = urls.start_path_segment();
                        str_path.append(base_path.data(), 2); // "C:"
                        urls.save_path_segment();
                        // Note: This is a (platform - independent) Windows drive letter quirk.
                    }
                }
            }
            state = path_state;
        }
    }

    if (state == file_host_state) {
        const auto end_of_authority = std::find_if(pointer, last, detail::is_special_authority_end_char<CharT>);

        if (pointer == end_of_authority) {
            // buffer is the empty string
            // set empty host
            urls.set_empty_host();
            // if state override is given, then return
            if (state_override)
                return validation_errc::ok;
            state = path_start_state;
        } else if (!state_override && end_of_authority - pointer == 2 &&
            detail::is_windows_drive(pointer[0], pointer[1])) {
            // buffer is a Windows drive letter
            // TODO-WARN: validation error
            state = path_state;
            // Note: This is a (platform - independent) Windows drive letter quirk.
            // buffer is not reset here and instead used in the path state.
            // TODO: buffer is not reset here and instead used in the path state
        } else {
            // parse and set host:
            const auto res = parse_host(urls, pointer, end_of_authority);
            if (res != validation_errc::ok || !urls.need_save())
                return res; // TODO-ERR: failure
            // if host is "localhost", then set host to the empty string
            if (urls.get_part_view(url::HOST) == string_view{ "localhost", 9 }) {
                // set empty host
                urls.empty_host();
            }
            // if state override is given, then return
            if (state_override)
                return validation_errc::ok;
            pointer = end_of_authority;
            state = path_start_state;
        }
    }

    if (!urls.need_save())
        return validation_errc::ok;

    if (state == path_start_state) {
        if (urls.is_special_scheme()) {
            if (pointer != last) {
                switch (*pointer) {
                case '\\':
                    // TODO-WARN: validation error
                case '/':
                    ++pointer;
                }
            }
            if (pointer == last) {
                // Optimization:
                // "ws://h", "ws://h\" and "ws://h/" parses to "ws://h/"
                // See: https://github.com/whatwg/url/pull/847
                urls.append_empty_path_segment();
                urls.commit_path();
                return validation_errc::ok;
            }
            state = path_state;
        } else if (pointer != last) {
            if (!state_override) {
                switch (pointer[0]) {
                case '?':
                    // TODO: set url's query to the empty string
                    state = query_state;
                    ++pointer;
                    break;
                case '#':
                    // TODO: set url's fragment to the empty string
                    state = fragment_state;
                    ++pointer;
                    break;
                case '/':
                    ++pointer;
                    [[fallthrough]];
                default:
                    state = path_state;
                    break;
                }
            } else {
                if (pointer[0] == '/') ++pointer;
                state = path_state;
            }
        } else {
            // EOF
            if (state_override && urls.is_null(url::HOST))
                urls.append_empty_path_segment();
            // otherwise path is empty
            urls.commit_path();
            return validation_errc::ok;
        }
    }

    if (state == path_state) {
        const auto end_of_path = state_override ? last :
            std::find_if(pointer, last, [](CharT c) { return c == '?' || c == '#'; });

        parse_path(urls, pointer, end_of_path);
        pointer = end_of_path;

        // the end of path parse
        urls.commit_path();

        if (pointer == last)
            return validation_errc::ok; // EOF

        const CharT ch = *pointer++;
        if (ch == '?') {
            // TODO: set url's query to the empty string
            state = query_state;
        } else {
            // ch == '#'
            // TODO: set url's fragment to the empty string
            state = fragment_state;
        }
    }

    if (state == opaque_path_state) {
        const auto end_of_path =
            std::find_if(pointer, last, [](CharT c) { return c == '?' || c == '#'; });

        // UTF-8 percent encode using the C0 control percent-encode set,
        // and append the result to url's path string
        std::string& str_path = urls.start_path_string();
        do_opaque_path(pointer, end_of_path, str_path);
        urls.save_path_string();
        pointer = end_of_path;

        if (pointer == last)
            return validation_errc::ok; // EOF

        const CharT ch = *pointer++;
        if (ch == '?') {
            // TODO: set url's query to the empty string
            state = query_state;
        } else {
            // ch == '#'
            // TODO: set url's fragment to the empty string
            state = fragment_state;
        }
    }

    if (state == query_state) {
        const auto end_of_query = state_override ? last : std::find(pointer, last, '#');

        // TODO-WARN:
        //for (auto it = pointer; it < end_of_query; ++it) {
        //  UCharT c = static_cast<UCharT>(*it);
        //  // 1. If c is not a URL code point and not "%", validation error.
        //  // 2. If c is "%" and remaining does not start with two ASCII hex digits, validation error.
        //}

#ifdef UPA_URL_USE_ENCODING
        // scheme_inf_ == nullptr, if unknown scheme
        if (!urls.scheme_inf() || !urls.scheme_inf()->is_special || urls.scheme_inf()->is_ws)
            encoding = "UTF-8";
#endif

        // Let query_cpset be the special-query percent-encode set if url is special;
        // otherwise the query percent-encode set.
        const auto& query_cpset = urls.is_special_scheme()
            ? special_query_no_encode_set
            : query_no_encode_set;

        // Percent-encode after encoding, with encoding, buffer, and query_cpset, and append
        // the result to url’s query.
        // TODO: now supports UTF-8 encoding only, maybe later add other encodings
        std::string& str_query = urls.start_part(url::QUERY);
        // detail::append_utf8_percent_encoded(pointer, end_of_query, query_cpset, str_query);
        while (pointer != end_of_query) {
            // UTF-8 percent encode c using the fragment percent-encode set
            // and ignore '\0'
            const auto uch = static_cast<UCharT>(*pointer);
            if (uch >= 0x80) {
                // invalid utf-8/16/32 sequences will be replaced with kUnicodeReplacementCharacter
                detail::append_utf8_percent_encoded_char(pointer, end_of_query, str_query);
            } else {
                // Just append the 7-bit character, possibly percent encoding it
                const auto uc = static_cast<unsigned char>(uch);
                if (!detail::is_char_in_set(uc, query_cpset))
                    detail::append_percent_encoded_byte(uc, str_query);
                else
                    str_query.push_back(uc);
                ++pointer;
            }
            // TODO-WARN:
            // If c is not a URL code point and not "%", validation error.
            // If c is "%" and remaining does not start with two ASCII hex digits, validation error.
            // Let bytes be the result of encoding c using encoding ...
        }
        urls.save_part();
        urls.set_flag(url::QUERY_FLAG);

        pointer = end_of_query;
        if (pointer == last)
            return validation_errc::ok; // EOF
        // *pointer == '#'
        //TODO: set url's fragment to the empty string
        state = fragment_state;
        ++pointer; // skip '#'
    }

    if (state == fragment_state) {
        // https://url.spec.whatwg.org/#fragment-state
        std::string& str_frag = urls.start_part(url::FRAGMENT);
        while (pointer < last) {
            // UTF-8 percent encode c using the fragment percent-encode set
            const auto uch = static_cast<UCharT>(*pointer);
            if (uch >= 0x80) {
                // invalid utf-8/16/32 sequences will be replaced with kUnicodeReplacementCharacter
                detail::append_utf8_percent_encoded_char(pointer, last, str_frag);
            } else {
                // Just append the 7-bit character, possibly percent encoding it
                const auto uc = static_cast<unsigned char>(uch);
                if (detail::is_char_in_set(uc, fragment_no_encode_set)) {
                    str_frag.push_back(uc);
                } else {
                    // other characters are percent encoded
                    detail::append_percent_encoded_byte(uc, str_frag);
                }
                ++pointer;
            }
            // TODO-WARN:
            // If c is not a URL code point and not "%", validation error.
            // If c is "%" and remaining does not start with two ASCII hex digits, validation error.
        }
        urls.save_part();
        urls.set_flag(url::FRAGMENT_FLAG);
    }

    return validation_errc::ok;
}

// internal functions

template <typename CharT>
inline validation_errc url_parser::parse_host(url_serializer& urls, const CharT* first, const CharT* last) {
    return host_parser::parse_host(first, last, !urls.is_special_scheme(), urls);
}

template <typename CharT>
inline void url_parser::parse_path(url_serializer& urls, const CharT* first, const CharT* last) {
    // path state; includes:
    // 1. [ (/,\) - 1, 2, 3, 4 - [ 1 (if first segment), 2 ] ]
    // 2. [ 1 ... 4 ]
    static constexpr auto escaped_dot = [](const CharT* const pointer) constexpr -> bool {
        // "%2e" or "%2E"
        return pointer[0] == '%' && pointer[1] == '2' && (pointer[2] | 0x20) == 'e';
    };
    static constexpr auto double_dot = [](const CharT* const pointer, const std::size_t len) constexpr -> bool {
        switch (len) {
        case 2: // ".."
            return pointer[0] == '.' && pointer[1] == '.';
        case 4: // ".%2e" or "%2e."
            return (pointer[0] == '.' && escaped_dot(pointer + 1)) ||
                (escaped_dot(pointer) && pointer[3] == '.');
        case 6: // "%2e%2e"
            return escaped_dot(pointer) && escaped_dot(pointer + 3);
        default:
            return false;
        }
    };
    static constexpr auto single_dot = [](const CharT* const pointer, const std::size_t len) constexpr -> bool {
        switch (len) {
        case 1: return pointer[0] == '.';
        case 3: return escaped_dot(pointer); // "%2e"
        default: return false;
        }
    };

    // parse path's segments
    auto pointer = first;
    while (true) {
        const auto end_of_segment = urls.is_special_scheme()
            ? std::find_if(pointer, last, detail::is_slash<CharT>)
            : std::find(pointer, last, '/');

        // end_of_segment >= pointer
        const std::size_t len = end_of_segment - pointer;
        const bool is_last = end_of_segment == last;
        // TODO-WARN: 1. If url is special and c is "\", validation error.

        if (double_dot(pointer, len)) {
            urls.shorten_path();
            if (is_last) urls.append_empty_path_segment();
        } else if (single_dot(pointer, len)) {
            if (is_last) urls.append_empty_path_segment();
        } else {
            if (len == 2 &&
                urls.is_file_scheme() &&
                urls.is_empty_path() &&
                detail::is_windows_drive(pointer[0], pointer[1]))
            {
                // replace the second code point in buffer with ":"
                std::string& str_path = urls.start_path_segment();
                str_path += static_cast<char>(pointer[0]);
                str_path += ':';
                urls.save_path_segment();
                //Note: This is a (platform-independent) Windows drive letter quirk.
            } else {
                std::string& str_path = urls.start_path_segment();
                do_path_segment(pointer, end_of_segment, str_path);
                urls.save_path_segment();
                // end of segment
                pointer = end_of_segment;
            }
        }
        // next segment
        if (is_last) break;
        pointer = end_of_segment + 1; // skip '/' or '\'
    }
}

template <typename CharT>
inline void url_parser::do_path_segment(const CharT* pointer, const CharT* last, std::string& output) {
    using UCharT = std::make_unsigned_t<CharT>;

    // TODO-WARN: 2. [ 1 ... 2 ] validation error.
    while (pointer < last) {
        // UTF-8 percent encode c using the default encode set
        const auto uch = static_cast<UCharT>(*pointer);
        if (uch >= 0x80) {
            // invalid utf-8/16/32 sequences will be replaced with 0xfffd
            detail::append_utf8_percent_encoded_char(pointer, last, output);
        } else {
            // Just append the 7-bit character, possibly percent encoding it
            const auto uc = static_cast<unsigned char>(uch);
            if (!detail::is_char_in_set(uc, path_no_encode_set))
                detail::append_percent_encoded_byte(uc, output);
            else
                output.push_back(uc);
            ++pointer;
        }
    }
}

template <typename CharT>
inline void url_parser::do_opaque_path(const CharT* pointer, const CharT* last, std::string& output) {
    using UCharT = std::make_unsigned_t<CharT>;

    // 3. of "opaque path state"
    // TODO-WARN: 3. [ 1 ... 2 ] validation error.
    //  1. If c is not EOF code point, not a URL code point, and not "%", validation error.
    //  2. If c is "%" and remaining does not start with two ASCII hex digits, validation error.

    if (pointer != last) {
        // If path ends with a space, the space is percent encoded and appended
        // to the output at the end of processing.
        const bool ends_with_space = *(last - 1) == ' ';
        if (ends_with_space)
            --last;
        while (pointer < last) {
            // UTF-8 percent encode c using the C0 control percent-encode set (U+0000 ... U+001F and >U+007E)
            const auto uch = static_cast<UCharT>(*pointer);
            if (uch >= 0x7f) {
                // invalid utf-8/16/32 sequences will be replaced with 0xfffd
                detail::append_utf8_percent_encoded_char(pointer, last, output);
            } else {
                // Just append the 7-bit character, percent encoding C0 control chars
                const auto uc = static_cast<unsigned char>(uch);
                if (uc <= 0x1f)
                    detail::append_percent_encoded_byte(uc, output);
                else
                    output.push_back(uc);
                ++pointer;
            }
        }
        // %20 - percent encoded space
        if (ends_with_space)
            output.append("%20");
    }
}

} // namespace detail


// path util

inline string_view url::get_path_first_string(std::size_t len) const {
    string_view pathv = get_part_view(PATH);
    if (pathv.length() == 0 || has_opaque_path())
        return pathv;
    // skip '/'
    pathv.remove_prefix(1);
    if (pathv.length() == len || (pathv.length() > len && pathv[len] == '/')) {
        return { pathv.data(), len };
    }
    return { pathv.data(), 0 };
}

// path shortening

inline bool url::get_path_rem_last(std::size_t& path_end, std::size_t& path_segment_count) const {
    if (path_segment_count_ > 0) {
        // Remove path's last item
        const char* const first = norm_url_.data() + part_end_[url::PATH-1];
        const char* const last = norm_url_.data() + part_end_[url::PATH];
        const char* it = detail::find_last(first, last, '/');
        if (it == last) it = first; // remove full path if '/' not found
        // shorten
        path_end = it - norm_url_.data();
        path_segment_count = path_segment_count_ - 1;
        return true;
    }
    return false;
}

// https://url.spec.whatwg.org/#shorten-a-urls-path

inline bool url::get_shorten_path(std::size_t& path_end, std::size_t& path_segment_count) const {
    assert(!has_opaque_path());
    if (path_segment_count_ == 0)
        return false;
    if (is_file_scheme() && path_segment_count_ == 1) {
        const string_view path1 = get_path_first_string(2);
        if (path1.length() == 2 &&
            detail::is_normalized_windows_drive(path1[0], path1[1]))
            return false;
    }
    // Remove path's last item
    return get_path_rem_last(path_end, path_segment_count);
}


namespace detail {

// url_serializer class

inline void url_serializer::shorten_path() {
    assert(last_pt_ <= url::PATH);
    if (url_.get_shorten_path(url_.part_end_[url::PATH], url_.path_segment_count_))
        url_.norm_url_.resize(url_.part_end_[url::PATH]);
}

// set scheme

inline std::string& url_serializer::start_scheme() {
    url_.norm_url_.clear(); // clear all
    return url_.norm_url_;
}

inline void url_serializer::save_scheme() {
    set_scheme(url_.norm_url_.length());
    url_.norm_url_.push_back(':');
}

// set url's part

inline void url_serializer::fill_parts_offset(url::PartType t1, url::PartType t2, std::size_t offset) {
    for (int ind = t1; ind < t2; ++ind)
        url_.part_end_[ind] = offset;
}

inline std::string& url_serializer::start_part(url::PartType new_pt) {
    // offsets of empty parts (until new_pt) are also filled
    auto fill_start_pt = static_cast<url::PartType>(static_cast<int>(last_pt_)+1);
    switch (last_pt_) {
    case url::SCHEME:
        // if host is non-null
        if (new_pt <= url::HOST)
            url_.norm_url_.append("//");
        break;
    case url::USERNAME:
        if (new_pt == url::PASSWORD) {
            url_.norm_url_ += ':';
            break;
        } else {
            url_.part_end_[url::PASSWORD] = url_.norm_url_.length();
            fill_start_pt = url::HOST_START; // (url::PASSWORD + 1)
        }
        [[fallthrough]];
    case url::PASSWORD:
        if (new_pt == url::HOST)
            url_.norm_url_ += '@';
        break;
    case url::HOST:
    case url::PORT:
        break;
    case url::PATH:
        if (new_pt == url::PATH) // continue on path
            return url_.norm_url_;
        break;
    default: break;
    }

    fill_parts_offset(fill_start_pt, new_pt, url_.norm_url_.length());

    switch (new_pt) {
    case url::PORT:
        url_.norm_url_ += ':';
        break;
    case url::QUERY:
        url_.norm_url_ += '?';
        break;
    case url::FRAGMENT:
        url_.norm_url_ += '#';
        break;
    default: break;
    }

    assert(last_pt_ < new_pt || (last_pt_ == new_pt && is_empty(last_pt_)));
    // value to url_.part_end_[new_pt] will be assigned in the save_part()
    last_pt_ = new_pt;
    return url_.norm_url_;
}

inline void url_serializer::save_part() {
    url_.part_end_[last_pt_] = url_.norm_url_.length();
}

// The append_empty_path_segment() appends the empty string to url’s path (list);
// it is called from these places:
// 1) path_start_state -> [5.]
// 2) path_state -> [1.2.2. ".." ]
// 3) path_state -> [1.3. "." ]
inline void url_serializer::append_empty_path_segment() {
    start_path_segment();
    save_path_segment();
}

inline std::string& url_serializer::start_path_segment() {
    // appends new segment to path: / seg1 / seg2 / ... / segN
    std::string& str_path = start_part(url::PATH);
    str_path += '/';
    return str_path;
}

inline void url_serializer::save_path_segment() {
    save_part();
    url_.path_segment_count_++;
}

inline void url_serializer::commit_path() {
    // "/." path prefix
    adjust_path_prefix();
}

inline void url_serializer::adjust_path_prefix() {
    // "/." path prefix
    // https://url.spec.whatwg.org/#url-serializing (4.1.)
    string_view new_prefix;
    if (is_null(url::HOST) && url_.path_segment_count_ > 1) {
        const auto pathname = get_part_view(url::PATH);
        if (pathname.length() > 1 && pathname[0] == '/' && pathname[1] == '/')
            new_prefix = { "/.", 2 };
    }
    if (is_empty(url::PATH_PREFIX) != new_prefix.empty())
        replace_part(url::PATH_PREFIX, new_prefix.data(), new_prefix.length());
}

inline std::string& url_serializer::start_path_string() {
    return start_part(url::PATH);
}

inline void url_serializer::save_path_string() {
    assert(url_.path_segment_count_ == 0);
    save_part();
}


inline void url_serializer::set_empty_host() {
    start_part(url::HOST);
    save_part();
    set_host_type(HostType::Empty);
}

inline void url_serializer::empty_host() {
    // It is called right after a host parsing
    assert(last_pt_ == url::HOST);

    const std::size_t host_end = url_.part_end_[url::HOST_START];
    url_.part_end_[url::HOST] = host_end;
    url_.norm_url_.resize(host_end);

    url_.set_host_type(HostType::Empty);
}

// host_output overrides

inline std::string& url_serializer::hostStart() {
    return start_part(url::HOST);
}

inline void url_serializer::hostDone(HostType ht) {
    save_part();
    set_host_type(ht);

    // non-null host
    if (!is_empty(url::PATH_PREFIX)) {
        // remove '/.' path prefix
        replace_part(url::PATH_PREFIX, nullptr, 0);
    }
}

// append parts from other url

inline void url_serializer::append_parts(const url& src, url::PartType t1, url::PartType t2, PathOpFn pathOpFn) {
    // See URL serializing
    // https://url.spec.whatwg.org/#concept-url-serializer
    const url::PartType ifirst = [&]() {
        if (t1 <= url::HOST) {
            // authority, host
            if (!src.is_null(url::HOST)) {
                if (t1 == url::USERNAME && src.has_credentials())
                    return url::USERNAME;
                return url::HOST;
            }
            return url::PATH_PREFIX;
        }
        // t1 == PATH
        return t1;
    }();

    if (!need_save()) return;

    // copy flags; they can be used when copying / serializing url parts below
    unsigned mask = 0;
    for (int ind = t1; ind <= t2; ++ind) {
        mask |= url::kPartFlagMask[ind];
    }
    url_.flags_ = (url_.flags_ & ~mask) | (src.flags_ & mask);

    // copy parts & str
    if (ifirst <= t2) {
        int ilast = t2;
        for (; ilast >= ifirst; --ilast) {
            if (src.part_end_[ilast])
                break;
        }
        if (ifirst <= ilast) {
            // prepare buffer to append data
            // IMPORTANT: do before any url_ members modifications!
            std::string& norm_url = start_part(ifirst);

            // last part and url_.path_segment_count_
            std::size_t lastp_end = src.part_end_[ilast];
            if (pathOpFn && ilast == url::PATH) {
                std::size_t segment_count = src.path_segment_count_;
                // https://isocpp.org/wiki/faq/pointers-to-members
                // todo: use std::invoke (c++17)
                (src.*pathOpFn)(lastp_end, segment_count);
                url_.path_segment_count_ = segment_count;
            } else if (ifirst <= url::PATH && url::PATH <= ilast) {
                url_.path_segment_count_ = src.path_segment_count_;
            }
            // src
            const std::size_t offset = src.part_end_[ifirst - 1] + detail::kPartStart[ifirst];
            const char* const first = src.norm_url_.data() + offset;
            const char* const last = src.norm_url_.data() + lastp_end;
            // dest
            const auto delta = util::checked_diff<std::ptrdiff_t>(norm_url.length(), offset);
            // copy normalized url string from src
            norm_url.append(first, last);
            // adjust url_.part_end_
            for (int ind = ifirst; ind < ilast; ++ind) {
                // if (src.part_end_[ind]) // it is known, that src.part_end_[ind] has value, so check isn't needed
                url_.part_end_[ind] = src.part_end_[ind] + delta;
            }
            // ilast part from lastp
            url_.part_end_[ilast] = lastp_end + delta;
            last_pt_ = static_cast<url::PartType>(ilast);
        }
    }
}

// replace part in url

inline std::size_t url_serializer::get_part_pos(const url::PartType pt) const {
    return pt > url::SCHEME ? url_.part_end_[pt - 1] : 0;
}

inline std::size_t url_serializer::get_part_len(const url::PartType pt) const {
    return url_.part_end_[pt] - url_.part_end_[pt - 1];
}

inline void url_serializer::replace_part(const url::PartType new_pt, const char* str, const std::size_t len) {
    replace_part(new_pt, str, len, new_pt, 0);
}

inline void url_serializer::replace_part(const url::PartType last_pt, const char* str, const std::size_t len,
    const url::PartType first_pt, const std::size_t len0)
{
    const std::size_t b = get_part_pos(first_pt);
    const std::size_t l = url_.part_end_[last_pt] - b;
    url_.norm_url_.replace(b, l, str, len);
    std::fill(std::begin(url_.part_end_) + first_pt, std::begin(url_.part_end_) + last_pt, b + len0);
    // adjust positions
    const auto diff = util::checked_diff<std::ptrdiff_t>(len, l);
    if (diff) {
        for (auto it = std::begin(url_.part_end_) + last_pt; it != std::end(url_.part_end_); ++it) {
            if (*it == 0) break;
            // perform arithmetics using signed type ptrdiff_t, because diff can be negative
            *it = static_cast<std::ptrdiff_t>(*it) + diff;
        }
    }
}


// url_setter class

// inline url_setter::~url_setter() {}

//???
inline void url_setter::reserve(std::size_t new_cap) {
    strp_.reserve(new_cap);
}

// set scheme

inline std::string& url_setter::start_scheme() {
    return strp_;
}

inline void url_setter::save_scheme() {
    replace_part(url::SCHEME, strp_.data(), strp_.length());
    set_scheme(strp_.length());
}

// set/clear/empty url's part

inline std::string& url_setter::start_part(url::PartType new_pt) {
    assert(new_pt > url::SCHEME);
    curr_pt_ = new_pt;
    if (url_.part_end_[new_pt]) {
        // is there any part after new_pt?
        if (new_pt < url::FRAGMENT && url_.part_end_[new_pt] < url_.norm_url_.length()) {
            use_strp_ = true;
            switch (new_pt) {
            case url::HOST:
                if (get_part_len(url::SCHEME_SEP) < 3)
                    strp_ = "://";
                else
                    strp_.clear();
                break;
            case url::PASSWORD:
            case url::PORT:
                strp_ = ':';
                break;
            case url::QUERY:
                strp_ = '?';
                break;
            default:
                strp_.clear();
                break;
            }
            return strp_;
        }
        // Remove new_pt part
        last_pt_ = static_cast<url::PartType>(static_cast<int>(new_pt) - 1);
        url_.norm_url_.resize(url_.part_end_[last_pt_]);
        url_.part_end_[new_pt] = 0;
        // if there are empty parts after new_pt, then set their end positions to zero
        for (auto pt = static_cast<int>(new_pt) + 1; pt <= url::FRAGMENT && url_.part_end_[pt]; ++pt)
            url_.part_end_[pt] = 0;
    } else {
        last_pt_ = find_last_part(new_pt);
    }

    use_strp_ = false;
    return url_serializer::start_part(new_pt);
}

inline void url_setter::save_part() {
    if (use_strp_) {
        if (curr_pt_ == url::HOST) {
            if (get_part_len(url::SCHEME_SEP) < 3)
                // SCHEME_SEP, USERNAME, PASSWORD, HOST_START; HOST
                replace_part(url::HOST, strp_.data(), strp_.length(), url::SCHEME_SEP, 3);
            else
                replace_part(url::HOST, strp_.data(), strp_.length());
        } else {
            const bool empty_val = strp_.length() <= detail::kPartStart[curr_pt_];
            switch (curr_pt_) {
            case url::USERNAME:
            case url::PASSWORD:
                if (!empty_val && !has_credentials()) {
                    strp_ += '@';
                    // USERNAME, PASSWORD; HOST_START
                    replace_part(url::HOST_START, strp_.data(), strp_.length(), curr_pt_, strp_.length() - 1);
                    break;
                } else if (empty_val && is_empty(curr_pt_ == url::USERNAME ? url::PASSWORD : url::USERNAME)) {
                    // both username and password will be empty, so also drop '@'
                    replace_part(url::HOST_START, "", 0, curr_pt_, 0);
                    break;
                }
                [[fallthrough]];
            default:
                if ((curr_pt_ == url::PASSWORD || curr_pt_ == url::PORT) && empty_val)
                    strp_.clear(); // drop ':'
                replace_part(curr_pt_, strp_.data(), strp_.length());
                break;
            }
        }
        // cleanup
        strp_.clear();
    } else {
        url_serializer::save_part();
    }
}

inline void url_setter::clear_part(const url::PartType pt) {
    if (url_.part_end_[pt]) {
        replace_part(pt, "", 0);
        url_.flags_ &= ~(1u << pt); // set to null
    }
}

inline void url_setter::empty_part(const url::PartType pt) {
    if (url_.part_end_[pt]) {
        replace_part(pt, "", 0);
    }
}

inline void url_setter::empty_host() {
    empty_part(url::HOST);
    url_.set_host_type(HostType::Empty);
}

inline std::string& url_setter::start_path_segment() {
    //curr_pt_ = url::PATH; // not used
    strp_ += '/';
    return strp_;
}

inline void url_setter::save_path_segment() {
    path_seg_end_.push_back(strp_.length());
}

inline void url_setter::commit_path() {
    // fill part_end_ until url::PATH if not filled
    for (int ind = url::PATH; ind > 0; --ind) {
        if (url_.part_end_[ind]) break;
        url_.part_end_[ind] = url_.norm_url_.length();
    }
    // replace path part
    replace_part(url::PATH, strp_.data(), strp_.length());
    url_.path_segment_count_ = path_seg_end_.size();

    // "/." path prefix
    adjust_path_prefix();
}

// https://url.spec.whatwg.org/#shorten-a-urls-path

inline void url_setter::shorten_path() {
    if (path_seg_end_.size() == 1) {
        if (is_file_scheme() && strp_.length() == 3 &&
            detail::is_normalized_windows_drive(strp_[1], strp_[2]))
            return;
        path_seg_end_.pop_back();
        strp_.clear();
    } else if (path_seg_end_.size() >= 2) {
        path_seg_end_.pop_back();
        strp_.resize(path_seg_end_.back());
    }
}

inline bool url_setter::is_empty_path() const {
    assert(!url_.has_opaque_path());
    // path_seg_end_ has meaning only if path is a list (path isn't opaque)
    return path_seg_end_.empty();
}

inline url::PartType url_setter::find_last_part(url::PartType pt) const {
    for (int ind = pt; ind > 0; --ind)
        if (url_.part_end_[ind])
            return static_cast<url::PartType>(ind);
    return url::SCHEME;
}

/// @brief Check UNC path
///
/// Input - path string with the first two backslashes skipped
///
/// @param[in] first start of path string
/// @param[in] last end of path string
/// @return pointer to the end of the UNC share name, or `nullptr`
///   if input is not valid UNC
template <typename CharT>
inline const CharT* is_unc_path(const CharT* first, const CharT* last)
{
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsc/149a3039-98ce-491a-9268-2f5ddef08192
    std::size_t path_components_count = 0;
    const CharT* end_of_share_name = nullptr;
    const auto* start = first;
    while (start != last) {
        const auto* pcend = std::find_if(start, last, detail::is_windows_slash<CharT>);
        // path components MUST be at least one character in length
        if (start == pcend)
            return nullptr;
        // path components MUST NOT contain a backslash (\) or a null
        if (std::find(start, pcend, '\0') != pcend)
            return nullptr;

        ++path_components_count;

        switch (path_components_count) {
        case 1:
            // Check the first UNC path component (hostname)
            switch (pcend - start) {
            case 1:
                // Do not allow "?" and "." hostnames, because "\\?\" means Win32 file
                // namespace and "\\.\" means Win32 device namespace
                if (start[0] == '?' || start[0] == '.')
                    return nullptr;
                break;
            case 2:
                // Do not allow Windows drive letter, because it is not a valid hostname
                if (detail::is_windows_drive(start[0], start[1]))
                    return nullptr;
                break;
            }
            // Accept UNC path with hostname, even if it does not contain share-name
            end_of_share_name = pcend;
            break;
        case 2:
            // Check the second UNC path component (share name).
            // Do not allow "." and ".." as share names, because they have
            // a special meaning and are removed by the URL parser.
            switch (pcend - start) {
            case 1:
                if (start[0] == '.')
                    return nullptr;
                break;
            case 2:
                if (start[0] == '.' && start[1] == '.')
                    return nullptr;
                break;
            }
            // A valid UNC path MUST contain two or more path components
            end_of_share_name = pcend;
            break;
        default:;
        }
        if (pcend == last) break;
        start = pcend + 1; // skip '\'
    }
    return end_of_share_name;
}

/// @brief Check path contains ".." segment
///
/// @param[in] first start of path string
/// @param[in] last end of path string
/// @param[in] is_slash function to check char is slash (or backslash)
/// @return true if path contains ".." segment
template <typename CharT, typename IsSlash>
constexpr bool has_dot_dot_segment(const CharT* first, const CharT* last, IsSlash is_slash) {
    if (last - first >= 2) {
        const auto* ptr = first;
        const auto* end = last - 1;
        while ((ptr = std::char_traits<CharT>::find(ptr, end - ptr, '.')) != nullptr) {
            if (ptr[1] == '.' &&
                (ptr == first || is_slash(*(ptr - 1))) &&
                (last - ptr == 2 || is_slash(ptr[2])))
                return true;
            // skip '.' and following char
            ptr += 2;
            if (ptr >= end)
                break;
        }
    }
    return false;
}

} // namespace detail


// URL utilities (non-member functions)

/// @brief URL equivalence
///
/// Determines if @a lhs equals to @a rhs, optionally with an @a exclude_fragments flag.
/// More info: https://url.spec.whatwg.org/#concept-url-equals
///
/// @param[in] lhs,rhs URLs to compare
/// @param[in] exclude_fragments exclude fragments when comparing
[[nodiscard]] inline bool equals(const url& lhs, const url& rhs, bool exclude_fragments = false) {
    return lhs.serialize(exclude_fragments) == rhs.serialize(exclude_fragments);
}

/// @brief Lexicographically compares two URL's
[[nodiscard]] inline bool operator==(const url& lhs, const url& rhs) noexcept {
    return lhs.norm_url_ == rhs.norm_url_;
}

/// @brief Performs stream output on URL
///
/// Outputs URL serialized to ASCII string
///
/// @param[in] os the output stream to write to
/// @param[in] url the @ref url object to serialize and output
/// @return a reference to the output stream
/// @see https://url.spec.whatwg.org/#url-serializing
inline std::ostream& operator<<(std::ostream& os, const url& url) {
    return os << url.norm_url_;
}

/// @brief Swaps the contents of two URLs
///
/// Swaps the contents of the @a lhs and @a rhs URLs
///
/// @param[in,out] lhs
/// @param[in,out] rhs
inline void swap(url& lhs, url& rhs) noexcept {
    lhs.swap(rhs);
}

/// @brief File path format
enum class file_path_format {
    posix = 1,  ///< POSIX file path format
    windows,    ///< Windows file path format
#ifdef _WIN32
    native = windows ///< The file path format corresponds to the OS on which the code was compiled
#else
    native = posix   ///< The file path format corresponds to the OS on which the code was compiled
#endif
};

/// @brief Make URL from OS file path
///
/// The file path must be absolute and must not contain any dot-dot (..)
/// segments.
///
/// There is a difference in how paths with dot-dot segments are normalized in the OS and in the
/// WHATWG URL standard. For example, in POSIX the path `/a//../b` is normalized to `/b`, while
/// the URL parser normalizes this path to `/a/b`. This library does not implement OS specific path
/// normalization, which is the main reason why it does not accept paths with dot-dot segments.
/// Therefore, if there are such segments in the path, it should be normalized by OS tools before
/// being submitted to this function. Normalization can be done using the POSIX `realpath`
/// function, the Windows `GetFullPathName` function, or, if you are using C++17, the
/// `std::filesystem::canonical` function.
///
/// Throws url_error exception on error.
///
/// @param[in] str absolute file path string
/// @param[in] format file path format, one of upa::file_path_format::posix,
///   upa::file_path_format::windows, upa::file_path_format::native
/// @return file URL
/// @see [Pathname (POSIX)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap03.html#tag_03_254),
///   [realpath](https://pubs.opengroup.org/onlinepubs/9799919799/functions/realpath.html),
///   [GetFullPathName](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfullpathnamew),
///   [std::filesystem::canonical](https://en.cppreference.com/w/cpp/filesystem/canonical)
template <class StrT, enable_if_str_arg_t<StrT> = 0>
[[nodiscard]] inline url url_from_file_path(StrT&& str, file_path_format format = file_path_format::native) {
    using CharT = str_arg_char_t<StrT>;
    const auto inp = make_str_arg(std::forward<StrT>(str));
    const auto* first = inp.begin();
    const auto* last = inp.end();

    if (first == last) {
        throw url_error(validation_errc::file_empty_path, "Empty file path");
    }

    const auto* pointer = first;
    const auto* start_of_check = first;
    const code_point_set* no_encode_set = nullptr;

    std::string str_url("file://");

    if (format == file_path_format::posix) {
        if (!detail::is_posix_slash(*first))
            throw url_error(validation_errc::file_unsupported_path, "Non-absolute POSIX path");
        if (detail::has_dot_dot_segment(start_of_check, last, detail::is_posix_slash<CharT>))
            throw url_error(validation_errc::file_unsupported_path, "Unsupported file path");
        // Absolute POSIX path
        no_encode_set = &posix_path_no_encode_set;
    } else {
        // Windows path?
        bool is_unc = false;

        // https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file
        // https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats
        // https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation
        if (last - pointer >= 2 &&
            detail::is_windows_slash(pointer[0]) &&
            detail::is_windows_slash(pointer[1])) {
            pointer += 2; // skip '\\'

            // It is Win32 namespace path or UNC path?
            if (last - pointer >= 2 &&
                (pointer[0] == '?' || pointer[0] == '.') &&
                detail::is_windows_slash(pointer[1])) {
                // Win32 File ("\\?\") or Device ("\\.\") namespace path
                pointer += 2; // skip "?\" or ".\"
                if (last - pointer >= 4 &&
                    (pointer[0] | 0x20) == 'u' &&
                    (pointer[1] | 0x20) == 'n' &&
                    (pointer[2] | 0x20) == 'c' &&
                    detail::is_windows_slash(pointer[3])) {
                    pointer += 4; // skip "UNC\"
                    is_unc = true;
                }
            } else {
                // UNC path
                is_unc = true;
            }
        }
        start_of_check = is_unc
            ? detail::is_unc_path(pointer, last)
            : detail::is_windows_os_drive_absolute_path(pointer, last);
        if (start_of_check == nullptr ||
            detail::has_dot_dot_segment(start_of_check, last, detail::is_windows_slash<CharT>))
            throw url_error(validation_errc::file_unsupported_path, "Unsupported file path");
        no_encode_set = &raw_path_no_encode_set;
        if (!is_unc) str_url.push_back('/'); // start path
    }

    // Check for null characters
    if (util::contains_null(start_of_check, last))
        throw url_error(validation_errc::null_character, "Path contains null character");

    // make URL
    detail::append_utf8_percent_encoded(pointer, last, *no_encode_set, str_url);
    return url(str_url);
}

/// @brief Make URL from OS file path
///
/// Throws url_error exception on error.
///
/// @param[in] path absolute file path
/// @return file URL
[[nodiscard]] inline url url_from_file_path(const std::filesystem::path& path) {
#ifdef _WIN32
    // On Windows, the native path is encoded in UTF-16
    return url_from_file_path(path.native());
#else
    // Ensure string input is UTF-8 encoded
    return url_from_file_path(path.u8string());
#endif
}

/// @brief Get OS path from file URL
///
/// Throws url_error exception on error.
///
/// @param[in] file_url file URL
/// @param[in] format file path format, one of upa::file_path_format::posix,
///   upa::file_path_format::windows, upa::file_path_format::native
/// @return OS path encoded in UTF-8
[[nodiscard]] inline std::string path_from_file_url(const url& file_url, file_path_format format = file_path_format::native) {
    if (!file_url.is_file_scheme())
        throw url_error(validation_errc::not_file_url, "Not a file URL");

    // source
    const auto hostname = file_url.hostname();
    const bool is_host = !hostname.empty();

    // target
    std::string path;

    if (format == file_path_format::posix) {
        if (is_host)
            throw url_error(validation_errc::file_url_cannot_have_host, "POSIX path cannot have host");
        // percent decode pathname
        detail::append_percent_decoded(file_url.pathname(), path);
    } else {
        // format == file_path_format::windows
        if (is_host) {
            // UNC path cannot have "." hostname, because "\\.\" means Win32 device namespace
            if (hostname == ".")
                throw url_error(validation_errc::file_url_unsupported_host, "UNC path cannot have \".\" hostname");
            // UNC path
            path.append("\\\\");
            if (file_url.host_type() == HostType::IPv6) {
                // Form an IPV6 address host-name by substituting hyphens for the colons and appending ".ipv6-literal.net"
                // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/62e862f4-2a51-452e-8eeb-dc4ff5ee33cc
                std::replace_copy(std::next(hostname.begin()), std::prev(hostname.end()),
                    std::back_inserter(path), ':', '-');
                path.append(".ipv6-literal.net");
            } else {
                path.append(hostname);
            }
        }

        // percent decode pathname and normalize slashes
        const auto start = static_cast<std::ptrdiff_t>(path.length());
        detail::append_percent_decoded(file_url.pathname(), path);
        std::replace(std::next(path.begin(), start), path.end(), '/', '\\');

        if (is_host) {
            if (!detail::is_unc_path(path.data() + 2, path.data() + path.length()))
                throw url_error(validation_errc::file_url_invalid_unc, "Invalid UNC path");
        } else {
            if (detail::pathname_has_windows_os_drive(path)) {
                path.erase(0, 1); // remove leading '\\'
                if (path.length() == 2)
                    path.push_back('\\'); // "C:" -> "C:\"
            } else {
                // https://datatracker.ietf.org/doc/html/rfc8089#appendix-E.3.2
                // Maybe a UNC path. Possible variants:
                // 1) file://///host/path -> \\\host\path
                // 2) file:////host/path -> \\host\path
                const auto count_leading_slashes = std::find_if(
                    path.data(),
                    path.data() + std::min(static_cast<std::size_t>(4), path.length()),
                    [](char c) { return c != '\\'; }) - path.data();
                if (count_leading_slashes == 3)
                    path.erase(0, 1); // remove leading '\\'
                else if (count_leading_slashes != 2)
                    throw url_error(validation_errc::file_url_not_windows_path, "Not a Windows path");
                if (!detail::is_unc_path(path.data() + 2, path.data() + path.length()))
                    throw url_error(validation_errc::file_url_invalid_unc, "Invalid UNC path");
            }
        }
    }

    // Check for null characters
    if (util::contains_null(path.begin(), path.end()))
        throw url_error(validation_errc::null_character, "Path contains null character");

    return path;
}

/// @brief Get OS path as std::filesystem::path from file URL
///
/// Throws url_error exception on error.
///
/// @param[in] file_url file URL
/// @return OS path as std::filesystem::path
[[nodiscard]] inline std::filesystem::path fs_path_from_file_url(const url& file_url) {
#ifdef UPA_CPP_20
    const std::string path_str = path_from_file_url(file_url);
    // the path_str is encoded in UTF-8
    const auto* first = reinterpret_cast<const char8_t*>(path_str.data());
    const auto* last = first + path_str.size();
    return { first, last, std::filesystem::path::native_format };
#else
    // the u8path is deprecated in C++20
    return std::filesystem::u8path(path_from_file_url(file_url));
#endif
}

// Upa URL version functions

/// @brief Get library version encoded to one number
///
/// For example, for the 2.1.0 version, it returns 0x00020100.
///
/// @return encoded version
UPA_API std::uint32_t version_num();

/// @brief Check used library version
///
/// Check that the Upa URL library used is compatible with the header
/// files. This makes sense when using the shared Upa URL library.
///
/// @return true if they are compatible
inline bool check_version() {
    constexpr auto sover_mask = static_cast<std::uint32_t>(-1) ^
        static_cast<std::uint32_t>(0xFF);
    return (version_num() & sover_mask) ==
        (static_cast<std::uint32_t>(UPA_URL_VERSION_NUM) & sover_mask);
}

} // namespace upa


namespace std {

/// @brief std::hash specialization for upa::url class
template<>
struct hash<upa::url> {
    [[nodiscard]] std::size_t operator()(const upa::url& url) const noexcept {
        return std::hash<std::string>{}(url.norm_url_);
    }
};

} // namespace std

// Includes that require the url class declaration
// #include "url_search_params-inl.h"
// Copyright 2016-2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//
// This file should be included at the end of url.h.
// It needs declarations of url, url_search_params and
// url_search_params_ptr classes
//

#ifndef UPA_URL_SEARCH_PARAMS_INL_H
#define UPA_URL_SEARCH_PARAMS_INL_H

#include <memory> // std::addressof


namespace upa {

// url_search_params class

inline url_search_params::url_search_params(url* url_ptr)
    : params_(do_parse(false, url_ptr->get_part_view(url::QUERY)))
    , url_ptr_(url_ptr)
{}

inline void url_search_params::update() {
    if (url_ptr_ && url_ptr_->is_valid()) {
        detail::url_setter urls(*url_ptr_);

        if (empty()) {
            // set query to null
            urls.clear_part(url::QUERY);
        } else {
            std::string& str_query = urls.start_part(url::QUERY);
            serialize(str_query);
            urls.save_part();
            urls.set_flag(url::QUERY_FLAG); // not null query
        }
    }
}

namespace detail {

 // url_search_params_ptr class

inline url_search_params_ptr& url_search_params_ptr::operator=(const url_search_params_ptr& other) {
    if (ptr_ && this != std::addressof(other)) {
        if (other.ptr_) {
            ptr_->copy_params(*other.ptr_);
        } else {
            assert(ptr_->url_ptr_);
            ptr_->parse_params(ptr_->url_ptr_->get_part_view(url::QUERY));
        }
    }
    return *this;
}


} // namespace detail
} // namespace upa

#endif // UPA_URL_SEARCH_PARAMS_INL_H
 // IWYU pragma: export

#endif // UPA_URL_H
