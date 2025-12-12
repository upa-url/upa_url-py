// Copyright 2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//
#ifndef UPA_PY_BIND_UTIL_H
#define UPA_PY_BIND_UTIL_H

#include <nanobind/nanobind.h>
#include <cstddef>
#include <string_view>

namespace upa::py {

namespace nb = nanobind;

inline std::string_view to_string_view(nb::str str) {
    Py_ssize_t ssize{};

    // On error, the PyUnicode_AsUTF8AndSize sets an exception, sets
    // ssize to -1 (atarting with Python 3.13) and returns NULL.
    // https://docs.python.org/3/c-api/unicode.html#c.PyUnicode_AsUTF8AndSize
    const char* pdata = PyUnicode_AsUTF8AndSize(str.ptr(), &ssize);
    if (pdata != nullptr)
        return { pdata, static_cast<std::size_t>(ssize) };
    return {};
}

inline std::string_view to_string_view(nb::bytes bytes) {
    return { bytes.c_str(), bytes.size() };
}

inline nb::str to_str(std::string_view sv) {
    return nb::str{ sv.data(), sv.length() };
}

} // namespace upa::py

#endif // UPA_PY_BIND_UTIL_H
