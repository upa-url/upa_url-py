// Copyright 2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//
#include "upa/url.h"
#include "upa/public_suffix_list.h"
#include "bind_util.h"
#include <nanobind/stl/optional.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/string_view.h>
#include <optional>

namespace upa::py {
namespace {

class public_suffix_list_py : public upa::public_suffix_list {
public:
    inline void push_line(std::string_view line) {
        upa::public_suffix_list::push_line(ctx_, line);
    }
    inline void push(std::string_view buff) {
        upa::public_suffix_list::push(ctx_, buff);
    }
    inline void push_bytes(nb::bytes bytes) {
        upa::public_suffix_list::push(ctx_, to_string_view(bytes));
    }
    inline bool finalize() {
        return upa::public_suffix_list::finalize(ctx_);
    }
private:
    push_context ctx_;
};

} // namespace

void bind_psl(nb::module_& m) {
    // PSL class
    nb::class_<public_suffix_list_py>(m, "PSL")
        // Load Public Suffix List using push interface
        .def(nb::init<>())
        .def("push_line", &public_suffix_list_py::push_line, nb::arg("line"))
        .def("push", &public_suffix_list_py::push, nb::arg("buff"))
        .def("push", &public_suffix_list_py::push_bytes, nb::arg("buff"))
        .def("finalize", &public_suffix_list_py::finalize)

        // Load Public Suffix List from file
        .def("__init__", [](public_suffix_list_py* t, std::string_view filename) {
                new (t) public_suffix_list_py{};
                if (!t->load(filename))
                    throw std::runtime_error("Error loading Public Suffix List from file.");
            }, nb::arg("filename"))
        .def_static("load", [](std::string_view filename)
            -> std::optional<public_suffix_list_py> {
                public_suffix_list_py psl;
                if (psl.load(filename))
                    return psl;
                return std::nullopt;
            }, nb::arg("filename"))

        // Get public suffix
        .def("public_suffix", [](const public_suffix_list_py& self,
            std::string_view str_host, bool ascii) {
                if (ascii) {
                    return to_str(self.get_suffix(str_host));
                }
                return to_str(self.get_suffix_view(str_host));
            }, nb::arg("host"), nb::arg("ascii") = true)
        .def("public_suffix", [](const public_suffix_list_py& self,
            const upa::url& url) {
                return self.get_suffix_view(url);
            }, nb::arg("url"))
        // Get registrable domain
        .def("registrable_domain", [](const public_suffix_list_py& self,
            std::string_view str_host, bool ascii) {
                if (ascii) {
                    return to_str(self.get_suffix(str_host,
                        upa::public_suffix_list::option::registrable_domain));
                }
                return to_str(self.get_suffix_view(str_host,
                    upa::public_suffix_list::option::registrable_domain));
            }, nb::arg("host"), nb::arg("ascii") = true)
        .def("registrable_domain", [](const public_suffix_list_py& self,
            const upa::url& url) {
                return self.get_suffix_view(url,
                    upa::public_suffix_list::option::registrable_domain);
            }, nb::arg("url"))
        ;
}

} // namespace upa::py
