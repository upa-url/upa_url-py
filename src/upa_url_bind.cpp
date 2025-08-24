// Copyright 2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//

#include "upa/url.h"
#include <nanobind/nanobind.h>
#include <nanobind/make_iterator.h>
#include <nanobind/stl/list.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/string_view.h>
#include <optional>

namespace nb = nanobind;

NB_MODULE(upa_url, m) {
    m.doc() = "upa_url module";

    m.attr("__version__") = "0.0.1";

    // URL class
    nb::class_<upa::url>(m, "URL")
        .def(nb::init<std::string_view>(), nb::arg("url"))
        .def(nb::init<std::string_view, std::string_view>(), nb::arg("url"), nb::arg("base"))
        .def_prop_rw("href", &upa::url::get_href, &upa::url::set_href<std::string_view>)
        .def_prop_ro("origin", &upa::url::origin)
        .def_prop_rw("protocol", &upa::url::get_protocol, &upa::url::set_protocol<std::string_view>)
        .def_prop_rw("username", &upa::url::get_username, &upa::url::set_username<std::string_view>)
        .def_prop_rw("password", &upa::url::get_password, &upa::url::set_password<std::string_view>)
        .def_prop_rw("host", &upa::url::get_host, &upa::url::set_host<std::string_view>)
        .def_prop_rw("hostname", &upa::url::get_hostname, &upa::url::set_hostname<std::string_view>)
        .def_prop_rw("port", &upa::url::get_port, &upa::url::set_port<std::string_view>)
        .def_prop_rw("pathname", &upa::url::get_pathname, &upa::url::set_pathname<std::string_view>)
        .def_prop_rw("search", &upa::url::get_search, &upa::url::set_search<std::string_view>)
        .def_prop_ro("searchParams", [](upa::url& self) {
                return std::addressof(self.search_params());
            }, nb::rv_policy::reference_internal)
        .def_prop_rw("hash", &upa::url::get_hash, &upa::url::set_hash<std::string_view>)
        .def("__str__", &upa::url::get_href)
        // static functions
        .def_static("canParse", [](std::string_view url, std::optional<std::string_view> base) {
                if (base)
                    return upa::url::can_parse(url, *base);
                return upa::url::can_parse(url);
            }, nb::arg("url"), nb::arg("base") = nb::none())
        .def_static("parse", [](std::string_view url, std::optional<std::string_view> base)
            -> std::optional<upa::url> {
                upa::url u;
                if (base) {
                    if (upa::success(u.parse(url, *base)))
                        return u;
                } else {
                    if (upa::success(u.parse(url)))
                        return u;
                }
                return std::nullopt;
            }, nb::arg("url"), nb::arg("base") = nb::none())
        ;

    // URLSearchParams class
    nb::class_<upa::url_search_params>(m, "URLSearchParams")
        .def(nb::init<>())
        .def(nb::init<std::string_view>())
        //TODO: add more constructors
        .def_prop_ro("size", &upa::url_search_params::size)
        .def("__len__", &upa::url_search_params::size)
        .def("append", &upa::url_search_params::append<std::string_view, std::string_view>,
            nb::arg("name"), nb::arg("value"))
        .def("delete", [](upa::url_search_params& self, std::string_view name,
            std::optional<std::string_view> value) {
                if (value)
                    self.del(name, *value);
                else
                    self.del(name);
            }, nb::arg("name"), nb::arg("value") = nb::none())
        .def("get", &upa::url_search_params::get<std::string_view>,
            nb::arg("name"))
        .def("getAll", &upa::url_search_params::get_all<std::string_view>,
            nb::arg("name"))
        .def("has", [](upa::url_search_params& self, std::string_view name,
            std::optional<std::string_view> value) {
                if (value)
                    return self.has(name, *value);
                return self.has(name);
            }, nb::arg("name"), nb::arg("value") = nb::none())
        .def("set", &upa::url_search_params::set<std::string_view, std::string_view>,
            nb::arg("name"), nb::arg("value"))
        .def("sort", &upa::url_search_params::sort)
        .def("__iter__", [](upa::url_search_params& self) {
                return nb::make_iterator(nb::type<upa::url_search_params>(),
                    "iterator", self.begin(), self.end());
            }, nb::keep_alive<0, 1>())
        .def("keys", [](upa::url_search_params& self) {
                return nb::make_key_iterator(nb::type<upa::url_search_params>(),
                    "iterator", self.begin(), self.end());
            }, nb::keep_alive<0, 1>())
        .def("values", [](upa::url_search_params& self) {
                return nb::make_value_iterator(nb::type<upa::url_search_params>(),
                    "iterator", self.begin(), self.end());
            }, nb::keep_alive<0, 1>())
        .def("__str__", &upa::url_search_params::to_string)
        ;
}
