// Copyright 2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//
#include "upa/url.h"
#include "upa/urlpattern.h"
#include "upa/regex_engine_srell.h"
#include "bind_util.h"
#include <nanobind/stl/optional.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/string_view.h>
#include <optional>

namespace upa::py {
namespace {

using urlpattern = typename upa::urlpattern<upa::regex_engine_srell>;

nb::dict to_dict(nb::object obj) {
    if (obj.is_none())
        return {};
    if (nb::isinstance<nb::dict>(obj))
        return nb::cast<nb::dict>(obj);
    if (nb::hasattr(obj, "__dict__"))
        return nb::cast<nb::dict>(obj.attr("__dict__"));
    // usupported type
    throw nb::type_error("Not a dictionary");
}

nb::dict to_dict(const upa::urlpattern_component_result& cres) {
    nb::dict d_cres, d_groups;

    d_cres["input"] = to_str(cres.input);
    for (const auto& [key, val] : cres.groups) {
        if (val)
            d_groups[to_str(key)] = to_str(*val);
        else
            d_groups[to_str(key)] = nb::none();
    }
    d_cres["groups"] = d_groups;

    return d_cres;
}

nb::dict to_dict(const upa::urlpattern_result& res) {
    nb::dict d_res;

    d_res["protocol"] = to_dict(res.protocol);
    d_res["username"] = to_dict(res.username);
    d_res["password"] = to_dict(res.password);
    d_res["hostname"] = to_dict(res.hostname);
    d_res["port"] = to_dict(res.port);
    d_res["pathname"] = to_dict(res.pathname);
    d_res["search"] = to_dict(res.search);
    d_res["hash"] = to_dict(res.hash);

    return d_res;
}

upa::urlpattern_init to_urlpattern_init(nb::object obj) {
    const auto d_init = to_dict(obj);

    upa::urlpattern_init init;
    for (auto [key, value] : d_init) {
        init.set(
            nb::cast<std::string_view>(key),
            nb::cast<std::string>(nb::str(value)));
    }
    return init;
}

upa::urlpattern_options to_urlpattern_options(nb::object obj) {
    upa::urlpattern_options opt;

    nb::dict d = to_dict(obj);
    opt.ignore_case = static_cast<bool>(nb::bool_(d.get("ignoreCase", nb::bool_(false))));
    return opt;
}

} // namespace

void bind_urlpattern(nb::module_& m) {
    nb::class_<urlpattern>(m, "URLPattern")
        // constructors
        .def("__init__", [](urlpattern* t, std::string_view input, std::string_view baseURL,
            nb::object options) {
                new (t) urlpattern(input, baseURL, to_urlpattern_options(options));
            }, nb::arg("input"), nb::arg("baseURL"), nb::arg("options") = nb::none())
        .def("__init__", [](urlpattern* t, std::string_view input, nb::object options) {
                new (t) urlpattern(input, to_urlpattern_options(options));
            }, nb::arg("input"), nb::arg("options") = nb::none())
        .def("__init__", [](urlpattern* t, nb::object input, nb::object options) {
                const auto init = to_urlpattern_init(input);
                const auto opt = to_urlpattern_options(options);

                new (t) urlpattern(init, opt);
            }, nb::arg("input") = nb::none(), nb::arg("options") = nb::none())

        // test
        .def("test", [](const urlpattern& self, std::string_view input, std::optional<std::string_view> baseURL) -> bool {
                return self.test(input, baseURL);
            }, nb::arg("input"), nb::arg("baseURL") = nb::none())
        .def("test", [](const urlpattern& self, nb::object input) -> bool {
                return self.test(to_urlpattern_init(input));
            }, nb::arg("input") = nb::none())

        // exec
        .def("exec", [](const urlpattern& self, nb::str input, std::optional<nb::str> baseURL) -> nb::object {
                const auto sv_input = to_string_view(input);
                std::optional<std::string_view> base;
                if (baseURL)
                    base = to_string_view(*baseURL);

                const auto res = self.exec(sv_input, base);
                if (res) {
                    auto d_res = to_dict(*res);
                    nb::list inputs;
                    inputs.append(input);
                    if (baseURL)
                        inputs.append(*baseURL);
                    d_res["inputs"] = inputs;
                    return d_res;
                }
                return nb::none();
            }, nb::arg("input"), nb::arg("baseURL") = nb::none())
        .def("exec", [](const urlpattern& self, nb::object input) -> nb::object {
                const auto res = self.exec(to_urlpattern_init(input));
                if (res) {
                    auto d_res = to_dict(*res);
                    nb::list inputs;
                    inputs.append(input);
                    d_res["inputs"] = inputs;
                    return d_res;
                }
                return nb::none();
            }, nb::arg("input") = nb::none())

        // properties
        .def_prop_ro("protocol", &urlpattern::get_protocol)
        .def_prop_ro("username", &urlpattern::get_username)
        .def_prop_ro("password", &urlpattern::get_password)
        .def_prop_ro("hostname", &urlpattern::get_hostname)
        .def_prop_ro("port", &urlpattern::get_port)
        .def_prop_ro("pathname", &urlpattern::get_pathname)
        .def_prop_ro("search", &urlpattern::get_search)
        .def_prop_ro("hash", &urlpattern::get_hash)
        .def_prop_ro("hasRegExpGroups", &urlpattern::has_regexp_groups)
        ;
}

} // namespace upa::py
