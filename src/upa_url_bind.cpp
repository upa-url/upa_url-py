// Copyright 2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//

#include "upa/url.h"
#include "upa/public_suffix_list.h"
#include <nanobind/nanobind.h>
#include <nanobind/make_iterator.h>
#include <nanobind/stl/list.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/string_view.h>
#include <optional>

namespace nb = nanobind;

namespace {

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

NB_MODULE(upa_url, m) {
    m.doc() = "upa_url module";

    // URL class
    nb::class_<upa::url>(m, "URL")
        .def("__init__", [](upa::url* t, std::string_view url, std::optional<std::string_view> base) {
                if (base)
                    new (t) upa::url(url, *base);
                else
                    new (t) upa::url(url);
            }, nb::arg("url"), nb::arg("base") = nb::none())
        .def(nb::init<std::string_view, const upa::url&>(), nb::arg("url"), nb::arg("base"))
        .def("__copy__", [](const upa::url& self) {
                return upa::url(self);
            })
        .def("__deepcopy__", [](const upa::url& self, nb::dict) {
                return upa::url(self);
            })
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
        .def_static("canParse", [](std::string_view url, const upa::url& base) {
                return upa::url::can_parse(url, base);
            }, nb::arg("url"), nb::arg("base"))
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
        .def_static("parse", [](std::string_view url, const upa::url& base)
            -> std::optional<upa::url> {
                upa::url u;
                if (upa::success(u.parse(url, base)))
                    return u;
                return std::nullopt;
            }, nb::arg("url"), nb::arg("base"))
        ;

    // URLSearchParams class
    nb::class_<upa::url_search_params>(m, "URLSearchParams")
        // constructors
        .def(nb::init<>())
        .def(nb::init<std::string_view>())
        .def("__init__", [](upa::url_search_params* t, nb::dict dict) {
                new (t) upa::url_search_params{};
                for (auto [key, value] : dict)
                    t->append(
                        to_string_view(nb::str(key)),
                        to_string_view(nb::str(value)));
            })
        .def("__init__", [](upa::url_search_params* t, nb::iterable iterable) {
                new (t) upa::url_search_params{};
                for (auto item : iterable) {
                    if (nb::isinstance<nb::tuple>(item)) {
                        auto tup = nb::tuple(item);
                        if (tup.size() != 2)
                            nb::raise("each inner tuple must contain 2 items");
                        t->append(
                            to_string_view(nb::str(nb::handle(tup[0]))),
                            to_string_view(nb::str(nb::handle(tup[1]))));
                        continue;
                    }
                    if (nb::isinstance<nb::list>(item)) {
                        auto lst = nb::list(item);
                        if (lst.size() != 2)
                            nb::raise("each inner list must contain 2 items");
                        t->append(
                            to_string_view(nb::str(nb::handle(lst[0]))),
                            to_string_view(nb::str(nb::handle(lst[1]))));
                        continue;
                    }
                    nb::raise("items must be tuples or lists");
                }
            })

        .def("__copy__", [](const upa::url_search_params& self) {
                return upa::url_search_params(self);
            })
        .def("__deepcopy__", [](const upa::url_search_params& self, nb::dict) {
                return upa::url_search_params(self);
            })
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
