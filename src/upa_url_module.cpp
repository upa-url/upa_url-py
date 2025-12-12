// Copyright 2025 Rimas Misevičius
// Distributed under the BSD-style license that can be
// found in the LICENSE file.
//
#include "bind_util.h"

namespace upa::py {

extern void bind_url(nb::module_& m);
extern void bind_psl(nb::module_& m);

} // namespace upa::py

NB_MODULE(upa_url, m) {
    m.doc() = "upa_url module";

    upa::py::bind_url(m);
    upa::py::bind_psl(m);
}
