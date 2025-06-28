#include <nanobind/nanobind.h>
#include <stdexcept>
#include "typeenv.hpp"


namespace nb = nanobind;

std::shared_ptr<PyIRTypeEnv> PyIRTypeEnv::_from_c(const IRTypeEnv* c_tyenv) {
    throw std::runtime_error("Not implemented");
}

void bind_typeenv(nb::module_& m) {
    // IRTypeEnv class
    nb::class_<PyIRTypeEnv>(m, "IRTypeEnv")
        .def(nb::init<>())
        .def(nb::init<const std::vector<std::string>&, const std::string&>())
        .def_rw("types", &PyIRTypeEnv::types)
        .def_rw("wordty", &PyIRTypeEnv::wordty)
        .def("extend", &PyIRTypeEnv::extend)
        .def("lookup", &PyIRTypeEnv::lookup)
        .def("types_used", &PyIRTypeEnv::types_used)
        .def("__str__", &PyIRTypeEnv::__str__)
        .def_static("_from_c", &PyIRTypeEnv::_from_c, nb::rv_policy::take_ownership);
}
