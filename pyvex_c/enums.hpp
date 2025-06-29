#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace nb = nanobind;

// Base VEXObject class
class VEXObject {
public:
    virtual ~VEXObject() = default;
    
    virtual bool __eq__(const VEXObject& other) const {
        return typeid(*this) == typeid(other);
    }
    
    virtual size_t __hash__() const {
        return std::hash<std::string>{}(typeid(*this).name());
    }
};

// PyIRRegArray class
class PyIRRegArray : public VEXObject {
public:
    int base;
    std::string elemTy;
    int nElems;

    PyIRRegArray(int base, const std::string& elemTy, int nElems)
        : base(base), elemTy(elemTy), nElems(nElems) {}

    std::string __str__() const;

    bool __eq__(const VEXObject& other) const override;

    size_t __hash__() const override;

    static std::shared_ptr<PyIRRegArray> _from_c(const IRRegArray* c_arr);
    static IRRegArray* _to_c(const PyIRRegArray& arr);
};

// PyIRCallee class
class PyIRCallee : public VEXObject {
public:
    int regparms;
    std::string name;
    int mcx_mask;

    PyIRCallee(int regparms, const std::string& name, int mcx_mask)
        : regparms(regparms), name(name), mcx_mask(mcx_mask) {}

    std::string __str__() const;

    bool __eq__(const VEXObject& other) const override;

    size_t __hash__() const override;

    static std::shared_ptr<PyIRCallee> _from_c(const IRCallee* c_callee);

    static IRCallee* _to_c(const PyIRCallee& callee);
};

void bind_enums(nb::module_& m);