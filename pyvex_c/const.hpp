#include <string>
#include <vector>
#include <unordered_map>


// Base PyIRConst class
class PyIRConst {
public:
    std::string type;
    int size;
    std::string tag;
    std::string op_format;

    PyIRConst() {}
    virtual ~PyIRConst() = default;

    virtual std::string __str__() const = 0;
    void pp() const;

    bool __eq__(const PyIRConst& other) const { return false; }

    virtual size_t __hash__() const { return 0; }

    // Static factory method from C IRConst
    static std::shared_ptr<PyIRConst> _from_c(const ::IRConst* c_const);

    // Convert to C IRConst
    virtual IRConst* _to_c() const = 0;
};