#include <nanobind/nanobind.h>
#include <string>
#include <vector>
#include <unordered_map>

namespace nb = nanobind;

class PyIRConst;
class PyIRTypeEnv;

// Base IRExpr class
class PyIRExpr {
public:
    std::string tag;

    virtual ~PyIRExpr() = default;

    void pp() const;

    virtual std::string __str__() const {
        return _pp_str();
    }

    virtual std::string _pp_str() const = 0;

    virtual std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const = 0;

    virtual std::vector<std::shared_ptr<PyIRConst>> constants() const = 0;

    virtual int result_size(const PyIRTypeEnv& tyenv) const = 0;

    virtual std::string result_type(const PyIRTypeEnv& tyenv) const = 0;

    virtual void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) = 0;

    virtual bool typecheck(const PyIRTypeEnv& tyenv) const = 0;

    static std::shared_ptr<PyIRExpr> _from_c(const IRExpr* c_expr);
    // static IRExpr* _to_c(const PyIRExpr& expr);
    static std::shared_ptr<PyIRExpr> _translate(const IRExpr* c_expr) { return _from_c(c_expr); }
};

void bind_expr(nb::module_& m);