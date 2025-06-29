#include <string>
#include <vector>
#include <unordered_map>
#include <memory>

namespace nb = nanobind;

void bind_stmt(nb::module_& m);

class PyIRExpr;
class PyIRTypeEnv;

// Base IRStmt class
class PyIRStmt {
public:
    std::string tag;
    int tag_int = 0;

    virtual ~PyIRStmt() = default;

    void pp() const;

    virtual std::vector<std::shared_ptr<PyIRExpr>> child_expressions() const = 0;
    
    std::vector<std::shared_ptr<PyIRExpr>> expressions() const {
        return child_expressions();
    }

    virtual std::vector<std::shared_ptr<PyIRConst>> constants() const = 0;

    static std::shared_ptr<PyIRStmt> _from_c(const ::IRStmt* c_stmt);

    virtual bool typecheck(const PyIRTypeEnv& tyenv) const = 0;

    virtual void replace_expression(const std::unordered_map<std::shared_ptr<PyIRExpr>, std::shared_ptr<PyIRExpr>>& replacements) = 0;

    virtual std::string __str__() const {
        return pp_str("", "", nullptr);
    }

    virtual std::string pp_str(const std::string& reg_name, const std::string& arch, const PyIRTypeEnv* tyenv) const = 0;
};