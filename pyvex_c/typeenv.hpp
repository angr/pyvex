#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
extern "C" {
#include "pyvex.h"
}


// PyIRTypeEnv class for managing temporary variable types
class PyIRTypeEnv {
public:
    std::vector<std::string> types;
    std::string wordty;

    PyIRTypeEnv() : wordty("Ity_I64") {}

    PyIRTypeEnv(const std::vector<std::string>& types, const std::string& wordty)
        : types(types), wordty(wordty) {}

    void extend(const std::string& ty) {
        types.push_back(ty);
    }

    std::string lookup(int tmp) const {
        if (tmp >= 0 && tmp < static_cast<int>(types.size())) {
            return types[tmp];
        }
        throw std::runtime_error("Invalid temporary number: " + std::to_string(tmp));
    }

    size_t types_used() const {
        return types.size();
    }

    std::string __str__() const {
        std::string result = "IRTypeEnv([";
        for (size_t i = 0; i < types.size(); ++i) {
            if (i > 0) result += ", ";
            result += types[i];
        }
        result += "])";
        return result;
    }

    static std::shared_ptr<PyIRTypeEnv> _from_c(const IRTypeEnv* c_tyenv);
};