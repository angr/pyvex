from _pyvex import Const, U1, U8, U16, U32, U64, F32, F64, V128, V256, get_type_size, get_tag_size

# TODO: Add F32i, F64i

predefined_types = [U1, U8, U16, U32, U64, F32, F64, V128, V256]
predefined_types_map = {c.type: c for c in predefined_types}
predefined_classes_map = {c.tag: c for c in predefined_types}

# Integer Type Imagination
class_cache = {1: U1, 8: U8, 16: U16, 32: U32, 64: U64}

def vex_int_class(size):
    try:
        return class_cache[size]
    except KeyError:

        class VexInt(IRConst):
            type = "Ity_I%d" % size
            tag = "Ico_U%d" % size
            op_format = str(size)

            def __init__(self, value):
                IRConst.__init__(self)
                self._value = value

            def __str__(self):
                return f"(0x{self.value:x} :: {self.type})"

        VexInt.__name__ = "U%d" % size
        class_cache[size] = VexInt
        return VexInt

def ty_to_const_class(ty):
    try:
        return predefined_types_map[ty]
    except KeyError:
        if is_int_ty(ty):
            size = get_type_size(ty)
            return vex_int_class(size)
        else:
            raise ValueError("Type %s does not exist" % ty)