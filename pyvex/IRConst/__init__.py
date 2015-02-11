from .. import vex

# IRConst heirarchy
class IRConst(vex): pass

class U1(IRConst):
    def __str__(self):
        return "%d" % self.value

class U8(IRConst):
    def __str__(self):
        return "0x%02x" % self.value

class U16(IRConst):
    def __str__(self):
        return "0x%04x" % self.value

class U32(IRConst):
    def __str__(self):
        return "0x%08x" % self.value

class U64(IRConst):
    def __str__(self):
        return "0x%016x" % self.value

class F32(IRConst):
    def __str__(self):
        return "%f" % self.value

class F32i(IRConst):
    def __str__(self):
        return "%f" % self.value

class F64(IRConst):
    def __str__(self):
        return "%f" % self.value

class F64i(IRConst):
    def __str__(self):
        return "%f" % self.value

class V128(IRConst):
    def __str__(self):
        return "%x" % self.value

class V256(IRConst):
    def __str__(self):
        return "%x" % self.value
