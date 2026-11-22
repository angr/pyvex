import pytest

import pyvex


@pytest.mark.parametrize("prefix", [b"", b"\xf0"], ids=["unlocked", "locked"])
def test_cmpxchg_memory32_accumulator(prefix):
    arch = pyvex.ARCH_AMD64
    code = prefix + b"\x0f\xb1\x0f"  # [lock] cmpxchg dword ptr [rdi], ecx
    block = pyvex.lift(code, 0x4000, arch, opt_level=-1)
    assert block.size == len(code)
    assert block.jumpkind == "Ijk_Boring"

    # Follow temporary copies from the accumulator write to its two inputs.
    definitions = {s.tmp: s.data for s in block.statements if isinstance(s, pyvex.stmt.WrTmp)}

    def resolve(expr):
        while isinstance(expr, pyvex.expr.RdTmp) and expr.tmp in definitions:
            expr = definitions[expr.tmp]
        return expr

    rax = arch.get_register_offset("rax")
    (write,) = (s for s in block.statements if isinstance(s, pyvex.stmt.Put) and s.offset == rax)
    choice = resolve(write.data)
    assert isinstance(choice, pyvex.expr.ITE)

    # The true arm must correspond to ZF set (AMD64CondZ).
    predicate = resolve(choice.cond)
    assert isinstance(predicate, pyvex.expr.Unop) and predicate.op == "Iop_64to1"
    condition = resolve(predicate.args[0])
    assert isinstance(condition, pyvex.expr.CCall) and condition.cee.name == "amd64g_calculate_condition"
    assert condition.args[0] == pyvex.expr.Const(pyvex.const.U64(4))

    # Equality leaves all 64 bits untouched. Inequality writes the old dword to EAX.
    assert resolve(choice.iftrue) == pyvex.expr.Get(rax, "Ity_I64")
    failure = resolve(choice.iffalse)
    assert isinstance(failure, pyvex.expr.Unop) and failure.op == "Iop_32Uto64"
    old = resolve(failure.args[0])
    if prefix:
        (cas,) = (s for s in block.statements if isinstance(s, pyvex.stmt.CAS))
        assert old == pyvex.expr.RdTmp(cas.oldLo)
    else:
        assert isinstance(old, pyvex.expr.Load) and old.ty == "Ity_I32"
