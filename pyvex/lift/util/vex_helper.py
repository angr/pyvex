from pyvex.const import U1, U8, U16, U32, U64
from pyvex.expr import Const, RdTmp, Unop, Binop, Triop, Qop, Load, CCall
from pyvex.stmt import WrTmp, Put, IMark, Store, NoOp, Exit
from pyvex.enums import IRCallee

class Type:
    bit = 'Ity_I1'
    int_1 = 'Ity_I1'
    byte = 'Ity_I8'
    int_8 = 'Ity_I8'
    int_16 = 'Ity_I16'
    int_32 = 'Ity_I32'
    int_64 = 'Ity_I64'
    int_128 = 'Ity_I128'
    ieee_float_16 = 'Ity_F16'
    ieee_float_32 = 'Ity_F32'
    ieee_float_64 = 'Ity_F64'
    ieee_float_128 = 'Ity_F128'
    decimal_float_32 = 'Ity_D32'
    decimal_float_64 = 'Ity_D64'
    decimal_float_128 = 'Ity_D128'
    simd_vector_128 = 'Ity_V128'
    simd_vector_256 = 'Ity_V256'

class JumpKind:
    Boring = 'Ijk_Boring'
    Call = 'Ijk_Call'
    Segfault = 'Ijk_SigSEGV'
    Exit = 'Ijk_Exit'
    Syscall = 'Ijk_Sys_syscall'
    Sysenter = 'Ijk_Sys_sysenter'
    Invalid = 'Ijk_INVALID'
def get_operand_type_descriptor(t):
    type_to_size_map = {
        Type.int_1: '1',
        Type.int_8: '8',
        Type.int_16: '16',
        Type.int_32: '32',
        Type.int_64: '64',
        Type.int_128: '128',
        Type.ieee_float_32: 'F32',
        Type.ieee_float_64: 'F64',
        Type.ieee_float_128: 'F128',
    }
    return type_to_size_map[t]

def make_format_op_generator(fmt_string):
    def gen(arg_types):
        converted_arg_types = map(get_operand_type_descriptor, arg_types)
        op = fmt_string.format(arg_t=converted_arg_types)
        return op
    return gen


def make_const(t, val):
    supported_type_consts = {
        Type.int_1: U1,
        Type.int_8: U8,
        Type.int_16: U16,
        Type.int_32: U32,
        Type.int_64: U64
    }
    if t in supported_type_consts:
        return Const(supported_type_consts[t](val))

    raise NotImplemented('There is no constant for variable type {} implemented.'.format(t))


class IRSBCustomizer(object):
    def __init__(self, irsb):
        self.irsb = irsb

    def lookup_tmp_type(self, tmp):
        return self.irsb.tyenv.lookup(tmp)

    def add_tmp(self, t):
        return self.irsb.tyenv.add(t)
    ######################################
    #    Temporary variable management   #
    ######################################
    def mktmp(self, expr):
        tmp = self.irsb.tyenv.add(expr.result_type(self.irsb.tyenv))
        self.irsb.statements += [WrTmp(tmp, expr)]
        return tmp

    def append_stmt(self, stmt):
        self.irsb.statements += [stmt]

    def imark(self, int_addr, int_length, int_delta=0):
        self.irsb.statements += [IMark(int_addr, int_length, int_delta)]

    def put(self, expr_val, tuple_reg):
        self.irsb.statements += [Put(expr_val, tuple_reg)]

    def store(self, addr, expr, endness):
        self.irsb.statements += [Store(addr, expr, endness)]

    def noop(self):
        self.irsb.statements += [NoOp()]

    def add_exit(self, guard, dst, jk, ip):
        """
        Add an exit out of the middle of an IRSB.
        (e.g., a conditional jump)
        :param guard: An expression, the exit is taken if true
        :param dst: the destination of the exit (a Const)
        :param jk: the JumpKind of this exit (probably Ijk_Boring)
        :param ip: FIXME (assumed to be the IP of the exit)
        """
        self.irsb.statements += [Exit(guard, dst, jk, ip)]

    """
    Operations
    ---------------------------------------------------------------------------------------------------------------
    The operation functions are wrappers for certain classes of operations in VEX with dynamic typing. The correct
    VEX opcode is chosen based on the arguments that are passed in. Calling operation functions will not result in any
    modifications to the underlying IRSB.

    Operation functions can easily be identified by their names starting with 'op_'
    """

    ###########################
    #         HELPERS         #
    ###########################
    def op_generic(self, Operation, op_generator):

        def instance(*args):
            # For easy use, automatically RdTmp anything that isn't already an IRExpr, contemplate if this is wanted
            # args = [RdTmp(arg) if not isinstance(IRExpr, arg) else arg for arg in args_raw]
            # For now not used, maybe to be brought in later
            arg_types = [arg.result_type(self.irsb.tyenv) for arg in args]

            op = Operation(op_generator(arg_types), args)
            return op

        return instance

    def op_binary(self, op_format_str):
        return self.op_generic(Binop, op_format_str)

    def op_unary(self, op_format_str):
        return self.op_generic(Unop, op_format_str)

    def op_binary_multichain(self, op_lambda, *expr_arg_list):
        if len(expr_arg_list) == 1:
            return expr_arg_list[0]

        elif len(expr_arg_list) == 2:
            return op_lambda(expr_arg_list[0], expr_arg_list[1])

        else:
            extra = None
            if len(expr_arg_list) % 2 == 1:
                extra = expr_arg_list[-1]
                expr_arg_list = expr_arg_list[:-1]

            one_step = [op_lambda(expr_arg_list[i], expr_arg_list[i + 1]) for i in range(0, len(expr_arg_list), 2)]
            combined = self.op_binary_multichain(op_lambda, *one_step)
            final_result = combined if extra is None else op_lambda(combined, extra)
            return final_result

    def op_logic_dnf(self, dnf):
        clause = []

        for conj in dnf:
            clause.append(self.op_binary_multichain(self.op_and, *conj))

        expr_result = self.op_binary_multichain(self.op_or, *clause)
        return expr_result

    def op_logic_on_bit(self, lambda_op, *expr_args, **kwargs):
        t_wide = kwargs.pop('t_wide', Type.int_64)
        expr_args_64 = [self.op_widen_int_unsigned(t_wide, e) for e in expr_args]
        expr_applied = self.op_narrow_int(Type.int_1, lambda_op(*expr_args_64), high_half=False)
        return expr_applied


    ###########################
    #     IMPLEMENTATIONS     #
    ###########################

    def op_cmp(self, comparison, expr_a, expr_b):
        return self.op_binary(lambda arg_ts: 'Iop_Cmp' + comparison + get_operand_type_descriptor(arg_ts[0]))(expr_a, expr_b)

    def op_cmp_eq(self, expr_a, expr_b):
        return self.op_cmp('EQ', expr_a, expr_b)


    def op_shift_right(self, expr_val, expr_num_bits):
        return self.op_binary(make_format_op_generator('Iop_Shr{arg_t[0]}'))(expr_val, expr_num_bits)

    def op_shift_left(self, expr_val, expr_num_bits):
        return self.op_binary(make_format_op_generator('Iop_Shl{arg_t[0]}'))(expr_val, expr_num_bits)

    def op_or(self, expr_val, expr_mask):
        return self.op_binary(make_format_op_generator('Iop_Or{arg_t[0]}'))(expr_val, expr_mask)

    def op_xor(self, expr_a, expr_b):
        return self.op_binary(make_format_op_generator('Iop_Xor{arg_t[0]}'))(expr_a, expr_b)

    def op_and(self, expr_val, expr_mask):
        return self.op_binary(make_format_op_generator('Iop_And{arg_t[0]}'))(expr_val, expr_mask)

    def op_not(self, expr_val):
        return self.op_unary(make_format_op_generator('Iop_Not{arg_t[0]}'))(expr_val)

    def op_extract_lsb(self, expr_val):
        return self.op_unary(make_format_op_generator('Iop_{arg_t[0]}to1'))(expr_val)


    def op_narrow_int(self, t_dest, expr_val, high_half=False):
        op_name = '{op}{high}to{dest}'.format(op='Iop_{arg_t[0]}',
                                              high='HI' if high_half else '',
                                              dest=get_operand_type_descriptor(t_dest))
        return self.op_unary(make_format_op_generator(op_name))(expr_val)

    def op_widen_int(self, t_dest, expr_val, signed=False):
        op_name = '{op}{sign}to{dest}'.format(op='Iop_{arg_t[0]}',
                                              sign='S' if signed else 'U',
                                              dest=get_operand_type_descriptor(t_dest))
        return self.op_unary(make_format_op_generator(op_name))(expr_val)

    def op_widen_int_signed(self, t_dest, expr_val):
        return self.op_widen_int(t_dest, expr_val, signed=True)

    def op_widen_int_unsigned(self, t_dest, expr_val):
        return self.op_widen_int(t_dest, expr_val, signed=False)


    def op_add(self, expr_a, expr_b):
        return self.op_binary(make_format_op_generator('Iop_Add{arg_t[0]}'))(expr_a, expr_b)


    def op_sub(self, expr_a, expr_b):
        return self.op_binary(make_format_op_generator('Iop_Sub{arg_t[0]}'))(expr_a, expr_b)

    def op_mull(self, expr_v, expr_mul, signed=True):
        return self.op_binary(make_format_op_generator('Iop_Mull' + ('S' if signed else 'U') + '{arg_t[0]}'))(expr_v, expr_mul)

    def op_ccall(selfself, retty, funcstr, args):
        return CCall(retty, IRCallee(len(args), funcstr, 1234, 0xffff), args)



    """
    Actions
    ---------------------------------------------------------------------------------------------------------------
    Action functions capsule common patterns while building custom IRSBs. Any intermediate results must be stored in
    temporary variables. This means that calling these procedure functions WILL modify the underlying IRSB!
    Action functions return the temporary variables from which their result can be accessed. In most cases this is a
    single variable, however, depending on the procedure, multiple results may be returned.

    While this is not necessarily efficient it only generates inefficient patterns that should be easy to eliminate
    during post-processing and optimization.

    Action functions can easily be identified by their names starting with 'act_'
    """

    def act_extract_bit(self, tmp_val, int_bit_idx):
        tmp_shifted = self.mktmp(self.op_shift_right(RdTmp(tmp_val), make_const(Type.int_8, int_bit_idx)))
        tmp_widened = self.mktmp(self.op_widen_int_unsigned(Type.int_64, RdTmp(tmp_shifted)))
        tmp_extracted = self.mktmp(self.op_extract_lsb(RdTmp(tmp_widened)))
        return tmp_extracted

    # This could technically be implemented as an operation, but conceptually I like it better as a procedure
    def act_set_bit_const(self, tmp_val, int_bit_idx, set_bit):
        t = self.irsb.tyenv.lookup(tmp_val)
        if set_bit:
            tmp_result = self.mktmp(self.op_or(RdTmp(tmp_val), make_const(t, 1 << int_bit_idx)))
        else:
            tmp_result = self.mktmp(self.op_and(RdTmp(tmp_val), make_const(t, ~(1 << int_bit_idx))))

        return tmp_result

    def act_set_bit_from_tmp(self, tmp_val, int_bit_idx, tmp_bit):
        val_type = self.irsb.tyenv.lookup(tmp_val)

        tmp_bit_widened = self.mktmp(self.op_widen_int_unsigned(val_type, RdTmp(tmp_bit)))
        tmp_bitmask = self.mktmp(self.op_shift_left(RdTmp(tmp_bit_widened), make_const(Type.int_8, int_bit_idx)))

        tmp_val_anded = self.mktmp(self.op_and(RdTmp(tmp_val), RdTmp(tmp_bitmask)))
        tmp_val_ored = self.mktmp(self.op_or(RdTmp(tmp_val_anded), RdTmp(tmp_bitmask)))

        return tmp_val_ored

