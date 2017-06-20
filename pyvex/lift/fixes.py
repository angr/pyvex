from . import Lifter, register

class FixesPostProcessor(Lifter):
    def postprocess(self):
        self.irsb.statements = [x for x in self.irsb.statements if x.tag != 'Ist_NoOp']

        funcname = "_post_process_%s" % self.irsb.arch.name
        if hasattr(self, funcname):
            getattr(self, funcname)()

    def _post_process_ARM(self):
        # Jumpkind
        if self.irsb.jumpkind == "Ijk_Boring":
            # If PC is moved to LR, then this should be an Ijk_Call
            #
            # Example:
            # MOV LR, PC
            # MOV PC, R8

            # Note that the value of PC is directly used in IRStatements, i.e
            # instead of having:
            #   t0 = GET:I32(pc)
            #   PUT(lr) = t0
            # we have:
            #   PUT(lr) = 0x10400
            # The only case (that I've seen so far) where a temporary variable
            # is assigned to LR is:
            #   t2 = ITE(cond, t0, t1)
            #   PUT(lr) = t2

            pc_holders = {}
            lr_store_pc = False
            inst_ctr = 0
            next_irsb_addr = self.irsb.statements[0].addr + self.irsb.size
            for stt in self.irsb.statements:
                if type(stt) == stmt.Put:
                    # LR is modified just before the last instruction of the
                    # block...
                    if stt.offset == self.irsb.arch.registers['lr'][0] \
                       and inst_ctr == self.irsb.instructions - 1:
                        # ... by a constant, so test whether it is the address
                        # of the next IRSB
                        if type(stt.data) == expr.Const:
                            if stt.data.con.value == next_irsb_addr:
                                lr_store_pc = True
                        # ... by a temporary variable, so test whether it holds
                        # the address of the next IRSB
                        elif type(stt.data) == expr.RdTmp:
                            if next_irsb_addr == pc_holders.get(stt.data.tmp):
                                lr_store_pc = True
                        break
                    else:
                        reg_name = self.irsb.arch.translate_register_name(stt.offset)
                        if type(stt.data) == expr.Const:
                            pc_holders[reg_name] = stt.data.con.value
                        elif type(stt.data) == expr.RdTmp and pc_holders.get(stt.data.tmp) is not None:
                            pc_holders[reg_name] = pc_holders[stt.data.tmp]
                        elif type(stt.data) == expr.Get and pc_holders.get(stt.data.offset) is not None:
                            pc_holders[reg_name] = pc_holders[stt.data.offset]
                elif type(stt) == stmt.WrTmp:
                    # the PC value may propagate through the block, and since
                    # LR is modified at the end of the block, the PC value have
                    # to be incremented in order to match the address of the
                    # next IRSB. So the only propagation ways that can lead to
                    # a function call are:
                    #   - Iop_Add* operations (even "sub r0, #-4" is compiled
                    #   as "add r0, #4")
                    #   - Iop_And*, Iop_Or*, Iop_Xor*, Iop_Sh*, Iop_Not* (there
                    #   may be some tricky and twisted ways to increment PC)
                    if type(stt.data) in (expr.Unop, expr.Binop, expr.Triop, expr.Qop):
                        if all(type(a) == expr.Const
                               or (type(a) == expr.RdTmp and pc_holders.get(a.tmp) is not None)
                                    for a in stt.data.args):
                            op = stt.data.op
                            vals = [a.con.value if type(a) == expr.Const else pc_holders[a.tmp] \
                                    for a in stt.data.args]
                            if 'Iop_Add' in op:
                                pc_holders[stt.tmp] = sum(vals)
                            elif 'Iop_And' in op:
                                pc_holders[stt.tmp] = reduce(lambda a, b: a & b, vals)
                            elif 'Iop_Or' in op:
                                pc_holders[stt.tmp] = reduce(lambda a, b: a | b, vals)
                            elif 'Iop_Xor' in op:
                                pc_holders[stt.tmp] = reduce(lambda a, b: a ^ b, vals)
                            elif 'Iop_Shl' in op:
                                pc_holders[stt.tmp] = vals[0] << vals[1]
                            elif any(o in op for o in ('Iop_Shr', 'Iop_Sar')):
                                pc_holders[stt.tmp] = vals[0] >> vals[1]
                    elif type(stt.data) == expr.Get:
                        reg_name = self.irsb.arch.translate_register_name(stt.data.offset)
                        if pc_holders.get(reg_name) is not None:
                            pc_holders[stt.tmp] = pc_holders[reg_name]
                    elif type(stt.data) == expr.ITE:
                        for d in (stt.data.iffalse, stt.data.iftrue):
                            if type(d) == expr.Const:
                                pc_holders[stt.tmp] = d.con.value
                            elif type(d) == expr.RdTmp and pc_holders.get(d.tmp) is not None:
                                pc_holders[stt.tmp] = pc_holders[d.tmp]
                    elif type(stt.data) == expr.RdTmp and pc_holders.get(stt.data.tmp) is not None:
                        pc_holders[stt.tmp] = pc_holders[stt.data.tmp]
                    elif type(stt.data) == expr.Const:
                        pc_holders[stt.tmp] = stt.data.con.value

                elif type(stt) == stmt.IMark:
                    inst_ctr += 1

            if lr_store_pc:
                self.irsb.jumpkind = 'Ijk_Call'

    _post_process_ARMEL = _post_process_ARM
    _post_process_ARMHF = _post_process_ARM

    def _post_process_MIPS32(self):
        # Handle unconditional branches
        # `beq $zero, $zero, xxxx`
        # It is translated to
        #
        # 15 | ------ IMark(0x401684, 4, 0) ------
        # 16 | t0 = CmpEQ32(0x00000000, 0x00000000)
        # 17 | PUT(128) = 0x00401688
        # 18 | ------ IMark(0x401688, 4, 0) ------
        # 19 | if (t0) goto {Ijk_Boring} 0x401684
        # 20 | PUT(128) = 0x0040168c
        # 21 | t4 = GET:I32(128)
        # NEXT: PUT(128) = t4; Ijk_Boring
        #

        stts = self.irsb.statements
        tmp_exit = None
        exit_stt_idx = None
        dst = None

        for i, stt in reversed(list(enumerate(stts))):
            if tmp_exit is None:
                # Looking for the Exit statement
                if isinstance(stt, stmt.Exit) and \
                        isinstance(stt.guard, expr.RdTmp):
                    tmp_exit = stt.guard.tmp
                    dst = stt.dst
                    exit_stt_idx = i
            else:
                # Looking for the WrTmp statement
                if isinstance(stt, stmt.WrTmp) and \
                                stt.tmp == tmp_exit:
                    if isinstance(stt.data, expr.Binop) and \
                                    stt.data.op == 'Iop_CmpEQ32' and \
                            isinstance(stt.data.child_expressions[0], expr.Const) and \
                            isinstance(stt.data.child_expressions[1], expr.Const) and \
                                    stt.data.child_expressions[0].con.value == stt.data.child_expressions[
                                1].con.value:

                        # Create a new IRConst
                        irconst = expr.Const.__new__(expr.Const)    # XXX: does this work???
                        irconst.con = dst
                        irconst.tag = 'Iex_Const'

                        self.irsb.statements = self.irsb.statements[: exit_stt_idx] + self.irsb.statements[exit_stt_idx + 1:]
                        # Replace the default exit!
                        self.irsb.next = irconst

                    else:
                        break

register(FixesPostProcessor)

from .. import stmt, expr
