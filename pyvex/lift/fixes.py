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

            pc_holders = []
            lr_store_pc = False
            inst_ctr = 1
            next_inst_addr = self.irsb.statements[0].addr + self.irsb.size
            for stt in reversed(list(self.irsb.statements)):
                # lr is modified within the last 2 instructions of the block... 
                if isinstance(stt, stmt.Put) and inst_ctr == 2:
                    if stt.offset == self.irsb.arch.registers['lr'][0]:
                        # ... by a temporary variable, so track it down to see whether
                        # pc is the source of the write
                        if isinstance(stt.data, expr.RdTmp):
                            pc_holders.append(stt.data.tmp)
                        # ... by a constant, so test whether it is the address of the
                        # next instruction
                        elif isinstance(stt.data, expr.Const):
                            if stt.data.con == next_inst_addr:
                                lr_store_pc = True
                            break
                # Tracking down the temporary variable that modifies lr
                if isinstance(stt, stmt.WrTmp) and stt.tmp in pc_holders:
                    # pc found
                    if isinstance(stt.data, expr.Get):
                        if stt.data.offset == self.irsb.arch.registers['pc'][0]:
                            lr_store_pc = True
                            break
                    # the temporary variable can hold not exactly pc but
                    # something relative to pc
                    elif isinstance(stt.data, (expr.Unop, expr.Binop,
                                               expr.Triop, expr.Qop)):
                        pc_holders.pop()
                        for arg in stt.data.args:
                            if isinstance(arg, expr.RdTmp):
                                pc_holders.append(arg.tmp)
                if isinstance(stt, stmt.IMark):
                    inst_ctr += 1

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
