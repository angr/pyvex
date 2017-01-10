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

            lr_store_id = None
            inst_ctr = 1
            for i, stt in reversed(list(enumerate(self.irsb.statements))):
                if isinstance(stt, stmt.Put):
                    if stt.offset == self.irsb.arch.registers['lr'][0]:
                        lr_store_id = i
                        break
                if isinstance(stt, stmt.IMark):
                    inst_ctr += 1

            if lr_store_id is not None and inst_ctr == 2:
                self.irsb.jumpkind = "Ijk_Call"

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
                        irconst.result_type = dst.type
                        irconst.tag = 'Iex_Const'

                        self.irsb.statements = self.irsb.statements[: exit_stt_idx] + self.irsb.statements[exit_stt_idx + 1:]
                        # Replace the default exit!
                        self.irsb.next = irconst

                    else:
                        break

register(FixesPostProcessor)

from .. import stmt, expr
