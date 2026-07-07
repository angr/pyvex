import logging

import bitstring

from pyvex.lifting.util import JumpKind, Type
from pyvex.lifting.util.instr_helper import Instruction, ParseError
from pyvex.lifting.util.lifter_helper import GymratLifter
from pyvex.types import Arch

log = logging.getLogger(__name__)


class ARMInstruction(Instruction):  # pylint: disable=abstract-method
    # NOTE: WARNING: There is no CPSR in VEX's ARM implementation
    # You must use straight nasty hacks instead.

    # NOTE 2: Something is goofy w/r/t archinfo and VEX; cc_op3 is used in ccalls, but there's
    # no cc_op3 in archinfo, angr itself uses cc_depn instead.  We do the same.

    def match_instruction(self, data, bitstrm):
        """
        ARM Instructions are pretty dense, so let's do what we can to weed them out
        """
        if "c" not in data or data["c"] == "1111":
            raise ParseError("Invalid ARM Instruction")

    def get_N(self):
        cc_op = self.get("cc_op", Type.int_32)
        cc_dep1 = self.get("cc_dep1", Type.int_32)
        cc_dep2 = self.get("cc_dep2", Type.int_32)
        cc_depn = self.get("cc_ndep", Type.int_32)
        return self.ccall(Type.int_32, "armg_calculate_flag_n", [cc_op, cc_dep1, cc_dep2, cc_depn])

    def get_C(self):
        cc_op = self.get("cc_op", Type.int_32)
        cc_dep1 = self.get("cc_dep1", Type.int_32)
        cc_dep2 = self.get("cc_dep2", Type.int_32)
        cc_depn = self.get("cc_ndep", Type.int_32)
        return self.ccall(Type.int_32, "armg_calculate_flag_c", [cc_op, cc_dep1, cc_dep2, cc_depn])

    def get_V(self):
        cc_op = self.get("cc_op", Type.int_32)
        cc_dep1 = self.get("cc_dep1", Type.int_32)
        cc_dep2 = self.get("cc_dep2", Type.int_32)
        cc_depn = self.get("cc_ndep", Type.int_32)
        return self.ccall(Type.int_32, "armg_calculate_flag_v", [cc_op, cc_dep1, cc_dep2, cc_depn])

    def get_Z(self):
        cc_op = self.get("cc_op", Type.int_32)
        cc_dep1 = self.get("cc_dep1", Type.int_32)
        cc_dep2 = self.get("cc_dep2", Type.int_32)
        cc_depn = self.get("cc_ndep", Type.int_32)
        return self.ccall(Type.int_32, "armg_calculate_flag_z", [cc_op.rdt, cc_dep1.rdt, cc_dep2.rdt, cc_depn.rdt])

    def evaluate_condition(self):
        # condition codes should be in 'c'
        cond = self.data["c"]
        if cond == "0000":
            # equal, z set
            return self.get_Z() == 1
        elif cond == "0001":
            # not equal, Z clear
            return self.get_Z() == 0
        elif cond == "0010":
            # Carry, C set
            return self.get_C() == 1
        elif cond == "0011":
            # Carry Clear, C clear
            return self.get_C() == 0
        elif cond == "0100":
            # MI / neagative / N set
            return self.get_N() == 1
        elif cond == "0101":
            # PL / plus / positive / N clear
            return self.get_N() == 0
        elif cond == "0110":
            # VS / V set / Overflow
            return self.get_V() == 1
        elif cond == "0111":
            # VC / V Clear / no overflow
            return self.get_V() == 0
        elif cond == "1000":
            # Hi / unsigned higher / C set, Z clear
            return (self.get_C() == 1) & (self.get_Z() == 0)
        elif cond == "1001":
            # LS / C clear, Z set
            return (self.get_C() == 0) & (self.get_Z() == 1)
        elif cond == "1011":
            # LT / Less than / N != V
            return self.get_N() != self.get_V()
        elif cond == "1100":
            # GT / greater than / Z clear and (n == v)
            return (self.get_Z() == 1) & (self.get_N() != self.get_V())
        elif cond == "1101":
            # LE / less than or equal to / Z set OR (N != V)
            return (self.get_Z() == 1) | (self.get_N() != self.get_V())
        else:
            # No condition
            return None

    def _load_le_instr(self, bitstream: bitstring.ConstBitStream, numbits: int) -> str:
        # THUMB mode instructions swap endianness every two bytes!
        if (self.addr & 1) == 1 and numbits > 16:
            chunk = ""
            oldpos = bitstream.pos
            try:
                for _ in range(0, numbits, 16):
                    chunk += bitstring.Bits(uint=bitstream.peek("uintle:%d" % 16), length=16).bin
                    bitstream.pos += 16
            finally:
                bitstream.pos = oldpos
            return chunk
        return super()._load_le_instr(bitstream, numbits)


class Instruction_MRC(ARMInstruction):
    name = "MRC"
    bin_format = "cccc1110CCC1nnnnddddppppOOOOOOOO"
    # 11101110000100010001111100010000
    # c = cond
    # C = Coprocessor operation mode
    # d = CPd
    # O = Offset
    # p = CP#

    def compute_result(self):  # pylint: disable=arguments-differ
        # TODO at least look at the conditionals
        # TODO Clobber the dst reg of MCR
        # TODO maybe treat coproc regs as simple storage (even though they are very much not)
        log.debug("Ignoring MRC instruction at %#x.", self.addr)


class Instruction_MCR(ARMInstruction):
    name = "MCR"
    bin_format = "cccc1110CCC0nnnnddddppppOOOOOOOO"
    # 11101110000000010000111100010000
    # c = cond
    # C = Coprocessor operation mode
    # d = CPd
    # O = Offset
    # p = CP#

    def compute_result(self):  # pylint: disable=arguments-differ
        # TODO at least look at the conditionals
        # TODO Clobber the dst reg of MCR
        # TODO maybe treat coproc regs as simple storage (even though they are very much not)
        log.debug("Ignoring MCR instruction at %#x.", self.addr)


class Instruction_MSR(ARMInstruction):
    name = "MSR"
    bin_format = "cccc00i10d10xxxj1111ssssssssssss"
    #             11100011001000011111000010010001
    #             11100001011011111111000000000001

    def compute_result(self):  # pylint: disable=arguments-differ
        log.debug(
            "Ignoring MSR instruction at %#x. VEX cannot support this instruction. "
            "See pyvex/lifting/gym/arm_spotter.py",
            self.addr,
        )


class Instruction_MRS(ARMInstruction):
    name = "MRS"
    bin_format = "cccc00010s001111dddd000000000000"

    def compute_result(self):  # pylint: disable=arguments-differ
        log.debug(
            "Ignoring MRS instruction at %#x. VEX cannot support this instruction. "
            "See pyvex/lifting/gym/arm_spotter.py",
            self.addr,
        )


class Instruction_STM(ARMInstruction):
    name = "STM"
    bin_format = "cccc100pu1w0bbbbrrrrrrrrrrrrrrrr"

    def match_instruction(self, data, bitstrm):
        # If we don't push anything, that's not real
        if int(data["r"]) == 0:
            raise ParseError("Invalid STM instruction")
        return True

    def compute_result(self):  # pylint: disable=arguments-differ
        log.debug(
            "Ignoring STMxx ^ instruction at %#x. This mode is not implemented by VEX! "
            "See pyvex/lifting/gym/arm_spotter.py",
            self.addr,
        )


class Instruction_LDM(ARMInstruction):
    name = "LDM"
    bin_format = "cccc100PU1W1bbbbrrrrrrrrrrrrrrrr"

    def match_instruction(self, data, bitstrm):
        # If we don't push anything, that's not real
        if int(data["r"]) == 0:
            raise ParseError("Invalid LDM instruction")
        return True

    def compute_result(self):  # pylint: disable=arguments-differ
        # test if PC will be set. If so, the jumpkind of this block should be Ijk_Ret
        log.debug("Spotting an LDM instruction at %#x.  This is not fully tested.  Prepare for errors.", self.addr)

        src_n = f"r{int(self.data['b'], 2)}"
        src = self.get(src_n, Type.int_32)

        for reg_num, bit in enumerate(self.data["r"]):
            reg_num = 15 - reg_num
            if bit == "1":
                if self.data["P"] == "1":
                    if self.data["U"] == "0":
                        src += 4
                    else:
                        src -= 4
                val = self.load(src, Type.int_32)
                self.put(val, f"r{reg_num}")
                if self.data["P"] == "0":
                    if self.data["U"] == "0":
                        src += 4
                    else:
                        src -= 4
                # If we touch PC, we're doing a RET!
                if reg_num == 15 and bit == "1":
                    cond = self.evaluate_condition()
                    if cond is not None:
                        self.jump(cond, val, JumpKind.Ret)
                    else:
                        self.jump(None, val, JumpKind.Ret)
        # Write-back
        if self.data["W"] == "1":
            self.put(src, src_n)


class Instruction_STC(ARMInstruction):
    name = "STC"
    bin_format = "cccc110PUNW0nnnnddddppppOOOOOOOO"

    def compute_result(self):  # pylint: disable=arguments-differ
        # TODO At least look at the conditionals
        log.debug("Ignoring STC instruction at %#x.", self.addr)


class Instruction_STC_THUMB(ARMInstruction):
    name = "STC"
    bin_format = "111c110PUNW0nnnnddddppppOOOOOOOO"

    def compute_result(self):  # pylint: disable=arguments-differ
        # TODO At least look at the conditionals
        log.debug("Ignoring STC instruction at %#x.", self.addr)


class Instruction_LDC(ARMInstruction):
    name = "LDC"
    bin_format = "cccc110PUNW1nnnnddddppppOOOOOOOO"

    def compute_result(self):  # pylint: disable=arguments-differ
        # TODO At least look at the conditionals
        # TODO Clobber the dest reg of LDC
        # TODO Maybe clobber the dst reg of CDP, if we're really adventurous
        log.debug("Ignoring LDC instruction at %#x.", self.addr)


class Instruction_LDC_THUMB(ARMInstruction):
    name = "LDC"
    bin_format = "111c110PUNW1nnnnddddppppOOOOOOOO"

    def compute_result(self):  # pylint: disable=arguments-differ
        # TODO At least look at the conditionals
        # TODO Clobber the dest reg of LDC
        # TODO Maybe clobber the dst reg of CDP, if we're really adventurous
        log.debug("Ignoring LDC instruction at %#x.", self.addr)


class Instruction_CDP(Instruction):
    name = "CDP"
    bin_format = "cccc1110oooonnnnddddppppPPP0mmmm"
    # c = cond
    # d = CPd
    # O = Offset
    # p = CP#

    def compute_result(self):  # pylint: disable=arguments-differ
        # TODO At least look at the conditionals
        # TODO Maybe clobber the dst reg of CDP, if we're really adventurous
        log.debug("Ignoring CDP instruction at %#x.", self.addr)


##
## Thumb! (ugh)
##


class ThumbInstruction(Instruction):  # pylint: disable=abstract-method
    def mark_instruction_start(self):
        self.irsb_c.imark(self.addr - 1, self.bytewidth, 1)

    def _special_reg_name(self, name, fallback=None):
        """
        Some MSR/MRS special registers (MSP, PSP, CPSR/XPSR, PRIMASK, ...) are
        only banked as separate registers on ArchARMCortexM. On other ARM
        variants, fall back to a generic register (e.g. "sp") if one is
        given; otherwise return None if this special register has no
        equivalent here.
        """
        for candidate in (name, fallback):
            if candidate is None:
                continue
            try:
                self.arch.get_register_offset(candidate)
                return candidate
            except (KeyError, ValueError):
                continue
        return None

    def _get_special_reg(self, name, fallback=None):
        """
        Read a banked special register (e.g. PRIMASK, MSP) if it exists on
        this architecture; otherwise log and return None.
        """
        reg = self._special_reg_name(name, fallback)
        if reg is None:
            log.debug(
                "[thumb] FIXME: %s at %#x is reading from unsupported special register %s on this "
                "architecture. Ignoring the instruction.",
                self.name,
                self.addr,
                name.upper(),
            )
            return None
        return self.get(reg, Type.int_32)

    def _put_special_reg(self, val, name, fallback=None):
        """
        Write a banked special register (e.g. PRIMASK, MSP) if it exists on
        this architecture; otherwise log and do nothing.
        """
        reg = self._special_reg_name(name, fallback)
        if reg is None:
            log.debug(
                "[thumb] FIXME: %s at %#x is writing to unsupported special register %s on this "
                "architecture. Ignoring the instruction.",
                self.name,
                self.addr,
                name.upper(),
            )
            return
        self.put(val, reg)

    def _read_cpsr_field(self, extract):
        """
        Read a field out of CPSR/XPSR via `extract(xpsr) -> value`, or return
        None if this architecture has no such banked register.
        """
        xpsr = self._get_special_reg("cpsr")
        if xpsr is None:
            return None
        return extract(xpsr)

    def _update_cpsr(self, update):
        """
        Read-modify-write CPSR/XPSR via `update(xpsr) -> new_xpsr`. Logs and
        does nothing if this architecture has no such banked register.
        """
        reg = self._special_reg_name("cpsr")
        if reg is None:
            log.debug(
                "[thumb] FIXME: %s at %#x is writing to unsupported special register CPSR/XPSR on this "
                "architecture. Ignoring the instruction.",
                self.name,
                self.addr,
            )
            return
        xpsr = self.get(reg, Type.int_32)
        self.put(update(xpsr), reg)


class Instruction_tCPSID(ThumbInstruction):
    name = "CPSID"
    bin_format = "101101x0011x0010"

    def compute_result(self):  # pylint: disable=arguments-differ
        # TODO haha lol yeah right
        log.debug("[thumb] Ignoring CPS instruction at %#x.", self.addr)


ASPR_MASK = 0b11111000000011110000000000000000
IPSR_MASK = 0b00000000000000000000000111111111
EPSR_MASK = 0b00000111000000001111110000000000


def get_apsr(xpsr):
    return xpsr & ASPR_MASK


def set_apsr(xpsr, apsr):
    return (xpsr & ~ASPR_MASK) | (apsr & ASPR_MASK)


def get_ipsr(xpsr):
    return xpsr & IPSR_MASK


def set_ipsr(xpsr, ipsr):
    return (xpsr & ~IPSR_MASK) | (ipsr & IPSR_MASK)


def get_epsr(xpsr):
    return xpsr & EPSR_MASK


def set_epsr(xpsr, epsr):
    return (xpsr & ~EPSR_MASK) | (epsr & EPSR_MASK)


class Instruction_tMSR(ThumbInstruction):
    name = "tMSR"
    bin_format = "10x0mmxxssssssss11110011100Rrrrr"

    def compute_result(self):  # pylint: disable=arguments-differ
        spec_reg = int(self.data["s"], 2)
        src_reg = f"r{int(self.data['r'], 2)}"

        # If 0, do not write the SPSR
        if self.data["R"] == "0":
            src_val = self.get(src_reg, Type.int_32)
            match spec_reg:
                case 0b00000000:  # APSR
                    # TODO: check mask
                    self._update_cpsr(lambda xpsr: set_apsr(xpsr, src_val))
                case 0b00000001:  # IAPSR
                    self._update_cpsr(lambda xpsr: set_ipsr(set_apsr(xpsr, src_val), src_val))
                case 0b00000010:  # EAPSR
                    self._update_cpsr(lambda xpsr: set_epsr(set_apsr(xpsr, src_val), src_val))
                case 0b00000011:  # XPSR
                    self._update_cpsr(lambda xpsr: src_val)
                case 0b00000101:  # IPSR
                    self._update_cpsr(lambda xpsr: set_ipsr(xpsr, src_val))
                case 0b00000110:  # EPSR
                    self._update_cpsr(lambda xpsr: set_epsr(xpsr, src_val))
                case 0b00000111:  # IEPSR
                    self._update_cpsr(lambda xpsr: set_epsr(set_ipsr(xpsr, src_val), src_val))
                case 0b00001000:  # MSP
                    self._put_special_reg(src_val, "msp", "sp")
                case 0b00001001:  # PSP
                    self._put_special_reg(src_val, "psp")
                case 0b00001010:  # MSPLIM
                    self._put_special_reg(src_val, "msplim")
                case 0b00001011:  # PSPLIM
                    self._put_special_reg(src_val, "psplim")
                case 0b00010000:  # PRIMASK
                    self._put_special_reg(src_val, "primask")
                case 0b00010001:  # BASEPRI
                    self._put_special_reg(src_val, "basepri")
                case 0b00010010:  # BASEPRI_MAX
                    log.debug(
                        "[thumb] FIXME: tMSR at %#x is writing to unsupported special register BASEPRI_MAX."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b00010011:  # FAULTMASK
                    self._put_special_reg(src_val, "faultmask")
                case 0b00010100:  # CONTROL
                    self._put_special_reg(src_val, "control")
                case 0b00100000:  # PAC_KEY_P_0
                    log.debug(
                        "[thumb] FIXME: tMSR at %#x is writing to unsupported special register PAC_KEY_P_0."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b00100001:  # PAC_KEY_P_1
                    log.debug(
                        "[thumb] FIXME: tMSR at %#x is writing to unsupported special register PAC_KEY_P_1."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b00100010:  # PAC_KEY_P_2
                    log.debug(
                        "[thumb] FIXME: tMSR at %#x is writing to unsupported special register PAC_KEY_P_2."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b00100011:  # PAC_KEY_P_3
                    log.debug(
                        "[thumb] FIXME: tMSR at %#x is writing to unsupported special register PAC_KEY_P_3."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b00100100:  # PAC_KEY_U_0
                    log.debug(
                        "[thumb] FIXME: tMSR at %#x is writing to unsupported special register PAC_KEY_U_0."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b00100101:  # PAC_KEY_U_1
                    log.debug(
                        "[thumb] FIXME: tMSR at %#x is writing to unsupported special register PAC_KEY_U_1."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b00100110:  # PAC_KEY_U_2
                    log.debug(
                        "[thumb] FIXME: tMSR at %#x is writing to unsupported special register PAC_KEY_U_2."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b00100111:  # PAC_KEY_U_3
                    log.debug(
                        "[thumb] FIXME: tMSR at %#x is writing to unsupported special register PAC_KEY_U_3."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b10001000:  # MSP_NS
                    self._put_special_reg(src_val, "msp_ns")
                case 0b10001001:  # PSP_NS
                    self._put_special_reg(src_val, "psp_ns")
                case 0b10001010:  # MSPLIM_NS
                    self._put_special_reg(src_val, "msplim_ns")
                case 0b10001011:  # PSPLIM_NS
                    self._put_special_reg(src_val, "psplim_ns")
                case 0b10010000:  # PRIMASK_NS
                    self._put_special_reg(src_val, "primask_ns")
                case 0b10010001:  # BASEPRI_NS
                    self._put_special_reg(src_val, "basepri_ns")
                case 0b10010011:  # FAULTMASK_NS
                    self._put_special_reg(src_val, "faultmask_ns")
                case 0b10010100:  # CONTROL_NS
                    log.debug(
                        "[thumb] FIXME: tMSR at %#x is writing to unsupported special register CONTROL_NS."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b10011000:  # SP_NS
                    log.debug(
                        "[thumb] FIXME: tMSR at %#x is writing to unsupported special register SP_NS."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b10100000:  # PAC_KEY_P_0_NS
                    log.debug(
                        "[thumb] FIXME: tMSR at %#x is writing to unsupported special register PAC_KEY_P_0_NS."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b10100001:  # PAC_KEY_P_1_NS
                    log.debug(
                        "[thumb] FIXME: tMSR at %#x is writing to unsupported special register PAC_KEY_P_1_NS."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b10100010:  # PAC_KEY_P_2_NS
                    log.debug(
                        "[thumb] FIXME: tMSR at %#x is writing to unsupported special register PAC_KEY_P_2_NS."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b10100011:  # PAC_KEY_P_3_NS
                    log.debug(
                        "[thumb] FIXME: tMSR at %#x is writing to unsupported special register PAC_KEY_P_3_NS."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b10100100:  # PAC_KEY_U_0_NS
                    log.debug(
                        "[thumb] FIXME: tMSR at %#x is writing to unsupported special register PAC_KEY_U_0_NS."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b10100101:  # PAC_KEY_U_1_NS
                    log.debug(
                        "[thumb] FIXME: tMSR at %#x is writing to unsupported special register PAC_KEY_U_1_NS."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b10100110:  # PAC_KEY_U_2_NS
                    log.debug(
                        "[thumb] FIXME: tMSR at %#x is writing to unsupported special register PAC_KEY_U_2_NS."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b10100111:  # PAC_KEY_U_3_NS
                    log.debug(
                        "[thumb] FIXME: tMSR at %#x is writing to unsupported special register PAC_KEY_U_3_NS."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case _:
                    log.debug(
                        "[thumb] FIXME: tMSR at %#x is writing to unsupported special register %#x."
                        "Ignoring the instruction.",
                        self.addr,
                        spec_reg,
                    )
        else:
            log.debug("[thumb] FIXME: tMSR at %#x is writing to SPSR." "Ignoring the instruction.", self.addr)


class Instruction_tMRS(ThumbInstruction):
    name = "tMRS"
    bin_format = "10x0mmmmxxxxxxxx11110011111Rrrrr"

    def compute_result(self):  # pylint: disable=arguments-differ
        spec_reg = int(self.data["x"], 2)
        dest_reg = f"r{int(self.data['m'], 2)}"

        spec_val = None

        # Reading from CPSR
        if self.data["R"] == "0":
            # See special registers constants here:
            # https://github.com/aquynh/capstone/blob/45bec1a691e455b864f7e4d394711a467e5493dc/arch/ARM/ARMInstPrinter.c#L1654
            match spec_reg:
                case 0b00000000:  # APSR
                    spec_val = self._read_cpsr_field(get_apsr)
                case 0b00000001:  # IAPSR
                    spec_val = self._read_cpsr_field(lambda xpsr: get_apsr(xpsr) | get_ipsr(xpsr))
                case 0b00000010:  # EAPSR
                    spec_val = self._read_cpsr_field(lambda xpsr: get_apsr(xpsr) | get_epsr(xpsr))
                case 0b00000011:  # XPSR
                    spec_val = self._read_cpsr_field(lambda xpsr: xpsr)
                case 0b00000101:  # IPSR
                    spec_val = self._read_cpsr_field(get_ipsr)
                case 0b00000110:  # EPSR
                    spec_val = self._read_cpsr_field(get_epsr)
                case 0b00000111:  # IEPSR
                    spec_val = self._read_cpsr_field(lambda xpsr: get_ipsr(xpsr) | get_epsr(xpsr))
                case 0b00001000:  # MSP
                    spec_val = self._get_special_reg("msp", "sp")
                case 0b00001001:  # PSP
                    spec_val = self._get_special_reg("psp")
                case 0b00001010:  # MSPLIM
                    spec_val = self._get_special_reg("msplim")
                case 0b00001011:  # PSPLIM
                    spec_val = self._get_special_reg("psplim")
                case 0b00010000:  # PRIMASK
                    spec_val = self._get_special_reg("primask")
                case 0b00010001:  # BASEPRI
                    spec_val = self._get_special_reg("basepri")
                case 0b00010010:  # BASEPRI_MAX
                    log.debug(
                        "[thumb] FIXME: tMRS at %#x is reading from unsupported special register BASEPRI_MAX."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b00010011:  # FAULTMASK
                    spec_val = self._get_special_reg("faultmask")
                case 0b00010100:  # CONTROL
                    spec_val = self._get_special_reg("control")
                case 0b00100000:  # PAC_KEY_P_0
                    log.debug(
                        "[thumb] FIXME: tMRS at %#x is reading from unsupported special register PAC_KEY_P_0."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b00100001:  # PAC_KEY_P_1
                    log.debug(
                        "[thumb] FIXME: tMRS at %#x is reading from unsupported special register PAC_KEY_P_1."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b00100010:  # PAC_KEY_P_2
                    log.debug(
                        "[thumb] FIXME: tMRS at %#x is reading from unsupported special register PAC_KEY_P_2."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b00100011:  # PAC_KEY_P_3
                    log.debug(
                        "[thumb] FIXME: tMRS at %#x is reading from unsupported special register PAC_KEY_P_3."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b00100100:  # PAC_KEY_U_0
                    log.debug(
                        "[thumb] FIXME: tMRS at %#x is reading from unsupported special register PAC_KEY_U_0."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b00100101:  # PAC_KEY_U_1
                    log.debug(
                        "[thumb] FIXME: tMRS at %#x is reading from unsupported special register PAC_KEY_U_1."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b00100110:  # PAC_KEY_U_2
                    log.debug(
                        "[thumb] FIXME: tMRS at %#x is reading from unsupported special register PAC_KEY_U_2."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b00100111:  # PAC_KEY_U_3
                    log.debug(
                        "[thumb] FIXME: tMRS at %#x is reading from unsupported special register PAC_KEY_U_3."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b10001000:  # MSP_NS
                    spec_val = self._get_special_reg("msp_ns")
                case 0b10001001:  # PSP_NS
                    spec_val = self._get_special_reg("psp_ns")
                case 0b10001010:  # MSPLIM_NS
                    spec_val = self._get_special_reg("msplim_ns")
                case 0b10001011:  # PSPLIM_NS
                    spec_val = self._get_special_reg("psplim_ns")
                case 0b10010000:  # PRIMASK_NS
                    spec_val = self._get_special_reg("primask_ns")
                case 0b10010001:  # BASEPRI_NS
                    spec_val = self._get_special_reg("basepri_ns")
                case 0b10010011:  # FAULTMASK_NS
                    spec_val = self._get_special_reg("faultmask_ns")
                case 0b10010100:  # CONTROL_NS
                    spec_val = self._get_special_reg("control_ns")
                case 0b10011000:  # SP_NS
                    spec_val = self._get_special_reg("sp_main_ns")
                case 0b10100000:  # PAC_KEY_P_0_NS
                    log.debug(
                        "[thumb] FIXME: tMRS at %#x is reading from unsupported special register PAC_KEY_P_0_NS."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b10100001:  # PAC_KEY_P_1_NS
                    log.debug(
                        "[thumb] FIXME: tMRS at %#x is reading from unsupported special register PAC_KEY_P_1_NS."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b10100010:  # PAC_KEY_P_2_NS
                    log.debug(
                        "[thumb] FIXME: tMRS at %#x is reading from unsupported special register PAC_KEY_P_2_NS."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b10100011:  # PAC_KEY_P_3_NS
                    log.debug(
                        "[thumb] FIXME: tMRS at %#x is reading from unsupported special register PAC_KEY_P_3_NS."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b10100100:  # PAC_KEY_U_0_NS
                    log.debug(
                        "[thumb] FIXME: tMRS at %#x is reading from unsupported special register PAC_KEY_U_0_NS."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b10100101:  # PAC_KEY_U_1_NS
                    log.debug(
                        "[thumb] FIXME: tMRS at %#x is reading from unsupported special register PAC_KEY_U_1_NS."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b10100110:  # PAC_KEY_U_2_NS
                    log.debug(
                        "[thumb] FIXME: tMRS at %#x is reading from unsupported special register PAC_KEY_U_2_NS."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case 0b10100111:  # PAC_KEY_U_3_NS
                    log.debug(
                        "[thumb] FIXME: tMRS at %#x is reading from unsupported special register PAC_KEY_U_3_NS."
                        "Ignoring the instruction.",
                        self.addr,
                    )
                case _:
                    log.debug(
                        "[thumb] FIXME: tMRS at %#x is reading from unsupported special register %#x."
                        "Ignoring the instruction.",
                        self.addr,
                        spec_reg,
                    )
        else:
            log.debug("[thumb] tMRS at %#x is reading SPSR." "Ignoring the instruction.", self.addr)

        if spec_val is not None:
            self.put(spec_val, dest_reg)


class Instruction_tDMB(ThumbInstruction):
    name = "DMB"
    bin_format = "100011110101xxxx1111001110111111"

    def compute_result(self):  # pylint: disable=arguments-differ
        # TODO haha lol yeah right
        log.debug("[thumb] Ignoring DMB instruction at %#x.", self.addr)


class Instruction_WFI(ThumbInstruction):
    name = "WFI"
    bin_format = "10111111001a0000"
    # 1011111100110000

    def compute_result(self):  # pylint: disable=arguments-differ
        log.debug("[thumb] Ignoring WFI instruction at %#x.", self.addr)


class ARMSpotter(GymratLifter):
    arm_instrs = [
        Instruction_MRC,
        Instruction_MCR,
        Instruction_MSR,
        Instruction_MRS,
        Instruction_STM,
        Instruction_LDM,
        Instruction_STC,
        Instruction_LDC,
        Instruction_CDP,
    ]
    thumb_instrs = [
        Instruction_tCPSID,
        Instruction_tMSR,
        Instruction_tMRS,
        Instruction_WFI,
        Instruction_tDMB,
        Instruction_STC_THUMB,
        Instruction_LDC_THUMB,
    ]

    def __init__(self, arch: Arch, addr: int):
        super().__init__(arch, addr)
        self.thumb: bool = False

    def _lift(self):
        if self.irsb.addr & 1:
            # Thumb!
            self.instrs = self.thumb_instrs
            self.thumb = True
        else:
            self.instrs = self.arm_instrs
            self.thumb = False
        super()._lift()
