#!/usr/bin/python3
# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
import re
import sys
from contextlib import contextmanager
from enum import IntEnum
from io import StringIO

import atheris

with atheris.instrument_imports(include=["pyvex"]):
    import pyvex

# Additional imports
from enhanced_fdp import EnhancedFuzzedDataProvider

register_error_msg = re.compile("Register .*? does not exist!")


@contextmanager
def nostdout():
    saved_stdout = sys.stdout
    saved_stderr = sys.stderr
    sys.stdout = StringIO()
    sys.stderr = StringIO()
    yield
    sys.stdout = saved_stdout
    sys.stderr = saved_stderr


# Save all available architectures off
available_archs = [
    pyvex.ARCH_X86,
    pyvex.ARCH_AMD64,
    pyvex.ARCH_ARM_LE,
    pyvex.ARCH_ARM_BE,
    pyvex.ARCH_ARM64_LE,
    pyvex.ARCH_ARM64_BE,
    pyvex.ARCH_PPC32,
    pyvex.ARCH_PPC64_BE,
    pyvex.ARCH_PPC64_LE,
    pyvex.ARCH_S390X,
    pyvex.ARCH_MIPS32_BE,
    pyvex.ARCH_MIPS32_LE,
    pyvex.ARCH_MIPS64_BE,
    pyvex.ARCH_MIPS64_LE,
]


class SupportedOptLevels(IntEnum):
    """
    Enumerates the supported optimization levels within pyvex, as derived from the documentation
    """

    StrictUnopt = -1
    Unopt = 0
    Opt = 1
    StrictOpt = 2


def consume_random_arch(fdp: atheris.FuzzedDataProvider) -> pyvex.arches.PyvexArch:
    return fdp.PickValueInList(available_archs)


def TestOneInput(data: bytes):
    fdp = EnhancedFuzzedDataProvider(data)

    arch = consume_random_arch(fdp)

    try:
        with nostdout():
            data = fdp.ConsumeRandomBytes()
            max_bytes = fdp.ConsumeIntInRange(0, len(data))
            irsb = pyvex.lift(
                data,
                fdp.ConsumeInt(arch.bits),
                arch,
                max_bytes=fdp.ConsumeIntInRange(0, len(data)),
                max_inst=fdp.ConsumeInt(16),
                bytes_offset=fdp.ConsumeIntInRange(0, max_bytes),
                opt_level=fdp.PickValueInEnum(SupportedOptLevels),
            )
            irsb.pp()
        return 0
    except pyvex.PyVEXError:
        return -1
    except ValueError as e:
        if re.match(register_error_msg, str(e)):
            return -1
        raise e
    except OverflowError:
        return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
