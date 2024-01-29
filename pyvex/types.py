from typing import TYPE_CHECKING, Any, Dict, List, Optional, Protocol, Tuple, Union, runtime_checkable

from cffi.api import FFI


class Register(Protocol):
    """
    A register. Pyvex should probably not have this dependency.
    """

    name: str


class Arch(Protocol):
    """
    An architecture description.
    """

    name: str
    ip_offset: int
    bits: int
    instruction_endness: str
    memory_endness: str
    byte_width: int
    register_list: List[Register]
    registers: Dict[str, Tuple[int, int]]

    def translate_register_name(self, offset: int, size: Optional[int] = None) -> Optional[str]: ...

    def get_register_offset(self, name: str) -> int: ...


@runtime_checkable
class LibvexArch(Protocol):
    """
    The description for an architecture that is usable with libvex
    """

    vex_arch: str
    vex_archinfo: Dict[str, Any]


PyLiftSource = Union[bytes, bytearray, memoryview]
if TYPE_CHECKING:
    CLiftSource = FFI.CData
else:
    CLiftSource = None
LiftSource = Union[PyLiftSource, CLiftSource]
