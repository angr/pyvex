import sys
import pyvex
import binascii
from r2.r_core import *
from r2.r_bin import *

def disass_func(c, binary, f):
  if f.ninstr == 0: return None
  c.seek(f.addr, 0)
  c.block_size(f.size)

  # R2 Base64 print doesn't work for cmd_str
  fbytes = c.cmd_str("p8")
  fbytes = binascii.unhexlify(fbytes.strip())
  assert len(fbytes) == f.size

  irsb = pyvex.IRSB(bytes=fbytes, mem_addr=f.addr)
  return (f.name, irsb)

def load_file(f):
  core = RCore()
  open_res = core.file_open(f, 0, 0)
  if open_res is None:
    raise IOError("Radare failed to open file: " + repr(f))
  bs = open(f, "rb").read()

  core.bin_load(None)
  core.cmd0("e scr.interactive=false")
  core.anal_all()

  b = core.bin
  info = b.get_info()
  if not info:
    raise IOError("Radare failed to get program info!")

  anal = core.anal
  fcns = anal.get_fcns()

  return list(filter(None, (disass_func(core, b, f) for f in fcns)))

if __name__ == "__main__":
  funcs = load_file(sys.argv[1])
  for n,func in funcs:
    print n
    func.pp()
