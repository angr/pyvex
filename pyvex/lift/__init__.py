from ..block import IRSB
from .lifter import Lifter, Postprocessor

lifters = []
postprocessors = []

def register(lifter, arch):
    if issubclass(lifter, Lifter):
        lifters.append((lifter, arch))
    if issubclass(lifter, Postprocessor):
        postprocessors.append((lifter, arch))

from ..errors import PyVEXError

from .libvex import LibVEXLifter
from .fixes import FixesPostProcessor
