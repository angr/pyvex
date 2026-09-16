import io
import pickle

import cffi
import cffi.model
import pytest

import pyvex.native as native


def _restricted_loads(blob):
    return native._RestrictedUnpickler(io.BytesIO(blob)).load()


def test_rejects_arbitrary_callable_gadget():
    class Evil:
        def __reduce__(self):
            return (print, ("pwned",))

    # A bare pickle.loads would invoke the callable; the restricted unpickler refuses.
    with pytest.raises(pickle.UnpicklingError):
        _restricted_loads(pickle.dumps(Evil()))


def test_rejects_cffi_model_helper_function():
    class Evil2:
        def __reduce__(self):
            return (cffi.model.global_cache, ())

    with pytest.raises(pickle.UnpicklingError):
        _restricted_loads(pickle.dumps(Evil2()))


def test_allows_legitimate_cffi_model_cache():
    ffi = cffi.FFI()
    ffi.cdef("typedef struct { int x; int y; } P; int add(int, int); enum C { A, B };")
    legit = {"_declarations": ffi._parser._declarations, "_int_constants": ffi._parser._int_constants}
    loaded = _restricted_loads(pickle.dumps(legit))
    assert set(loaded) == {"_declarations", "_int_constants"}
    assert loaded["_declarations"].keys() == legit["_declarations"].keys()
