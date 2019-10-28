import re
import os
import sys
import cffi
import subprocess
import platform

import logging
l = logging.getLogger('cffier')
l.setLevel(logging.DEBUG)


def find_good_scan(questionable):
    known_good = []

    end_line = len(questionable)

    while len(questionable):
        ffi = cffi.FFI()
        l.debug("scan - trying %d good and %d questionable", len(known_good), len(questionable))

        candidate = known_good + questionable[:end_line]
        failed_line = -1

        try:
            ffi.cdef('\n'.join(candidate))

            known_good = candidate
            questionable = questionable[end_line:]
            end_line = len(questionable)
        except AssertionError:
            questionable = questionable[1:]
            end_line = len(questionable)
        except cffi.CDefError as e:
            if '<cdef source string>' in str(e):
                failed_line = int(str(e).split('\n')[-1].split(':')[1])-1
            elif str(e).count(':') >= 2:
                failed_line = int(str(e).split('\n')[1].split(':')[1])
                failed_line_description = str(e).split('\n')[0]
                idx1 = failed_line_description.index('"')
                idx2 = failed_line_description.rindex('"')
                failed_reason = failed_line_description[idx1+1:idx2]

                for i in range(failed_line, -1, -1):
                    if failed_reason in candidate[i]:
                        failed_line = i
            elif 'unrecognized construct' in str(e):
                failed_line = int(str(e).split()[1][:-1])-1
            elif 'end of input' in str(e):
                end_line -= 1
            else:
                raise Exception("Unknown error")
        except cffi.FFIError as e:
            if str(e).count(':') >= 2:
                failed_line = int(str(e).split('\n')[0].split(':')[1])-1
            else:
                raise Exception("Unknown error")

        if failed_line != -1:
            end_line = failed_line-len(known_good)

        if end_line == 0:
            questionable = questionable[1:]
            end_line = len(questionable)
    return known_good


def doit(vex_path):
    cpplist = ['cl', 'cpp']
    cpp = os.getenv("CPP")
    if cpp:
        cpplist.insert(0, cpp)
    if platform.system() == 'Darwin':
        cpplist.insert(0, "clang")

    errs = []
    for cpp in cpplist:
        cmd = [cpp, '-I' + vex_path, os.path.join("pyvex_c", "pyvex.h")]
        if cpp in ('cl', 'clang', 'gcc', 'cc', 'clang++', 'g++'):
            cmd.append("-E")
        try:
            p = subprocess.Popen(cmd,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            header, stderr = p.communicate()
            try:
                header = header.decode("utf-8")
                stderr = stderr.decode("utf-8")
            except UnicodeDecodeError:
                # They don't have to be unicode on Windows
                pass

            if not header.strip() or p.returncode != 0:
                errs.append((" ".join(cmd), p.returncode, stderr))
                continue
            else:
                break
        except OSError:
            errs.append((" ".join(cmd), -1, "does not exist"))
            continue
    else:
        l.warning("failed commands:\n" +
                  "\n".join("{} ({}) -- {}".format(*e) for e in errs))
        raise Exception(
            "Couldn't process pyvex headers." +
            "Please set CPP environmental variable to local path of \"cpp\"." +
            "Note that \"cpp\" and \"g++\" are different."
        )
    # header = vex_pp + pyvex_pp

    linesep = '\r\n' if '\r\n' in header else '\n'
    ffi_text = linesep.join(line for line in header.split(linesep) if '#' not in line and line.strip() != '' and 'jmp_buf' not in line and not ('=' in line and ';' in line))
    ffi_text = re.sub('\{\s*\} NoOp;', '{ int DONOTUSE; } NoOp;', ffi_text)
    ffi_text = re.sub('__attribute__\s*\(.*\)', '', ffi_text)
    ffi_text = re.sub('__declspec\s*\([^\)]*\)', '', ffi_text)
    ffi_text = ffi_text.replace('__const', 'const')
    ffi_text = ffi_text.replace('__inline', '')
    ffi_text = ffi_text.replace('__w64', '')
    ffi_text = ffi_text.replace('__cdecl', '')
    ffi_text = ffi_text.replace('__int64', 'long')
    ffi_lines = ffi_text.split(linesep)

    good = find_good_scan(ffi_lines)
    good += ['extern VexControl vex_control;']

    with open('pyvex/vex_ffi.py', 'w') as fp:
        fp.write('ffi_str = """' + '\n'.join(good) + '"""\n')
        fp.write('guest_offsets = ' + repr(get_guest_offsets(vex_path)) + '\n')

def get_guest_offsets(vex_path):
    fname = os.path.join(vex_path, 'libvex_guest_offsets.h')
    out = {}
    with open(fname) as fp:
        for line in fp:
            if line.startswith('#define'):
                _, names, val = line.split()
                val = int(val, 0)
                assert names.startswith('OFFSET_')
                _, arch, reg = names.split('_', 2)
                out[(arch, reg.lower())] = val
    return out

if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.DEBUG)
    doit(sys.argv[1])
