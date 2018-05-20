import subprocess as sp
import re
from collections import defaultdict

__all__ = ['ArmBinary', 'X86Binary']

class Binary:
    _objdump_opts = []

    def __init__(self, binary, prefix=''):
        self.binary = binary
        self.OBJDUMP_BIN = prefix + 'objdump'
        self.READELF_BIN = prefix + 'readelf'
        self.CPPFILT_BIN = prefix + 'c++filt'

    def get_callgraph(self):
        """Return adjacency list of all functions.

        Leaves are included. Self-references are excluded.
        Only direct calls are accounted for, indirect calls and storing
        a pointer to a function are not accounted for.
        """
        cmd = [self.OBJDUMP_BIN, '-d'] + self._objdump_opts + [self.binary]
        f = sp.run(cmd, stdout=sp.PIPE, check=True).stdout
        g = defaultdict(set)

        rc = re.compile(r'<(.*?)>:')
        rb = re.compile(r'<([^+>]+)')
        current = None

        for l in f.decode('ascii').split('\n'):
            m = rc.search(l)
            if m:
                current = m.group(1)
                g[current]
                continue
            fields = l.split('\t', 3)
            if len(fields) < 3:
                continue
            ia = fields[2].split()
            instr = ia[0]
            trg = ia[-1]
            if self._is_branch(instr) and '<' in trg:
                target = rb.search(trg).group(1)
                if current != target:
                    g[current].add(target)
        return g

    def get_symbol_sizes(self):
        f = sp.run([self.READELF_BIN, '-s', '-W', self.binary], stdout=sp.PIPE, check=True).stdout.decode('ascii').split('\n')
        res = dict()
        for l in f:
            l = l.split()
            if len(l) < 8:
                continue
            try:
                size = int(l[2])
                name = l[7]
                res[name] = size
            except ValueError:
                continue
        return res

    def demangle(self, mangled):
        """For a list of mangled names, return a list of demangled names"""
        input = '\n'.join(mangled).encode('ascii')
        res = sp.run([self.CPPFILT_BIN], input=input, stdout=sp.PIPE, check=True)
        out = res.stdout.decode('ascii').split('\n')
        return out

    def demangle_map(self, mangled):
        """Return dict mapping mangled names to their unmangled names."""
        return dict(zip(mangled, self.demangle(mangled)))

class ArmBinary(Binary):
    _is = 'blx,bx,bl,b'.split(',')
    _cs = 'eq,ne,cs,hs,cc,lo,mi,pl,vs,vc,hi,ls,ge,lt,gt,le,'.split(',')
    _ws = '.n,.w,'.split(',')

    def __init__(self, binary, prefix='arm-none-eabi-'):
        super().__init__(binary, prefix=prefix)

    @staticmethod
    def _stripprefix(s, prefs):
        """If some element of `prefs` is a prefix of `s`, strip it and return
        the rest, otherwise return None.

        If `s` is None, return None (allows for monadic use).
        """
        if s is None:
            return None
        if s == '':
            return s
        for p in prefs:
            if s.startswith(p):
                return s[len(p):]
        return None

    def _is_branch(self, i):
        """Return true if `i` is a branch instruction."""
        i2 = self._stripprefix(i, self._is)
        i3 = self._stripprefix(i2, self._cs)
        i4 = self._stripprefix(i3, self._ws)
        return i4 == ''

class X86Binary(Binary):
    _objdump_opts = ['-Mintel-mnemonics']
    _is = 'jmp,je,jne,jg,jge,ja,jae,jl,jle,jb,jbe,jo,jno,jz,jnz,js,jns,call'.split(',')
    def _is_branch(self, i):
        return i in self._is
