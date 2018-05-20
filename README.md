# pybintools
Python utility for extracting callgraphs and other related info from unstripped binaries.
# Usage
```python
from bintools import *
from pprint import pprint

# X86 binary with default tools
b = X86Binary('/bin/sh')

# ARM binary; arm-none-eabi-* tools are used
b = ARMBinary('my_arm_binary')

# use custom tools
b = ARMBinary('my_arm_binary', prefix='/path/to/toolchain/arm-linux-gnueabihf-')

# Get callgraph. C++ names are mangled.
g = b.get_callgraph()
pprint(g)

# demangle names and transform graph
dm = b.demangle_map(g.keys())
g_demangled = dict((dm[u], [dm.get(v,v) for v in vs]) for u,vs in g.items())

# get symbol sizes
sizes = b.get_symbol_sizes()
pprint(sizes)
```
