#!/usr/bin/env python3

import subprocess

args = [
    'run_qsym_afl.py', '-o', 'output', '-a', 'afl-master_1', '-n', 'qsym',
    '--', '/d/p/justafl/imginfo', '-f', '@@'
]

print(" ".join(args))

proc = subprocess.Popen(args=args)
