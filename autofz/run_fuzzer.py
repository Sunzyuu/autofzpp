import os
from time import sleep
from typing import Dict
INPUT_DIR = 'queue'
CRASH_DIR = 'crashes'

# NOTE: you can define your own config
CONFIG: Dict = {
    # these will be default parameters for cli.py
    'scheduler': {
        'prep_time': 300,
        'focus_time': 300,
        'coverage_update_time': 30,
        'sync_time': 300,
        'timeout': '24h'
    },
    # unused now
    'docker': {
        'root_dir': '/work/autofz',
        'network': 'autofz'
    },
    # binary directories for AFL-compiled binaries
    # justafl is used to get AFL bitmap
    # aflasan is used to triage crashes/bugs
    'evaluator': {
        'binary_root': '/d/p/justafl',
        'binary_crash_root': '/d/p/aflasan',
    },
    # only specify basic things
    # how to launch fuzzers with proper arguments is handled by fuzzer driver
    'fuzzer': {
        'afl': {
            'input_dir': INPUT_DIR, # queue dir
            'crash_dir': CRASH_DIR,
            'skip_crash_file': ['README.txt'],
            'command': '/fuzzer/afl/afl-fuzz', # fuzzer binary path
            'target_root': '/d/p/justafl', # which binary is used to fuzz
            'afl_based': True,
        },
        'aflfast': {
            'input_dir': INPUT_DIR,
            'crash_dir': CRASH_DIR,
            'skip_crash_file': ['README.txt'],
            'command': '/fuzzer/aflfast/afl-fuzz',
            'target_root': '/d/p/justafl',
            'afl_based': True
        },
        'fairfuzz': {
            'input_dir': INPUT_DIR,
            'crash_dir': CRASH_DIR,
            'skip_crash_file': ['README.txt'],
            'command': '/fuzzer/afl-rb/afl-fuzz',
            'target_root': '/d/p/justafl',
            'afl_based': True
        },
        'mopt': {
            'input_dir': INPUT_DIR,
            'crash_dir': CRASH_DIR,
            'skip_crash_file': ['README.txt'],
            'command': '/fuzzer/MOpt-AFL/MOpt/afl-fuzz',
            'target_root': '/d/p/justafl',
            'afl_based': True,
        },
        'learnafl': {
            'input_dir': INPUT_DIR,
            'crash_dir': CRASH_DIR,
            'skip_crash_file': ['README.txt'],
            'command': '/fuzzer/LearnAFL/afl-fuzz',
            'target_root': '/d/p/justafl',
            'afl_based': True
        },
        'qsym': {
            'input_dir': INPUT_DIR,
            'crash_dir': CRASH_DIR,
            'skip_crash_file': ['README.txt'],
            'afl_based': True,
            'target_root': '/d/p/normal',  # for qsym
            # afl_command # reuse base afl
            'qsym_command': '/fuzzer/qsym/bin/run_qsym_afl.py'
        },
        'lafintel': {
            'input_dir': INPUT_DIR,
            'crash_dir': CRASH_DIR,
            'skip_crash_file': ['README.txt'],
            'command': '/fuzzer/afl++/afl-fuzz',
            'target_root': '/d/p/lafintel',
            'afl_based': True
        },
        'redqueen': {
            'input_dir': INPUT_DIR,
            'crash_dir': CRASH_DIR,
            'skip_crash_file': ['README.txt'],
            'target_root': '/d/p/aflclangfast',
            'target_root_cmp': '/d/p/aflclangfastcmplog',
            'command': '/fuzzer/afl++/afl-fuzz',
            'afl_based': True
        },
        'radamsa': {
            'input_dir': INPUT_DIR,
            'crash_dir': CRASH_DIR,
            'skip_crash_file': ['README.txt'],
            'target_root': '/d/p/aflclangfast',
            'command': '/fuzzer/afl++/afl-fuzz',
            'aflpp_dir': '/fuzzer/afl++',
            'afl_based': True
        },
        'angora': {
            'input_dir': INPUT_DIR,
            'crash_dir': CRASH_DIR,
            'create_output_dir': False,
            'target_root': '/d/p/angora/fast',
            'target_root_taint': '/d/p/angora/taint',
            'command': '/fuzzer/angora/angora_fuzzer',
            'afl_based': False,
        },
        'libfuzzer': {
            'input_dir': INPUT_DIR,
            'crash_dir': CRASH_DIR,
            'target_root': '/d/p/libfuzzer',
            'skip_crash_file': ['README.txt'],
            'command': None,  # target as fuzzer
            'afl_based': False
        }
    },
    # each target has a group like unibench/fuzzer-test-suite
    'target': {
        'pcapfix': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/pcap',
            'input_model': 'pcap.xml',
            'code_dir': 'unibench/pcapfix',
            'args': {
                'default': '-d @@',
            },
            'unsupported': ['libfuzzer']
        },
        'exiv2': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/jpg',
            'code_dir': 'unibench/exiv2-0.26',
            'input_model': 'jpeg.xml',
            'dict': 'jpeg.dict',
            # default is AFL-style (@@ for input file)
            'args': {
                'default': '@@',
            },
            # fuzzers that do not support this target.
            # autofz will do some sanity check when started.
            'unsupported': ['libfuzzer']
        },
        'gdk-pixbuf-pixdata': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/jpg',
            'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            'input_model': 'jpeg.xml',
            'dict': 'jpeg.dict',
            'args': {
                'default': '@@ /dev/null',
            },
            'unsupported': ['libfuzzer', 'angora', 'qsym']
        },
        'imginfo': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/jpg',
            'code_dir': 'unibench/jasper-2.0.12',
            'input_model': 'jpeg.xml',
            'dict': 'jpeg.dict',
            'args': {
                'default': '-f @@',
            },
            'unsupported': ['libfuzzer']
        },
        'jhead': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/jpg',
            'code_dir': 'unibench/jhead-3.00',
            'input_model': 'jpeg.xml',
            'dict': 'jpeg.dict',
            'args': {
                'default': '@@',
            },
            'unsupported': ['libfuzzer']
        },
        'tiffsplit': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/tiff',
            'dict': 'tiff.dict',
            'code_dir': 'unibench/libtiff-3.9.7',
            'args': {
                'default': '@@',
            },
            'unsupported': ['libfuzzer']
        },
        'lame': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/mp3',
            'code_dir': 'unibench/lame-3.99.5',
            'input_model': 'mp3.xml',
            'args': {
                'default': '@@ /dev/null',
            },
            'unsupported': ['libfuzzer']
        },
        'mp3gain': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/mp3',
            'code_dir': 'unibench/mp3gain-1.5.2',
            'input_model': 'mp3.xml',
            'args': {
                'default': '@@',
            },
            'unsupported': ['libfuzzer']
        },
        'wav2swf': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/wav',
            'input_model': 'wav.xml',
            'dict': 'wav.dict',
            'code_dir': 'unibench/swftools-0.9.2',
            'args': {
                'default': '-o /dev/null @@',
            },
            'unsupported': ['libfuzzer', 'angora']
        },
        'ffmpeg': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/mp4',
            'input_model': 'mp4.xml',
            'code_dir': 'unibench/ffmpeg-4.0.1',
            'args': {
                'default': '-y -i @@ -c:v mpeg4 -c:a copy -f mp4 /dev/null',
            },
            'unsupported': ['libfuzzer']
        },
        'flvmeta': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/flv',
            'code_dir': 'unibench/flvmeta-1.2.1',
            'args': {
                'default': '@@',
            },
            'unsupported': ['libfuzzer']
        },
        'mp42aac': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/mp4',
            'input_model': 'mp4.xml',
            'code_dir': 'unibench/Bento4-1.5.1-628',
            'args': {
                'default': '@@ /dev/null',
            },
            'unsupported': ['libfuzzer']
        },
        'cflow': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/text',
            'code_dir': 'unibench/cflow-1.6',
            'args': {
                'default': '@@',
            },
            'unsupported': ['libfuzzer']
        },
        'infotocap6.4': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/text',
            'code_dir': 'unibench/ncurses-6.4',
            'args': {
                'default': '-o /dev/null @@',
            },
            'unsupported': ['libfuzzer']
        },
        'infotocap': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/text',
            'code_dir': 'unibench/ncurses-6.1',
            'args': {
                'default': '-o /dev/null @@',
            },
            'unsupported': ['libfuzzer']
        },
        'jq': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/text',
            'dict': 'json.dict',
            'code_dir': 'unibench/jq-1.5',
            'args': {
                'default': '. @@',
            },
            'unsupported': ['libfuzzer']
        },
        'mujs': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/text',
            'code_dir': 'unibench/mujs-1.0.2',
            'args': {
                'default': '@@',
            },
            'unsupported': ['libfuzzer']
        },
        'pdftotext': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/pdf',
            'input_model': 'pdf.xml',
            'dict': 'pdf.dict',
            'code_dir': 'unibench/xpdf-4.00',
            'args': {
                'default': '@@ /dev/null',
            },
            'unsupported': ['libfuzzer']
        },
        'sqlite3': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/pdf',
            'dict': 'sql.dict',
            'code_dir': 'unibench/SQLite-3.8.9',
            'args': {
                'default': '',
            },
            'unsupported': ['libfuzzer']
        },
        'nm': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/obj',
            'input_model': 'elf.xml',
            'dict': 'elf.dict',
            'code_dir': 'unibench/binutils-5279478',
            'args': {
                'default':
                '-A -a -l -S -s --special-syms --synthetic --with-symbol-versions -D @@',
            },
            'unsupported': ['libfuzzer']
        },
        'objdump': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/obj',
            'input_model': 'elf.xml',
            'dict': 'elf.dict',
            'code_dir': 'unibench/binutils-2.28',
            'args': {
                'default': '-S @@',
            },
            'unsupported': ['libfuzzer']
        },
        'tcpdump': {
            'group': 'unibench',
            'seed': '/seeds/unibench/general_evaluation/pcap',
            'input_model': 'pcap.xml',
            'code_dir': 'unibench/libpcap-1.8.1',
            'args': {
                'default': '-e -vv -nr @@',
            },
            'unsupported': ['libfuzzer']
        },
        'boringssl-2016-02-12': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/fuzzer-test-suite/boringssl-2016-02-12',
            'code_dir': 'fuzzer-test-suite-build/boringssl-2016-02-12',
            'args': {
                'default': '@@',
            }
        },
        'c-ares-CVE-2016-5180': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/custom/empty',
            'code_dir': 'fuzzer-test-suite-build/c-ares-CVE-2016-5180',
            'args': {
                'default': '@@',
            }
        },
        'freetype2-2017': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/fuzzer-test-suite/freetype2-2017',
            'input_model': 'xtf.xml',
            'code_dir': 'fuzzer-test-suite-build/freetype2-2017',
            'args': {
                'default': '@@',
            }
        },
        'guetzli-2017-3-30': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/fuzzer-test-suite/guetzli-2017-3-30',
            'code_dir': 'fuzzer-test-suite-build/guetzli-2017-3-30',
            'args': {
                'default': '@@',
            }
        },
        'harfbuzz-1.3.2': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/fuzzer-test-suite/harfbuzz-1.3.2',
            'code_dir': 'fuzzer-test-suite-build/harfbuzz-1.3.2',
            'args': {
                'default': '@@',
            }
        },
        'json-2017-02-12': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/fuzzer-test-suite/json-2017-02-12',
            'dict': 'json.dict',
            'code_dir': 'fuzzer-test-suite-build/json-2017-02-12',
            'args': {
                'default': '@@',
            }
        },
        'lcms-2017-03-21': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/fuzzer-test-suite/lcms-2017-03-21',
            'code_dir': 'fuzzer-test-suite-build/lcms-2017-03-21',
            'args': {
                'default': '@@',
            }
        },
        'libarchive-2017-01-04': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/fuzzer-test-suite/libarchive-2017-01-04',
            'code_dir': 'fuzzer-test-suite-build/libarchive-2017-01-04',
            'args': {
                'default': '@@',
            }
        },
        'libjpeg-turbo-07-2017': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/fuzzer-test-suite/libjpeg-turbo-07-2017',
            'input_model': 'jpeg.xml',
            'dict': 'jpeg.dict',
            'code_dir': 'fuzzer-test-suite-build/libjpeg-turbo-07-2017',
            'args': {
                'default': '@@',
            }
        },
        'libpng-1.2.56': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/fuzzer-test-suite/libpng-1.2.56',
            'input_model': 'png.xml',
            'dict': 'png.dict',
            'code_dir': 'fuzzer-test-suite-build/libpng-1.2.56',
            'args': {
                'default': '@@',
            }
        },
        'libssh-2017-1272': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/custom/empty',
            'code_dir': 'fuzzer-test-suite-build/libssh-2017-1272',
            'args': {
                'default': '@@',
            }
        },
        'libxml2-v2.9.2': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/custom/empty',
            'dict': 'xml.dict',
            'code_dir': 'fuzzer-test-suite-build/libxml2-v2.9.2',
            'args': {
                'default': '@@',
            }
        },
        'llvm-libcxxabi-2017-01-27': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/custom/empty',
            'code_dir': 'fuzzer-test-suite-build/llvm-libcxxabi-2017-01-27',
            'args': {
                'default': '@@',
            },
            'unsupported': ['afl']
        },
        'openssl-1.0.1f': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/fuzzer-test-suite/openssl-1.0.1f',
            'code_dir': 'fuzzer-test-suite-build/openssl-1.0.1f',
            'args': {
                'default': '@@',
            }
        },
        'openssl-1.0.2d': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/fuzzer-test-suite/openssl-1.0.2d',
            'code_dir': 'fuzzer-test-suite-build/openssl-1.0.2d',
            'args': {
                'default': '@@',
            }
        },
        'openssl-1.1.0c-bignum': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/fuzzer-test-suite/openssl-1.1.0c-bignum',
            'code_dir': 'fuzzer-test-suite-build/openssl-1.1.0c',
            'args': {
                'default': '@@',
            }
        },
        'openssl-1.1.0c-x509': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/fuzzer-test-suite/openssl-1.1.0c-x509',
            'code_dir': 'fuzzer-test-suite-build/openssl-1.1.0c',
            'args': {
                'default': '@@',
            }
        },
        'openthread-2018-02-27-radio': {
            'group': 'fuzzer-test-suite',
            'seed':
            '/seeds/fuzzer-test-suite/openthread-2018-02-27/seeds-radio',
            'code_dir': 'fuzzer-test-suite-build/openthread-2018-02-27',
            'args': {
                'default': '@@',
            }
        },
        'openthread-2018-02-27-ip6': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/custom/empty',
            'code_dir': 'fuzzer-test-suite-build/openthread-2018-02-27',
            'args': {
                'default': '@@',
            }
        },
        'pcre2-10.00': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/custom/empty',
            'code_dir': 'fuzzer-test-suite-build/pcre2-10.00',
            'args': {
                'default': '@@',
            }
        },
        'proj4-2017-08-14': {
            'group': 'fuzzer-test-suite',  # seed too big for AFL ( > 1M)
            # 'seed': '/seeds/fuzzer-test-suite/proj4-2017-08-14',
            'seed': '/seeds/custom/empty',
            'code_dir': 'fuzzer-test-suite-build/proj4-2017-08-14',
            'args': {
                'default': '@@',
            }
        },
        're2-2014-12-09': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/custom/empty',
            'code_dir': 'fuzzer-test-suite-build/re2-2014-12-09',
            'args': {
                'default': '@@',
            }
        },
        'sqlite-2016-11-14': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/custom/empty',
            'dict': 'sql.dict',
            'code_dir': 'fuzzer-test-suite-build/sqlite-2016-11-14',
            'args': {
                'default': '@@',
            }
        },
        'vorbis-2017-12-11': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/fuzzer-test-suite/vorbis-2017-12-11',
            'input_model': 'ogg.xml',
            'code_dir': 'fuzzer-test-suite-build/vorbis-2017-12-11',
            'args': {
                'default': '@@',
            }
        },
        'woff2-2016-05-06': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/fuzzer-test-suite/woff2-2016-05-06',
            'code_dir': 'fuzzer-test-suite-build/woff2-2016-05-06',
            'args': {
                'default': '@@',
            }
        },
        'wpantund-2018-02-27': {
            'group': 'fuzzer-test-suite',
            'seed': '/seeds/fuzzer-test-suite/wpantund-2018-02-27',
            'code_dir': 'fuzzer-test-suite-build/wpantund-2018-02-27',
            'args': {
                'default': '@@',
            }
        }
    }
}





def get_fuzzer_config(fuzzer):
    fuzzers = CONFIG['fuzzer']

    """Returns the fuzzer config for the given fuzzer name."""
    if fuzzer not in fuzzers:
        raise ValueError('Fuzzer %s not found' % fuzzer)
    return fuzzers[fuzzer]

def get_target(target):
    targets = CONFIG['target']

    """Returns the fuzzer config for the given fuzzer name."""
    if target not in targets:
        raise ValueError('Fuzzer %s not found' % target)
    return targets[target]

def gen_AFL_run_args(fuzzer_name, taget_name, output ):
    fuzzer = get_fuzzer_config(fuzzer_name)
    target = get_target(taget_name)
    args = []
    args += [fuzzer['command'], '-i', target['seed'], '-o', output]
    args += ['-m', 'none']
    args += ['-t', '1000+']
    if fuzzer_name == 'aflfast':
        args += ['-p', 'fast']
    args += ['--', fuzzer['target_root'] + "/" + target['group'] + "/" + taget_name + "/" + taget_name]
    args += target['args']['default'].split(' ')
    return ' '.join(args)

# def gen_qsym_run_args():

def gen_run_commands(target= ''):
    if target == '':
        print("target is null")
    # fuzzing时间
    output_root = "/work/autofz"
    timeout = "12h"
    Timeout = timeout
    output_root = "/work/autofz"
    fuzzers = ['afl', 'aflfast', 'fairfuzz']
    targets = ['tiffsplit']  # 'tiffsplit', 'infotocap', 'nm', 'pdftotext', 'jhead', 'mujs', 'tcpdump', 'objdump']
    commands = []
    for fuzzer in fuzzers:
        for i in range(1, 6):
            output = output_root + "/" + target + "/" + fuzzer + "/" + str(i)
            kw = gen_AFL_run_args(fuzzer, target, output)
            kw = "timeout " + Timeout + " " + kw
            commands.append(kw)
    print(commands)
    return commands



import subprocess
def run_command(command):
    # command = 'timeout 12h /fuzzer/afl/afl-fuzz -i /seeds/unibench/general_evaluation/jpg -o /work/autofz/exiv2/afl/1 -m none -t 1000+ -- /d/p/justafl/unibench/exiv2/exiv2 @@'
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process

def get_coverage():
    targets = ['exiv2', 'tiffsplit', 'infotocap', 'nm', 'pdftotext', 'jhead', 'mujs', 'tcpdump', 'objdump']
    fuzzers = ['afl', 'aflfast', 'fairfuzz']
    output_root = "/work/autofz"
    result = {}
    for target in targets:
        result[target] = {}
        for fuzzer in fuzzers:
            total_coverage = 0
            count = 0
            for i in range(1, 6):
                output = output_root + "/" + target + "/" + fuzzer + "/" + str(i)
                fuzzer_stats = output + "/" + "fuzzer_stats"
                print(fuzzer_stats)
                if os.path.exists(fuzzer_stats):
                    with open(fuzzer_stats, 'r') as f:
                        lines = f.readlines()
                        for line in lines:
                            if line.startswith('bitmap_cvg'):
                                print(line)
                                coverage_value = float(line.split(':')[1].strip()[:-1]) * 0.01
                                total_coverage += coverage_value
                                print(coverage_value)
                                count += 1
            if count > 0:
                average_coverage = total_coverage / count
                result[target][fuzzer] = average_coverage * 65535
                print(f'{target}: {fuzzer}: {average_coverage:.2f}')
            else:
                result[target][fuzzer] = 0
    for res in result:
        print(f'{res}: {result[res]}')

import sys
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python script.py <fuzzer_type>")
        sys.exit(1)
    target = sys.argv[1]
    print(target)
    commands = gen_run_commands(target)
    for command in commands:
        print(command)
        # sleep(1)
        # process = run_command(command)
        # print(process.communicate())





