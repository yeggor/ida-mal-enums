import glob
import json
import os

import ida_bytes
import idc

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# template for searching csv files with hashes
HASHES_TMPL = os.path.join(CURRENT_DIR, 'shellcode_hashes', 'hashes', '*')

# uncomment the hash type if you want to create enumerations from it
HASH_TYPES = [
    'crc32',
    # 'ror11AddHash32',
    # 'rol7XorHash32',
    # 'hash_Carbanak',
    # 'ror13AddHash32Sub1',
    # 'rol7AddHash32',
    # 'sll1AddHash32',
    # 'ror9AddHash32',
    # 'ror13AddHash32',
    # 'rol3XorEax',
    # 'rol5AddHash32',
    # 'shl7shr19Hash32',
    # 'ror13AddHash32AddDll',
    # 'mult21AddHash32',
    # 'poisonIvyHash',
    # 'add1505Shl5Hash32',
    # 'ror7AddHash32',
    # 'hash_ror13AddUpperDllnameHash32',
    # 'rol7AddXor2Hash32',
    # 'ror13AddWithNullHash32',
    # 'fnv1Xor67f',
    # 'addRor4WithNullHash32',
    # 'dualaccModFFF1Hash'
]


def create_enums(lib_fpath):
    lib_fname = lib_fpath.split(os.sep)[-1]
    lib_name = lib_fname.split('.')[0]
    enum_ids = {}
    for hash_name in HASH_TYPES:
        enum_name = '{}_{}'.format(lib_name, hash_name)
        enum_ids[enum_name] = idc.add_enum(-1, enum_name, ida_bytes.dec_flag())
    f = open(lib_fpath, 'r')
    while(True):
        line_csv = f.readline()
        if not line_csv:
            break
        csv_hash_value, csv_func_name, csv_lib_name, csv_hash_name = line_csv.split(',')
        csv_hash_name = csv_hash_name[:len(csv_hash_name) - 1]
        if not csv_hash_name in HASH_TYPES:
            continue
        csv_lib_name, _ = os.path.splitext(csv_lib_name)
        csv_enum_name = '{}_{}'.format(csv_lib_name, csv_hash_name)
        idc.add_enum_member(
            enum_ids[csv_enum_name],
            '{}_{}'.format(csv_hash_name, csv_func_name),
            int(csv_hash_value, 16),
            -1
        )
    f.close()

def main():
    libs = glob.glob(HASHES_TMPL)
    for lib in libs:
        print('[current file] {}'.format(lib))
        create_enums(lib)

if __name__ == '__main__':
    main()
