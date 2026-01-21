from pyeda.inter import exprvars, truthtable, espresso_exprs
from pyeda.boolalg.table import truthtable, truthtable2expr 
from pyeda.boolalg.minimization import espresso_exprs

SBOXES = [
    [ # S1
        14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
        0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
        4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
        15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
    ],
    [ # S2
        15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
        3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
        0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
        13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
    ],
    [ # S3
        10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
        13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
        13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
        1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
    ],
    [ # S4
        7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
        13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
        10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
        3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
    ],
    [ # S5
        2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
        14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
        4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
        11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
    ],
    [ # S6
        12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
        10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
        9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
        4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
    ],
    [ # S7
        4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
        13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
        1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
        6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
    ],
    [ # S8
        13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
        1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
        7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
        2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
    ]
]



def sbox_row_col(bits):
    b0,b1,b2,b3,b4,b5 = bits
    row = (b5 << 1) | b0
    col = (b4 << 3) | (b3 << 2) | (b2 << 1) | b1
    return row, col

def truth_table(sbox, out_bit):
    f = [0]*64
    for v in range(64):
        bits = [(v >> i) & 1 for i in range(6)]
        row, col = sbox_row_col(bits)
        val = sbox[16*row + col]
        f[v] = (val >> out_bit) & 1
    return f

def anf_from_truth(f):
    a = f[:]
    for i in range(6):
        step = 1 << i
        for x in range(64):
            if x & step:
                a[x] ^= a[x ^ step]
    return [mask for mask in range(64) if a[mask] == 1]

def mask_to_code(mask, names):
    if mask == 0:
        return "all1"
    vars = [names[i] for i in range(6) if (mask >> i) & 1]
    if len(vars) == 1:
        return vars[0]
    code = f"_mm256_and_si256({vars[0]}, {vars[1]})"
    for v in vars[2:]:
        code = f"_mm256_and_si256({code}, {v})"
    return code

def xor_chain(exprs):
    if not exprs:
        return "_mm256_setzero_si256()"
    acc = exprs[0]
    for e in exprs[1:]:
        acc = f"_mm256_xor_si256({acc}, {e})"
    return acc

def generate_sbox(sbox, idx):
    names = ["a0","a1","a2","a3","a4","a5"]
    print(f"// ===== S{idx} =====")
    print("{")
    base = (idx-1)*6
    for i in range(6):
        print(f"    __m256i a{i} = Ebits[{base+i}];")
    print("    __m256i all1 = _mm256_set1_epi32(-1);")

    for out_bit in range(4):
        f = truth_table(sbox, out_bit)
        masks = anf_from_truth(f)
        terms = [mask_to_code(m, names) for m in masks]
        expr = xor_chain(terms)
        print(f"    __m256i y{out_bit} = {expr};")

    out = (idx-1)*4
    print(f"    S_out[{out+0}] = y0;")
    print(f"    S_out[{out+1}] = y1;")
    print(f"    S_out[{out+2}] = y2;")
    print(f"    S_out[{out+3}] = y3;")
    print("}")
    print()

def main():
    for i, s in enumerate(SBOXES, start=1):
        generate_sbox(s, i)

if __name__ == "__main__":
    main()
