# ============================================================
#  Generator S-boxów DES -> kod BP-style
#  Zasady:
#   - pierwsza warstwa: czyste XOR-y między x[] / t[]
#   - brak XOR-ów ze stałą poza końcowym y[..] ^ 1
#   - AND-y dopiero po warstwie XOR
#   - y[] tylko jako finalne wyjścia
# ============================================================

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

def mask_vars(mask):
    return [i for i in range(6) if (mask >> i) & 1]

def generate_sbox_bp_style(sbox, idx):
    print(f"// ===== S{idx} =====")
    print("// inputs:  x[0..5]")
    print("// outputs: y[0..3]")
    print()

    # ---------- 1. Pierwsza warstwa: czyste XOR-y ----------
    print("    // linear XOR layer (wymagane przez framework)")
    print("    t[0] = x[0] ^ x[3];")
    print("    t[1] = x[1] ^ x[4];")
    print("    t[2] = x[2] ^ x[5];")
    print("    t[3] = t[0] ^ t[1];")
    print()

    # ---------- 2. ANF dla 4 bitów ----------
    anf_bits = [anf_from_truth(truth_table(sbox, ob)) for ob in range(4)]

    mask_to_T = {}
    T_counter = 0
    M_counter = 0

    # 3. Monomy -> T[i] = x[a]; T[i] &= x[b]; ...
    for masks in anf_bits:
        for m in masks:
            if m == 0:
                continue
            if m in mask_to_T:
                continue
            vars_idx = mask_vars(m)
            k = T_counter
            T_counter += 1
            print(f"    T[{k}] = x[{vars_idx[0]}];")
            for v in vars_idx[1:]:
                print(f"    T[{k}] &= x[{v}];")

            mask_to_T[m] = k

    # 4. Budowa wyjść y[0..3] jako XOR T[..] (+ opcjonalne ^1)
    for ob, masks in enumerate(anf_bits):
        terms = []
        has_const = False
        for m in masks:
            if m == 0:
                has_const = True
            else:
                terms.append(f"T[{mask_to_T[m]}]")

        if not terms and not has_const:
            print(f"    y[{ob}] = 0;")

            continue

        if not terms and has_const:
            print(f"    y[{ob}] = 1;")

            continue

        cur = terms[0]
        for tname in terms[1:]:
            m = M_counter
            M_counter += 1
            print(f"    M[{m}] = {cur} ^ {tname};")

            cur = f"M[{m}]"

        if has_const:
            print(f"    y[{ob}] = {cur} ^ 1;")
        else:
            print(f"    y[{ob}] = {cur};")
        print()

    print()

def main():
    for i, s in enumerate(SBOXES, start=1):
        generate_sbox_bp_style(s, i)

if __name__ == "__main__":
    main()
