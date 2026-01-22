#  Python generator ANF → zoptymalizowany kod C++ dla S‑boxów
#  zgodny z aktualną feistel_bitslice (wejścia/wyjścia)
#  + domknięcie po podmaskach
#  + DP po maskach (optymalne rozbicia AND‑ów)

from pyeda.inter import exprvars, truthtable, espresso_exprs
from pyeda.boolalg.table import truthtable, truthtable2expr 
from pyeda.boolalg.minimization import espresso_exprs
from itertools import combinations

# ------------------------------------------------------------
# 1. DES S‑boxy (wstaw swoje SBOXES tutaj)

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

# ------------------------------------------------------------
# 2. Funkcje pomocnicze

def sbox_row_col(bits):
    # bits = [b0..b5], b0 = LSB
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

def mask_bits(mask):
    return [i for i in range(6) if (mask >> i) & 1]

def var_name(mask):
    if mask == 0:
        return "all1"  # stała 1 → w C++: __m256i all1 = _mm256_set1_epi32(-1);
    bits = mask_bits(mask)
    if len(bits) == 1:
        return f"a{bits[0]}"
    return "t_" + "_".join(str(b) for b in bits)


# ------------------------------------------------------------
# 3. DP po maskach: optymalne rozbicia AND‑ów

def compute_mask_closure(anf_bits):
    """Domknięcie po podmaskach dla wszystkich masek z ANF."""
    closure = set()
    for masks in anf_bits:
        for m in masks:
            closure.add(m)
            sub = m
            while sub:
                sub = (sub - 1) & m
                if sub:
                    closure.add(sub)
    return closure

def compute_optimal_splits(masks_closure):
    """
    DP po maskach:
    cost[mask] = minimalna liczba AND‑ów, żeby zbudować maskę,
    split[mask] = (A, B) takie, że mask = A ∪ B, A∩B=∅, koszt minimalny.
    """
    # sortujemy po liczbie bitów, potem po wartości
    masks_sorted = sorted(masks_closure, key=lambda m: (bin(m).count("1"), m))

    cost = {}
    split = {}

    for m in masks_sorted:
        bits = mask_bits(m)
        if len(bits) <= 1:
            cost[m] = 0
            split[m] = None
            continue

        best_cost = None
        best_split = None

        # wszystkie właściwe, niepuste podmaski
        sub = m
        while sub:
            sub = (sub - 1) & m
            if not sub or sub == m:
                continue
            other = m ^ sub
            if other == 0:
                continue

            # koszt = koszt(sub) + koszt(other) + 1 (AND)
            c = cost.get(sub, 0) + cost.get(other, 0) + 1
            if best_cost is None or c < best_cost:
                best_cost = c
                best_split = (sub, other)

        cost[m] = best_cost
        split[m] = best_split

    return cost, split

# ------------------------------------------------------------
# 4. Generowanie zoptymalizowanego kodu C++

def generate_sbox_cpp(sbox, idx):
    print(f"// ===== S{idx} =====")
    print("{")

    base = (idx - 1) * 6

    # wejścia: a0 = bit0, a5 = bit5 (odwrócone Ebits)
    print(f"    __m256i a0 = Ebits[{base+5}];")
    print(f"    __m256i a1 = Ebits[{base+4}];")
    print(f"    __m256i a2 = Ebits[{base+3}];")
    print(f"    __m256i a3 = Ebits[{base+2}];")
    print(f"    __m256i a4 = Ebits[{base+1}];")
    print(f"    __m256i a5 = Ebits[{base+0}];")
    print("    __m256i all1 = _mm256_set1_epi32(-1);")
    print()

    # ANF dla 4 bitów wyjściowych
    anf_bits = [anf_from_truth(truth_table(sbox, out_bit)) for out_bit in range(4)]

    # domknięcie po podmaskach
    masks_closure = compute_mask_closure(anf_bits)

    # DP: optymalne rozbicia
    cost, split = compute_optimal_splits(masks_closure)

    # generowanie AND‑ów w kolejności rosnącej liczby bitów
    masks_sorted = sorted(masks_closure, key=lambda m: (bin(m).count("1"), m))

    for m in masks_sorted:
        bits = mask_bits(m)
        if len(bits) <= 1:
            continue  # a0..a5

        A, B = split[m]
        left = var_name(A)
        right = var_name(B)
        print(f"    __m256i {var_name(m)} = _mm256_and_si256({left}, {right});")

    print()

    # wyjścia y0..y3 (ANF)
    for out_bit, masks in enumerate(anf_bits):
        if not masks:
            print(f"    __m256i y{out_bit} = _mm256_setzero_si256();")
            continue

        expr = var_name(masks[0])
        for m in masks[1:]:
            expr = f"_mm256_xor_si256({expr}, {var_name(m)})"

        print(f"    __m256i y{out_bit} = {expr};")

    print()

    # wyjście: y3 = MSB, y0 = LSB
    out = (idx - 1) * 4
    print(f"    S_out[{out+0}] = y3;")
    print(f"    S_out[{out+1}] = y2;")
    print(f"    S_out[{out+2}] = y1;")
    print(f"    S_out[{out+3}] = y0;")

    print("}")
    print()


# 5. Główna pętla

def main():
    for i, s in enumerate(SBOXES, start=1):
        generate_sbox_cpp(s, i)

if __name__ == "__main__":
    main()
