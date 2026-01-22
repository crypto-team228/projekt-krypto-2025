# ============================================================
#  ANF -> kod S-boxa w stylu T[], M[], y[]
#  - wejścia: x[0..5]
#  - wyjścia: y[0..3]
#  - pośrednie: T[i] (liniowe), M[i] (nieliniowe)
# ============================================================

from pyeda.inter import exprvars
from pyeda.boolalg.table import truthtable
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

def truth_table_for_bit(sbox, out_bit):
    f = []
    for v in range(64):
        bits = [(v >> i) & 1 for i in range(6)]
        row, col = sbox_row_col(bits)
        val = sbox[16*row + col]
        f.append((val >> out_bit) & 1)
    return f

def anf_expr_for_bit(sbox, out_bit):
    # użyjemy espresso, żeby dostać sensowną sumę iloczynów
    X = exprvars('x', 6)
    tt = truthtable(X, truth_table_for_bit(sbox, out_bit))
    expr = tt.to_dnf()
    expr, = espresso_exprs(expr)


    return expr

def generate_sbox_T_M_y(sbox, idx):
    print(f"// ===== S{idx} =====")
    print("// inputs:  x[0..5]")
    print("// outputs: y[0..3]")
    print()

    # 1) ANF / suma iloczynów dla każdego bitu wyjściowego
    expr_bits = [anf_expr_for_bit(sbox, ob) for ob in range(4)]

    T_counter = 0
    M_counter = 0

    # map: monom (tuple of vars) -> T index
    monom_to_T = {}

    def emit_monom(monom):
        nonlocal T_counter, M_counter
        monom = tuple(sorted(monom, key=lambda v: int(str(v)[1:])))  # sort by index
        if monom in monom_to_T:
            return monom_to_T[monom]

        vars_idx = [int(str(v)[1:]) for v in monom]  # x0..x5 -> 0..5

        # T[k] = x[a]; T[k] &= x[b]; T[k] &= x[c]...
        k = T_counter
        T_counter += 1
        print(f"    T[{k}] = x[{vars_idx[0]}];")
        for j in vars_idx[1:]:
            print(f"    T[{k}] &= x[{j}];")
        print()
        monom_to_T[monom] = k
        return k

    # 2) dla każdego bitu wyjściowego: zbierz monomy i zbuduj XOR z T[]
    for ob, expr in enumerate(expr_bits):
        # rozbij na sumę iloczynów
        # expr jest w DNF/ANF po espresso, iterujemy po mintermach
        terms = []

        # stała 1?
        if expr.is_one():
            terms.append("1")
        elif expr.is_zero():
            # y[ob] = 0
            print(f"    y[{ob}] = 0;")
            print()
            continue
        else:
            # expr może być OR sumą iloczynów
            # normalizujemy do listy składników
            ors = [expr] if expr.is_and() or expr.is_literal() else list(expr.xs)
            for term in ors:
                if term.is_literal():
                    if term.is_complement():
                        # ~x[i] = 1 ^ x[i] -> zrobimy T z negacją
                        v = term.x
                        idxv = int(str(v)[1:])
                        k = T_counter
                        T_counter += 1
                        print(f"    T[{k}] = 1 ^ x[{idxv}];")
                        print()
                        terms.append(f"T[{k}]")
                    else:
                        v = term
                        idxv = int(str(v)[1:])
                        k = T_counter
                        T_counter += 1
                        print(f"    T[{k}] = x[{idxv}];")
                        print()
                        terms.append(f"T[{k}]")
                else:
                    # iloczyn wielu zmiennych
                    lits = term.xs
                    monom = []
                    negs = []
                    for lit in lits:
                        if lit.is_complement():
                            negs.append(lit.x)
                        else:
                            monom.append(lit)
                    # negacje zrobimy jako osobne T i potem AND
                    base_T = None
                    if monom:
                        base_T_idx = emit_monom(monom)
                        base_T = f"T[{base_T_idx}]"
                    # negacje
                    for nv in negs:
                        idxv = int(str(nv)[1:])
                        kneg = T_counter
                        T_counter += 1
                        print(f"    T[{kneg}] = 1 ^ x[{idxv}];")
                        print()
                        if base_T is None:
                            base_T = f"T[{kneg}]"
                        else:
                            # M jako AND T & Tneg
                            m = M_counter
                            M_counter += 1
                            print(f"    M[{m}] = {base_T} & T[{kneg}];")
                            print()
                            base_T = f"M[{m}]"
                    terms.append(base_T)

        # teraz zbuduj y[ob] jako XOR tych terms
        if not terms:
            print(f"    y[{ob}] = 0;")
            print()
            continue

        cur = terms[0]
        for t in terms[1:]:
            m = M_counter
            M_counter += 1
            print(f"    M[{m}] = {cur} ^ {t};")
            print()
            cur = f"M[{m}]"

        print(f"    y[{ob}] = {cur};")
        print()

    print()

def main():
    for i, s in enumerate(SBOXES, start=1):
        generate_sbox_T_M_y(s, i)

if __name__ == "__main__":
    main()
