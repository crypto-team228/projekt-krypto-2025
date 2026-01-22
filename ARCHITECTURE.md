# architecture

## cel i zakres systemu

System jest modularną biblioteką kryptograficzną z aplikacją CLI, testami i benchmarkami.  
Główne cele projektu:

- implementacja własnych szyfrów blokowych: AES, TDES oraz TDES_avx2,
- porównanie ich z bibliotekami referencyjnymi: CryptoPP, libsodium, OpenSSL,
- udostępnienie użytkownikowi narzędzia CLI do szyfrowania i deszyfrowania,
- zapewnienie testów zgodności (m.in. NIST) oraz benchmarków wydajności.

Zakres funkcjonalny obejmuje:

- szyfrowanie i deszyfrowanie danych z linii komend,
- obsługę trybów pracy: ECB, CBC, CTR,
- obsługę kodowań: UTF8, HEX,
- modularną architekturę umożliwiającą łatwe rozszerzanie.

---

## przegląd architektury

### struktura modułów

src/
├── core/      → interfejsy, fabryki, logika wspólna
├── cipher/    → AES, TDES, TDES_avx2
├── mode/      → ECB, CBC, CTR, BlockMode
├── utils/     → DataConverter, narzędzia pomocnicze
└── cli/       → aplikacja CLI


Dodatkowe katalogi:

- tests/ – testy jednostkowe + wektory NIST,
- bench/ – benchmarki porównawcze,
- external/ – biblioteki referencyjne.

---

### diagram komponentów

+-------------------+        +-------------------+
|       CLI         |        |     Benchmarks    |
|  (crypto_app_cli) |        |   (bench_*)       |
+---------+---------+        +---------+---------+
|                            |
v                            v
+-------------------+        +-------------------+
|   Core (API)      |<------>|   External libs   |
| CipherFactory     |        | (CryptoPP, etc.)  |
| ModeFactory       |        +-------------------+
+---------+---------+
|
v
+-------------------+
|   Cipher module   |
| AES, TDES,        |
| TDES_avx2         |
+---------+---------+
|
v
+-------------------+
|   Mode module     |
| ECB, CBC, CTR     |
| BlockMode         |
+-------------------+

+-------------------+
|   Utils           |
| DataConverter     |
+-------------------+


---

## wzorce projektowe

### factory method / abstract factory

- CipherFactory::create(algorithm)
- ModeFactory::create(mode)

Umożliwia łatwe dodawanie nowych algorytmów i trybów.

---

### strategy

- algorytm szyfrujący (AES/TDES/TDES_avx2) jest strategią operacji na bloku,
- tryb pracy (CBC/CTR/ECB) jest strategią przetwarzania strumienia bloków.

---

### bridge

Oddzielenie hierarchii algorytmów od hierarchii trybów.

---

### template method

BlockMode definiuje szkielet operacji, a konkretne tryby implementują szczegóły.

---

## struktury danych i przepływ

### struktury danych

- std::vector<uint8_t> – podstawowy typ danych binarnych,
- kodowania: UTF8, HEX,
- rozmiary bloków:
  - AES: 16 bajtów,
  - TDES / TDES_avx2: 8 bajtów.

---

### pipeline kryptograficzny

Input bytes
↓
Padding
↓
Tryb pracy (CBC/CTR/ECB)
↓
Algorytm (AES/TDES/TDES_avx2)
↓
Output bytes


---

### diagram sekwencji (cli → szyfrowanie)

User
|
|  args (--text, --key, --algorithm, --mode, ...)
v
CLI
| decode inputs
| validate key/iv
v
CipherFactory ---------> Cipher (AES/TDES/TDES_avx2)
| setKey
v
ModeFactory   ----------> Mode (CBC/CTR/ECB)
| setIV / setPadding
v
mode.encrypt(data, cipher)
|
v
encode output
|
v
stdout


---

## interakcja z użytkownikiem (cli)

### opis

CLI umożliwia wybór algorytmu, trybu, paddingu, kodowania oraz operacji encrypt/decrypt.

### przykład użycia

crypto_app_cli \
--text "Hello" \
--text-encoding utf8 \
--key "00112233445566778899AABBCCDDEEFF" \
--key-encoding hex \
--algorithm AES \
--mode CBC \
--iv "0102030405060708090A0B0C0D0E0F10" \
--operation encrypt \
--padding PKCS7 \
--output-encoding hex


---

## element wow – tdes_avx2

TDES_avx2 to wysoko zoptymalizowana implementacja TDES:

- minimalizacja operacji XOR i AND,
- wykorzystanie AVX2 do równoległego przetwarzania bloków,
- bitslice / SIMD,
- pełna zgodność z interfejsem Cipher.

---

## testy i benchmarki

- testy jednostkowe (GoogleTest),
- wektory NIST (AESAVS, XTS),
- benchmarki porównawcze z CryptoPP, libsodium, OpenSSL.

---

## rozszerzalność

Architektura umożliwia łatwe dodawanie nowych algorytmów, trybów, opcji CLI oraz benchmarków.

System jest modularny, przejrzysty i przygotowany na dalszy rozwój.
