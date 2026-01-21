# projekt-krypto-2025

Projekt implementujący algorytmy szyfrowania symetrycznego AES i Triple DES (3DES).

## Opis projektu

Projekt zawiera implementację dwóch klasycznych algorytmów szyfrowania blokowego:

- **AES** (Advanced Encryption Standard) - nowoczesny standard szyfrowania z kluczem 128/192/256-bitowym
- **Triple DES (3DES)** - wzmocniona wersja algorytmu DES wykorzystująca trzykrotne szyfrowanie

## Struktura projektu

```
├── include/              # Pliki nagłówkowe
│   ├── cipher/
│   │   ├── cipher.hpp    # Interfejs bazowy
│   │   ├── AES/
│   │   │   └── aes.hpp   # Interfejs AES
│   │   └── TDES/
│   │       └── tdes.hpp  # Interfejs Triple DES
│   ├── mode/
│   │   ├── mode.hpp      # Interfejs trybu
│   │   ├── ECB.hpp       # Electronic Codebook
│   │   ├── CBC.hpp       # Cipher Block Chaining
│   │   ├── CTR.hpp       # Counter mode
│   │   └── GCM.hpp       # Galois/Counter Mode
│   ├── core/
│   │   ├── cipherFactory.hpp
│   │   └── modeFactory.hpp
│   └── utils/
│       └── DataConverter.hpp
├── src/                  # Implementacja
│   ├── cli/
│   │   └── cli.cpp       # Interfejs wiersza poleceń
│   ├── cipher/
│   │   ├── AES/
│   │   │   └── aes.cpp
│   │   └── TDES/
│   │       ├── tdes.cpp
│   │       └── tdes_tables.cpp
│   └── mode/
│       ├── ECB.cpp
│       ├── CBC.cpp
│       ├── CTR.cpp
│       └── GCM.cpp
└── tests/                # Testy jednostkowe
```

## Wymagania

- CMake 3.15 lub nowszy
- Kompilator C++ z obsługą C++17
- System operacyjny: Linux, macOS, Windows

## Kompilacja

```bash
cmake -B build
cmake --build build
```

## Interfejs wiersza poleceń (CLI)

### Użycie

```bash
./build/crypto_app_cli [OPCJE]
```

### Opcje

| Opcja | Opis |
|-------|------|
| `-t, --text` | Tekst do zaszyfrowania/odszyfrowania (wymagane) |
| `--text-encoding` | Kodowanie wejścia: `utf8` (domyślne), `hex` |
| `-k, --key` | Klucz szyfrowania (wymagane) |
| `--key-encoding` | Kodowanie klucza: `hex` (domyślne), `utf8` |
| `-a, --algorithm` | Algorytm: `AES` (domyślne), `TDES` |
| `-m, --mode` | Tryb: `ECB`, `CBC` (domyślne), `CTR` |
| `--iv` | Wektor inicjalizacyjny (hex, wymagane dla CBC/CTR) |
| `-o, --operation` | Operacja: `encrypt` (domyślne), `decrypt` |
| `-p, --padding` | Padding: `PKCS7` (domyślne), `Zero`, `None` |
| `--output-encoding` | Kodowanie wyjścia: `hex` (domyślne), `utf8` |

### Rozmiary kluczy

- **AES**: 16, 24 lub 32 bajty (128/192/256 bitów)
- **TDES**: 24 bajty (192 bity)

### Rozmiary IV

- **AES**: 16 bajtów
- **TDES**: 8 bajtów

### Przykłady

#### Szyfrowanie AES-ECB

```bash
./crypto_app_cli \
    -t "Hello World" \
    -k 000102030405060708090a0b0c0d0e0f \
    -a AES -m ECB -o encrypt
```

#### Szyfrowanie AES-CBC

```bash
./crypto_app_cli \
    -t "Hello World" \
    -k 000102030405060708090a0b0c0d0e0f \
    --iv 00112233445566778899aabbccddeeff \
    -a AES -m CBC -o encrypt
```

#### Deszyfrowanie (wyjście hex)

```bash
./crypto_app_cli \
    -t 7dac0ef1c64ed14497730815a8ac4e84 \
    --text-encoding hex \
    -k 000102030405060708090a0b0c0d0e0f \
    -a AES -m ECB -o decrypt
```

#### Deszyfrowanie (wyjście tekstowe)

```bash
./crypto_app_cli \
    -t 7dac0ef1c64ed14497730815a8ac4e84 \
    --text-encoding hex \
    -k 000102030405060708090a0b0c0d0e0f \
    -a AES -m ECB -o decrypt \
    --output-encoding utf8
```

#### Szyfrowanie TDES

```bash
./crypto_app_cli \
    -t "Secret" \
    -k 0123456789abcdef0123456789abcdef0123456789abcdef \
    -a TDES -m ECB -o encrypt
```

## Funkcjonalność

### AES

- Szyfrowanie bloków 128-bitowych (16 bajtów)
- Obsługa kluczy 128/192/256-bitowych
- Tryby operacji: ECB, CBC, CTR, GCM
- Pełna implementacja transformacji AES (SubBytes, ShiftRows, MixColumns, AddRoundKey)

### Triple DES (3DES)

- Szyfrowanie z użyciem trzech 64-bitowych kluczy
- Operacja EDE (Encrypt-Decrypt-Encrypt)
- Tryby operacji: ECB, CBC, CTR
- Pełna implementacja funkcji Feistela i tablic permutacji DES

## Testy

Uruchomienie testów jednostkowych:

```bash
cmake --build build --target crypto_tests
./build/crypto_tests
```

## Benchmarki

Projekt zawiera narzędzie do pomiaru wydajności algorytmów szyfrowania.

### Kompilacja benchmarków

```bash
cmake --build build --target crypto_bench
```

### Użycie

```bash
./build/bench/crypto_bench [OPCJE]
```

### Opcje

| Opcja | Opis |
|-------|------|
| `--iters <N>` | Liczba iteracji dla każdego testu (domyślnie: 100) |
| `--output <plik>` | Ścieżka do pliku wynikowego CSV (domyślnie: `bench_results.csv`) |

### Przykłady

```bash
# Uruchomienie z domyślnymi ustawieniami (100 iteracji)
./build/bench/crypto_bench

# Szybki test z 10 iteracjami
./build/bench/crypto_bench --iters 10

# Zapis wyników do własnego pliku
./build/bench/crypto_bench --iters 50 --output wyniki.csv
```

### Testowane konfiguracje

| Algorytm | Tryby | Rozmiar klucza | Rozmiar IV |
|----------|-------|----------------|------------|
| AES-128 | ECB, CBC, CTR, GCM | 16 bajtów | 16 bajtów |
| AES-256 | ECB, CBC, CTR, GCM | 32 bajty | 16 bajtów |
| TDES | ECB | 24 bajty | - |

### Rozmiary danych testowych

Benchmark mierzy wydajność dla następujących rozmiarów danych:
- 1 KB (1024 B)
- 4 KB (4096 B)
- 16 KB (16384 B)
- 64 KB (65536 B)
- 256 KB (262144 B)

### Format wyjścia

Wyniki zapisywane są w formacie CSV z następującymi kolumnami:

| Kolumna | Opis |
|---------|------|
| `algo` | Nazwa algorytmu (AES-128, AES-256, TDES) |
| `mode` | Tryb operacji (ECB, CBC, CTR, GCM) |
| `size_bytes` | Rozmiar danych testowych w bajtach |
| `throughput_MBps` | Przepustowość w MB/s |
| `latency_usec` | Opóźnienie na operację w mikrosekundach |

### Przykładowe wyjście konsoli

```
[*] Starting benchmarks (iters=100)...
[*] AES-128 ECB size=1024
[*] AES-128 CBC size=1024
...

=== Summary ===
Algorithm   Mode  Size        Throughput    Latency
------------------------------------------------------
AES-128     ECB   1024        5.50       MB/s177.45     us
AES-128     CBC   1024        4.80       MB/s203.33     us
...
```

## Uwagi bezpieczeństwa

**UWAGA**: Ta implementacja jest przeznaczona wyłącznie do celów edukacyjnych. Nie należy jej używać w środowisku produkcyjnym bez dokładnej weryfikacji i audytu bezpieczeństwa.

## Autorzy

Oleksandr Abelmas
Michał Maszka
Vlad Bondarchuk

