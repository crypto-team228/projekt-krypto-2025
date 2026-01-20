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

## Uwagi bezpieczeństwa

**UWAGA**: Ta implementacja jest przeznaczona wyłącznie do celów edukacyjnych. Nie należy jej używać w środowisku produkcyjnym bez dokładnej weryfikacji i audytu bezpieczeństwa.

## Autorzy

Oleksandr Abelmas
Michał Maszka
Vlad Bondarchuk

