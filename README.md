# projekt-krypto-2025

Projekt implementujący algorytmy szyfrowania symetrycznego AES-128 i Triple DES (3DES).

## Opis projektu

Projekt zawiera implementację dwóch klasycznych algorytmów szyfrowania blokowego:

- **AES-128** (Advanced Encryption Standard) - nowoczesny standard szyfrowania z 128-bitowym kluczem
- **Triple DES (3DES)** - wzmocniona wersja algorytmu DES wykorzystująca trzykrotne szyfrowanie

## Struktura projektu

```
├── include/              # Pliki nagłówkowe
│   ├── mylib.hpp
│   ├── AES/
│   │   └── aes.hpp      # Interfejs AES
│   ├── TDES/
│   │   └── tdes.hpp     # Interfejs Triple DES
│   └── Tools/
│       ├── enums.h
│       └── stringConversions.h
├── src/                  # Implementacja
│   ├── AES_main.cpp     # Program demonstracyjny AES
│   ├── TDES_main.cpp    # Program demonstracyjny Triple DES
│   ├── AES/
│   │   └── aes.cpp      # Implementacja AES
│   └── TDES/
│       ├── tdes.cpp     # Implementacja Triple DES
│       └── tdes_tables.cpp
└── tests/                # Testy jednostkowe
    ├── test_aes.cpp
    └── test_main.cpp
```

## Wymagania

- CMake 3.15 lub nowszy
- Kompilator C++ z obsługą C++11 lub nowszego
- System operacyjny: Linux, macOS, Windows

## Kompilacja

### Linux / macOS

```bash
# Utworzenie katalogu build
mkdir -p build
cd build

# Generowanie plików budowy
cmake ..

# Kompilacja
cmake --build .
```

### Windows

```bash
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

## Uruchomienie

Po pomyślnej kompilacji w katalogu `build/` znajdą się dwa programy:

```bash
# Uruchomienie demonstracji AES
./AES_app

# Uruchomienie demonstracji Triple DES
./TDES_app
```

## Funkcjonalność

### AES-128

- Szyfrowanie bloków 128-bitowych (16 bajtów)
- Deszyfrowanie bloków
- Tryb operacji: ECB (Electronic Codebook)
- Pełna implementacja transformacji AES (SubBytes, ShiftRows, MixColumns, AddRoundKey)
- Ekspansja klucza dla 10 rund

### Triple DES (3DES)

- Szyfrowanie z użyciem trzech 64-bitowych kluczy
- Deszyfrowanie
- Operacja EDE (Encrypt-Decrypt-Encrypt)
- Konwersja między formatami hex i tekstem
- Pełna implementacja funkcji Feistela i tablic permutacji DES

## Testy

Uruchomienie testów jednostkowych:

```bash
cd build
ctest
```

## Generowanie plików CMake

Projekt zawiera skrypt `generate_cmake.py` do automatycznego generowania plików `CMakeLists.txt`:

```bash
python3 generate_cmake.py
```

## Uwagi bezpieczeństwa

⚠️ **UWAGA**: Ta implementacja jest przeznaczona wyłącznie do celów edukacyjnych. Nie należy jej używać w środowisku produkcyjnym bez dokładnej weryfikacji i audytu bezpieczeństwa.

- Brak implementacji bezpiecznych trybów operacji (np. CBC, GCM)
- Brak ochrony przed atakami bocznymi kanałami (timing attacks)
- Klucze przechowywane w pamięci bez dodatkowej ochrony

## Autorzy

crypto-team228

## Licencja

Projekt edukacyjny - 2025
