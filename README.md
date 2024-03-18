# KRY - Projekt 2 - MAC za použití SHA-256 & Length extension attack

#### Autor: Dominik Nejedlý (xnejed09)

### Implementace

Program je implementován v jazyce C17 a zdrojové soubory jsou překládány pomocí [GCC](https://gcc.gnu.org).

### Překlad

Zdrojové soubory lze přeložit pomocí nástroje `Makefile` příkazem `make`.

### Spuštění a ovládání

Program očekává vstupní zprávu na standardním vstupu (STDIN) a lze jej spustit následujícím příkazem:

    ./kry [-c|-s|-v|-e] [-k KEY] [-m CHS] [-n NUM] [-a MSG]

Aplikaci lze spustit vždy právě s jedním z následujících přepínačů, jež určují její právě zvolenou funkcionalitu:

- `-c` - Vypočte SHA-256 kontrolní součet a vytiskne jej na standardní výstup.
- `-s` - S využitím SHA-256 vypočte MAC vstupní zprávy a vytiskne jej na standardní výstup. Při spuštění musí být rovněž specifikován tajný klíč pomocí parametru `-k`.
- `-v` - Ověří MAC pro daný klíč a vstupní zprávu a vrací hodnotu 0 pokud je MAC validní, jinak vrací hodnotu 1. Při spuštění musí být specifikván tajný klíč pomocí parametru `-k` a referenční MAC pomocí parametru `-m`.
- `-e` - Provede lengthextension attack na MAC a vstupní zprávu. Nový MAC a prodlouženou vstupní zprávu tiskne na standardní výstup. Při spuštění musí být specifikován MAC vstupní zprávy pomocí parametru `-m`, délka tajného klíče pomocí parametru `-n` a prodloužení vstupní zprávy pomocí parametru `-a`.

Dle zvolené funkcionality může program při spuštění vyžadovat některé z následujících dodatečných vstupních parametrů:

- `-k KEY` - Specifikuje tajný klíč pro výpočet MAC vstupní zprávy. Klíč musí splňovat formát dle regulárního výrazu `^[A-Za-z0-9]*$`.
- `-m CHS` - Specifikuje MAC vstupní zprávy pro jeho ověření nebo provedení útoku. MAC musí splňovat formát dle regulárního výrazu `^[A-Fa-f0-9]*$`.
- `-n NUM` - Specifikuje délku tajného klíče pro provedení útoku.
- `-a MSG` - Specifikuje prodloužení vstupní zprávy pro provedení útoku. Prodloužení vstupní zprávy musí splňovat formát dle regulárního výrazu `^[a-zA-Z0-9!#$%&'"()*+,\-.\/:;<>=?@[\]\\^_{}|~]*$`.
