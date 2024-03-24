# KRY - Projekt 2 - MAC za použití SHA-256 & Length extension attack

#### Autor: Dominik Nejedlý (xnejed09)

## Popis

Tento program dle zvolené funkcionality vypočítá SHA-256 kontrolní součet vstupní zprávy, vypočítá MAC vstupní zprávy pro daný klíč, ověří validitu MAC vstupní zprávy pro daný klíč nebo provede [length extension útok](https://lord.io/length-extension-attacks/) na MAC a vstupní zprávu. Výpočet MAC je založen na strategii *secret prefix*:

$$\mathit{MAC} = \mathit{SHA256}(\mathit{SECRET\_KEY} + \mathit{MSG})$$

Length extension útok pak využívá této strategie pro výpočet MAC a na základě již spočteného MAC pro originální zprávu, délky klíče a originální zprávy dopočítá validní MAC pro zarovnanou originální zprávu rozšířenou na konci o další text.

## Implementace

Program je implementován v jazyce C17 a zdrojové soubory jsou překládány pomocí [GCC](https://gcc.gnu.org). Vstupním bodem programu je funkce `main` v modulu `main.c`, která zajišťuje provedení zvolené funkcionality programu nad vstupní zprávou.

### Načítání vstupních argumentů

Načítání vstupních argumentů zajišťuje modul `args.c` s rozhraním `args.h`. Ke zpracování vstupních argumentů je využita funkce `getopt` z modulu `getopt.h`. Modul `args.c` poskytuje funkci `parse_args`, která zajišťuje načtení vstupních argumentů a validitu jejich použití. V případě validních vstupních argumentů vrací tato fuknce hodnotu `true`, jinak vrací `false`.

### Načítání vstupní zprávy

Načítání vstupní zprávy zajišťuje modul `input.c` s rozhraním `input.h`. Tento modul definuje datovou strukturu `data_container_t`, která slouží pro uchování vstupních dat (vstupní zprávy) proměnné délky během běhu programu, a poskytuje základní fuknce pro práci s touto strukturou. Funkce `init_container` slouží k inicializaci datového objekt `data_container_t`, funkce `reset_container` uvolní data načtená v datovém objektu `data_container_t` a následně jej inicializuje, funkce `extend_container` rozšíří datový objekt `data_container_t` o (přidá na konec datového objektu) specifikovaná data a funkce `load_input` rozšíří datový objekt `data_container_t` o data na standardním vstupu, případně v souboru. Funkce `load_input` načítá data znak po znaku pomocí funkce `fgetc` a každý načtený znak ukládá jako 8 bitové celé číslo bez znaménka. Z toho důvodu program předpokládá, že je vstupní zpráva složena z 8 bitových znaků, jinak není načtena korektně.

### SHA-256

Výpočet SHA-256 kontrolního součtu zajišťuje modul `sha256.c` s rozhraním `sha256.h`. Algoritmus SHA-256 je implementován dle standardu [NIST FIPS 180-4](http://dx.doi.org/10.6028/NIST.FIPS.180-4). Samotný výpočet SHA-256 kontrolního součtu poskytuje funkce `sha256`. Pro provedení length extension útoku umožňuje tato fuknce nastavení počáteční hodnoty kontrolního součtu a počtu již dříve zpracovaných znaků (odpovídajícímu zvolené počáteční hodnotě kontrolního součtu), aby bylo možné provést korektní rozšíření původní zprávy a dopočítat správnou délku zprávy nové. Dále tento modul poskytuje funkci `get_padded_msg_len`, která počítá délku zarovnané zprávy, a funkci `print_padded_msg`, která zprávu vytiskne v zarovnaném tvaru.

## Překlad

Zdrojové soubory lze přeložit pomocí nástroje `Makefile` příkazem `make`.

## Spuštění a ovládání

Program očekává vstupní zprávu na standardním vstupu (STDIN) a lze jej spustit následujícím příkazem:

    ./kry [-c|-s|-v|-e] [-k KEY] [-m CHS] [-n NUM] [-a MSG]

Aplikaci lze spustit vždy právě s jedním z následujících přepínačů, jež určují její právě zvolenou funkcionalitu:

- `-c` - Vypočte SHA-256 kontrolní součet a vytiskne jej na standardní výstup.
- `-s` - S využitím SHA-256 vypočte MAC vstupní zprávy a vytiskne jej na standardní výstup. Při spuštění musí být rovněž specifikován tajný klíč pomocí parametru `-k`.
- `-v` - Ověří MAC pro daný klíč a vstupní zprávu a vrací hodnotu 0 pokud je MAC validní, jinak vrací hodnotu 1. Při spuštění musí být specifikván tajný klíč pomocí parametru `-k` a referenční MAC pomocí parametru `-m`.
- `-e` - Provede length extension útok na MAC a vstupní zprávu. Nový MAC a prodlouženou vstupní zprávu tiskne na standardní výstup. Při spuštění musí být specifikován MAC vstupní zprávy pomocí parametru `-m`, délka tajného klíče pomocí parametru `-n` a prodloužení vstupní zprávy pomocí parametru `-a`.

Dle zvolené funkcionality může program při spuštění vyžadovat některé z následujících dodatečných vstupních parametrů:

- `-k KEY` - Specifikuje tajný klíč pro výpočet MAC vstupní zprávy. Klíč musí splňovat formát dle regulárního výrazu `^[A-Za-z0-9]*$`.
- `-m CHS` - Specifikuje MAC vstupní zprávy pro jeho ověření nebo provedení útoku. MAC musí splňovat formát dle regulárního výrazu `^[A-Fa-f0-9]*$`.
- `-n NUM` - Specifikuje délku tajného klíče pro provedení útoku.
- `-a MSG` - Specifikuje prodloužení vstupní zprávy pro provedení útoku. Prodloužení vstupní zprávy musí splňovat formát dle regulárního výrazu `^[a-zA-Z0-9!#$%&'"()*+,\-.\/:;<>=?@[\]\\^_{}|~]*$`.

## Příklady použití

### SHA-256 kontrolní součet

    $ echo -ne "zprava" | ./kry -c
    d8305a064cd0f827df85ae5a7732bf25d578b746b8434871704e98cde3208ddf
    $

### MAC

    $ echo -ne "zprava" | ./kry -s -k heslo
    23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e
    $

### Ověření validity MAC

#### Validní MAC

    $ echo -ne "zprava" | ./kry -v -k heslo -m 23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e
    $ echo $?
    0
    $

#### Nevalidní MAC

    $ echo -ne "message" | ./kry -v -k password -m 23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e
    $ echo $?
    1
    $

### Length extension útok

    $ echo -ne "zprava" | ./kry -e -n 5 -a ==message -m 23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e
    a3b205a7ebb070c26910e1028322e99b35e846d5db399aae295082ddecf3edd3 zprava\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x58==message
    $
