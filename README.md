# Biblioteka STL

Serwis WWW z katalogiem plików STL do druku 3D, w którym **każdy plik jest podpisany
kryptograficznie**, a jego integralność sprawdzana jest przy każdym pobraniu — najpierw
po stronie serwera, potem jeszcze raz w przeglądarce użytkownika. Plik, który nie
przejdzie kontroli, nie zostaje wydany i trafia do kwarantanny.

Projekt powstał wokół jednego wymagania: *nikt nie może podmienić pliku w bibliotece na
inny*. Odpowiedzią nie jest sam token pod plikiem — to trzy [niezależne
warstwy](#dlaczego-sam-token-to-za-mało), z których najważniejszą jest podpis Ed25519
składany kluczem trzymanym **poza serwerem**.

### Co to potrafi

- Katalog modeli z wyszukiwarką, kategoriami i licencjami.
- Konta użytkowników — pobierają wyłącznie zalogowani, każdy link jest imienny i wygasa.
- Panel administratora: dodawanie modeli, wgrywanie plików, audyt integralności, dziennik zdarzeń.
- Podgląd 3D modelu w przeglądarce (obrót myszą, zoom kółkiem).
- Weryfikacja pobranego pliku offline, bez ufania serwerowi — osobnym skryptem bez zależności.
- Audyt całej biblioteki z linii poleceń, gotowy pod crona.

### Stack

Python 3.9+ · FastAPI · SQLite · czysty JavaScript. Frontend nie ma **żadnych**
zewnętrznych zależności — podgląd 3D jest napisany bezpośrednio na WebGL, więc strona
działa przy CSP bez `unsafe-inline` i bez odpytywania jakiegokolwiek CDN-a.

---

## Dlaczego sam „token" to za mało

Token pod plikiem nie chroni przed podmianą pliku — chroni tylko przed pobraniem go
przez niepowołaną osobę. To dwie różne rzeczy. Dlatego są tu trzy niezależne warstwy:

| Warstwa | Mechanizm | Przed czym chroni |
|---|---|---|
| **Integralność** | SHA-256 każdego pliku, liczone przy wgraniu i przeliczane przy każdym wydaniu | Zmiana choćby jednego bajtu — uszkodzenie dysku, podmiana pliku |
| **Autentyczność** | Podpis **Ed25519** manifestu pliku | Podmiana pliku **razem** z poprawieniem sumy kontrolnej w bazie danych |
| **Kontrola dostępu** | Token **HMAC-SHA256** w jednorazowym, wygasającym linku | Pobieranie przez osoby bez konta, przeklejanie linków |

Kluczowa jest warstwa druga. Jeżeli napastnik włamie się na serwer, ma dostęp i do
plików, i do bazy danych — może podmienić plik i „naprawić" jego hash. Nie podrobi
jednak podpisu, jeśli klucz prywatny nie leży na tym serwerze. To właśnie jest sens
[trybu offline](#tryb-offline--zalecany-w-produkcji).

### Co dokładnie jest podpisywane

Podpis nie obejmuje samych bajtów pliku, tylko jego **manifest** — kanoniczny JSON:

```json
{"filename":"wieszak.stl","key_id":"52ef20536348f151","model":"wieszak",
 "publisher":"biblioteka-stl","schema":"stl-library/manifest/v1","sha256":"9becf9...",
 "size":1848,"uploaded_at":1754136000}
```

Klucze posortowane, bez spacji — dzięki temu serwer, narzędzie podpisujące i weryfikator
liczą podpis dokładnie z tych samych bajtów. Manifest wiąże treść (`sha256`) z nazwą,
rozmiarem, modelem i wydawcą, więc nie da się podstawić autentycznie podpisanego pliku
pod inną pozycję w katalogu.

### Ścieżka pliku wynika z jego treści

Pliki leżą w `data/storage/ab/cd/abcd…stl`, gdzie nazwa to własne SHA-256 pliku.
Podmiana treści natychmiast rozjeżdża się ze ścieżką — wykrywalne bez zaglądania do bazy.
Przy okazji ten sam plik wgrany dwa razy zajmuje miejsce raz.

### Weryfikacja po stronie przeglądarki

Przycisk „Pobierz" nie prowadzi wprost do pliku. Przeglądarka pobiera go do pamięci,
liczy SHA-256 przez WebCrypto i porównuje z hashem z podpisanego manifestu. Dopiero
zgodność pozwala zapisać plik na dysk. Razem z modelem pobierany jest plik `.sig.json`,
którym można potwierdzić autentyczność później, offline, bez ufania serwerowi:

```bash
python3 tools/verify_stl.py wieszak.stl wieszak.stl.sig.json
```

`verify_stl.py` nie ma żadnych zależności — ma wbudowaną implementację weryfikacji
Ed25519, więc możesz go dać użytkownikom bez instrukcji instalowania czegokolwiek.

---

## Uruchomienie

```bash
cd stl-library
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt
```

Wygeneruj klucze podpisu:

```bash
./.venv/bin/python tools/keygen.py
```

Skopiuj `.env.example` do `.env` i uzupełnij `STL_SECRET_KEY`, `STL_SIGNING_PUBLIC_KEY`
oraz dane pierwszego administratora. Potem:

```bash
./run.sh
```

Biblioteka stoi pod http://127.0.0.1:8000, panel administratora pod `/admin`.

Kilka przykładowych modeli do obejrzenia (do usunięcia, gdy wgrasz swoje):

```bash
./.venv/bin/python tools/seed_demo.py
```

Do pracy na localhoście ustaw w `.env` również `STL_COOKIE_SECURE=false` — bez tego
przeglądarka odrzuci ciasteczko sesji na połączeniu bez HTTPS.

Plik `.env` **nie jest** wersjonowany (zawiera klucze), więc po sklonowaniu repozytorium
trzeba go utworzyć od nowa na podstawie `.env.example`.

---

## Dwa tryby podpisywania

### Tryb online (domyślny, wygodny)

`STL_SIGNING_PRIVATE_KEY` ustawiony na serwerze. Wgrany plik jest podpisywany od razu.
Wada: kto przejmie serwer, ten może podpisać dowolny plik. Nadaje się do pracy lokalnej
i do bibliotek, w których podmiana pliku nie jest realnym zagrożeniem.

### Tryb offline — zalecany w produkcji

Na serwerze **nie ma** `STL_SIGNING_PRIVATE_KEY` — tylko klucz publiczny. Wgrane pliki
mają status `pending` i **nie da się ich pobrać**. Podpisy składasz ze swojego komputera:

```bash
export STL_SIGNING_PRIVATE_KEY=<hex klucza prywatnego>
python3 tools/sign_pending.py --url https://twoja-biblioteka.pl --email admin@example.com
```

Skrypt pobiera listę plików bez podpisu, odtwarza manifesty, podpisuje je lokalnie
i odsyła same podpisy. Klucz prywatny nigdy nie opuszcza Twojej maszyny.

Serwer nie ufa temu, co dostaje: sam odtwarza manifest z własnych danych, porównuje
z nadesłanym, sprawdza podpis kluczem publicznym i przelicza plik na dysku. Podpis
złożony obcym kluczem albo manifest, który się nie zgadza — odrzucone.

---

## Audyt

Ręcznie (przycisk w panelu) albo z linii poleceń:

```bash
./.venv/bin/python tools/audit.py
```

Przelicza SHA-256 każdego pliku i sprawdza podpisy. Co nie przejdzie kontroli, trafia do
kwarantanny i znika z katalogu. Kod wyjścia `1` przy wykrytych problemach — nadaje się
pod crona:

```cron
17 4 * * * cd /srv/stl-library && ./.venv/bin/python tools/audit.py || mail -s "Biblioteka STL: problem" ty@example.com
```

---

## Testy

```bash
./.venv/bin/python tests/e2e.py
```

34 testy na prawdziwym serwerze. Poza podstawami (logowanie, uprawnienia, CSRF, walidacja
STL) test odgrywa rolę napastnika i sprawdza dwa scenariusze podmiany:

1. **podmiana pliku na dysku** → serwer odmawia wydania, plik trafia do kwarantanny;
2. **podmiana pliku + poprawienie sumy kontrolnej i rozmiaru w bazie danych** → zatrzymana
   na niezgodności podpisanego manifestu, mimo że baza „wygląda" poprawnie.

Dodatkowo sprawdza, że `verify_stl.py` wyłapuje podmianę u użytkownika oraz że wbudowana
implementacja Ed25519 daje ten sam wynik co biblioteka `cryptography`.

---

## Pozostałe zabezpieczenia

- **Hasła** — PBKDF2-HMAC-SHA256, 260 000 iteracji, losowa sól na konto.
- **Sesje** — ciasteczko HttpOnly, SameSite=Lax, Secure, podpisane HMAC-em z terminem ważności.
- **CSRF** — double-submit cookie; każde żądanie zmieniające stan musi przynieść nagłówek
  `X-CSRF-Token` zgodny z ciasteczkiem.
- **Limit logowań** — 10 prób na parę (e-mail, IP) w 15 minut; jeden komunikat błędu
  niezależnie od tego, czy konto istnieje.
- **Linki do pobrania** — ważne 5 minut, związane z użytkownikiem, plikiem i jego hashem.
  Przeklejenie tokenu pod inny plik nie zadziała.
- **Walidacja uploadu** — sprawdzenie struktury STL (binarny i ASCII), limit rozmiaru,
  sanityzacja nazwy pliku, zapis przez plik tymczasowy.
- **Nagłówki** — CSP bez `unsafe-inline`, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`.
- **Dziennik zdarzeń** — logowania, wgrania, podpisy, kwarantanny, audyty.

---

## Wdrożenie produkcyjne

1. Postaw za HTTPS (nginx/Caddy) — bez tego `STL_COOKIE_SECURE=true` zablokuje logowanie.
2. `STL_SECRET_KEY` wygeneruj raz i nie zmieniaj (zmiana wylogowuje wszystkich).
3. Wybierz tryb offline: usuń `STL_SIGNING_PRIVATE_KEY` z serwera.
4. Zrób kopię zapasową klucza prywatnego offline — jego utrata oznacza podpisanie całej
   biblioteki od nowa nowym kluczem.
5. Backup obejmuje `data/library.db` **i** `data/storage/`. Sam plik bazy bez plików
   (albo odwrotnie) jest bezużyteczny.
6. Uruchamiaj przez systemd albo `uvicorn --workers N` za proxy; katalog `data/` powinien
   należeć do użytkownika usługi i nie być serwowany bezpośrednio przez serwer WWW.
7. Ustaw crona z `tools/audit.py`.

### Czego to nie załatwia

- Nie chroni przed podmianą pliku **zanim** go podpiszesz — podpisujesz to, co dostaniesz.
  Jeżeli źródło modeli jest niepewne, sprawdź plik przed wgraniem.
- Nie chroni przed administratorem, który świadomie podpisze zły plik.
- W trybie online nie chroni przed przejęciem serwera — do tego służy tryb offline.
- Nie zajmuje się prawami autorskimi do modeli; pole `license` jest wyłącznie opisowe.

---

## Struktura

```
app/
  config.py     konfiguracja ze zmiennych środowiskowych
  db.py         SQLite: schemat i dostęp
  security.py   hasła, tokeny HMAC, manifesty i podpisy Ed25519
  storage.py    magazyn adresowany treścią, walidacja STL
  integrity.py  ścieżka weryfikacji przed wydaniem pliku
  main.py       API i routing
static/         frontend: katalog, widok modelu, podgląd 3D, panel admina
tools/
  keygen.py       generowanie pary kluczy
  sign_pending.py podpisywanie z maszyny offline
  verify_stl.py   weryfikator dla użytkowników (bez zależności)
  audit.py        audyt integralności pod crona
  seed_demo.py    przykładowe modele
tests/e2e.py    testy end-to-end, w tym symulacja podmiany plików
```
