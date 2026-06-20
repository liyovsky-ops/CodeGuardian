# 🛡️ Code Guardian

Kompletny atlas zagrożeń bezpieczeństwa kodu — interaktywna strona referencyjna dla
developerów (junior → senior) i security engineerów.

## Co to jest

Statyczna strona prezentująca **10 kategorii** i **70+ konkretnych zagrożeń** bezpieczeństwa
aplikacji (OWASP aligned). Dla każdego zagrożenia:

- nazwa, opis, identyfikator (np. `2.2`),
- **severity badge** (🔴 Critical / 🟠 High / 🟡 Medium / 🔵 Low),
- **trudność wykrycia** (Easy / Medium / Hard / Very Hard),
- klikalne **CWE** (link do cwe.mitre.org),
- zakładki **Podatny kod** / **Bezpieczny kod** z podświetlaniem składni,
- przycisk **kopiowania** przykładu.

Dodatkowo: macierz wykrywalności (static vs runtime) oraz wnioski dla developerów.

## Funkcje UX

- Sticky sidebar z kategoriami + licznikami (desktop), hamburger menu (mobile)
- Wyszukiwarka + filtry po severity i trudności
- Rozwijane karty (collapsible), pasek postępu czytania, „back to top”
- Dark / light mode (zapamiętywany)
- Deep-linki (np. `#threat-2.2`) automatycznie otwierają kartę

## Uruchomienie

Otwórz `index.html` w przeglądarce. Działa przez `file://`, bez serwera i bez npm.

```
xdg-open index.html        # Linux
start index.html           # Windows
```

## Stack

Vanilla HTML / CSS / JS. Podświetlanie składni: **Prism.js** (CDN, z autoloaderem;
gdy CDN niedostępny — kod wyświetla się czytelnie jako zwykły monospace).

## Struktura

```
CodeGuardian/
  index.html          # szkielet strony
  assets/
    data.js           # baza zagrożeń (źródło: SECURITY_THREATS.md)
    app.js            # render + interaktywność
    style.css         # style (dark/light, responsive)
  README.md
```

## Źródło wiedzy

Cała treść pochodzi z `SECURITY_THREATS.md` (War Room). Przykłady „PODATNE” są
wyłącznie ilustracyjne — **nie używać w produkcji**.
