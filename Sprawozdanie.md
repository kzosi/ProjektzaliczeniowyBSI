# Audyt aplikacji vulpy
### Michał Macias, Zofia Kościńska 

## Podsumowanie

Raport jest podsumowaniem testów bezpieczeństwa aplikacji webowej Vulpy. Jest to aplikacja blogowa napisana w języku Python, wykorzystująca framework Flask oraz bazę danych SQLite. Repozytorium jest publiczne, a aplikacja występuje w dwóch wersjach: **GOOD**, uwzględniającej najlepsze praktyki bezpiecznego programowania, oraz **BAD**, zawierającej celowo wprowadzone podatności.

#### Funkcjonalności aplikacji:
- rejestracja i logowanie
- publikowanie oraz przeglądanie postów
- uwierzytelnianie dwuskładnikowe (MFA)
- dostęp do API do odczytu i zapisu postów

Ostatnia aktualizacja: styczeń 2025</br>
Wersja aplikacji: 1.0.0

#### Technologie wykorzystane w aplikacji:
- Python 3
- Flask
- SQLite
- Werkzeug
- Docker
- SSL/TLS

#### Opinia:</br>
Aplikacja została zaprojektowana jako narzędzie edukacyjne do nauki testowania bezpieczeństwa. Zaletą jest podział na wersje **GOOD** i **BAD**, co umożliwia porównanie i analizę podatności w kontrolowanym środowisku. Najistotniejsze problemy w wersji **BAD** obejmują:
- podatność na SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- brak odpowiednich mechanizmów uwierzytelniania ról użytkowników

Zaletą aplikacji jest wykorzystanie popularnych technologii i frameworków, co ułatwia wdrożenie i analizę testów bezpieczeństwa.

#### Struktura aplikacji
Testy przeprowadzone były w środowisku lokalnym z wykorzystaniem Dockera. Aplikacja działała w dwóch kontenerach:
- kontener z aplikacją Flask
- kontener z bazą danych SQLite

Audyt został oparty na metodyce OWASP TOP 10 w wersji 2021. Testy przeprowadziliśmy ręcznie, analizując kod źródłowy i wyszukując w nim błędy oraz podatności.

## Klasyfikacja błędów:
- High
  - Wrażliwość na SQL Injection
  - Przechowywanie wrażliwych danych w postaci tekstu jawnego
  - Ujawnianie klucza API w logach
  - Brak walidacji wejścia dla nazwy użytkownika
- Medium
  - Hardkodowany URL API
  - Brak obsługi błędów dla wywołań żądań
  - Brak walidacji złożoności haseł
- Low
   - HTTP zamiast HTTPS
   - Słaba generacja kluczy
   - Hardkodowane hasła
 
## Zlokalizowane problemy
### 1. Wrażliwość na SQL Injection
#### Czynności prowadzące do wykrycia błędu i opis
Bezpośrednie wstawianie danych wejściowych, takich jak username i password, do zapytania SQL bez żadnej walidacji lub filtrowania stanowi poważne zagrożenie, ponieważ umożliwia atakującemu manipulowanie zapytaniem. Takie podejście stwarza ryzyko SQL Injection, które jest jednym z najczęściej wykorzystywanych rodzajów ataków na aplikacje webowe. Atakujący może wprowadzić specjalnie przygotowane dane, które zmieniają strukturę zapytania SQL, co prowadzi do nieautoryzowanego dostępu do systemu lub baz danych. Na przykład, jeśli atakujący poda jako nazwę użytkownika wartość ' OR '1'='1, zapytanie może zostać zmodyfikowane w sposób, który zawsze zwróci wynik, umożliwiając dostęp bez znajomości prawidłowego hasła.
```python
user = c.execute("SELECT * FROM users WHERE username = '{}' and password = '{}'".format(username, password)).fetchone()
```
```python
c.execute("UPDATE users SET password = '{}' WHERE username = '{}'".format(password, username))
```
#### Sugerowane formy poprawy zabezpieczeń
Aby zabezpieczyć kod przed atakami SQL Injection, należy unikać bezpośredniego wstawiania danych wejściowych, takich jak nazwa użytkownika czy hasło, do zapytań SQL w formie tekstu. Zamiast tego, należy korzystać z zapytań parametryzowanych (ang. parameterized queries), które traktują dane wejściowe jako oddzielne parametry, a nie część zapytania SQL. Dzięki temu baza danych automatycznie dba o odpowiednią walidację i formatowanie danych wejściowych, co uniemożliwia wstrzykiwanie złośliwego kodu i chroni aplikację przed atakami typu SQL Injection.
```python
user = c.execute("SELECT * FROM users WHERE username = ? and password = ?", (username, password)).fetchone()
```
```python
c.execute("UPDATE users SET password = ? WHERE username = ?", (password, username))
```
### 2. Przechowywanie wrażliwych danych w postaci tekstu jawnego
#### Czynności prowadzące do wykrycia błędu i opis
#### Sugerowane formy poprawy zabezpieczeń
### 3. Ujawnianie klucza API w logach
#### Czynności prowadzące do wykrycia błędu i opis
Klucz API jest wyświetlany w logach, następuje ujawnienie wrażliwych informacji. Klucze API są poufnymi danymi, które powinny być traktowane z dużą ostrożnością, ponieważ ich ujawnienie może prowadzić do nieautoryzowanego dostępu do systemu lub usług. Eksponowanie takich informacji w logach jest niebezpieczne, ponieważ logi mogą być dostępne dla nieupoważnionych użytkowników, co zwiększa ryzyko ataków, takich jak przejęcie dostępu do API lub inne formy wykorzystania wrażliwych danych.
```python
print('Received key:', api_key
```
#### Sugerowane formy poprawy zabezpieczeń
Aby zapobiec temu zagrożeniu, należy unikać logowania wrażliwych danych, takich jak klucze API, hasła czy dane użytkowników. Zamiast tego, w logach powinny pojawiać się jedynie wiadomości zastępcze, które nie ujawniają rzeczywistych informacji, np. "Received API key" zamiast pełnego klucza. Dodatkowo, dobrym rozwiązaniem jest korzystanie z odpowiednich narzędzi do zarządzania logami, które pozwalają na maskowanie wrażliwych danych. Takie podejście znacząco podnosi poziom bezpieczeństwa aplikacji, minimalizując ryzyko przypadkowego lub złośliwego dostępu do poufnych informacji.
### 4. Brak walidacji wejścia dla nazwy użytkownika
#### Czynności prowadzące do wykrycia błędu i opis
Aplikacja nie sprawdza, czy username spełnia określone wymagania, takie jak długość, dozwolone znaki czy pustość, co może prowadzić do błędnych zapytań HTTP i problemów z bezpieczeństwem, takich jak ataki typu SQL injection czy XSS. Brak walidacji umożliwia użytkownikowi wprowadzenie nieprawidłowych danych, które mogą zakłócić działanie systemu.
```python
@click.argument('username')
def cmd_api_client(username):
    r = requests.get('http://127.0.1.1:5000/api/post/{}'.format(username))
```
#### Sugerowane formy poprawy zabezpieczeń
Aby zapobiec tym problemom, warto dodać kontrolę, która upewni się, że username nie jest pusty, ma odpowiednią długość i zawiera tylko dozwolone znaki, np. alfanumeryczne. Taka walidacja pozwoli uniknąć błędów oraz poprawi bezpieczeństwo aplikacji. Implementując te proste zasady, aplikacja stanie się bardziej niezawodna i bezpieczna.
```python
def cmd_api_client(username):
    # Walidacja wejścia dla nazwy użytkownika
    if not username:
        click.echo('Username cannot be empty.')
        return
    if len(username) < 3 or len(username) > 30:
        click.echo('Username must be between 3 and 30 characters long.')
        return
    if not re.match('^[a-zA-Z0-9_]+$', username):
        click.echo('Username can only contain letters, digits, and underscores.')
        return
```
### 5. Hardkodowany URL API
#### Czynności prowadzące do wykrycia błędu i opis

W kodzie znajduje się wywołanie HTTP za pomocą hardkodowanego URL:
```python
r = requests.post('http://127.0.1.1:5000/api/key', json={'username':username, 'password':password})
```
Hardkodowanie URL w kodzie oznacza, że adres serwera jest zapisany na stałe, co zmniejsza elastyczność aplikacji i sprawia, że zmiana środowiska (np. zmiana z środowiska deweloperskiego na produkcyjne) staje się bardziej kłopotliwa. Jeśli kod z takim URL trafi do produkcji, może to prowadzić do niezamierzonego ujawnienia wewnętrznych punktów końcowych API. Dodatkowo, serwer dostępny pod takim URL może być dostępny tylko w określonym środowisku, co może skutkować problemami, gdy aplikacja zostanie uruchomiona na innym serwerze lub w chmurze, gdzie ten sam adres IP nie będzie dostępny.

W przypadku zastosowania takiego hardkodowanego adresu URL, jeśli aplikacja zostanie wdrożona na produkcyjnym serwerze, użytkownicy mogą uzyskać dostęp do punktów końcowych, które nie powinny być dostępne publicznie. Może to prowadzić do wycieków informacji lub innych ataków. Warto również zauważyć, że taki sposób konfiguracji utrudnia zarządzanie aplikacją w różnych środowiskach, ponieważ każda zmiana URL wymaga edytowania kodu, a nie tylko modyfikacji w konfiguracji.
#### Sugerowane formy poprawy zabezpieczeń
Aby rozwiązać ten problem, należy przenieść URL bazowy do zewnętrznego źródła konfiguracyjnego, jak plik konfiguracyjny lub zmienne środowiskowe, co pozwala na łatwiejszą modyfikację i zarządzanie aplikacją w różnych środowiskach. Można to osiągnąć poprzez użycie zmiennych środowiskowych lub dedykowanych plików konfiguracyjnych. Przykład z wykorzystaniem zmiennej środowiskowej:
```python
API_BASE_URL = os.getenv('API_BASE_URL', 'http://127.0.1.1:5000')
```
W takim przypadku aplikacja będzie korzystać z adresu URL określonego w zmiennej środowiskowej API_BASE_URL, a jeśli ta zmienna nie jest ustawiona, użyje domyślnego adresu URL. Dzięki temu, aby zmienić środowisko, wystarczy tylko zaktualizować zmienną środowiskową lub plik konfiguracyjny, co sprawia, że aplikacja jest bardziej elastyczna i łatwiejsza w utrzymaniu.

Dodatkowo, korzystanie z zewnętrznych plików konfiguracyjnych lub zmiennych środowiskowych pozwala na większe bezpieczeństwo, ponieważ wrażliwe dane, jak adresy URL do interfejsów API, nie są ujawniane bezpośrednio w kodzie źródłowym aplikacji.
### 6. Brak obsługi błędów dla wywołań żądań
#### Czynności prowadzące do wykrycia błędu i opis
#### Sugerowane formy poprawy zabezpieczeń
### 7. Brak walidacji złożoności haseł
#### Czynności prowadzące do wykrycia błędu i opis
#### Sugerowane formy poprawy zabezpieczeń
### 8. HTTP zamiast HTTPS
#### Czynności prowadzące do wykrycia błędu i opis
#### Sugerowane formy poprawy zabezpieczeń
### 9. Słaba generacja kluczy
#### Czynności prowadzące do wykrycia błędu i opis
#### Sugerowane formy poprawy zabezpieczeń
### 10. Hardkodowane hasła
#### Czynności prowadzące do wykrycia błędu i opis
#### Sugerowane formy poprawy zabezpieczeń
