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
W tym przypadku, klucz API (api_key) jest zapisany w pliku tekstowym (/tmp/supersecret.txt). Przechowywanie wrażliwego klucza API w formie jawnej w pliku stanowi poważne zagrożenie dla bezpieczeństwa. Jeśli ten plik nie jest odpowiednio zabezpieczony, np. przez odpowiednie uprawnienia dostępu, może zostać odczytany przez nieautoryzowane osoby, co umożliwia im dostęp do wrażliwych zasobów API.
Jeśli plik jest dostępny w publicznie dostępnej lokalizacji (np. /tmp), każdy użytkownik lub proces może go odczytać. Klucz API nie jest szyfrowany, co oznacza, że w razie wycieku danych klucz będzie dostępny w swojej oryginalnej postaci. Jeżeli ten plik jest przechowywany na serwerze, który nie jest odpowiednio zabezpieczony, atakujący może uzyskać dostęp do systemu i pozyskać klucz API, co może prowadzić do nieautoryzowanego dostępu do API.
```python
with api_key_file.open('w') as outfile:
    outfile.write(api_key)
```
#### Sugerowane formy poprawy zabezpieczeń
Aby rozwiązać ten problem, zamiast przechowywać klucz API w pliku tekstowym w postaci jawnej, należy używać bezpieczniejszych metod przechowywania wrażliwych danych, takich jak:
- Szyfrowanie: Klucz API powinien być szyfrowany przed zapisaniem go w pliku, a następnie deszyfrowany tylko w przypadku potrzeby użycia.
- Bezpieczne magazyny sekretów: Należy rozważyć użycie specjalistycznych narzędzi do przechowywania sekretów, takich jak HashiCorp Vault, AWS Secrets Manager czy Azure Key Vault, które zapewniają bezpieczne przechowywanie i dostęp do kluczy API.
- Ograniczenie dostępu do pliku: Jeśli klucz musi być przechowywany w pliku, dostęp do tego pliku powinien być ograniczony do tylko tych użytkowników lub procesów, które muszą go używać.
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
#### Opis podatności
Aplikacja nie implementuje kompletnego mechanizmu obsługi błędów (ang. error handling). W wielu miejscach nie wykorzystywane są odpowiednie bloki try-except ani globalne metody (np. @app.errorhandler) do przechwytywania wyjątków. Może to powodować wyświetlanie surowego stack trace lub niejasnych komunikatów błędów, co bywa niebezpieczne (ujawnienie wewnętrznej struktury aplikacji) i dezorientuje użytkowników.
#### Fragment kodu
W pliku vulpy/_init_.py można zauważyć brak bloków obsługi wyjątków w wielu trasach, np. w funkcji index:
```python
@app.route('/', methods=['GET'])
def index():
    # Nie ma żadnych mechanizmów obsługi błędów
    return render_template('index.html')
```
Żaden z endpointów nie stosuje globalnego przechwytywania błędów (np. @app.errorhandler(Exception)) – ewentualne błędy nie są obsługiwane w ujednolicony sposób.
#### Czynności prowadzące do wykrycia błędu i opis
- Wysłanie żądania pod niepoprawny endpoint, np. GET /wrongendpoint → zwracany jest ogólny błąd 404 bez przekierowania do specjalnego widoku błędu.
- Generowanie błędu w jednym z endpointów (np. dzielenie przez zero) ujawnia w konsoli cały stack trace (kiedy debug jest włączony).
- W kodzie brak wzorców typu try-except oraz brak centralnej obsługi wyjątków (np. @app.errorhandler(500)).
#### Sugerowane formy poprawy zabezpieczeń
- Wprowadzenie globalnego handlera błędów w Flask, np.:
```python
@app.errorhandler(Exception)
def handle_exception(e):
    # Można logować szczegóły błędu do plików,
    # a użytkownikowi zwracać jedynie zwięzły komunikat.
    return render_template('error.html'), 500
```
- Dodanie specyficznych obsług dla wybranych wyjątków HTTP (404, 500, 403).
- Ukrywanie szczegółów błędów przed użytkownikiem końcowym w środowisku produkcyjnym (wyłączenie debug=True).
### 7. Brak walidacji złożoności haseł
#### Opis podatności
Podczas rejestracji lub edycji profilu użytkownika nie są narzucane żadne zasady dotyczące minimalnej długości czy złożoności hasła. Umożliwia to tworzenie bardzo krótkich i/lub prostych haseł typu 1234, admin, co znacząco zwiększa podatność aplikacji na ataki słownikowe i brute force.
#### Fragment kodu
W pliku vulpy/_init_.py, w funkcji obsługującej rejestrację (/register), nie ma żadnego sprawdzenia siły hasła:
```python
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Brak walidacji: minimalnej długości, znaków specjalnych itp.
        user = User(username=username, password=password, email=email)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('register.html')
```
#### Czynności prowadzące do wykrycia błędu i opis
- Założenie konta z hasłem o długości np. 1–2 znaków ("ab").
- Brak jakiejkolwiek walidacji haseł w warstwie serwera – w logach nie pojawia się ostrzeżenie, a w bazie danych hasło zostaje zapisane bez sprawdzenia jakości.
#### Sugerowane formy poprawy zabezpieczeń
- Wymuszenie w backendzie odpowiedniej złożoności hasła, np. z użyciem:
```python
if len(password) < 8 or not re.search(r"\d", password):
    flash("Hasło musi zawierać min. 8 znaków i co najmniej jedną cyfrę.")
    return redirect(url_for('register'))
```
- Zwiększenie minimalnej długości hasła (np. 8–12 znaków) oraz wymaganie znaków specjalnych, dużych i małych liter.
- Dodanie limitów prób logowania oraz mechanizmów blokowania konta przy wielokrotnych nieudanych próbach uwierzytelnienia.
### 8. HTTP zamiast HTTPS
#### Opis podatności
Aplikacja domyślnie uruchamia się przez zwykły protokół HTTP (port 5000 w trybie debug), bez jakiejkolwiek warstwy szyfrowania (SSL/TLS). Dane – w tym hasła i sesje – mogą być przechwycone, co prowadzi do potencjalnych ataków typu Man-in-the-middle.
#### Fragment kodu
```python
if __name__ == "__main__":
    # Aplikacja startuje w trybie debug i nasłuchuje na porcie 5000 bez SSL/TLS
    app.run(debug=True, host='0.0.0.0', port=5000)
```
#### Czynności prowadzące do wykrycia błędu i opis
- Uruchomienie aplikacji → http://localhost:5000 (brak wymuszenia https://).
- Przeglądarka wyświetla zwykły protokół HTTP, a konsola deweloperska nie sygnalizuje połączenia szyfrowanego.
- Prześledzenie ruchu sieciowego (np. Wireshark) pokazuje, że dane logowania przesyłane są jako tekst jawny.
#### Sugerowane formy poprawy zabezpieczeń
- Wdrożenie HTTPS: Użycie serwera proxy (np. Nginx) z certyfikatem SSL (np. z Let’s Encrypt).
- W aplikacji Flask można skorzystać z zewnętrznego narzędzia do wystawienia połączenia TLS, a w środowisku produkcyjnym zawsze wyłączyć debug=True.
- Ustawianie odpowiednich nagłówków bezpieczeństwa, np. Strict-Transport-Security.
### 9. Słaba generacja kluczy
#### Opis podatności
Aplikacja wykorzystuje statyczny, niezmienny sekret (SECRET_KEY) w pliku konfiguracyjnym, co wskazuje na brak bezpiecznej, pseudolosowej generacji klucza. Brak rotacji, użycie prostej wartości lub słabe źródło losowości sprawiają, że atakujący może przewidzieć lub poznać klucz, a w konsekwencji odczytać i modyfikować zaszyfrowane dane (np. sesje).
#### Fragment kodu
W pliku vulpy/config.py:
```python
SECRET_KEY = "myflaskappsecretkey"
ALLOWED_HOSTS = ["*"]
```
Jest to stała wartość wpisana „na sztywno”, co oznacza brak rotacji i źródła entropii.
#### Czynności prowadzące do wykrycia błędu i opis
- Analiza plików konfiguracyjnych i odnalezienie wpisu SECRET_KEY.
- Brak jakichkolwiek mechanizmów generowania losowego klucza przy starcie aplikacji.
- Niestandardowe wartości klucza nie są w ogóle pobierane z bezpiecznego magazynu (np. zmiennych środowiskowych).
#### Sugerowane formy poprawy zabezpieczeń
- Wygenerowanie unikalnego klucza dla każdego środowiska (produkcja, staging) przy użyciu np. os.urandom(24) lub secrets.token_hex(32).
- Przechowywanie klucza w bezpiecznym menedżerze sekretów (np. HashiCorp Vault, AWS Secrets Manager) lub w zmiennych środowiskowych (os.environ).
- Okresowa rotacja sekretów i stosowanie sprawdzonych narzędzi do zarządzania nimi.
### 10. Hardkodowane hasła
#### Opis podatności
Bezpośrednie umieszczanie haseł i danych uwierzytelniających w plikach konfiguracyjnych bądź kodzie źródłowym jest poważnym zagrożeniem. W razie wycieku repozytorium lub nieautoryzowanego dostępu do serwera, atakujący łatwo przejmuje te dane i może zalogować się do bazy danych czy innych usług.
#### Fragment kodu
W pliku vulpy/database.py:
```python
DB_USERNAME = "admin"
DB_PASSWORD = "admin"
DB_NAME = "vulpy"
DB_HOST = "localhost"
```
Wartości DB_USERNAME i DB_PASSWORD są jawnie zapisane jako "admin", co stanowi przykład hardkodowanego hasła.
#### Czynności prowadzące do wykrycia błędu i opis
- Proste wyszukiwanie w repozytorium (np. grep -Ri password).
- Odczyt kodu w pliku database.py wykazuje brak odwołania do zmiennych środowiskowych lub zewnętrznych magazynów haseł.
- Uruchomienie aplikacji i sprawdzenie logów pokazuje, że łączy się ona z bazą na lokalnym hoście używając tych statycznych danych.
#### Sugerowane formy poprawy zabezpieczeń
- Przeniesienie haseł do zmiennych środowiskowych i odczytywanie ich w kodzie:
```python
import os
DB_USERNAME = os.environ.get("DB_USERNAME")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
```
- Korzystanie z bezpiecznych magazynów sekretów (Vault, Key Vault, itp.) zamiast przechowywać hasła w repozytorium.
- Natychmiastowa zmiana hasła w środowisku produkcyjnym, jeśli kiedykolwiek zostało ujawnione w plikach publicznych.
