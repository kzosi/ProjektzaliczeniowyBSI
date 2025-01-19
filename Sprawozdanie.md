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
#### Sugerowane formy poprawy zabezpieczeń
### 2. Przechowywanie wrażliwych danych w postaci tekstu jawnego
#### Czynności prowadzące do wykrycia błędu i opis
#### Sugerowane formy poprawy zabezpieczeń
### 3. Ujawnianie klucza API w logach
#### Czynności prowadzące do wykrycia błędu i opis
#### Sugerowane formy poprawy zabezpieczeń
### 4. Brak walidacji wejścia dla nazwy użytkownika
#### Czynności prowadzące do wykrycia błędu i opis
#### Sugerowane formy poprawy zabezpieczeń
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
