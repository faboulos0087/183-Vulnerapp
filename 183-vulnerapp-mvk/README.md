# VulnerApp Whitehat

## Starten

```console
./gradlew bootRun
```

Dann <http://localhost:8080/> aufrufen.

Demo-Konten:

| Benutzer | Passwort           | Rolle |
|----------|--------------------|-------|
| admin    | `Sup3rSecretAdmin` | ADMIN |
| fuu      | `BarbarossA123`    | USER  |

## Tests

```console
./gradlew test
```

35 Sicherheits-Integrationstests mit `WebTestClient`
([SecurityIntegrationTest](src/test/java/ch/bbw/m183/vulnerapp/SecurityIntegrationTest.java)).

## Pflicht-Anforderungen — Umsetzung im Überblick

| Anforderung | Wo umgesetzt |
|-------------|--------------|
| Korrekte REST-Verben | [AdminController](src/main/java/ch/bbw/m183/vulnerapp/controller/AdminController.java) `POST/GET/DELETE`, [BlogController](src/main/java/ch/bbw/m183/vulnerapp/controller/BlogController.java) `GET/POST` |
| Session-basierte Authentifizierung | [SecurityConfig](src/main/java/ch/bbw/m183/vulnerapp/SecurityConfig.java) `formLogin`, [RestfulFormService](src/main/java/ch/bbw/m183/vulnerapp/service/RestfulFormService.java) JSON-Login |
| RBAC (User / Admin) | [UserEntity.role](src/main/java/ch/bbw/m183/vulnerapp/datamodel/UserEntity.java) → `UserDetailsService` (SecurityConfig) → `hasRole`-Matcher |
| CSRF-Protection | Spring Security SPA-CSRF via `csrf.spa()` in [SecurityConfig](src/main/java/ch/bbw/m183/vulnerapp/SecurityConfig.java); Frontend in [script.js](src/main/resources/static/script.js) sendet `X-XSRF-TOKEN` |
| Sichere Passwort-Speicherung | `BCryptPasswordEncoder` in [SecurityConfig](src/main/java/ch/bbw/m183/vulnerapp/SecurityConfig.java), Passwort-Regeln in [UserCreateDto](src/main/java/ch/bbw/m183/vulnerapp/datamodel/UserCreateDto.java) |
| Hibernate-Validator (REST + DB) | `@Valid` in den Controllern, `@NotBlank/@Size/@Pattern` in [UserEntity](src/main/java/ch/bbw/m183/vulnerapp/datamodel/UserEntity.java), [BlogEntity](src/main/java/ch/bbw/m183/vulnerapp/datamodel/BlogEntity.java), [UserCreateDto](src/main/java/ch/bbw/m183/vulnerapp/datamodel/UserCreateDto.java); JPA `validation.mode=AUTO` in [application.yaml](src/main/resources/application.yaml) |
| SQLi-Behebung | [UserService](src/main/java/ch/bbw/m183/vulnerapp/service/UserService.java) nutzt `findById` statt String-Concat |
| XSS-Behebung | [script.js](src/main/resources/static/script.js) rendert mit `textContent`; CSP-Header in SecurityConfig |
| CSRF-Behebung | Siehe Punkt CSRF-Protection oben |
| WebTestClient-Tests | [SecurityIntegrationTest](src/test/java/ch/bbw/m183/vulnerapp/SecurityIntegrationTest.java) — Zugriffsmatrix gemäss Auftrag plus gezielte Regressionstests |

### Zusätzliche (nicht-geforderte) Härtungen

CSP/X-Frame/Referrer-Header, Cookie-Flags `HttpOnly`/`SameSite=strict`,
deaktiviertes Payload-Logging (Passwort-Leak ins Server-Log), versteckte Stack-Traces.
Method-based Security via `@EnableMethodSecurity` und `@PreAuthorize("hasRole('ADMIN')")`
auf [AdminService](src/main/java/ch/bbw/m183/vulnerapp/service/AdminService.java) als
Defense-in-Depth zusätzlich zur URL-basierten Autorisierung.
In der Aufgabe unter "Zusätzlich" gelistet; nicht für Note 5 nötig.

## Endpunkt-Verhalten

| Endpunkt | anonymous | User ohne CSRF | User mit CSRF | Admin mit CSRF |
|----------|-----------|----------------|---------------|----------------|
| `GET /` | 200 | 200 | 200 | 200 |
| `GET /api/blog` | 200 | 200 | 200 | 200 |
| `POST /api/blog` | 401 | 403 | 201 | 201 |
| `GET /api/user/whoami` | 401 | 200 | 200 | 200 |
| `/api/admin/*` | 401 | 403 | 403 | 200/201/204 |
| `GET /actuator/health` | 200 ohne Details | 200 mit Details | 200 mit Details | 200 mit Details |

## Warum die CSRF-Implementation funktioniert

CSRF nutzt aus, dass der Browser bei einer Cross-Site-Request automatisch Cookies
mitsendet — eine fremde Seite kann also im Namen des eingeloggten Opfers `POST /api/blog`
abschicken. Das **Double-Submit-Cookie**-Muster bricht den Angriff:

1. Spring Security konfiguriert mit `csrf.spa()` das CSRF-Verhalten für ein JavaScript-
   Frontend. Der Browser erhält ein `XSRF-TOKEN`-Cookie, das der eigene Code lesen kann.
2. Der eigene JS-Code liest das Cookie und schickt den Wert als `X-XSRF-TOKEN`-Header bei
   jeder schreibenden Anfrage mit.
3. Eine fremde Origin kann das Cookie **nicht lesen** (Same-Origin-Policy) und den Header
   **nicht setzen** (Browser blocken Cross-Origin-Custom-Header). Der Spring-CSRF-Filter
   vergleicht Cookie und Header constant-time und lehnt sonst ab.
4. Bei erfolgreichem Login rotiert die `CsrfAuthenticationStrategy` den Token implizit,
   beim Logout wird das Cookie aktiv gelöscht.

`GET/HEAD/OPTIONS` werden nicht geprüft, weil sie laut RFC nichts ändern dürfen — deshalb
ist es essentiell, dass die schreibenden Operationen wie `deleteUser` jetzt `DELETE` sind
und nicht mehr `GET` (Punkt 1 der Pflicht-Anforderungen).

## Diskussion und Selbstevaluation

### Welche Mechanismen wo und warum

- **REST-Verben**: Schreibende `GET`-Endpoints (`/api/admin/delete/{user}`) konnten per
  `<img src="…">` ausgenutzt werden, ohne CSRF-Token, weil GET vom CSRF-Filter nicht
  geprüft wird. Mit `DELETE`/`POST` greift der CSRF-Schutz.
- **Session-Auth + RBAC**: Ohne authentifizierte Identität gibt es keine Autorisierung;
  ohne Rolle keine Trennung User/Admin. Die Authority kommt aus dem DB-Feld
  `UserEntity.role`, nicht hardcoded.
- **CSRF**: Siehe Abschnitt oben. Funktioniert nur, weil zustandsverändernde Operationen
  ausschliesslich über CSRF-pflichtige Methoden laufen.
- **BCrypt + Passwort-Regeln**: BCrypt enthält Salt und ist absichtlich langsam (resistent
  gegen GPU-Brute-Force). Plaintext-Passwörter werden nie persistiert; im JSON-Output sind
  sie via `@JsonProperty(WRITE_ONLY)` unsichtbar.
- **Validation**: Controller-seitig per `@Valid`, zusätzlich Hibernate-seitig vor jedem
  Persist. Greift auch, wenn ein anderer Pfad als der Controller eine Entity speichert.
- **SQLi**: Native-Query mit String-Concat ersetzt durch `JpaRepository.findById` —
  ein parametrisiertes Prepared-Statement.
- **XSS**: `textContent` statt `innerHTML` rendert HTML als Text statt zu interpretieren.

### Weitere mögliche Sicherheitsmechanismen

- **Rate-Limit auf `/login`** (z. B. Bucket4j) gegen Brute-Force.
- **OIDC** (`spring-security-oauth2-client`) statt eigener Passwort-Speicherung.
- **MFA / TOTP** als zweiter Faktor, mindestens für Admins.
- **HSTS-Header** in Produktion erzwingt HTTPS.
- **Audit-Log** für sensitive Admin-Operationen.
- **`spring-data-pageable-max-page-size`** gegen `?size=1000000`-DOS.

### Schwierigkeiten / was anders gemacht werden sollte

- **CSRF-Token-Rotation nach Login**: Spring 6 löscht das anonyme XSRF-Cookie beim Login
  und issued kein neues im selben Response — erst der nächste Request bringt ein frisches
  Token. Hat im Test-Aufbau zu falschen 403-Failures geführt, gelöst durch einen
  zusätzlichen `GET` nach jedem `loginAs`.
- **Entity vs. DTO für Passwort-Validierung**: Erste Version hatte Passwort-Regeln direkt
  auf `UserEntity`; beim Persistieren scheiterte die Validierung am BCrypt-Hash, der das
  Pattern nicht erfüllt. Aufgelöst durch [UserCreateDto](src/main/java/ch/bbw/m183/vulnerapp/datamodel/UserCreateDto.java).
- **Anonymes CSRF-Fail → 401 statt 403**: Bei anonymen Requests delegiert Spring CSRF-Fehler
  an den `AuthenticationEntryPoint` (= 401), nicht an den `AccessDeniedHandler` (= 403).
  Das musste in einem Test entsprechend abgebildet werden.
- **Beim nächsten Mal**: Tests parallel zur Implementation schreiben, nicht erst am Schluss
  — die Suite hat mehrere stille Konfigurations-Schiefstände aufgedeckt, die beim
  Hand-Test nicht aufgefallen wären.

### Aufwand vs. Ertrag

Die Pflicht-Massnahmen kosten zusammen rund 8 Stunden Implementation plus etwa 2 Stunden
Test/Debug. Spring Security übernimmt fast alle harten Teile (CSRF-Token-Handling, Session,
BCrypt) — man muss vor allem wissen, welche Defaults stehen bleiben sollen und welche
explizit gesetzt werden müssen. Das Verhältnis ist hier sehr günstig: jede einzelne
Pflicht-Massnahme verhindert eine ganze Angriffsklasse.

Allgemein im Betrieb gilt: die erste Stunde Sicherheitsarbeit ist hundertfach mehr wert
als die hundertste. Authentifizierung, RBAC, CSRF, Input-Validation, Passwort-Hashing und
HTTPS sind günstige No-Brainer mit grosser Wirkung. MFA, vollständige CSP ohne
`unsafe-inline`, WebAuthn, automatisches Pentesting kosten dramatisch mehr und lohnen sich
nur abhängig vom Bedrohungsmodell. Der wirklich teure Anteil ist nicht das Implementieren,
sondern das Aufrechterhalten — Dependency-Updates, CVE-Monitoring, Log-Auswertung —, und
da rentiert sich Investition in Tooling (Dependabot, SCA) mehr als jede zusätzliche
Härtungsmassnahme.
