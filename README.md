Selbstvaluation:
1. Diskutieren Sie, welche Sicherheitsmechanismen wo implementiert wurden und warum diese die Sicherheit der Applikation verbessern, in Ihren eigenen Worten.

SQLi: Im Original wurde der Username direkt in eine SQL-Query eingebaut.
Ich habe das mit findById() ersetzt, damit landet der User-Input nie direkt
im SQL-String. Das habe ich im USerServive.java iimplementiert

XSS-Fehler: Ich habe einen CSP-Header im SecurityConfig gesetzt, der das laden fremder Scripts verhindert, da am anfang die HTLM Inhalte im innerHTML gerendert wurden, was eingeschleusten code ausführen konnte. Das habe ich im script.js auf textContent umgestellt, was jetzt alles als normalen Text behandelt.

CSrf: Ich habe den CookieCsrfTokenReposetory im SecurityConfig eingebaut, da legt spring einen Token als Cookie ab, dieser wird vom Frontend gelesen und schickt ihn im Header mit.

Passwörter: Ich habe BCrypt im SecurityConfig verwendet, dass Passwörter als Hash speichert, was heisst, das sie unleserlich werden. Zusätzlich habe ich Passwortregeln, wie min. 10 Zeichen im UserCreateDTO implementiert.

Rollen: Ich habe zwei Rollen hinzugefügt, mit getrennten End-Points, dass habe ich mit session-basiertem Login mit Spring Security gemacht. Die zugriffskontrolle läuft über Spring Security im Security Config und im AdminService wird nochmals die Rolle geprüft.

Input-Validierung: Ich habe @Valid auf alle Controller-Methoden gesetzt und die Felder in den Entitäten annotiert. So werden Eingaben geprüft, bevor sie in die DB kommen.

2. Diskutieren Sie weitere mögliche und sinnvolle Sicherheitsmechanismen, die implementiert werden könnten, und eventuell eine Idee, wie das umgesetzt werden könnte.

Brute-Force-limit: Man könnte einen Filter vor /Login schalten, der nach 5 Fehlversuchen pro IP 15 Min sperrt.
So kann niemert automatisierte Passworter ausprobieren.

Session-Timeout: Man kann die Session nach 15 Minuten Timeouten lassen, falls jemand vergisst seinen Browser zu schliessen.

3. Reflektieren Sie über potenzielle Schwierigkeiten oder Probleme, die es bei der Implementierung dieses Projektes gab, und was anders gemacht werden sollte.

Ich hatte allgemein viele schwierigkeiten bei diesem Projekt und das unabhängig der Aufgabe. Eine AUfgabe die mir als bsp, schwierigkeiten gemacht habe, war die Passwörter im JSON zu speichern. Am anfang hat mir der End-Point immer der Passwort Hash in der API antowrt mitgeschickt, ich habe das mit @JsonProperty(WRITE_ONLY) gelöst.
Etwas was ich hätte anders machen können wäre das testen gewesen, ich habe oft die Aufgaben wie abgearbeitet und nicht wirklich getestet, was heisst, das ich gegen ende hin noch bugs beheben musste.

4. Wiegen Sie Aufwand und Ertrag von Sicherheitsmassnahmen bei Webapplikationen in Ihrer Erfahrung gegeneinander ab (in diesem4. Projekt und allgemein im Betrieb).

Also ich denke das die Zeit Ertrag Ratio nicht schlecht ist. Ich habe etwas länger gebraucht als die meisten, aber ich konnte die Applikation vor einfachen potenziellen angriffen schützen. Generell gilt, dass einfache Massnahmen wie Passwort Hashing oder Input Validierungen sich lohnen, da sie häufige Angriffe verhindern und im Vergleich ziemlich schnell gehen.