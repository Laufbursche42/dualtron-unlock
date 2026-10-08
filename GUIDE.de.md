# Anleitung

> **Wichtig für Fehler-Reports:** Schalte unten auf der Seite den **Diagnose-Log** ein, *bevor* du dich mit dem Scooter verbindest. Nur dann wird der komplette Verbindungsaufbau mitgeschnitten - und genau diese Zeilen brauchen wir in einem [Ticket](https://github.com/Laufbursche42/Laufbursche42/issues), um ein Problem nachzuvollziehen.

## Was du brauchst
- Einen DUALTRON- bzw. Minimotors-E-Scooter.
- Ein Handy oder einen Rechner mit **Chrome**, **Edge** oder auf iOS **Bluefy**. Safari und Firefox können kein Web Bluetooth.

## Verbinden
1. Bluetooth am Gerät einschalten, den Scooter einschalten (wecken).
2. Auf **Verbinden** tippen und den Scooter in der Liste auswählen.
3. Taucht er nicht auf, setze den Haken bei **Alle Geräte zeigen** und verbinde erneut. Der echte Test ist der gefundene Bluetooth-Dienst (0xFE60), nicht der angezeigte Name.
4. Nach dem Verbinden erscheinen die Karten für Live-Werte, Geschwindigkeit und Einstellungen. Die Seite fragt sofort Telemetrie und Einstellungen ab.

## Live-Werte lesen
Die Seite fragt den Scooter laufend ab, er antwortet mit Frames. Jede Kachel erscheint, sobald ihr Wert angekommen ist; ein Strich heißt nur, dass dieser Wert noch nicht kam. Unter den Kacheln kannst du mit **Alle empfangenen Frames** die Rohdaten pro Opcode mitlesen.

## Geschwindigkeit setzen
- **Entsperren** setzt das legale Limit auf **Aus**, **Sperren** auf **20 km/h**. Mit dem Auswahlfeld setzt du das Limit genau (Aus / 25 / 22 / 20 km/h).
- Der **Top-Speed-Prozentwert** begrenzt zusätzlich prozentual (wird auf 6 Bit, also 0 bis 63, begrenzt).
- Wichtig: Alle Schreibzugriffe sind ein Read-Modify-Write. Der Scooter muss seine Systemeinstellungen erst gemeldet haben, sonst wird nicht geschrieben. Ein Echo im Log heißt nur, dass der Scooter das Frame angenommen hat. Erst wenn sich das Limit in den Live-Werten ändert, ist der Wert wirklich aktiv.

## Weitere Einstellungen
Der maximale Gang sitzt in den Systemeinstellungen (Opcode 0x81, Byte 5). Es erscheinen nur Zeilen, deren Wert der Scooter auch meldet.

## Was bewusst fehlt
Sperre/Entsperre (Immobilizer), Licht und CCS/PAS gibt es als Opcodes im Protokoll, aber die genauen Payload-Bytes stehen nicht in der dekompilierten App. Darum sind sie hier nicht eingebaut. Wer das passende Frame mitgeschnitten hat, kann es über **Rohes Frame** senden.

## Erweiterte Einstellungen (Engine-Ebene)
**Rohes Frame** sendet deine Hex-Bytes unverändert. **Frame bauen** nimmt Opcode und Payload und ergänzt Header, Maske (Seed) und Prüfsumme selbst.

## Shortcuts
Kopiere den Link auf den Startbildschirm, dann ent- oder sperrt ein Tipp direkt. Auf iOS über Bluefy, und der Scooter muss vorher einmal normal verbunden gewesen sein.

## Wenn etwas nicht geht
- Kein Verbinden? Prüfe, dass der Browser Web Bluetooth kann, Bluetooth an ist und der Scooter wach ist. Mit **Alle Geräte zeigen** erneut versuchen.
- Nichts passiert nach einem Befehl? Schau ins Log: steht dort "gesendet" aber kein "bestätigt", hat die Firmware das Frame nicht quittiert. Steht dort "warte auf Systemeinstellungen", kam noch kein 0x01-Frame - kurz warten und erneut.
- **Diagnose: alle Geräte auflisten** im Log-Bereich zeigt alle Bluetooth-Dienste eines Geräts, ohne etwas zu schreiben - hilfreich für Support.

## Mithelfen
Willst du herausfinden, ob und wie Tuning bei deinem Scooter geht? Teste dieses Tool an deinem eigenen Fahrzeug und öffne ein Ticket auf [GitHub](https://github.com/Laufbursche42/Laufbursche42/issues) - mit deinem Modell und was funktioniert hat (oder nicht). So finden wir gemeinsam heraus, was bei welchem Modell möglich ist.
