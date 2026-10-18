# Gemeinsame Releases auf dem Heimserver

Alle vier Komponenten kommen aus diesem Repository: Events und Medienmonitor
aus `reolink_protect_events/`, Controls aus `services/controls/worker.py`, Archiv
aus `services/archive/proxy.cjs` und `services/archive/aac-clock.cjs`. Das frühere
Controls-Repository ist keine Build-Abhängigkeit. Private Konfiguration und
Zustand unter `/srv/cameras/protect/config` beziehungsweise `state` bleiben
außerhalb des Releases.

## Nur lokal bauen

```console
python tools/build_server_release.py --output-dir artifacts/server-releases
python tools/build_server_release.py --require-clean
```

Der erste Befehl erlaubt einen noch nicht committeten, lokal zu prüfenden Build.
`--require-clean` verlangt einen sauberen Commit und prüft jede aufgenommene Datei
gegen dessen Git-Blob; auch ignorierte, nicht committete Laufzeitdateien werden
abgelehnt. Der automatische Updatepfad verlangt diese Prüfung immer.

Das ZIP enthält ausschließlich freigegebenen öffentlichen Code und
`release.json`. Es verwendet das gemeinsame Format `schemaVersion: 1`,
`version: 2.0.0`. Dateiinhalt, Mitgliederreihenfolge, Manifest und ZIP-Zeitstempel
sind festgelegt; CRLF wird zu LF normalisiert. Der Release-Digest entsteht aus
den kanonischen Mitglieder-Metadaten. Der Builder überprüft sein Ergebnis mit
demselben Validator wie die Server-Stagingfunktion. Konfiguration, Journale,
Aufnahmen, Pillow-Binärpakete und systemd-Installation sind nicht enthalten.

## Commit testen und ausrollen

```console
python tools/serverrelease.py update
```

Dieser Befehl führt die Python-Tests sowie Syntax- und Funktionstests der
kanonischen Archivdateien aus. Anschließend baut er den unveränderten getesteten
Commit, prüft die vorhandene Installation, staged das öffentliche Bundle und
prüft den Kandidaten. Die Umschaltung aller vier eigenen Dienste verwendet den
vorher gelesenen Digest als Compare-and-swap-Bedingung. Abschließend wird die
aktive Installation erneut geprüft. Mit `--expected-current DIGEST` lässt sich
zusätzlich eine zuvor bewusst geprüfte Ausgangsversion fest vorgeben.

Ein schon aktiver identischer Digest wird nur geprüft. Fehlgeschlagene Tests,
Quelländerungen oder ein abweichender Ausgangsdigest verhindern die Umschaltung.
Die Serverfunktion bewahrt Konfiguration, Journale, Cursor, Manuellgruppen und
Monitorbudgets. Ein Rückwechsel betrifft den öffentlichen Code, nicht frühere
Stände dieser Daten. Scheitert die abschließende Prüfung, versucht der Controller
einen solchen Rückwechsel ausschließlich mit dem gerade aktivierten Digest als
CAS-Bedingung. Nach unklarem Transportabbruch wird keine Aktivierung blind
wiederholt.

Lesende Prüfung und gezielter Code-Rückwechsel stehen separat bereit:

```console
python tools/protect_server.py status
python tools/protect_server.py check
python tools/protect_server.py rollback --expected-current DIGEST
```

## Getrennte Push-Hooks

Die Installation der Hookdateien ist ein eigener, ausdrücklich auszuführender
Schritt. Das bloße Anlegen dieser Werkzeuge ändert keine vorhandenen Hooks:

```console
python tools/install_update_hook.py --scope events
python tools/install_update_hook.py --scope both --config PFAD_ZUR_PRIVATEN_CONTROLLERDATEI
```

Standard ist ausschließlich `events`: Ein Push des ausgecheckten Commits nach
`main` ruft `serverrelease.py update` auf. Andere Branches und Löschungen lösen
keinen Deploy aus. Der Bridge-Hook bleibt dabei unverändert.

Mit `--scope bridge` oder `both` erhält die Bridge ihren separaten
`protect_ops.py update --config ...`-Pfad. Für das migrierte Setup muss dessen
private Controllerdatei `architecture: heimserver` verwenden: Bridge-Audit,
Canary-/Aufnahmeprüfungen und Bridge-Rollback bleiben aktiv; eine alte
UDM-Events-Installation findet dabei nicht statt. Ein Bridge-Push ist kein
Ersatz für ein gemeinsames Serverrelease. Unbekannte vorhandene Hooks werden
erhalten und führen zu einer ausdrücklichen Installationsverweigerung.
