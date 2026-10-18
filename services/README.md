# Kanonische Serverdienste

Seit dem 18.10.2026 werden diese drei öffentlichen Laufzeitdateien gemeinsam mit
dem Events-Package aus **diesem Repository** gebaut:

- `controls/worker.py`: die begrenzte Controls-Schnittstelle zu den sechs Bridges.
- `archive/proxy.cjs`: Archivtransport und begrenzte UBV-WebSocket-Verarbeitung.
- `archive/aac-clock.cjs`: die dazugehörige AAC-/Zeitachsen-Kompatibilität.

Die Dateien wurden beim Zusammenführen byteidentisch aus
`reolink-protect-controls/worker.py` beziehungsweise dessen `archive/` übernommen.
Weitere Änderungen an diesen Diensten erfolgen hier. Das frühere Repository
bleibt als historische Quelle und für seine separaten Diagnose-/UI-Werkzeuge
erhalten; der Server-Build liest es nicht.

Die synthetischen Worker-Tests liegen in `tests/test_controls_service.py`, die
Archivtests neben dem Proxy unter `archive/test_proxy.cjs`. Sie verwenden
Offline-Fixtures und lokale Testverbindungen, keine produktiven Kameraaufnahmen.
Der Update-Controller führt beide Testgruppen aus. Private Konfiguration,
Passwörter, Journale, Aufnahmen und Deployzustand gehören nicht in diesen Ordner
oder in das Releasearchiv.
