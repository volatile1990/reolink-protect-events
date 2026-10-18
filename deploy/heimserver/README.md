# Betrieb auf dem Debian-Heimserver

Stand: 18.10.2026. Der Heimserver `192.168.1.175` führt Events, Medienmonitor,
Controls und Archiv aus. Diese vier Anwendungen teilen sich ein öffentliches
Release. Protect, seine Aufnahmen, PostgreSQL sowie die geprüften Service-/UI-
und Automatic-Anpassungen bleiben auf der UDM `192.168.1.1`. Der dortige
[Connector](../../reolink_protect_events/connector.py) wird nur bei SSH-Anfragen
ausgeführt; er ist kein zusätzlicher dauerhaft laufender Dienst.

Die Inbetriebnahmebelege liegen außerhalb dieses Repositorys unter
`output/protect-services-migration-20261018/` im übergeordneten Arbeitsordner.
Diese Anleitung beschreibt den eingerichteten Aufbau. Ein aktiver systemd-
Dienst allein ersetzt keine Prüfung von Events, Controls und Medienwiedergabe.

## Dienste und Startreihenfolge

[`reolink-protect.target`](reolink-protect.target) bündelt fünf eigene Dienste:

| Dienst | Aufgabe |
| --- | --- |
| [`reolink-protect-ssh.service`](reolink-protect-ssh.service) | Dauerverbindung und feste Weiterleitungen zur UDM |
| [`reolink-protect-events.service`](reolink-protect-events.service) | Sammlung, Journal, Zusammenführung und native Veröffentlichung |
| [`reolink-protect-media-monitor.service`](reolink-protect-media-monitor.service) | Medienprüfung und begrenzte Recorder-Wiederherstellung |
| [`reolink-protect-controls.service`](reolink-protect-controls.service) | Kamerasteuerung über den lokalen Unix-Socket |
| [`reolink-protect-archive.service`](reolink-protect-archive.service) | Archivtransport und AAC-Kompatibilität |

Alle fünf haben `PartOf=reolink-protect.target`; ein geordneter Target-Stopp
stoppt damit auch den Tunnel. Ein Code-Release schaltet die vier Anwendungen um
und lässt den separat eingerichteten SSH-Dienst unverändert. Events, Monitor
und Archiv verwenden `Wants`, nicht `Requires`, für SSH: Bei einer vorübergehend
getrennten UDM-Verbindung darf die Erfassung in das lokale Journal weiterlaufen.
Der Tunnel verbindet sich selbst erneut.

Die zusätzliche [`camera-host-access.service`](camera-host-access.service)
stellt den Netzwerkzugang des Hosts zu seinen eigenen macvlan-Bridges bereit.
Events, Monitor und Controls benötigen diesen Dienst. Er benötigt seinerseits
die bereits zur Kamera-Dockerinstallation gehörende `camera-vlan30.service`.
Diese VLAN-/Docker-Grundinstallation ist kein Bestandteil eines Protect-
Code-Releases.

Die Unitdateien werden als root unter `/etc/systemd/system/` installiert.
[`camera-host-access.py`](camera-host-access.py) gehört nach
`/usr/local/libexec/camera-host-access.py`. Das Target und der Hostzugang werden
für den Systemstart aktiviert. Die vier Anwendungen benötigen Python 3 mit
Pillow beziehungsweise Node; bei der Inbetriebnahme wurden Pillow 11.1.0 und
Node v20.19.2 geprüft. Python schreibt mit `-B` und
`PYTHONDONTWRITEBYTECODE=1` keine zusätzlichen Dateien in das geprüfte Release.
Die Dienste verwenden in diesem Aufbau root; ein Benutzerwechsel erfordert
eine gesonderte Anpassung von Schlüsseln, privaten Dateien und Socketrechten.

## Netz und SSH

Der Switch stellt auf `enp1s0` das Kamera-VLAN 30 bereit. Der vorhandene
VLAN-Dienst erstellt `enp1s0.30`. Der Hostzugang erstellt darauf das macvlan
`camera-host` mit MAC `02:42:c0:a8:1e:d9`, Adresse `192.168.30.217/32` und genau
sechs Hostrouten zu `192.168.30.210` bis `.215`, jeweils mit `.217` als Quelle.
Es wird keine zusätzliche Default-Route und keine neue Kameraadresse angelegt.

Auf der UDM erlaubt die Regel **Heimserver -> Gateway | Allow Protect SSH
TCP22**, ID `6ad51d3431dbcc76bc10e248`, ausschließlich TCP 22 von
`192.168.1.175/32` nach `192.168.1.1/32`. Die internen Protect-Ports bleiben
Loopback-Endpunkte. Der Serveralias `udm-protect` gehört in `/root/.ssh/config`:

```sshconfig
Host udm-protect
  HostName 192.168.1.1
  User root
  IdentityFile /srv/cameras/protect/access/id_ed25519
  IdentitiesOnly yes
  UserKnownHostsFile /srv/cameras/protect/access/known_hosts
  HostKeyAlias udm-protect
  StrictHostKeyChecking yes
  BatchMode yes
  ConnectTimeout 8
  ServerAliveInterval 15
  ServerAliveCountMax 3
  ControlMaster auto
  ControlPath /run/reolink-protect-ssh/master
  ControlPersist 60
  StreamLocalBindMask 0117
  StreamLocalBindUnlink yes
```

Das ist ein eigenes Dienstschlüsselpaar, kein kopierter persönlicher Schlüssel.
`access/`, `/root/.ssh/` und Schlüssel-/Trustdateien bleiben auf dem Server
root-privat (Verzeichnisse `0700`, Dateien `0600`). Der bekannte UDM-Hostschlüssel
wird geprüft übernommen, nicht blind per `accept-new` vertraut. Der öffentliche
Dienstschlüssel ist in UDM-`authorized_keys` auf die Quelladresse `.175`, den
ForcedCommand-Connector und die benötigten Weiterleitungen beschränkt. Die
TCP-Ziele sind `127.0.0.1:7080`, `7448`, `7443` und `7702`; der entfernte
TCP-Listener ist `127.0.0.1:7712`. Der Controls-Rückkanal ist der unten genannte
Unix-Socket. `stream:<port>`-Anfragen an den Connector transportieren begrenzte
Binärdaten; die Protokoll-/TLS-Verarbeitung bleibt auf dem Heimserver.

Die SSH-Unit stellt folgende Verbindungen her:

| Richtung | Listener | Ziel |
| --- | --- | --- |
| Server → UDM | Server `127.0.0.1:17080` | UDM `127.0.0.1:7080` Snapshot/Export |
| Server → UDM | Server `127.0.0.1:17448` | UDM `127.0.0.1:7448` DS |
| Server → UDM | Server `127.0.0.1:17443` | UDM `127.0.0.1:7443` API |
| Server → UDM | Server `127.0.0.1:17702` | UDM `127.0.0.1:7702` natives Archiv |
| UDM → Server | UDM `127.0.0.1:7712` | Server `127.0.0.1:7712` Archivproxy |
| UDM → Server | UDM `/run/reolink-protect-controls/controls.sock` | gleichnamiger Server-Socket |

**Der entfernte Controls-Socket benötigt auch serverseitige sshd-Einstellungen
auf der UDM.** Am Ende von `/etc/ssh/sshd_config` steht der auf diesen Client
begrenzte Block:

```sshconfig
Match User root Address 192.168.1.175
    StreamLocalBindMask 0117
    StreamLocalBindUnlink yes
```

Die Client-Einstellung allein setzt die Rechte des entfernten Listeners nicht.
Auf der UDM enthält `/etc/tmpfiles.d/reolink-protect-connector.conf`:

```text
d /run/reolink-protect-controls 2750 root unifi-protect -
```

Das Setgid-Verzeichnis vererbt dem von sshd erstellten Socket die Gruppe
`unifi-protect`; mit Maske `0117` erhält der Socket `0660`. Protect kann ihn so
verwenden, ohne dass das Verzeichnis für die Gruppe schreibbar sein muss. Auf
dem Server erstellt die Controls-Unit das lokale Verzeichnis `0750 root:root`
und den lokalen Socket `0660 root:root`. Vor einer Änderung der UDM-sshd-
Konfiguration sind Syntax und die effektiven Einstellungen für root von `.175`
zu prüfen; bestehende administrative SSH-Verbindungen bleiben dabei erhalten.

## Private Dateien und reproduzierbarer Bootstrap

Unter `/srv/cameras/protect/` sind die Verantwortlichkeiten getrennt:

| Pfad | Inhalt |
| --- | --- |
| `releases/<digest>`, `current`, `deployment.json` | öffentliches Release und dessen lokale Aktivierungsmetadaten |
| `config/events.json` | sechs Kameraabbildungen, vorhandene Zugangsdaten, Quell-/Gruppenoptionen und `protectRemote` |
| `config/controls.json` | sechs vorhandene Bridge-Zugänge für Controls |
| `config/archive.env` | öffentliche Archivparameter des folgenden Beispiels; Datei trotzdem `0600` |
| `state/events` | konsistentes SQLite-Journal samt Cursor, Outbox, Gruppen und Medienzustand |
| `state/monitor` | Prüfzustand, Wartungsbesitz, Reparaturbudgets und offene Wiederherstellungen |
| `access` | eigener Dienstschlüssel und geprüfter SSH-Trust |

Die privaten Verzeichnisse sind `0700`, Konfigurationsdateien `0600`, Eigentümer
root. Bestehende Kamera-/Frigate-Zugangsdaten werden bei der Ersteinrichtung nur
über geschützte Speicher-/SSH-Pfade übertragen. Ein öffentliches Repository
kann diese privaten Dateien und den konsistenten Zustand nicht ersetzen. Alte
und neue Events-Publisher dürfen niemals gleichzeitig dasselbe Journal oder
dieselben nativen Ereignisse beschreiben.

Die vollständigen öffentlichen Archivparameter benötigen keine Datei aus dem
früheren Controls-Repository:

```dotenv
LISTEN_HOST=127.0.0.1
LISTEN_PORT=7712
UPSTREAM_HOST=127.0.0.1
UPSTREAM_PORT=17702
TRANSFORM_PATH=/srv/cameras/protect/current/archive/aac-clock.cjs
MAX_SESSION_MS=0
MAX_SESSION_BYTES=0
IDLE_MS=0
MAX_SESSIONS=6
CAMERA_CHANNELS='{"6ac83993001a6d03e4001690":[0,2],"6ac83fed00bd6d03e4001b81":[0,2],"6ac844bd01096d03e4001f22":[0,2],"6ac844bf02026d03e4001f5f":[0,2],"6ac8ae7001ab6d03e4006410":[0,2],"6ac8ae7102b76d03e4006447":[0]}'
```

Auf der UDM wird die öffentliche `connector.py` als
`/usr/local/lib/reolink-protect-connector.py` root-owned installiert. Ihre private
`/data/reolink-protect-connector/config.json` enthält `protectUserId`, die sechs
`cameraIds` und die freigegebenen `hashPaths`. Die credentialfreie
`compatibility.json` enthält `protectUserId` und sechs `bridges`-Abbildungen
mit `cameraId`, `host` und optionaler `mac`. Der Marker
`server-architecture.json` sperrt den alten UDM-Installer. Die bereits geprüften
Protect-/UI-Ownershipbelege und ihre Backups bleiben für Compatibility auf der
UDM erhalten. Alle diese Connector-Konfigurationen bleiben root-privat.

## Updates und lokale Werkzeuge

Der Desktop verwendet den persönlichen, geprüften Alias `heimserver` mit
`sudo -n`. Der bestehende private Bridgecontroller liegt auf diesem Windows-PC
unter `C:/Users/marku/.codex/private/home-infrastructure/reolink-release-controller.json`;
sein geschützter Zugang wird über
`C:/Users/marku/.codex/tools/home-infrastructure/heimserver_access.py` ausgeführt.
Im Controller müssen `architecture: heimserver`, die Aliase und die aktuellen
Bridgepfade stehen. Inhalt und Sicherungen dieser Datei gehören außerhalb Git.

Events-Pushes verwenden `tools/serverrelease.py update`; Bridge-Pushes behalten
`tools/protect_ops.py update --config ...` mit Audit, Einzelrollout, AV-Gates und
Rollback. Die jeweiligen lokalen Hookziele liefert
`git rev-parse --git-path hooks/pre-push` im betreffenden Repository, normalerweise
`reolink-protect-events/.git/hooks/pre-push` und
`reolink-bridge/.git/hooks/pre-push`. Die neue Hookinstallation erfolgt separat
nach dem geprüften Quellcommit; diese Dokumentation installiert keine Hooks.

Die [Releaseanleitung](../../docs/server-release.md) beschreibt die Befehle;
[Deployment und Compatibility](../../docs/heimserver-deployment.md) erläutert
die CAS- und Zustandsregeln. Ein laufendes Update bewahrt private Konfiguration,
Journal und Monitorbudgets; ein Code-Rollback ist kein Restore dieser Daten.
