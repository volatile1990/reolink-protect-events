-- Synthetic Protect-shaped schema, never a production migration. The database
-- must first be marked by the isolated-container runner; otherwise fail closed.
DO $fixture$
BEGIN
 IF current_database() <> 'unifi-protect' OR
    COALESCE((SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()),'')
      <> 'reolink-protect-events isolated integration fixture' THEN
   RAISE EXCEPTION 'Refusing fixture reset outside the isolated integration database';
 END IF;
END $fixture$;
DROP SCHEMA public CASCADE;
CREATE SCHEMA public;
CREATE TABLE cameras (
 id varchar PRIMARY KEY,
 "featureFlags" json NOT NULL DEFAULT '{"hasSmartDetect":false,"syntheticUnchangedFlag":true}'::json,
 "smartDetectSettings" json NOT NULL DEFAULT '{"objectTypes":[]}'::json,
 "smartDetectZones" json NOT NULL DEFAULT '[]'::json,
 "isThirdPartyCamera" bool NOT NULL DEFAULT true,
 "isPairedWithAiPort" bool NOT NULL DEFAULT false,
 "updatedAt" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE events (
 id varchar PRIMARY KEY, type varchar NOT NULL, start bigint NOT NULL, "end" bigint,
 "cameraId" varchar NOT NULL REFERENCES cameras(id) ON DELETE CASCADE,
 "smartDetectTypes" json NOT NULL, metadata json NOT NULL, score bigint,
 "createdAt" timestamptz NOT NULL, "updatedAt" timestamptz NOT NULL,
 locked bool NOT NULL DEFAULT false, "thumbnailId" varchar, "thumbnailFullfovId" varchar,
 "deletedAt" timestamptz
);
CREATE TABLE thumbnails (
 id varchar PRIMARY KEY, "eventId" varchar REFERENCES events(id) ON DELETE CASCADE,
 "cameraId" varchar NOT NULL REFERENCES cameras(id) ON DELETE CASCADE,
 content bytea NOT NULL, width bigint NOT NULL, height bigint NOT NULL, timestamp bigint NOT NULL,
 "isFullfov" bool, locked bool NOT NULL DEFAULT false,
 "createdAt" timestamptz NOT NULL, "updatedAt" timestamptz NOT NULL
);
ALTER TABLE events ADD CONSTRAINT events_thumbnail FOREIGN KEY ("thumbnailId") REFERENCES thumbnails(id) ON DELETE SET NULL;
ALTER TABLE events ADD CONSTRAINT events_fullfov FOREIGN KEY ("thumbnailFullfovId") REFERENCES thumbnails(id) ON DELETE SET NULL;
CREATE TABLE "smartDetectObjects" (
 id varchar PRIMARY KEY, "eventId" varchar NOT NULL REFERENCES events(id) ON DELETE CASCADE,
 "cameraId" varchar NOT NULL REFERENCES cameras(id) ON DELETE CASCADE, type varchar NOT NULL,
 attributes json NOT NULL, metadata jsonb NOT NULL, "detectedAt" bigint NOT NULL,
 "thumbnailId" varchar REFERENCES thumbnails(id) ON DELETE SET NULL,
 "createdAt" timestamptz NOT NULL, "updatedAt" timestamptz NOT NULL
);
CREATE TABLE "smartDetectTracks" (
 id varchar PRIMARY KEY, "eventId" varchar NOT NULL REFERENCES events(id) ON DELETE CASCADE,
 "cameraId" varchar NOT NULL REFERENCES cameras(id) ON DELETE CASCADE, payload json NOT NULL,
 "createdAt" timestamptz NOT NULL, "updatedAt" timestamptz NOT NULL
);
CREATE TABLE labels (
 id varchar PRIMARY KEY, lid bigserial NOT NULL UNIQUE, name varchar NOT NULL,
 "lastSeen" bigint NOT NULL, "createdAt" timestamptz NOT NULL, "updatedAt" timestamptz NOT NULL
);
CREATE UNIQUE INDEX labels_name_key ON labels(name);
CREATE TABLE "detectionLabels" (
 id varchar PRIMARY KEY, "eventId" varchar NOT NULL REFERENCES events(id) ON DELETE CASCADE,
 "objectId" varchar REFERENCES "smartDetectObjects"(id) ON DELETE CASCADE,
 labels integer[] NOT NULL, "createdAt" timestamptz NOT NULL, "updatedAt" timestamptz NOT NULL
);
CREATE UNIQUE INDEX "detectionLabels_eventId_index_unique" ON "detectionLabels"("eventId") WHERE "objectId" IS NULL;
CREATE UNIQUE INDEX "detectionLabels_eventId_objectId_index_unique" ON "detectionLabels"("eventId","objectId") WHERE "objectId" IS NOT NULL;
INSERT INTO cameras(id) VALUES ('111111111111111111111111'),('222222222222222222222222');
