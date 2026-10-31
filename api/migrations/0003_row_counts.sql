-- Refreshed by the five-minute cron, keeping public metrics reads constant-size.
CREATE TABLE row_counts (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  devices INTEGER NOT NULL,
  windows INTEGER NOT NULL,
  alerts INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
INSERT INTO row_counts
SELECT 1, (SELECT COUNT(*) FROM devices), (SELECT COUNT(*) FROM windows),
  (SELECT COUNT(*) FROM alerts), unixepoch();
