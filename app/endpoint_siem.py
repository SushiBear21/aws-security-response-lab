"""Fixed SIEM queries and a narrow, explainable endpoint correlation rule."""

RULE = "endpoint-inventory-probe-v1"
IMAGE = r"c:\lab\inventoryprobe.exe"
WINDOW_SECONDS = 120

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    process_guid TEXT NOT NULL,
    event_id INTEGER NOT NULL,
    at TEXT NOT NULL,
    clock_us INTEGER NOT NULL,
    image TEXT NOT NULL,
    initiated INTEGER,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS endpoint_timeline ON events (host, process_guid, at);
"""

CORRELATION = """
SELECT p.payload AS process, n.payload AS network
FROM events AS p
JOIN events AS n ON n.host = p.host AND n.process_guid = p.process_guid
    AND n.image = p.image
WHERE p.event_id = 1 AND n.event_id = 3 AND n.initiated = 1
    AND p.image = ? AND n.at >= p.at
    AND n.clock_us - p.clock_us <= ?
ORDER BY p.host, p.process_guid, p.at, n.at, p.id, n.id
"""

TIMELINE = """
SELECT payload FROM events WHERE host = ? AND process_guid = ?
ORDER BY at, event_id, id
"""

COUNTS = """
SELECT host, event_id, count(*) AS events
FROM events GROUP BY host, event_id ORDER BY host, event_id
"""
