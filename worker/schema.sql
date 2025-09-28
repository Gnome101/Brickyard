-- Schema definition for the Brickyard Worker D1 database.
-- Run via `wrangler d1 execute lego_db --file=./schema.sql` after creating the DB.

-- Stores the generated LEGO designs keyed by a deterministic hash of prompt + agent.
CREATE TABLE IF NOT EXISTS designs (
    hash_id    TEXT PRIMARY KEY,
    prompt     TEXT NOT NULL,
    agent_type TEXT NOT NULL,
    model_json TEXT NOT NULL,
    created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Tracks accumulated votes per agent_type/prompt combination.
CREATE TABLE IF NOT EXISTS votes (
    agent_type TEXT NOT NULL,
    prompt     TEXT NOT NULL,
    count      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (agent_type, prompt)
);

-- Add future migrations below this line (e.g., indices) to keep schema.sql idempotent.
