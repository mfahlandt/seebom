-- 017_add_vex_provenance.up.sql
-- VEX statement provenance (#334): who (or what) decided a CVE status.
--
-- Once automated tooling (VEXViper, #338) produces OpenVEX alongside humans,
-- auditors must be able to tell machine drafts from human review. OpenVEX
-- already carries these fields; capturing them at ingest is forward-only-ish
-- (VEX docs are small and re-uploadable, but automated producers won't
-- re-send), so the columns land before the v1.0 freeze.
--
--   author        OpenVEX document `author` (required by the spec)
--   role          OpenVEX document `role`, e.g. "security team" or
--                 "automated" — low cardinality by nature
--   tooling       OpenVEX document `tooling`, set by automated producers
--   status_notes  OpenVEX statement `status_notes`; automated producers
--                 write confidence + reasoning summary here
--
-- UI badge (automated vs. human) and `?vex_source=` filter follow in
-- Phase 3; exposure on vulnerability rows is #335.
ALTER TABLE vex_statements ADD COLUMN IF NOT EXISTS author String DEFAULT '';
ALTER TABLE vex_statements ADD COLUMN IF NOT EXISTS role LowCardinality(String) DEFAULT '';
ALTER TABLE vex_statements ADD COLUMN IF NOT EXISTS tooling String DEFAULT '';
ALTER TABLE vex_statements ADD COLUMN IF NOT EXISTS status_notes String DEFAULT '';

