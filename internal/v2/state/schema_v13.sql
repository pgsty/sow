-- Candidate pool paths are looked up without scanning unrelated publication
-- history. Keep these indexes narrow; immutable identities stay in their tables.
CREATE INDEX package_objects_pool_path_folded ON package_objects(lower(pool_path));
CREATE INDEX publication_inventory_payload_path_folded ON publication_inventory(lower(path)) WHERE phase = 'payload';
CREATE INDEX publication_abandoned_payload_path_folded ON publication_abandoned_objects(lower(path)) WHERE phase = 'payload';

PRAGMA user_version = 13;
