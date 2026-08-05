-- Operation chronology is part of the audit contract. RFC3339Nano's default
-- variable-width fractional seconds are not lexicographically sortable around
-- exact-second values, so every stored Operation timestamp must use the fixed
-- 30-byte UTC representation produced by formatTimestamp.
CREATE TRIGGER operations_timestamp_insert_guard
BEFORE INSERT ON operations
WHEN length(NEW.created_at) != 30
  OR substr(NEW.created_at, 5, 1) != '-'
  OR substr(NEW.created_at, 8, 1) != '-'
  OR substr(NEW.created_at, 11, 1) != 'T'
  OR substr(NEW.created_at, 14, 1) != ':'
  OR substr(NEW.created_at, 17, 1) != ':'
  OR substr(NEW.created_at, 20, 1) != '.'
  OR substr(NEW.created_at, 30, 1) != 'Z'
  OR length(NEW.updated_at) != 30
  OR substr(NEW.updated_at, 5, 1) != '-'
  OR substr(NEW.updated_at, 8, 1) != '-'
  OR substr(NEW.updated_at, 11, 1) != 'T'
  OR substr(NEW.updated_at, 14, 1) != ':'
  OR substr(NEW.updated_at, 17, 1) != ':'
  OR substr(NEW.updated_at, 20, 1) != '.'
  OR substr(NEW.updated_at, 30, 1) != 'Z'
BEGIN
    SELECT RAISE(ABORT, 'operation timestamps must be fixed-width UTC');
END;

CREATE TRIGGER operations_timestamp_update_guard
BEFORE UPDATE OF created_at, updated_at ON operations
WHEN length(NEW.created_at) != 30
  OR substr(NEW.created_at, 5, 1) != '-'
  OR substr(NEW.created_at, 8, 1) != '-'
  OR substr(NEW.created_at, 11, 1) != 'T'
  OR substr(NEW.created_at, 14, 1) != ':'
  OR substr(NEW.created_at, 17, 1) != ':'
  OR substr(NEW.created_at, 20, 1) != '.'
  OR substr(NEW.created_at, 30, 1) != 'Z'
  OR length(NEW.updated_at) != 30
  OR substr(NEW.updated_at, 5, 1) != '-'
  OR substr(NEW.updated_at, 8, 1) != '-'
  OR substr(NEW.updated_at, 11, 1) != 'T'
  OR substr(NEW.updated_at, 14, 1) != ':'
  OR substr(NEW.updated_at, 17, 1) != ':'
  OR substr(NEW.updated_at, 20, 1) != '.'
  OR substr(NEW.updated_at, 30, 1) != 'Z'
BEGIN
    SELECT RAISE(ABORT, 'operation timestamps must be fixed-width UTC');
END;

PRAGMA user_version = 4;
