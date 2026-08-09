-- Membership tables are keyed by Dist first because Dist projection is their
-- primary access path.  Object lifecycle and semantic validation also need to
-- find every membership for one payload, so give those reverse lookups a
-- covering index instead of scanning the complete membership set per object.
CREATE INDEX memberships_package_sha256_idx
ON memberships(package_sha256, dist_name);

CREATE INDEX built_memberships_package_sha256_idx
ON built_memberships(package_sha256, dist_name);

CREATE INDEX prior_built_memberships_package_sha256_idx
ON prior_built_memberships(package_sha256, dist_name);

PRAGMA user_version = 9;
