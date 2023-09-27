-- name: create_access<!
INSERT INTO access
VALUES(:username, :scopename);
-- name: read_scopes
SELECT scopename
FROM access
WHERE username = :username;
-- name: read_access^
SELECT EXISTS (
		SELECT 1
		FROM access
		WHERE username = :username
			AND scopename = :scopename
	);
-- name: filter_access
SELECT *
FROM access
WHERE username LIKE :username COLLATE NOCASE
	AND scopename LIKE :scopename COLLATE NOCASE
LIMIT 30;
-- name: delete_access!
DELETE FROM access
WHERE username = :username
	AND scopename = :scopename;