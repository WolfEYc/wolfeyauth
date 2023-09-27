-- name: create_scope<!
INSERT INTO scope
VALUES(:name, :owner);
-- name: read_scope_existence$
SELECT EXISTS(
		SELECT 1
		FROM scope
		WHERE name = :name
	);
-- name: read_scope_owner$
SELECT owner
FROM scope
WHERE name = :name;
-- name: filter_scope
SELECT *
FROM scope
WHERE name LIKE :name COLLATE NOCASE
	AND owner LIKE :owner COLLATE NOCASE
LIMIT 30;
-- name: update_scope_owner<!
UPDATE scope
SET owner = :owner
WHERE name = :name;
-- name: delete_scope!
DELETE FROM scope
WHERE name = :name;