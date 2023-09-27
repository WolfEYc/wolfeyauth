-- name: create_user<!
INSERT INTO user
VALUES (:name, :hashedkey, NULL);
-- name: read_user^
SELECT *
FROM user
WHERE name = :name;
-- name: read_owned_scopes
SELECT *
FROM scope
WHERE owner = :owner;
-- name: filter_user
SELECT name
FROM user
WHERE name LIKE :name
    AND disabled = :disabled
LIMIT 30;
-- name: update_hashedkey!
UPDATE user
SET hashedkey = :hashedkey
WHERE name = :name;
-- name: update_disabled!
UPDATE user
SET disabled = :disabled
WHERE name = :name;
-- name: delete_user!
DELETE FROM user
WHERE name = :name;