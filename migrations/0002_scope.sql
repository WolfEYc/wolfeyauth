-- +migrate Up
CREATE TABLE scope (
	name VARCHAR(64) PRIMARY KEY,
	owner VARCHAR(64),
	FOREIGN KEY (owner) REFERENCES client(name) ON DELETE
	SET NULL
);
-- +migrate Down
DROP TABLE scope;