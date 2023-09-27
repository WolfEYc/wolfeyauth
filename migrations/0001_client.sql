-- +migrate Up
CREATE TABLE client (
	name VARCHAR(64) PRIMARY KEY,
	hashedkey VARCHAR(128) NOT NULL,
	disabled BOOL NOT NULL DEFAULT FALSE
);
-- +migrate Down
DROP TABLE client;