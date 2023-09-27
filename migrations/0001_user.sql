-- +migrate Up
CREATE TABLE user (
	name VARCHAR(64) PRIMARY KEY,
	hashedkey VARCHAR(128) NOT NULL,
	disabled BOOL
);
-- +migrate Down
DROP TABLE user;