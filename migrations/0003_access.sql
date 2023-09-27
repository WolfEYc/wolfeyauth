-- +migrate Up
CREATE TABLE access (
	username VARCHAR(64),
	scopename VARCHAR(64),
	PRIMARY KEY (username, scopename),
	FOREIGN KEY (username) REFERENCES user(name) ON DELETE CASCADE,
	FOREIGN KEY (scopename) REFERENCES scope(name) ON DELETE CASCADE
);
-- +migrate Down
DROP TABLE access;