-- +migrate Up
CREATE TABLE access (
	clientname VARCHAR(64),
	scopename VARCHAR(64),
	PRIMARY KEY (clientname, scopename),
	FOREIGN KEY (clientname) REFERENCES client(name) ON DELETE CASCADE,
	FOREIGN KEY (scopename) REFERENCES scope(name) ON DELETE CASCADE
);
-- +migrate Down
DROP TABLE access;