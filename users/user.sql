DROP TABLE IF EXISTS Users;

CREATE TABLE Users (first_name TEXT, last_name TEXT, username TEXT UNIQUE NOT NULL,
                    email TEXT PRIMARY KEY, salt TEXT, current_password_hash TEXT,
                    isEmployee INTEGER);