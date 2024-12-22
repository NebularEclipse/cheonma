DROP TABLE IF EXISTS user;

DROP TABLE IF EXISTS info;

CREATE TABLE
    user (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        info_id INTEGER UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        type TEXT DEFAULT 'regular' CHECK (type IN ('admin', 'regular')),
        FOREIGN KEY (info_id) REFERENCES info (id) ON DELETE CASCADE
    );

CREATE TABLE
    info (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        profile_picture TEXT
    );
