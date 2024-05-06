PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS user_account(
   id INTEGER PRIMARY KEY,
   account_name TEXT NOT NULL,
   email TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_character(
    id INTEGER PRIMARY KEY, 
    character TEXT NOT NULL,
    user_account_id INTEGER NOT NULL,
    FOREIGN KEY (user_account_id) REFERENCES user_account (id)
);