-- Create users table
CREATE TABLE users (
    chave_criptografia BYTEA PRIMARY KEY UNIQUE NOT NULL,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
);

-- Create passwords table
CREATE TABLE passwords (
    nonce BYTEA PRIMARY KEY,
    id  SERIAL NOT NULL,
    service VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    password BYTEA NOT NULL,
    folder VARCHAR(255) NOT NULL,
    chave BYTEA NOT NULL,
    FOREIGN KEY (chave) REFERENCES users (chave_criptografia)
);
