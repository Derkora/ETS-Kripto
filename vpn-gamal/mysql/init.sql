CREATE DATABASE IF NOT EXISTS secret_msg;
USE secret_msg;

CREATE TABLE IF NOT EXISTS msg_table (
    id INT AUTO_INCREMENT PRIMARY KEY,
    msg VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS elgamal_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    prime BIGINT,
    generator BIGINT,
    h BIGINT,
    private_key BIGINT
);
