CREATE TABLE security_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    username VARCHAR(100) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    event VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL
);

CREATE TABLE uploaded_security_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    username VARCHAR(100) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    event VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL
);