-- Create Users Table
CREATE TABLE IF NOT EXISTS users(
    user_id VARCHAR PRIMARY KEY,
    full_name TEXT,
    email_address VARCHAR,
    password VARCHAR
);

-- Create userInput Table
CREATE TABLE IF NOT EXISTS user_input(
    input_id VARCHAR PRIMARY KEY,
    user_id VARCHAR,
    input VARCHAR,
    created_at TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(user_id)
);

-- Create GeneratedRequirements Table
CREATE TABLE IF NOT EXISTS generated_requirements(
    requirement_id VARCHAR PRIMARY KEY,
    input_id VARCHAR,
    requirement TEXT,
    created_at TIMESTAMP,
    FOREIGN KEY(input_id) REFERENCES user_input(input_id)
);


ALTER TABLE users
ADD COLUMN role TEXT;


ALTER TABLE generated_requirements
ADD COLUMN status TEXT;
