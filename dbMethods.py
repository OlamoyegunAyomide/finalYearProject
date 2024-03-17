from log_config import logger
from db_provider import get_db
from models import users, user_input, generated_requirements
import sqlite3

def get_user_by_email(email_address):
    db = get_db()
    try:
        cursor = db.execute("SELECT * FROM users WHERE email_address = ?",(email_address,))
        user = cursor.fetchone()
        return user
    except Exception as e:
        logger.error(f"Error: {e}")

def check_user_exists(email_address):
    db = get_db()
    try:
        cursor = db.execute("SELECT * FROM users WHERE email_address =?",(email_address,))
        user = cursor.fetchone()
        return user
    except Exception as e:
        logger.error(f"Error: {e}")

def get_users():
    db = get_db()
    users = []
    try:
        cursor = db.execute("SELECT user_id, full_name, email_address FROM users")
        user_rows = cursor.fetchall()
        columns = ['user_id','full_name', 'email_address']
        users = [dict(zip(columns, row)) for row in user_rows]
    except Exception as e:
        logger.error(f"Error: {e}")
    finally:
        db.close()  # Ensure the database connection is closed
    return users

def create_user(user_id, full_name, email_address, password):
    db = get_db()
    try:
        cursor = db.execute("INSERT INTO users (user_id, full_name, email_address, password) VALUES (?,?,?,?)", (user_id, full_name, email_address, password))
        db.commit()
        return True
    except Exception as e:
        logger.error(f"Error: {e}")

def get_user_by_id(user_id):
    db = get_db()
    try:
        cursor = db.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        user_data = cursor.fetchone()
        if user_data is None:
            return None
        user = users(user_data['user_id'], user_data['full_name'], user_data['email_address'], user_data['password'])
        return user
    except Exception as e:
        logger.error(f"Error: {e}")

def get_user_profile(user_id):
    db = get_db()
    try:
        cursor = db.execute("SELECT full_name, email_address, password FROM users WHERE user_id = ?", (user_id,))
        user_details = cursor.fetchone()
        return user_details
    except Exception as e:
        logger.error(f"Error: {e}")

def update_profile(user_id, full_name=None, email_address=None, new_password=None):
    db = get_db()
    try:
        sql = "UPDATE users SET "
        params = []

        if full_name:
            sql += "full_name = ?, "
            params.append(full_name)
        if email_address:
            sql += "email_address = ?, "
            params.append(email_address)
        if new_password:
            sql += "password = ?, "
            params.append(new_password)

        # Remove trailing comma and space if any updates are present
        if params:
            sql = sql[:-2] 

        sql += " WHERE user_id = ?"
        params.append(user_id)

        cursor = db.execute(sql, params)
        db.commit()
        return True
    except Exception as e:
        logger.error(f"Error: {e}")

def add_user_input(input_id,user_id, input, created_at):
    db = get_db()
    try:
        db.execute("INSERT INTO user_input(input_id, user_id, input, created_at) VALUES (?,?,?,?)", (input_id, user_id, input, created_at))
        db.commit()
        return True
    except Exception as e:
        logger.error(f"Error: {e}")