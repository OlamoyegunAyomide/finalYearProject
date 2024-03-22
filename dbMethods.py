from log_config import logger
from db_provider import get_db
from models import users, user_input, generated_requirements
import sqlite3
from decouple import config
import google.generativeai as genai
import datetime
import uuid


def get_user_by_email(email_address):
    db = get_db()
    try:
        cursor = db.execute(
            "SELECT * FROM users WHERE email_address = ?", (email_address,)
        )
        user = cursor.fetchone()
        return user
    except Exception as e:
        logger.error(f"Error: {e}")


def check_user_exists(email_address):
    db = get_db()
    try:
        cursor = db.execute(
            "SELECT * FROM users WHERE email_address =?", (email_address,)
        )
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
        columns = ["user_id", "full_name", "email_address"]
        users = [dict(zip(columns, row)) for row in user_rows]
    except Exception as e:
        logger.error(f"Error: {e}")
    finally:
        db.close()  # Ensure the database connection is closed
    return users


def create_user(user_id, full_name, email_address, role, password):
    db = get_db()
    try:
        cursor = db.execute(
            "INSERT INTO users (user_id, full_name, email_address, role, password) VALUES (?,?,?,?,?)",
            (user_id, full_name, email_address, role, password),
        )
        db.commit()
        return True
    except Exception as e:
        logger.error(f"Error: {e}")


def get_user_by_id(user_id):
    db = get_db()
    try:
        cursor = db.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        user = cursor.fetchone()
        if not user:
            return None
        return user
    except Exception as e:
        logger.error(f"Error: {e}")


def get_user_profile(user_id):
    db = get_db()
    try:
        cursor = db.execute(
            "SELECT full_name, email_address, role, password FROM users WHERE user_id = ?",
            (user_id,),
        )
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
        if role:
            sql += "role = ?, "
            params.append(role)
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


def add_user_input(input_id, user_id, input, created_at):
    db = get_db()
    try:
        db.execute(
            "INSERT INTO user_input(input_id, user_id, input, created_at) VALUES (?,?,?,?)",
            (input_id, user_id, input, created_at),
        )
        db.commit()
        return True
    except Exception as e:
        logger.error(f"Error: {e}")


# ########### FETCH ALL USER INPUTS ###################


def get_user_inputs(user_id):
    db = get_db()
    try:
        cursor = db.execute("SELECT * FROM user_input WHERE user_id =?", (user_id,))
        user_inputs_rows = cursor.fetchall()
        columns = ["input_id", "user_id", "input", "created_at"]
        user_inputs = [dict(zip(columns, row)) for row in user_inputs_rows]
        return user_inputs
    except Exception as e:
        print(f"db_error : {e}")
        logger.error(f"Error: {e}")


# ########### FETCH SPECIFIC USER INPUT ###################


def get_user_input_by_id(user_id, input_id):
    db = get_db()
    try:
        cursor = db.execute(
            "SELECT * FROM user_input WHERE user_id = ? AND input_id = ?",
            (user_id, input_id),
        )
        input_data_row = cursor.fetchone()
        columns = ["input_id", "user_id", "input", "created_at"]
        input_data = dict(zip(columns, input_data_row))
        return input_data
    except Exception as e:
        logger.error(f"Error: {e}")


# ########### UPDATE USER INPUT ###################


def update_user_input(user_id, input_id, input_text):
    db = get_db()
    try:
        db.execute(
            "UPDATE user_input SET input = ? WHERE input_id = ? AND user_id = ?",
            (input_text, input_id, user_id),
        )
        db.commit()
        return True
    except Exception as e:
        logger.error(f"Error: {e}")


# ########### DELETE USER INPUT ###################


def delete_user_input(user_id, input_id):
    db = get_db()
    try:
        db.execute(
            "DELETE FROM user_input WHERE input_id = ? AND  user_id = ?",
            (input_id, user_id),
        )
        db.commit()
        return True
    except Exception as e:
        logger.error(f"Error: {e}")


###### GENERATE REQUIREMENTS FOR A NEW INPUT ######\

def generate_input_requirements(input_id, data):
    GOOGLE_API_KEY = config('GOOGLE_API_KEY')
    genai.configure(api_key=GOOGLE_API_KEY)

    model = genai.GenerativeModel('gemini-pro')
    chat = model.start_chat(history=[])

    response = chat.send_message(
        "Generate requirements for " + data)
    
    requirements = response.text

    created_at = datetime.datetime.utcnow()
    status = "pending"
    add_input_requirements(input_id, requirements, created_at, status)
    
    return requirements


######### SAVE GENERATED REQUIREMENTS TO DATABASE ############

def add_input_requirements(input_id, requirements, created_at, status):
    db = get_db()
    requirement_id = str(uuid.uuid4())
    try:
        db.execute("INSERT INTO generated_requirements(requirement_id, input_id, requirement, created_at, status) VALUES (?,?,?,?,?)", (requirement_id, input_id, requirements, created_at, status))
        db.commit()
        return True
    except Exception as e:
        logger.error(f"Error: {e}")

        

# ########### FETCH ALL USER REQUIREMENTS ###################

def get_all_requirements():
    print('start')
    db = get_db()
    try:
        cursor = db.execute("SELECT * FROM generated_requirements")
        user_requirements_rows = cursor.fetchall()
        print(user_requirements_rows)
        columns = ['requirement_id', 'input_id','requirement', 'created_at']
        user_requirements = [dict(zip(columns, row)) for row in user_requirements_rows]
        print(user_requirements)
        return user_requirements
    except Exception as e:
        print(f'db_error : {e}')
        logger.error(f"Error: {e}")

        

# ########### FETCH SPECIFC USER REQUIREMENTS ###################

def get_specific_user_requirements(user_id):
    print('start')
    db = get_db()
    try:
        user_inputs = get_user_inputs(user_id)
        user_requirements_list = []
        for input_data in user_inputs:
            cursor = db.execute("SELECT * FROM generated_requirements WHERE input_id = ?", (input_data['input_id'],))
            user_requirements_rows = cursor.fetchall()
            # print(user_requirements_rows)
            columns = ['requirement_id', 'input_id','requirement', 'created_at']
            user_requirements = [dict(zip(columns, row)) for row in user_requirements_rows]
            user_requirements_list.extend(user_requirements)
        return user_requirements_list
    except Exception as e:
        print(f'db_error : {e}')
        logger.error(f"Error: {e}")



        

# ########### FETCH SPECIFC USER INPUT REQUIREMENTS ###################

def get_specific_input_requirements(requirement_id):
    print('start')
    db = get_db()
    try:
        cursor = db.execute("SELECT * FROM generated_requirements WHERE requirement_id = ?", (requirement_id,))
        user_input_requirements_rows = cursor.fetchone()
        print(user_input_requirements_rows['requirement']) 
        if user_input_requirements_rows:
            # Convert row object to dictionary
            user_input_requirements = dict(user_input_requirements_rows)
            print(user_input_requirements['requirement']) 
            return user_input_requirements
    except Exception as e:
        print(f'db_error : {e}')
        logger.error(f"Error: {e}")




##### UPDATE REQUIREMENTS  IF THEY EXIST ALREADY #######


def update_input_requirements(requirement_id, requirements):
    db = get_db()
    try:
        db.execute("UPDATE generated_requirements SET requirement = ? WHERE requirement_id = ?", (requirements, requirement_id))
        db.commit()
        return True
    except Exception as e:
        logger.error(f"Error: {e}")


##### DELETE SPECIFIC REQUIREMENT FROM DATABASE #######

def delete_requirements(requirement_id):
    db = get_db()
    try:
        db.execute("DELETE FROM generated_requirements WHERE requirement_id = ?", (requirement_id,))
        db.commit()
        return True
    except Exception as e:
        logger.error(f"Error: {e}")
        

###### FETCH APPROVED REQUIREMENTS #########


###### CHANGE REQUIREMENTS STATUS ###########
        

def update_requirements_status(requirement_id, status):
    db = get_db()
    try:
        db.execute("UPDATE generated_requirements SET status = ? WHERE requirement_id = ?", (status, requirement_id))
        db.commit()
        return True
    except Exception as e:
        logger.error(f"Error: {e}")