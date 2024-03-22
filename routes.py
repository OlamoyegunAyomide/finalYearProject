from flask import Flask, Blueprint, make_response, jsonify, request, current_app
from dbMethods import (
    check_user_exists,
    create_user,
    get_user_by_id,
    get_users,
    get_user_by_email,
    get_user_profile,
    update_profile,
    add_user_input,
    get_user_inputs,
    get_user_input_by_id,
    update_user_input,
    delete_user_input,
    generate_input_requirements,
    get_all_requirements,
    get_specific_user_requirements,
    get_specific_input_requirements,
    update_input_requirements,
    delete_requirements,
    update_requirements_status,
    get_approved_user_requirements
)
from utils import valid_email
from werkzeug.security import generate_password_hash, check_password_hash
import uuid, jwt
import datetime
from functools import wraps
from log_config import logger
from decouple import config

endpoint = Blueprint("endpoint", __name__)


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if "x-access-tokens" in request.headers:
            token = request.headers["x-access-tokens"]
            # print(token)
        if not token:
            return jsonify({"message": "a valid token is missing"}), 401
        try:
            data = jwt.decode(
                token, current_app.config["SECRET_KEY"], algorithms=["HS256"]
            )
            current_user = get_user_by_id(data["user_id"])
            # print(current_user)
        except Exception as e:
            return jsonify({"message": "token is invalid"}), 401
            logger.error(f"Error: {e}")
        if not current_user:
            return jsonify({"message": "User not found"}), 401
        return f(current_user, *args, **kwargs)

    return decorator


# ##### DETECT USER ROLE ############
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(current_user, *args, **kwargs):
            if current_user['role'] != role:
                return make_response(jsonify({"message": "Access forbidden"}), 403)
            return f(current_user, *args, **kwargs)
        return decorated_function
    return decorator

@endpoint.route("/")
def home():
    return "Welcome"


# ##### FETCH ALL USERS #########
@endpoint.route("/api/users", methods=["GET"])
@token_required
@role_required("engineer") 
def get_all_users(current_user):
    try:
        users = get_users()
        return jsonify(users)
    except Exception as e:
        logger.error(f"Error: {e}")
        return make_response(jsonify({"message": "An unexpected error occurred"}), 500)

# ######## SIGN UP #############
@endpoint.route("/api/users/signup", methods=["POST"])
def signup():
    try:
        data = request.get_json()
        required_fields = ["full_name", "email_address", "role", "password"]
        # to check for missing fields
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return make_response(
                jsonify({"error": "missing field", "fields": missing_fields}), 400
            )

        if not valid_email(data["email_address"]):
            return make_response(jsonify({"error": "Invalid email address"}), 400)

        if check_user_exists(data["email_address"]):
            return make_response(jsonify({"message": "User already exists"}), 400)

        hashed_password = generate_password_hash(data["password"])
        user_id = str(uuid.uuid4())

        if create_user(
            user_id, data["full_name"], data["email_address"], data["role"], hashed_password
        ):
            return make_response(
                jsonify({"message": "User successfully registered"}), 201
            )
        else:
            return make_response(jsonify({"message": "Failed to create account"}), 400)
    except Exception as e:
        logger.error(f"Error: {e}")
        return make_response(jsonify({"message": "An unexpected error occurred"}), 400)

# ###########S SIGN IN ##########
@endpoint.route("/api/users/signin", methods=["POST"])
def signIn():
    try:
        data = request.get_json()
        if not data or "email_address" not in data or "password" not in data:
            return make_response("Invalid request", 400)
        user = get_user_by_email(data["email_address"])
        if not user:
            return make_response("Invalid email or password", 400)
        hashed_password = user["password"]
        if check_password_hash(hashed_password, data["password"]):
            token = jwt.encode(
                {
                    "user_id": user["user_id"],
                    "user_role": user["role"],
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=45),
                },
                current_app.config["SECRET_KEY"],
                algorithm="HS256",
            )
            return jsonify({"token": token})
        return make_response("Invalid email or password", 400)
    except Exception as e:
        logger.error(f"Error: {e}")
        return make_response(jsonify({"message": "An unexpected error occurred"}), 400)

# ##### VIEW PROFILE ##########
@endpoint.route("/api/users/<user_id>", methods=["GET", "PUT"])
@token_required
def view_profile(current_user, user_id):
    if request.method == "GET":  # to view user profile
        try:
            user = get_user_profile(user_id)
            if user is None:
                return make_response(jsonify({"User not found"}), 404)
            user_data = {
                "full_name": user[0],
                "email_address": user[1],
                "role": user[2],
                "password": user[3],
            }
            return jsonify(user_data), 200
        except Exception as e:
            logger.error(f"Error: {e}")
            return make_response(
                jsonify({"message": "An unexpected error occurred"}), 400
            )
    elif request.method == "PUT":  # to modify user profile
        try:
            data = request.get_json()
            full_name = data.get("full_name")
            email_address = data.get("email_address")
            role = data.get("role")
            new_password = data.get("new_password")

            if email_address and not valid_email(email_address):
                return make_response(jsonify({"message": "Invalid email address"}))

            hashed_password = (
                generate_password_hash(new_password) if new_password else None
            )

            if update_profile(user_id, full_name, email_address, role, hashed_password):
                return make_response(
                    jsonify({"message": "User profile updated successfully"}), 200
                )
            else:
                return make_response(
                    jsonify({"message": "Unable to update user profile"}), 500
                )
        except Exception as e:
            logger.error(f"Error: {e}")
            return make_response(
                jsonify({"message": "An unexpected error occurred"}), 400
            )


# ###### SUBMIT INPUT ##############
@endpoint.route("/api/input", methods=["POST"])
@token_required
def submit_input(current_user):
    try:
        data = request.get_json()
        if not data or "input" not in data:
            return make_response(jsonify({"message": "Missing field"}), 400)
        input_id = str(uuid.uuid4())
        created_at = datetime.datetime.utcnow()
        input = data["input"]
        if current_user is None:
            return make_response(jsonify({"message": "Invalid user information"}), 400)
        user_id = current_user["user_id"]
        print(user_id)
        if add_user_input(input_id, user_id, input, created_at):
            return make_response(
                jsonify({"message": "User input added successfully"}), 201
            )
        else:
            return make_response(jsonify({"message": "Failed to add user input"}), 400)
    except Exception as e:
        logger.exception(f"Error: {e}")
        return make_response(jsonify({"message": "An unexpected error occurred"}), 400)


# ########### FETCH ALL USER INPUTS ###################


@endpoint.route("/api/users/inputs", methods=["GET"])
@token_required
def get_all_user_inputs(current_user):
    try:
        user_id = current_user["user_id"]
        print(user_id)
        inputs = get_user_inputs(user_id)
        if inputs:
            return jsonify(inputs)
        else:
            return make_response(jsonify({"message": "You have no input"}), 404)
    except KeyError:
        return make_response(
            jsonify({"message": "User ID not found in current user data"}), 400
        )
    except Exception as e:
        logger.error(f"Error: {e}")
        return make_response(
            jsonify({"message": f"An unexpected error occurred: {e}"}), 400
        )


# ########### FETCH, UPDATE OR DELETE SPECIFIC USER INPUT ###################


@endpoint.route("/api/users/inputs/<input_id>", methods=["GET", "PUT", "DELETE"])
@token_required
def get_specific_user_input(current_user, input_id):

    user_id = current_user["user_id"]
    if request.method == "GET":  # to view user input
        try:
            print(user_id)
            print(input_id)
            input_data = get_user_input_by_id(user_id, input_id)
            if input_data:
                return jsonify(input_data)
            else:
                return make_response(jsonify({"message": "Input not found"}), 404)
        except Exception as e:
            logger.error(f"Error: {e}")
            return make_response(
                jsonify({"message": "An unexpected error occurred"}), 400
            )

    elif request.method == "PUT":  # to modify user input
        try:
            data = request.get_json()
            input_text = data.get("input")
            if not input_text:
                return make_response(jsonify({"message": "Input text missing"}), 400)
            if update_user_input(user_id, input_id, input_text):
                return make_response(
                    jsonify({"message": "Input updated successfully"}), 200
                )
            else:
                return make_response(
                    jsonify({"message": "Failed to update input"}), 500
                )
        except Exception as e:
            logger.error(f"Error: {e}")
            return make_response(
                jsonify({"message": "An unexpected error occurred"}), 500
            )

    elif request.method == "DELETE":  # to delete user input
        try:
            if delete_user_input(user_id, input_id):
                return make_response(
                    jsonify({"message": "Input deleted successfully"}), 200
                )
            else:
                return make_response(
                    jsonify({"message": "Failed to delete input"}), 500
                )
        except Exception as e:
            logger.error(f"Error: {e}")
            return make_response(
                jsonify({"message": "An unexpected error occurred"}), 500
            )


# ########### GENERATE REQUIREMENTS FOR SPECIFIC USER INPUT ###################


@endpoint.route("/api/users/inputs/<input_id>/requirements", methods=["POST"])
@token_required
def generate_requirements(current_user, input_id):
    user_id = current_user["user_id"]
    try:
        input_data = get_user_input_by_id(user_id, input_id)
        if input_data:
            json_response = jsonify(input_data)
            data = json_response.json["input"]
            # function to generate requirements for an input
            requirements = generate_input_requirements(input_id, data)
            # Return success response
            # return make_response(jsonify({"message": "Requirements generated successfully"}), 200)
            return requirements
        else:
            return make_response(jsonify({"message": "Input not found"}), 404)

    except Exception as e:
        logger.error(f"Error: {e}")
        return make_response(jsonify({"message": "An unexpected error occurred"}), 400)



# ########### FETCH ALL REQUIREMENTS ###################

@endpoint.route("/api/admin/requirements", methods=["GET"])
@token_required
@role_required("engineer") 
def get_all_users_requirements(current_user):
    print(current_user)
    try:
        user_id = current_user["user_id"]
        user_role = current_user["role"]
        print(user_id)
        print(user_role)
        requirements = get_all_requirements()
        if requirements:
            return jsonify(requirements)
        else:
            return make_response(jsonify({"message": "There are no avaiable requirements"}), 404)
    except KeyError:
        return make_response(
            jsonify({"message": "User ID not found in current user data"}), 400
        )
    except Exception as e:
        logger.error(f"Error: {e}")
        return make_response(
            jsonify({"message": f"An unexpected error occurred: {e}"}), 400
        )



# ########### FETCH SPECIFIC USER REQUIREMENTS ###################

@endpoint.route("/api/admin/requirements/user/<user_id>", methods=["GET"])
@token_required
@role_required("engineer") 
def get_specified_users_requirements(current_user, user_id):
    print(current_user['user_id'])
    try:
        # user_id = current_user["user_id"]
        user_role = current_user["role"]
        # print(user_id)
        # print(user_role)
        user_requirements = get_specific_user_requirements(user_id)
        if user_requirements:
            return jsonify(user_requirements)
        else:
            return make_response(jsonify({"message": "User has no requirements"}), 404)
    except KeyError:
        return make_response(
            jsonify({"message": "User ID not found in current user data"}), 400
        )
    except Exception as e:
        logger.error(f"Error: {e}")
        return make_response(
            jsonify({"message": f"An unexpected error occurred: {e}"}), 400
        )



# ########### FETCH, UPDATE OR DELETE SPECIFIC REQUIREMENT  ###################
@endpoint.route(
    "/api/admin/requirements/<requirement_id>", methods=["GET", "PUT", "DELETE"]
)
@token_required
@role_required("engineer") 
def handle_requirements(current_user, requirement_id):
    user_id = current_user["user_id"]
    if request.method == "GET":  # to view user input
        try:
            print(user_id)
            # print(input_id)
            input_requirements_data = get_specific_input_requirements(requirement_id)
            if input_requirements_data:
                return jsonify(input_requirements_data)
            else:
                return make_response(jsonify({"message": "Input has no requirements"}), 404)
        except Exception as e:
            logger.error(f"Error: {e}")
            return make_response(
                jsonify({"message": "An unexpected error occurred"}), 400
            )
    
    
    elif request.method == "PUT":  # to modify input requirements
        try:
            data = request.get_json()
            requirements = data.get("requirement")
            if not requirements:
                return make_response(jsonify({"message": "Requirements missing"}), 400)
            if update_input_requirements(requirement_id, requirements):
                return make_response(
                    jsonify({"message": "Requirements updated successfully"}), 200
                )
            else:
                return make_response(
                    jsonify({"message": "Failed to update requirement"}), 400
                )
        except Exception as e:
            logger.error(f"Error: {e}")
            return make_response(
                jsonify({"message": "An unexpected error occurred"}), 400
            )
    
    elif request.method == "DELETE":  # to delete user input
        try:
            if delete_requirements(requirement_id):
                return make_response(
                    jsonify({"message": "Requirements deleted successfully"}), 200
                )
            else:
                return make_response(
                    jsonify({"message": "Failed to delete requirements"}), 400
                )

        except Exception as e:
            logger.error(f"Error: {e}")
            return make_response(jsonify({"message": "An unexpected error occurred"}), 400)
        

# ############ APPROVE REQUIREMENTS ############
@endpoint.route(
    "/api/admin/requirements/<requirement_id>/status", methods=["PUT"]
)
@token_required
@role_required("engineer")
def update_requirements(current_user, requirement_id):
    try:
        data = request.get_json()
        status = data.get("status")
        if not status:
            return make_response(jsonify({"message": "Status missing"}), 400)
        if update_requirements_status(requirement_id, status):
            return make_response(
                jsonify({"message": "Requirement Status updated successfully"}), 200
            )
        else:
            return make_response(
                jsonify({"message": "Failed to update requirement"}), 400
            )
    except Exception as e:
        logger.error(f"Error: {e}")
        return make_response(
            jsonify({"message": "An unexpected error occurred"}), 400
        )
        
        
        
# ########### FETCH APPROVED USER REQUIREMENTS ###################

@endpoint.route("/api/user/requirements", methods=["GET"])
@token_required 
def get_approved_requirements(current_user):
    print(current_user['user_id'])
    try:
        user_id = current_user["user_id"]
        user_role = current_user["role"]
        # print(user_id)
        # print(user_role)
        approved_user_requirements = get_approved_user_requirements(user_id)
        if approved_user_requirements:
            return jsonify(approved_user_requirements)
        else:
            return make_response(jsonify({"message": "You have no approved requirements"}), 404)
    except KeyError:
        return make_response(
            jsonify({"message": "User ID not found in current user data"}), 400
        )
    except Exception as e:
        logger.error(f"Error: {e}")
        return make_response(
            jsonify({"message": f"An unexpected error occurred: {e}"}), 400
        )