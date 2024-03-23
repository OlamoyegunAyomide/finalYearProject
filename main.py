from flask import Flask
from log_config import logger
from flask_swagger_ui import get_swaggerui_blueprint
from db_provider import get_db, close_db, init_db
from routes import endpoint
import sqlite3
import os
from flask_cors import CORS

#application setup phase
def create_app():
    app = Flask(__name__, instance_relative_config=True)
    CORS(app, origins = ["*"])

    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'RequirementDetails.db'),
        DEBUG=True
    )
    try:
        os.makedirs(app.instance_path)
    except OSError as e:
        logger.error(f"Error: {e}")
        pass

    #to register the blueprint
    app.register_blueprint(endpoint)

    #for swagger documentation
    SWAGGER_URL="/swagger"
    API_URL="/static/swagger.json"

    swagger_ui_blueprint = get_swaggerui_blueprint(
        SWAGGER_URL,
        API_URL,
        config={
            'app_name': 'Requirement Elicitation System API'
        }
    )
    app.register_blueprint(swagger_ui_blueprint, url_prefix=SWAGGER_URL)

    return app

def init_app(app):
    app.teardown_appcontext(close_db)
    init_db(app)

app = create_app()
init_app(app)

if __name__ == "__main__":
    app.run(debug=True)