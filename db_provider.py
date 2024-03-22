from flask import Flask, request, make_response, current_app, g
import sqlite3
from log_config import logger

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    try:
        db = g.pop('db', None)
        if db is not None:
            db.close()
    except Exception as e:
        logger.error(f"Error: {e}")

def init_db(app): 
    try:
        with app.app_context():
            db = get_db()
            with current_app.open_resource('schema.sql') as f:
                db.executescript(f.read().decode('utf8'))
    except Exception as e:
        logger.error(f"Error:{e}")

