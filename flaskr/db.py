from flask import current_app, g
import sqlite3
import click
from flask.cli import with_appcontext

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types = sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row 
    return g.db


def init_db():
    db = get_db()
    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf-8'))
    


@with_appcontext
def init_app(app):
    init_db()
    app.teardown_appcontext(close_db)


def close_db(e=None):
    db = g.pop('db', None)

    if db is not None:
        db.close()


