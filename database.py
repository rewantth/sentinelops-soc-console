from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


def init_database(app):
    """Initialize SQLAlchemy and create tables automatically."""
    db.init_app(app)
    with app.app_context():
        db.create_all()
