from flask_sqlalchemy import SQLAlchemy
from flask_caching import Cache
from app import LogEntry

db = SQLAlchemy()
cache = Cache()

@cache.cached(timeout=300)
def get_ip_counts():
    return db.session.query(
        LogEntry.ip_address, db.func.count(LogEntry.ip_address).label('Count')
    ).group_by(LogEntry.ip_address).order_by(db.func.count(LogEntry.ip_address).desc()).limit(10).all()

@cache.cached(timeout=300)
def get_requests_over_time():
    return db.session.query(
        LogEntry.timestamp
    ).all()

@cache.cached(timeout=300)
def get_status_code_counts():
    return db.session.query(
        LogEntry.response_code, db.func.count(LogEntry.response_code).label('Count')
    ).group_by(LogEntry.response_code).order_by(db.func.count(LogEntry.response_code).desc()).all()
