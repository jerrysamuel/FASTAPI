from database import Base
from sqlalchemy import Column, Integer, String, Boolean, Float

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    best_time = Column(Integer, nullable=True, default=None)
