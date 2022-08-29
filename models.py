from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime, Table
from sqlalchemy.orm import relationship
import datetime

from database import Base

publication_authors = Table('publication_authors', Base.metadata,
    Column('user_id', ForeignKey('users.id'), primary_key=True),
    Column('publication_id', ForeignKey('publications.id'), primary_key=True)
)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    firs_name = Column(String(256))
    last_name = Column(String(256))
    phone_nomber = Column(String(256))
    email = Column(String, unique=True)
    type = Column(String(256))
    description = Column(String(800))
    profile = Column(String(900))
    hashed_password = Column(String(256))
    disabled = Column(Boolean,default=False)
    created_date = Column(DateTime,default=datetime.datetime.utcnow)
    publications = relationship("Publication", secondary="publication_authors", back_populates='users')

class Publication(Base):
    __tablename__ = 'publications'
    id = Column(Integer, primary_key=True)
    intituler = Column(String(256))
    description = Column(String(900))
    image = Column(String(900))
    is_validate = Column(Boolean,default=False)
    status = Column(String(256),default="activer")
    created_date = Column(DateTime,default=datetime.datetime.utcnow)
    owner_id = Column(Integer, ForeignKey("signales.id"))

    owner = relationship("Signale", back_populates="post")
    users = relationship("User", secondary="publication_authors", back_populates='publications')

class Signale(Base):
    __tablename__ = 'signales'
    id = Column(Integer, primary_key=True)
    commentaire = Column(String(900))
    created_date = Column(DateTime,default=datetime.datetime.utcnow)

    post = relationship("Publication", back_populates="owner")

class Note(Base):
    __tablename__ = 'notes'
    id = Column(Integer, primary_key=True)
    commentaire = Column(String(900))
    etoile = Column(Integer)
    created_date = Column(DateTime,default=datetime.datetime.utcnow)