from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy_utils import EmailType, URLType
import datetime

from database import Base

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    firs_name = Column(String(256))
    last_name = Column(String(256))
    phone_nomber = Column(String(256))
    email = Column(EmailType)
    type = Column(String(256))
    description = Column(String(800))
    profile = Column(URLType)
    passWord = Column(String(256))
    created_date = Column(DateTime,default=datetime.datetime.utcnow)

class Publication(Base):
    __tablename__ = 'publications'
    id = Column(Integer, primary_key=True)
    intituler = Column(String(256))
    description = Column(String(900))
    image = Column(URLType)
    is_validate = Column(Boolean,default=False)
    status = Column(String(256),default="activer")
    created_date = Column(DateTime,default=datetime.datetime.utcnow)
    owner_id = Column(Integer, ForeignKey("signales.id"))

    owner = relationship("Signale", back_populates="post")

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