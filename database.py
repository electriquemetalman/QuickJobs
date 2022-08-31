import boto3
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

client = boto3.client('ssm', 'us-east-1')

DB_URL = client.get_parameter(Name='/QuickJobs/rds/url')['Parameter']['Value']
DB_NAME = client.get_parameter(Name='/QuickJobs/rds/name')['Parameter']['Value']
DB_PASSWORD = client.get_parameter(Name='/QuickJobs/rds/password', WithDecryption=True)['Parameter']['Value']
DB_USER = client.get_parameter(Name='/QuickJobs/rds/user')['Parameter']['Value']


SQLALCHEMY_DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_URL}/{DB_NAME}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = "sqlite:///quickJob.sql"
#SQLALCHEMY_DATABASE_URL = "rds:///quickjobsdb.c4qgfmv4mo2i.us-west-1.rds.amazonaws.com"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

Base = declarative_base()
"""