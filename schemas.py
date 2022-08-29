from typing import Optional,Union
from xmlrpc.client import boolean
from pydantic import BaseModel, EmailStr
import datetime
from fastapi import Body


class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    firs_name: Union[str, None] = None   
     
class User (BaseModel):
    firs_name: Optional[str]
    last_name: Optional[str]
    phone_nomber: Optional[str]
    email: Optional[str]
    type: EmailStr
    description: Optional[str]
    profile: Optional[str]
    disabled: Optional[bool]
    created_date: Optional[datetime.datetime]
    class Config:
        orm_mode=True

class Create_user (BaseModel):
    firs_name: Optional[str]
    last_name: Optional[str]
    phone_nomber: Optional[str]
    email: EmailStr
    type: str
    description: Optional[str]
    profile: Optional[str]
    disabled: Optional[bool]
    hashed_password: str
    created_date: Optional[datetime.datetime]
    class Config:
        orm_mode=True
        schema_extra = {
            "example": {
                "type": "type",
                "email": "email",
                "hashed_password": "hashed_password"
            }
        }

class Login_user (BaseModel):
    email: EmailStr
    hashed_password: str
    class Config:
        orm_mode=True
        schema_extra = {
            "example": {
                "email": "email",
                "hashed_password": "hashed_password"
            }
        }                

class UserInDB(User):
    hashed_password: str    

class PublicationCreate(BaseModel):        
    intituler: str
    description: str
    image: Optional [str]
    is_validate: Optional[bool]
    status: Optional[str]
    created_date: Optional[datetime.datetime]
    owner_id: Optional[int]

    class Config:
        orm_mode=True
        schema_extra = {
            "example": {
                "intituler": "Foo",
                "description": "A very nice Item"
            }
        }

class PublicationValidate(BaseModel):        
    is_validate: bool
    class Config:
        orm_mode=True
        schema_extra = {
            "example": {
                "is_validate": "True/False"
            }
        }        

class SignaleCreate(BaseModel):
    id: int
    commentaire: str
    created_date: Optional[datetime.datetime]

    class Config:
        orm_mode=True
        schema_extra = {
            "example": {
                "commentaire": "commentaire",
            }
        }        

class NoteCreate(BaseModel):
    id: int
    commentaire: str
    etoile: str
    created_date: Optional[datetime.datetime]

    class Config:
        orm_mode=True
        schema_extra = {
            "example": {
                "commentaire": "commentaire",
                "etoile": "etoile",
            }
        }    