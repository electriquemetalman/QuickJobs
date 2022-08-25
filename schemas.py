from typing import Optional
from xmlrpc.client import boolean
from pydantic import BaseModel
import datetime
from fastapi import Body


class UserList(BaseModel):
    id: int
    firs_name: str
    last_name: str
    phone_nomber: str
    email: str
    type: str
    description: str
    profile: str
    created_date: Optional[datetime.datetime]

    class Config:
        orm_mode=True

class PublicationList(BaseModel):        
    id: int
    intituler: str
    description: str
    image: str
    is_validate: bool
    status: str
    created_date: Optional[datetime.datetime]
    owner_id: int

    class Config:
        orm_mode=True