from datetime import datetime, timedelta
import email
import time
from operator import truediv
from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm,HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from database import Base, engine, SessionLocal

import models
import schemas

SECRET_KEY = "2593fe453fd1c20c24068fc1af5575f1e8cb1a29f4d81d277129fe5c4694a942"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

Base.metadata.create_all(engine)

#start call fonction bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

#verify hashed password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

#get password hashed
def get_password_hash(password):
    return pwd_context.hash(password) 

#get user by email
def get_user_by_email(email: str, db: Session ):
    return db.query(models.User).filter(models.User.email == email).first() 

def get_user_by_id(user_id: int, db: Session ):
    return db.query(models.User).filter(models.User.id == user_id).filter(models.User.type == "employeur").first()    
     

"""
#get user
def get_user(username: str, UserInDB: schemas.UserInDB, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.firs_name == username).first()
    if user:
        user_dict = user.firs_name
        return UserInDB(**user_dict)         
"""
#create access token
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt    


#get curent user
async def get_current_user(TokenData: schemas.TokenData, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    email=token_data.email    
    user = get_user_by_email(email, db)
    if user is None:
        raise credentials_exception
    return user

"""
#get curent active user
async def get_current_active_user(current_user: schemas.User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
"""
"""
@app.post("/token", response_model= schemas.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.firs_name}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}
"""
@app.get("/")
def read_root():
    return {"Hello": "World"}
    

@app.post("/api/v1/create_user")
def create_user(User: schemas.Create_user, db: Session = Depends(get_db)):
    email = User.email
    exist_email = get_user_by_email(email, db)
    try:
        if exist_email:
            return "this user is alrady in the system"
        else:
            hash_pass = get_password_hash(User.hashed_password)
            new_user = models.User(
                type = User.type,
                email = User.email,
                hashed_password = hash_pass
            )
            db.add(new_user)
            db.commit()
            db.refresh(new_user)    
            return new_user
    except:
        raise HTTPException(status_code=404, detail="User have note added")

@app.post("/api/v1/login", response_model=schemas.Token)
def login(User: schemas.Login_user, db: Session = Depends(get_db)):
    try:
        email = User.email
        in_pass = User.hashed_password
        exist_user = get_user_by_email(email, db)
        password = exist_user.hashed_password
        if not exist_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"}
            )
        if not verify_password(in_pass, password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"}
            )
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": exist_user.email}, expires_delta=access_token_expires
        )     
        return  {"access_token": access_token, "token_type": "bearer"}    
    except:    
        raise HTTPException(status_code=404, detail="Incorrect username or password",headers={"WWW-Authenticate": "Bearer"}) 
        
@app.get("/api/v1/get_all_user")
def get_all_user(db: Session = Depends(get_db)):
    return db.query(models.User).all()


@app.get("/api/v1/list_publication")
def ListPublication(db: Session = Depends(get_db)):
    try:
        publication = db.query(models.Publication).filter(models.Publication.is_validate == True).filter(models.Publication.status == "activer").all()
        return publication
    except:
        raise HTTPException(status_code=404, detail="publication not found")    

@app.get("/api/v1/all_publication")
def AllPublication(db: Session = Depends(get_db)):
    try:
        publication = db.query(models.Publication).filter(models.Publication.status == "activer").all()
        return publication
    except:
        raise HTTPException(status_code=404, detail="publication not found")  
"""
def add_publicationAutor(user_id: int, publication: int, db: Session ):
    new_publicationAutor = models.PublicationAuthor(
                user_id = user_id,
                publication_id = publication
            )                
    db.add (new_publicationAutor)
    db.commit()
    db.refresh (new_publicationAutor)
"""
@app.get("/api/v1/user/{user_id}/all_publication")
def all_user_Publication(user_id: int, db: Session = Depends(get_db)):
    try:
        publication = db.query(models.Publication).filter(models.Publication.user_id == user_id).filter(models.Publication.is_validate == True).filter(models.Publication.status == "activer").all()
        return publication
    except:
        raise HTTPException(status_code=404, detail="publication not found")

@app.post("/api/v1/user/{user_id}/add_publication")
def create_publication(user_id: int, Publication: schemas.PublicationCreate, db: Session = Depends(get_db)):
    try:
        u_id = get_user_by_id(user_id, db)
        if u_id:
            new_publication = models.Publication(
                    intituler = Publication.intituler,
                    description = Publication.description,
                    user_id = user_id
                )       
            db.add(new_publication)
            db.commit()
            db.refresh(new_publication)
            return new_publication
        else:
            return "user dont exist"
    except:
        raise HTTPException(status_code=404, detail="publication are not add")    

@app.get("/api/v1/publication")
def get_allpublication_autor(db: Session = Depends(get_db)):
    publication_autor = db.query(models.PublicationAuthor).all()
    return publication_autor      

@app.put("/api/v1/update_publication/{id}")
def update_publication(id: int, Publication: schemas.PublicationCreate, db: Session = Depends(get_db)):
    try:
        publication_Object = db.query(models.Publication).get(id)
        publication_Object.intituler = Publication.intituler
        publication_Object.description = Publication.description
        db.commit() 
        db.refresh(publication_Object) 
        return publication_Object
    except:
        raise HTTPException(status_code=404, detail="publication are not update") 

@app.put("/api/v1/validate_publication/{id}")
def validate_publication(id: int, db: Session = Depends(get_db)):
    try:
        publication_Object = db.query(models.Publication).get(id)
        publication_Object.is_validate = True
        db.commit() 
        db.refresh(publication_Object) 
        return publication_Object
    except:
        raise HTTPException(status_code=404, detail="publication are not validate")

@app.put("/api/v1/desebel_publication/{id}")
def desebel_publication(id: int, db: Session = Depends(get_db)):
    try:
        publication_Object = db.query(models.Publication).get(id)
        publication_Object.status = "desactiver"
        db.commit() 
        db.refresh(publication_Object) 
        return publication_Object
    except:
        raise HTTPException(status_code=404, detail="publication are not desabel")                
    