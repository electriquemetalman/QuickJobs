from datetime import datetime, timedelta
from operator import truediv
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from database import Base, engine, SessionLocal

import models
import schemas
"""
SECRET_KEY = "2593fe453fd1c20c24068fc1af5575f1e8cb1a29f4d81d277129fe5c4694a942"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
"""
Base.metadata.create_all(engine)

#start call fonction bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

"""
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
"""
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
     

"""
#get user
def get_user(username: str, UserInDB: schemas.UserInDB, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.firs_name == username).first()
    if user:
        user_dict = user.firs_name
        return UserInDB(**user_dict)         
"""
"""
#authenticate user
def authenticate_user(username: str, password: str, db: Session = Depends(get_db)):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user
"""
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
"""
"""
#get curent user
async def get_current_user(TokenData: schemas.TokenData, token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.firs_name)
    if user is None:
        raise credentials_exception
    return user
"""
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

@app.post("/api/v1/login")
def login(User: schemas.Login_user, db: Session = Depends(get_db)):
    try:
        email = User.email
        in_pass = User.hashed_password
        exist_user = get_user_by_email(email, db)
        password = exist_user.hashed_password
        if not exist_user:
            return "email or password incorrect"
        if not verify_password(in_pass, password):
            return "email or password incorrect" 
        return  "user are authenticate"    
    except:    
        raise HTTPException(status_code=404, detail="authentification faild") 
        

@app.get("/api/v1/list_publication")
def ListPublication(db: Session = Depends(get_db)):
    try:
        publication = db.query(models.Publication).filter(models.Publication.is_validate == True).all()
        return publication
    except:
        raise HTTPException(status_code=404, detail="publication not found")    

@app.get("/api/v1/all_publication")
def AllPublication(db: Session = Depends(get_db)):
    try:
        publication = db.query(models.Publication).all()
        return publication
    except:
        raise HTTPException(status_code=404, detail="publication not found")          

@app.post("/api/v1/add_publication")
def create_publication(Publication: schemas.PublicationCreate, db: Session = Depends(get_db)):
    try:
        new_publication = models.Publication(
                intituler = Publication.intituler,
                description = Publication.description
            )
        db.add(new_publication)
        db.commit()
        db.refresh(new_publication)    
        return new_publication
    except:
        raise HTTPException(status_code=404, detail="publication are not add") 

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
def validate_publication(id: int, Publication: schemas.PublicationValidate, db: Session = Depends(get_db)):
    try:
        publication_Object = db.query(models.Publication).get(id)
        publication_Object.is_validate = Publication.is_validate
        db.commit() 
        db.refresh(publication_Object) 
        return publication_Object
    except:
        raise HTTPException(status_code=404, detail="publication are not validate")        
    