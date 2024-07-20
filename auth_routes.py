from fastapi import APIRouter, status, Depends, Request
from database import session, engine
from schemas import SignUpModel, LoginModel, TokenModel
from models import User
from fastapi.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.security import OAuth2PasswordBearer
import jwt
from fastapi.encoders import jsonable_encoder
from settings import Settings
from datetime import datetime
from datetime import timedelta


ALGORITHM = "HS256"
settings = Settings()
SECRET_KEY = settings.authjwt_secret_key
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


auth_router=APIRouter(
    prefix='/auth',
    tags=['Authentication']  # Grouping routes under 'Authentication' tag
)


session = session(bind=engine)

def create_access_token(data: dict, expires_delta):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    # check_token = payload.get("sub")

    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    email = payload.get("sub")

    user = session.query(User).filter(User.email ==  email).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user.email

@auth_router.post('/refresh')
async def refresh_token(payload:TokenModel):

    payload = verify_token(payload.refresh_token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    email = payload.get("sub")
    if email is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_expires_delta = timedelta(minutes=settings.access_token_expire_minutes)
    refresh_expires_delta = timedelta(days=settings.refresh_token_expire_days)
    access_token = create_access_token(data={"sub": email}, expires_delta=access_expires_delta)
    refresh_token = create_refresh_token(data={"sub": email}, expires_delta=refresh_expires_delta)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@auth_router.get('/')
async def test_route(current_user: dict = Depends(get_current_user)):
    return {'message': f'auth route working perfectly fine, user is: {current_user}'}


@auth_router.post('/signup', response_model=SignUpModel, status_code=status.HTTP_201_CREATED)
async def signup(user:SignUpModel):
    db_email = session.query(User).filter(User.email ==  user.email).first()

    print('user input: ', user)

    if db_email is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
            detail="User with email already exists"
            )
    

    db_username = session.query(User).filter(User.username ==  user.username).first()

    if db_username is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
            detail="User with username already exists"
            )

    if user.password_hash is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
            detail="User password is none"
            )
    else:
        password = generate_password_hash(user.password_has)
        
    
    new_user = User(
        username=user.username, 
        email=user.email, 
        password_hash = password,
        is_active=user.is_active,
        is_staff=user.is_staff
        )

    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    return new_user


@auth_router.post('/login', status_code=200)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db_user=session.query(User).filter(User.email==form_data.username).first()
    
    if db_user and check_password_hash(db_user.password_hash, form_data.password):
        access_expires_delta = timedelta(minutes=settings.access_token_expire_minutes)
        refresh_expires_delta = timedelta(days=settings.refresh_token_expire_days)
        access_token = create_access_token(data={"sub": db_user.email}, expires_delta=access_expires_delta)
        refresh_token = create_refresh_token(data={"sub": db_user.email}, expires_delta=refresh_expires_delta)

        user_data = User(
        username=db_user.username, 
        email=db_user.email, 
        is_active=db_user.is_active,
        is_staff=db_user.is_staff
        )
        
        return {"status": True, "data": user_data, "access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or password")