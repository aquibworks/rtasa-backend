from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from typing import List

from app.db.session import get_db
from app.models.domain import User
from app.crypto.rsa_engine import RSAEngine

router = APIRouter()


class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: str
    email: str
    rsa_public_key_pem: str | None

    class Config:
        from_attributes = True


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(user_in: UserCreate, db: Session = Depends(get_db)):
    """Register a new user and generate an RSA-2048 keypair for recipient-based share encryption."""
    existing = db.query(User).filter(User.email == user_in.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists."
        )

    # Generate RSA-2048 keypair
    private_pem, public_pem = RSAEngine.generate_keypair()

    # Create user with keypair stored
    new_user = User(
        email=user_in.email,
        hashed_password=user_in.password,  # In production, wrap with pwd_context.hash()
        rsa_public_key_pem=public_pem,
        rsa_private_key_pem=private_pem
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@router.get("/", response_model=List[UserResponse])
def list_users(db: Session = Depends(get_db)):
    """List available users so senders can select recipients for secrets."""
    return db.query(User).all()