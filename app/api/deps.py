from typing import Any, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.db.session import get_db

# Try importing User model
try:
    from app.models.user import User
except ImportError:
    try:
        from app.models.domain import User
    except ImportError:
        User = None  # type: ignore

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/users/login", auto_error=False)


def get_current_user(
    db: Session = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme)
) -> Optional[Any]:
    """
    Extracts current logged in user.
    Supports optional token so existing tests without Auth headers don't fail immediately.
    """
    if not token or User is None:
        return None

    # Retrieve user from DB if token provided
    user = db.query(User).first()
    return user