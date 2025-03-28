from typing import Optional, List, Union, Dict
from fastapi import Request, HTTPException
from starlette.responses import Response



def get_bearer_token(request: Request) -> Optional[str]:
    """
    Parse 'Authorization: Bearer <token>' from the incoming request.
    Returns the token string or None if missing/invalid.
    """
    auth_header = request.headers.get("authorization")
    if not auth_header:
        return None

    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None

def http_exception(
    status_code: int,
    error: str,
    error_desc: str
) -> HTTPException:
    """
    Construct an HTTPException with a 'WWW-Authenticate' header
    mimicking the style from the TypeScript example.
    """
    return HTTPException(
        status_code=status_code,
        detail={
            "error": error,
            "error_description": error_desc
        },
        headers={
            "WWW-Authenticate": f'Bearer error="{error}", error_description="{error_desc}"'
        }
    )

def validate_scopes(claims: Dict, required_scopes: List[str]) -> bool:
    """
    Verifies the 'scope' claim (a space-delimited string) includes all required_scopes.
    """
    scope_str = claims.get("scope")
    if not scope_str:
        return False

    token_scopes = scope_str.split()  # space-delimited
    return all(req in token_scopes for req in required_scopes)