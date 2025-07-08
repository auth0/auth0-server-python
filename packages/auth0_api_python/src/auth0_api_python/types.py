from typing import TypedDict, Optional

class RequestData(TypedDict):
    authorization_header: str
    dpop_proof:          Optional[str]
    http_method:        str
    http_url:           str