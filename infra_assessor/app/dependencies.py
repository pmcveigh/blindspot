from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from infra_assessor.storage.database import session_scope

DatabaseSession = Annotated[Session, Depends(session_scope)]
