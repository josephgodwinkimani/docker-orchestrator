from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    password: str


class UserLogin(UserBase):
    password: str


class User(UserBase):
    id: int
    is_active: bool
    created_at: datetime

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None


class DockerImage(BaseModel):
    id: str
    tags: List[str]
    created: str
    size: int


class DockerImageDetail(DockerImage):
    architecture: str
    os: str
    author: str
    config: Dict[str, Any]


class DockerContainer(BaseModel):
    id: str
    name: str
    image: str
    status: str
    created: str


class DockerContainerDetail(DockerContainer):
    ports: Dict[str, Any]
    mounts: List[Dict[str, Any]]
    command: List[str]
    environment: List[str]


class DockerContainerLogs(BaseModel):
    container_id: str
    logs: str


class ActionResponse(BaseModel):
    success: bool
    message: str
