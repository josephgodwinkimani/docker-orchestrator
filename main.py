import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session

import docker
import models
import schemas

# Import database models and configuration
from database import Base, SessionLocal, engine

# Create database tables
Base.metadata.create_all(bind=engine)

# Logging
logging.basicConfig(
    filename="api.log",
    level=logging.ERROR,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Initialize
app = FastAPI(title="Docker Orchestrator")

# Security configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-for-development")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Rate limiting configuration
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "50"))  # Requests per window
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))  # Window in seconds

# In-memory rate limiting store
# Structure: {user_email: [(timestamp1, count1), (timestamp2, count2), ...]}
rate_limit_store: Dict[str, List[tuple]] = defaultdict(list)

# Initialize Docker client
try:
    # Try to connect to the Docker daemon using the default socket path
    docker_client = docker.DockerClient(base_url="unix:///var/run/docker.sock")
except Exception as e:
    try:
        # Try to connect to the Docker daemon using the Windows socket path or via TCP
        docker_client = docker.DockerClient(base_url="tcp://localhost:2375")
    except Exception as e:
        logger.error(f"Failed to connect to Docker daemon: {str(e)}")
        # Initialize with None, will be handled in endpoints
        docker_client = None


# Database
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Docker client
def get_docker_client():
    if docker_client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Docker service is not available",
        )
    return docker_client


# Rate limiting middleware
# Limits are applied individually to each authenticated user
def rate_limit(user_email: str) -> None:
    """
    Check if the user has exceeded their rate limit.
    Raises an HTTPException if the rate limit is exceeded.
    """
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW

    # Clean up old entries outside the current window
    rate_limit_store[user_email] = [
        (ts, count) for ts, count in rate_limit_store[user_email] if ts >= window_start
    ]

    # Count total requests in the current window
    total_requests = sum(count for _, count in rate_limit_store[user_email])

    # Check if rate limit is exceeded
    if total_requests >= RATE_LIMIT_REQUESTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Try again in {int(RATE_LIMIT_WINDOW - (now - rate_limit_store[user_email][0][0]))} seconds",
        )

    # Record this request
    if rate_limit_store[user_email] and rate_limit_store[user_email][-1][0] == int(now):
        # Increment the count for the current second
        last_ts, count = rate_limit_store[user_email][-1]
        rate_limit_store[user_email][-1] = (last_ts, count + 1)
    else:
        # Add a new entry for the current second
        rate_limit_store[user_email].append((int(now), 1))


# Authentication functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def authenticate_user(db: Session, email: str, password: str):
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
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
    except JWTError:
        raise credentials_exception
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    return user


# Rate-limited user dependency
async def get_rate_limited_user(current_user: models.User = Depends(get_current_user)):
    rate_limit(current_user.email)
    return current_user


# Endpoints
@app.post("/login", response_model=schemas.Token)
async def login(user_credentials: schemas.UserLogin, db: Session = Depends(get_db)):
    user = authenticate_user(db, user_credentials.email, user_credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    db_user = models.User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


# Docker endpoints - now with rate limiting
@app.get("/images/", response_model=List[schemas.DockerImage])
async def list_images(
    current_user: models.User = Depends(get_rate_limited_user),
    docker_client: docker.DockerClient = Depends(get_docker_client),
):
    try:
        images = docker_client.images.list()
        return [
            schemas.DockerImage(
                id=image.id,
                tags=image.tags if image.tags else [],
                created=image.attrs["Created"],
                size=image.attrs["Size"],
            )
            for image in images
        ]
    except Exception as e:
        logger.error(f"Error fetching images: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error fetching images: {str(e)}")


@app.get("/containers/", response_model=List[schemas.DockerContainer])
async def list_containers(
    current_user: models.User = Depends(get_rate_limited_user),
    docker_client: docker.DockerClient = Depends(get_docker_client),
):
    try:
        containers = docker_client.containers.list(all=True)
        return [
            schemas.DockerContainer(
                id=container.id,
                name=container.name,
                image=(
                    container.image.tags[0]
                    if container.image.tags
                    else container.image.id
                ),
                status=container.status,
                created=container.attrs["Created"],
            )
            for container in containers
        ]
    except Exception as e:
        logger.error(f"Error fetching containers: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Error fetching containers: {str(e)}"
        )


@app.get("/images/{image_id}", response_model=schemas.DockerImageDetail)
async def get_image(
    image_id: str,
    current_user: models.User = Depends(get_rate_limited_user),
    docker_client: docker.DockerClient = Depends(get_docker_client),
):
    try:
        image = docker_client.images.get(image_id)
        return schemas.DockerImageDetail(
            id=image.id,
            tags=image.tags if image.tags else [],
            created=image.attrs["Created"],
            size=image.attrs["Size"],
            architecture=image.attrs["Architecture"],
            os=image.attrs["Os"],
            author=image.attrs.get("Author", ""),
            config=image.attrs.get("Config", {}),
        )
    except docker.errors.ImageNotFound:
        raise HTTPException(status_code=404, detail="Image not found")
    except Exception as e:
        logger.error(f"Error fetching image {image_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error fetching image: {str(e)}")


@app.get("/containers/{container_id}", response_model=schemas.DockerContainerDetail)
async def get_container(
    container_id: str,
    current_user: models.User = Depends(get_rate_limited_user),
    docker_client: docker.DockerClient = Depends(get_docker_client),
):
    try:
        container = docker_client.containers.get(container_id)
        return schemas.DockerContainerDetail(
            id=container.id,
            name=container.name,
            image=(
                container.image.tags[0] if container.image.tags else container.image.id
            ),
            status=container.status,
            created=container.attrs["Created"],
            ports=container.attrs["NetworkSettings"]["Ports"],
            mounts=container.attrs["Mounts"],
            command=(
                container.attrs["Config"]["Cmd"]
                if container.attrs["Config"]["Cmd"]
                else []
            ),
            environment=(
                container.attrs["Config"]["Env"]
                if container.attrs["Config"]["Env"]
                else []
            ),
        )
    except docker.errors.NotFound:
        raise HTTPException(status_code=404, detail="Container not found")
    except Exception as e:
        logger.error(f"Error fetching container {container_id}: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Error fetching container: {str(e)}"
        )


@app.get("/containers/{container_id}/logs", response_model=schemas.DockerContainerLogs)
async def get_container_logs(
    container_id: str,
    current_user: models.User = Depends(get_rate_limited_user),
    docker_client: docker.DockerClient = Depends(get_docker_client),
):
    try:
        container = docker_client.containers.get(container_id)
        logs = container.logs(tail=100)
        return schemas.DockerContainerLogs(
            container_id=container_id, logs=logs.decode("utf-8", errors="replace")
        )
    except docker.errors.NotFound:
        raise HTTPException(status_code=404, detail="Container not found")
    except Exception as e:
        logger.error(f"Error fetching logs for container {container_id}: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Error fetching container logs: {str(e)}"
        )


@app.delete("/images/{image_id}", response_model=schemas.ActionResponse)
async def delete_image(
    image_id: str,
    current_user: models.User = Depends(get_rate_limited_user),
    docker_client: docker.DockerClient = Depends(get_docker_client),
):
    try:
        docker_client.images.remove(image_id)
        return schemas.ActionResponse(
            success=True, message=f"Image {image_id} deleted successfully"
        )
    except docker.errors.ImageNotFound:
        raise HTTPException(status_code=404, detail="Image not found")
    except docker.errors.APIError as e:
        logger.error(f"Error deleting image {image_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error deleting image: {str(e)}")


@app.delete("/containers/{container_id}", response_model=schemas.ActionResponse)
async def delete_container(
    container_id: str,
    current_user: models.User = Depends(get_rate_limited_user),
    docker_client: docker.DockerClient = Depends(get_docker_client),
):
    try:
        container = docker_client.containers.get(container_id)
        container.remove(force=True)
        return schemas.ActionResponse(
            success=True, message=f"Container {container_id} deleted successfully"
        )
    except docker.errors.NotFound:
        raise HTTPException(status_code=404, detail="Container not found")
    except Exception as e:
        logger.error(f"Error deleting container {container_id}: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Error deleting container: {str(e)}"
        )


@app.post("/containers/{container_id}/stop", response_model=schemas.ActionResponse)
async def stop_container(
    container_id: str,
    current_user: models.User = Depends(get_rate_limited_user),
    docker_client: docker.DockerClient = Depends(get_docker_client),
):
    try:
        container = docker_client.containers.get(container_id)
        container.stop()
        return schemas.ActionResponse(
            success=True, message=f"Container {container_id} stopped successfully"
        )
    except docker.errors.NotFound:
        raise HTTPException(status_code=404, detail="Container not found")
    except Exception as e:
        logger.error(f"Error stopping container {container_id}: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Error stopping container: {str(e)}"
        )


@app.post("/containers/{container_id}/restart", response_model=schemas.ActionResponse)
async def restart_container(
    container_id: str,
    current_user: models.User = Depends(get_rate_limited_user),
    docker_client: docker.DockerClient = Depends(get_docker_client),
):
    try:
        container = docker_client.containers.get(container_id)
        container.restart()
        return schemas.ActionResponse(
            success=True, message=f"Container {container_id} restarted successfully"
        )
    except docker.errors.NotFound:
        raise HTTPException(status_code=404, detail="Container not found")
    except Exception as e:
        logger.error(f"Error restarting container {container_id}: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Error restarting container: {str(e)}"
        )


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
