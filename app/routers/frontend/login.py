from fastapi import APIRouter
from templates import templates

router = APIRouter(
    prefix="/login",
    tags=["login"],
)
