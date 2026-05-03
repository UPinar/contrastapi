"""Jinja2Templates singleton — shared between main.py and api/landing.py."""

from config import BASE_DIR
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory=BASE_DIR / "templates")
