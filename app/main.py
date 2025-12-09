
from fastapi import FastAPI, Request, Depends, Form, UploadFile, File, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlmodel import SQLModel, Field, Session, create_engine, select, delete
from starlette.middleware.sessions import SessionMiddleware
from passlib.hash import pbkdf2_sha256
from typing import Optional, List, Tuple
from pathlib import Path
import os, csv, io, httpx
import secrets
from datetime import datetime
import math
import re
import urllib.parse
from io import StringIO
import requests
from functools import lru_cache
from sqlalchemy.exc import NoResultFound
from sqlalchemy import create_engine
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
USE_LOCAL_SQLITE = os.getenv("USE_LOCAL_SQLITE", "0") == "1"
DATABASE_URL = os.getenv("DATABASE_URL")

if USE_LOCAL_SQLITE or not DATABASE_URL:
    DB_PATH = BASE_DIR / "mtg_friends.db"
    DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")


app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET", "dev-secret"))
app.mount("/static", StaticFiles(directory=BASE_DIR / "app" / "static"), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    name: str
    contact_link: Optional[str] = None
    password_hash: str

class CardListing(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    owner_id: int = Field(foreign_key="user.id")
    card_name: str
    set_name: Optional[str] = None
    condition: Optional[str] = None
    foil: bool = False
    quantity: int = 1
    scryfall_image_url: Optional[str] = None
    oracle_text: Optional[str] = None
    is_for_trade: bool = False
    price_usd: Optional[float] = None
    colors: Optional[str] = None
    type_line: Optional[str] = None
    mana_cost: Optional[str] = None     # e.g. "{1}{R}{R}"




class WishlistItem(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    owner_id: int = Field(foreign_key="user.id")
    card_name: str
    set_name: Optional[str] = None
    scryfall_image_url: Optional[str] = None
    oracle_text: Optional[str] = None
    price_usd: Optional[float] = None



class FriendGroup(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    owner_id: int = Field(foreign_key="user.id")


class GroupMember(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    group_id: int = Field(foreign_key="friendgroup.id")
    user_id: int = Field(foreign_key="user.id")

class GroupInvite(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    group_id: int = Field(foreign_key="friendgroup.id")
    token: str = Field(index=True, unique=True)
    created_by: int = Field(foreign_key="user.id")

class TradeClaim(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    requester_id: int = Field(foreign_key="user.id")      # who wants the card
    owner_id: int = Field(foreign_key="user.id")          # who has the card
    card_listing_id: int = Field(foreign_key="cardlisting.id")
    quantity: int = 1
    status: str = "open"                                  # open / completed / cancelled
    created_at: datetime = Field(default_factory=datetime.utcnow)

class PasswordResetToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    token: str = Field(index=True, unique=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    used: bool = Field(default=False)



def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session

def get_current_user(request: Request, session: Session = Depends(get_session)) -> Optional[User]:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return session.get(User, user_id)

def login_required(request: Request, current_user: User = Depends(get_current_user)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=302)
    return current_user

def parse_foil(value: str | None) -> bool:
    if not value:
        return False
    return value.strip().lower() in {"foil", "true", "yes", "1", "y"}


def normalize_name_and_set(raw_name: str, set_name: Optional[str]) -> tuple[str, Optional[str]]:
    """
    Handle inputs like:
      - 'Allosaurus Shepherd (2X2) 365 *F*'
      - 'Arid Mesa (MH2) 244'
      - 'Sol Ring'

    Returns (clean_name, set_code_or_None).

    - Extracts card name: 'Allosaurus Shepherd'
    - Extracts set code: '2X2'
    - Ignores collector number and trailing flags like '*F*'.
    - If set_name is already provided, we keep that and ignore extracted one.
    """
    if not raw_name:
        return "", set_name

    text = raw_name.strip()

    # Remove common trailing flags like "*F*", "*FOIL*", etc.
    # e.g. "Allosaurus Shepherd (2X2) 365 *F*" -> "Allosaurus Shepherd (2X2) 365"
    text = re.sub(r"\s+\*[^*]+\*\s*$", "", text)

    # Pattern: Name (SET) [123] [anything else...]
    # e.g. "Allosaurus Shepherd (2X2) 365"
    m = re.match(
        r"^(?P<name>.+?)\s*\((?P<set>[A-Za-z0-9]{2,5})\)\s*(?P<num>\d+)?(?:\s+.*)?$",
        text,
    )
    if not m:
        # No special pattern -> return as-is
        return text, set_name

    clean_name = m.group("name").strip()
    extracted_set = m.group("set").upper().strip()

    # Only use extracted set if caller didn't already specify one
    final_set = set_name or extracted_set

    return clean_name, final_set

import re
from typing import Optional


def parse_name_and_set(raw: str, existing_set: Optional[str] = None) -> tuple[str, Optional[str]]:
    """
    Parse Moxfield/EDH-style card strings into (name, set_code).

    Examples:
      'Allosaurus Shepherd (2X2) 365 *F*' -> ('Allosaurus Shepherd', '2X2')
      'Destiny Spinner (PLST) THB-168'    -> ('Destiny Spinner', 'PLST')
      'Arid Mesa (MH2) 244'              -> ('Arid Mesa', 'MH2')
      'Sol Ring'                          -> ('Sol Ring', None)

    If existing_set is provided (e.g. from a CSV 'Set Code' column),
    that takes priority over anything parsed from the string.
    """
    if not raw:
        return "", existing_set

    text = raw.strip()

    # Strip trailing flags like '*F*', '*FOIL*', etc.
    text = re.sub(r"\s+\*[^*]+\*\s*$", "", text)

    # Pattern 1: Name (SET) 123 ...
    m = re.match(
        r"^(?P<name>.+?)\s*\((?P<set>[A-Za-z0-9]{2,5})\)\s*(?P<rest>.*)$",
        text,
    )
    if m:
        clean_name = m.group("name").strip()
        detected_set = m.group("set").upper().strip()
        final_set = existing_set or detected_set
        return clean_name, final_set

    # Pattern 2: Name SET-123   (no parentheses, but card code at the end)
    m2 = re.match(
        r"^(?P<name>.+?)\s+(?P<set>[A-Za-z0-9]{2,5})-\d+\s*$",
        text,
    )
    if m2:
        clean_name = m2.group("name").strip()
        detected_set = m2.group("set").upper().strip()
        final_set = existing_set or detected_set
        return clean_name, final_set

    # Fallback: no recognizable set; just return the text and whatever set we already had
    return text, existing_set


SCRYFALL_NAMED_URL = "https://api.scryfall.com/cards/named"


scryfall_session = requests.Session()


@lru_cache(maxsize=4096)
def fetch_scryfall_info(name: str, set_code: Optional[str] = None) -> Tuple[Optional[str], Optional[str], Optional[float], Optional[str], Optional[str], Optional[str]]:
    """
    Return (image_url, oracle_text, price_usd, colors_str, type_line, mana_cost)

    - If set_code is provided, we ask Scryfall specifically for that set.
    - Otherwise we use the default/most recent printing for that card name.
    """
    name = (name or "").strip()
    if not name:
        return None, None, None, None, None, None

    base_url = "https://api.scryfall.com/cards/named"

    def do_request(params: dict) -> Optional[dict]:
        try:
            r = scryfall_session.get(base_url, params=params, timeout=6)
            if r.status_code != 200:
                return None
            return r.json()
        except Exception:
            return None

    data = None

    # 1) Try exact name + set if we have a set_code
    if set_code:
        data = do_request({"exact": name, "set": set_code.lower()})

    # 2) Fallback: exact name, any set
    if data is None:
        data = do_request({"exact": name})

    # 3) Fallback: fuzzy name, any set
    if data is None:
        data = do_request({"fuzzy": name})

    if data is None or "object" in data and data["object"] == "error":
        return None, None, None, None, None, None

    # Single-faced vs double-faced
    if "image_uris" in data:
        image_url = data["image_uris"].get("normal") or data["image_uris"].get("large")
    elif "card_faces" in data and data["card_faces"]:
        face0 = data["card_faces"][0]
        image_url = None
        if "image_uris" in face0:
            image_url = face0["image_uris"].get("normal") or face0["image_uris"].get("large")
    else:
        image_url = None

    oracle_text = data.get("oracle_text")
    if not oracle_text and "card_faces" in data and data["card_faces"]:
        oracle_text = data["card_faces"][0].get("oracle_text")

    price_raw = data.get("prices", {}).get("usd")
    try:
        price_usd = float(price_raw) if price_raw else None
    except ValueError:
        price_usd = None

    colors_list: List[str] = data.get("colors") or []
    colors_str = "".join(colors_list) if colors_list else None

    type_line = data.get("type_line")
    mana_cost = data.get("mana_cost") or None
    if not mana_cost and "card_faces" in data and data["card_faces"]:
        mana_cost = data["card_faces"][0].get("mana_cost")

    return image_url, oracle_text, price_usd, colors_str, type_line, mana_cost

def send_reset_email(to_email: str, reset_link: str) -> None:
    """
    Send a password reset email with a simple text body.
    Uses standard SMTP; configure via environment variables.
    """

    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    from_email = os.getenv("FROM_EMAIL", smtp_user)

    if not (smtp_host and smtp_user and smtp_password and from_email):
        print("[WARN] SMTP is not fully configured; cannot send reset email.")
        print(f"Reset link for {to_email}: {reset_link}")
        return

    subject = "MTG Friends Trades – Password reset"
    body = (
        "Hi,\n\n"
        "You requested a password reset for your MTG Friends Trades account.\n"
        "Click the link below to set a new password:\n\n"
        f"{reset_link}\n\n"
        "If you did not request this, you can ignore this email.\n"
    )

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
        print(f"[INFO] Sent reset email to {to_email}")
    except Exception as e:
        print(f"[ERROR] Failed to send reset email to {to_email}: {e}")
        # Still don’t tell the user; we only log this on the server


@app.on_event("startup")
def on_startup():
    create_db_and_tables()

@app.get("/")
def home(
    request: Request,
    current_user: Optional[User] = Depends(get_current_user),
):
    # If logged in, go straight to wishlist/dashboard
    if current_user:
        return RedirectResponse(url="/cards", status_code=302)

    # Otherwise show intro page
    return templates.TemplateResponse(
        "home.html",
        {
            "request": request,
            "current_user": None,
        },
    )

# Auth

@app.get("/register")
def register_get(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
def register_post(request: Request,
                  email: str = Form(...),
                  name: str = Form(...),
                  contact_link: str = Form(""),
                  password: str = Form(...),
                  session: Session = Depends(get_session)):
    existing = session.exec(select(User).where(User.email == email)).first()
    if existing:
        return templates.TemplateResponse("register.html", {"request": request, "error": "Email already registered."})
    user = User(email=email, name=name, contact_link=contact_link or "", password_hash=pbkdf2_sha256.hash(password))
    session.add(user)
    session.commit()
    session.refresh(user)
    request.session["user_id"] = user.id
    return RedirectResponse(url="/dashboard", status_code=302)

@app.get("/login")
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login_post(request: Request,
               email: str = Form(...),
               password: str = Form(...),
               session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.email == email)).first()
    if not user or not pbkdf2_sha256.verify(password, user.password_hash):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid email or password."})
    request.session["user_id"] = user.id
    return RedirectResponse(url="/dashboard", status_code=302)

@app.get("/logout")
@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)

@app.get("/profile")
def profile_page(
    request: Request,
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "current_user": current_user,
            "name_error": request.query_params.get("name_error"),
            "pwd_error": request.query_params.get("pwd_error"),
            "pwd_success": request.query_params.get("pwd_success"),
        },
    )


@app.post("/profile/update-name")
def update_profile_name(
    request: Request,
    name: str = Form(...),
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    name = name.strip()
    if not name:
        return RedirectResponse(
            url="/profile?name_error=Name+cannot+be+empty",
            status_code=302,
        )

    current_user.name = name
    session.add(current_user)
    session.commit()

    return RedirectResponse(url="/profile", status_code=302)


@app.post("/profile/change-password")
def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    new_password_confirm: str = Form(...),
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    # 1) Check current password is correct
    try:
        ok = pbkdf2_sha256.verify(current_password, current_user.password_hash)
    except Exception:
        ok = False

    if not ok:
        return RedirectResponse(
            url="/profile?pwd_error=Current+password+is+incorrect",
            status_code=302,
        )

    # 2) Check new password & confirmation match
    if new_password != new_password_confirm:
        return RedirectResponse(
            url="/profile?pwd_error=New+passwords+do+not+match",
            status_code=302,
        )

    # 3) (Optional but sensible) prevent empty password – no length restriction otherwise
    if not new_password:
        return RedirectResponse(
            url="/profile?pwd_error=New+password+cannot+be+empty",
            status_code=302,
        )

    # 4) Hash & save new password with pbkdf2_sha256
    current_user.password_hash = pbkdf2_sha256.hash(new_password)
    session.add(current_user)
    session.commit()

    return RedirectResponse(
        url="/profile?pwd_success=Password+updated+successfully",
        status_code=302,
    )

from fastapi import Form
from uuid import uuid4
from datetime import datetime, timedelta

@app.post("/forgot-password")
def forgot_password_submit(
    request: Request,
    email: str = Form(...),
    session: Session = Depends(get_session),
):
    # Always behave the same in the UI, whether or not the email exists.
    user = session.exec(
        select(User).where(User.email == email)
    ).first()

    if user:
        # Invalidate old tokens or just let them expire; we’ll keep it simple now.

        # Create a new token
        raw_token = str(uuid4())  # random string
        reset = PasswordResetToken(
            user_id=user.id,
            token=raw_token,
            created_at=datetime.utcnow(),
            used=False,
        )
        session.add(reset)
        session.commit()

        # Build a reset link – adjust base URL to your hosted URL later
        # For local dev:
        reset_link = f"{BASE_URL}/reset-password?token={raw_token}"

        # Send email (or log if SMTP is not configured)
        send_reset_email(user.email, reset_link)

    # UI message is intentionally generic: we don't leak if email exists.
    msg = (
        "If an account with that email exists, a reset link has been sent to it. "
        "Please check your inbox (and spam folder)."
    )

    return templates.TemplateResponse(
        "forgot_password.html",
        {
            "request": request,
            "message": msg,
        },
    )


@app.post("/forgot-password")
def forgot_password_submit(
    request: Request,
    email: str = Form(...),
    session: Session = Depends(get_session),
):
    email = email.strip().lower()
    user = session.exec(select(User).where(User.email == email)).first()

    if user:
        # generate a secure token
        token = secrets.token_urlsafe(32)

        reset = PasswordResetToken(
            user_id=user.id,
            token=token,
            used=False,
        )
        session.add(reset)
        session.commit()

        # In a real deployment you would send this via email.
        reset_url = f"/reset-password?token={token}"
        print(f"[PASSWORD RESET] Link for {user.email}: {reset_url}")

    # We always say "sent" to avoid leaking whether the email exists
    return RedirectResponse(url="/forgot-password?sent=1", status_code=302)

@app.get("/forgot-password")
def forgot_password_page(
    request: Request,
    message: str | None = None,
):
    """
    Show the 'forgot password' form.
    `message` can optionally be used to show a banner.
    """
    return templates.TemplateResponse(
        "forgot_password.html",
        {
            "request": request,
            "message": message,
        },
    )



@app.get("/reset-password")
def reset_password_page(
    request: Request,
    token: str,
    session: Session = Depends(get_session),
):
    reset = session.exec(
        select(PasswordResetToken).where(
            PasswordResetToken.token == token,
            PasswordResetToken.used == False,
        )
    ).first()

    if not reset:
        return templates.TemplateResponse(
            "reset_password_invalid.html",
            {"request": request, "current_user": None},
        )

    return templates.TemplateResponse(
        "reset_password.html",
        {
            "request": request,
            "current_user": None,
            "token": token,
            "error": request.query_params.get("error"),
        },
    )


@app.post("/reset-password")
def reset_password_submit(
    request: Request,
    token: str = Form(...),
    new_password: str = Form(...),
    new_password_confirm: str = Form(...),
    session: Session = Depends(get_session),
):
    reset = session.exec(
        select(PasswordResetToken).where(
            PasswordResetToken.token == token,
            PasswordResetToken.used == False,
        )
    ).first()

    if not reset:
        return templates.TemplateResponse(
            "reset_password_invalid.html",
            {"request": request, "current_user": None},
        )

    if len(new_password) < 6:
        return RedirectResponse(
            url=f"/reset-password?token={token}&error=Password+too+short",
            status_code=302,
        )

    if new_password != new_password_confirm:
        return RedirectResponse(
            url=f"/reset-password?token={token}&error=Passwords+do+not+match",
            status_code=302,
        )

    user = session.get(User, reset.user_id)
    if not user:
        return templates.TemplateResponse(
            "reset_password_invalid.html",
            {"request": request, "current_user": None},
        )

    user.password_hash = pwd_context.hash(new_password)
    reset.used = True
    session.add(user)
    session.add(reset)
    session.commit()

    return RedirectResponse(url="/login?reset=1", status_code=302)



# Dashboard

@app.get("/dashboard")
def dashboard(
    request: Request,
    q: str = "",
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    # base query: all wishes of this user
    wish_query = select(WishlistItem).where(WishlistItem.owner_id == current_user.id)

    # filter by card name if q is given
    if q:
        wish_query = wish_query.where(WishlistItem.card_name.contains(q))

    wishes = session.exec(
        wish_query.order_by(WishlistItem.card_name)
    ).all()

    # names of cards the user already has in their collection
    owned_rows = session.exec(
        select(CardListing.card_name).where(CardListing.owner_id == current_user.id)
    ).all()
    owned_names = {row[0] if isinstance(row, tuple) else row for row in owned_rows}

    has_collection = session.exec(
        select(CardListing).where(CardListing.owner_id == current_user.id)
    ).first() is not None

    has_wishlist = session.exec(
        select(WishlistItem).where(WishlistItem.owner_id == current_user.id)
    ).first() is not None

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "current_user": current_user,
            "wishes": wishes,
            "owned_names": owned_names,
            "has_collection": has_collection,
            "has_wishlist": has_wishlist,
            "q": q,
        },
    )

@app.post("/dashboard/add-card")
async def add_card(request: Request,
                   card_name: str = Form(...),
                   set_name: str = Form(""),
                   condition: str = Form(""),
                   foil: Optional[bool] = Form(False),
                   quantity: int = Form(1),
                   current_user: User = Depends(login_required),
                   session: Session = Depends(get_session)):
    clean_name = card_name.strip()
    clean_set = set_name.strip() or None
    clean_condition = condition.strip() or None
    scry_img, oracle_text, price_usd, colors_str, type_line, mana_cost = fetch_scryfall_info(clean_name, clean_set)

    card = CardListing(
        owner_id=current_user.id,
        card_name=clean_name,
        set_name=clean_set,
        condition=clean_condition,
        foil=bool(foil),
        quantity=quantity,
        scryfall_image_url=scry_img,
        oracle_text=oracle_text,
        is_for_trade=True,
        price_usd=price_usd,
        colors=colors_str,
        type_line=type_line,
        mana_cost=mana_cost,
    )


    session.add(card)
    session.commit()
    return RedirectResponse(url="/dashboard", status_code=302)

@app.post("/dashboard/wishlist/delete")
def delete_wish(
    request: Request,
    wish_id: int = Form(...),
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    wish = session.exec(
        select(WishlistItem).where(
            WishlistItem.id == wish_id,
            WishlistItem.owner_id == current_user.id,
        )
    ).first()

    if wish:
        session.delete(wish)
        session.commit()

    return RedirectResponse(url="/dashboard", status_code=302)

@app.post("/dashboard/wishlist/clear")
def clear_wishlist(
    request: Request,
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    wishes = session.exec(
        select(WishlistItem).where(WishlistItem.owner_id == current_user.id)
    ).all()

    owned_rows = session.exec(
        select(CardListing.card_name).where(CardListing.owner_id == current_user.id)
    ).all()
    owned_names = {row[0] if isinstance(row, tuple) else row for row in owned_rows}

    for w in wishes:
        if w.card_name in owned_names:
            continue  # skip cards you already own when searching matches
        # find friends' listings with w.card_name


    for w in wishes:
        session.delete(w)

    session.commit()
    return RedirectResponse(url="/dashboard", status_code=302)


@app.post("/dashboard/bulk-list")
def bulk_list_update(
    request: Request,
    action: str = Form(...),
    card_ids: List[int] = Form([]),
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    # Safety: only affect current user's cards
    q_base = select(CardListing).where(CardListing.owner_id == current_user.id)

    if action == "list_all":
        cards = session.exec(q_base).all()
        for c in cards:
            c.is_for_trade = True
            session.add(c)
        session.commit()

    elif action == "unlist_all":
        cards = session.exec(q_base).all()
        for c in cards:
            c.is_for_trade = False
            session.add(c)
        session.commit()

    elif action in ("list_selected", "unlist_selected") and card_ids:
        cards = session.exec(
            q_base.where(CardListing.id.in_(card_ids))
        ).all()
        for c in cards:
            if action == "list_selected":
                c.is_for_trade = True
            else:
                c.is_for_trade = False
            session.add(c)
        session.commit()

    referer = request.headers.get("referer") or "/collection"
    return RedirectResponse(url=referer, status_code=302)


@app.post("/dashboard/delete-card/{card_id}")
def delete_card(request: Request,
                card_id: int,
                current_user: User = Depends(login_required),
                session: Session = Depends(get_session)):
    card = session.get(CardListing, card_id)
    if not card or card.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Card not found")
    session.delete(card)
    session.commit()
    return RedirectResponse(url="/dashboard", status_code=302)

@app.post("/dashboard/import-csv")
async def import_csv(
    request: Request,
    csv_file: UploadFile = File(...),
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    if not csv_file.filename.endswith(".csv"):
        return RedirectResponse(url="/dashboard", status_code=302)

    contents = csv_file.file.read().decode("utf-8", errors="ignore")
    csv_file.file.close()

    f = StringIO(contents)
    reader = csv.DictReader(f)

    added_count = 0
    updated_count = 0
    skipped_count = 0

    # merge duplicates within the same CSV
    existing_map: dict[tuple[str, str | None], CardListing] = {}

    for row in reader:
        # --- Card name ---
        name = (
            (row.get("name") or "")
            or (row.get("Card") or "")
            or (row.get("Card Name") or "")
        ).strip()

        if not name:
            skipped_count += 1
            continue


        # --- Set / set code ---
        set_name = (
            (row.get("set") or "")
            or (row.get("Set") or "")
            or (row.get("Set Code") or "")
        ).strip() or None

        name, set_name = parse_name_and_set(name, set_name)

        # --- Quantity ---
        qty_raw = (
            (row.get("quantity") or "")
            or (row.get("Quantity") or "")
        ).strip()
        try:
            quantity = int(qty_raw) if qty_raw else 1
        except ValueError:
            quantity = 1

        # --- Foil ---
        foil_raw = (
            (row.get("foil") or "")
            or (row.get("Foil") or "")
            or (row.get("Foil/Etched") or "")
        )
        foil = parse_foil(foil_raw)

        # --- Condition ---
        condition = (
            (row.get("condition") or "")
            or (row.get("Condition") or "")
        ).strip() or None

        key = (name, set_name)

        # already seen in this CSV import
        if key in existing_map:
            existing = existing_map[key]
            existing.quantity = (existing.quantity or 0) + quantity
            updated_count += 1
            continue

        # already exists in DB for this user
        existing = session.exec(
            select(CardListing).where(
                CardListing.owner_id == current_user.id,
                CardListing.card_name == name,
                CardListing.set_name == set_name,
            )
        ).first()

        if existing:
            existing.quantity = (existing.quantity or 0) + quantity
            session.add(existing)
            existing_map[key] = existing
            updated_count += 1
            continue

        # brand new card: fetch Scryfall info
        scry_img, oracle_text, price_usd, colors_str, type_line, mana_cost = fetch_scryfall_info(
            name, set_name
        )

        card = CardListing(
            owner_id=current_user.id,
            card_name=name,
            set_name=set_name,
            condition=condition,
            foil=foil,
            quantity=quantity,
            scryfall_image_url=scry_img,
            oracle_text=oracle_text,
            is_for_trade=True,
            price_usd=price_usd,
            colors=colors_str,
            type_line=type_line,
            mana_cost=mana_cost,
        )

        session.add(card)
        existing_map[key] = card
        added_count += 1

    session.commit()

    params = {
        "csv_import_added": added_count,
        "csv_import_updated": updated_count,
        "csv_import_skipped": skipped_count,
    }
    qs = urllib.parse.urlencode(params)
    return RedirectResponse(url="/collection?" + qs, status_code=302)


@app.get("/api/card-autocomplete")
def card_autocomplete(q: str = "", limit: int = 10):
    q = q.strip()
    if not q:
        return {"suggestions": []}

    try:
        r = httpx.get(
            "https://api.scryfall.com/cards/autocomplete",
            params={"q": q, "include_extras": "true"},
            timeout=5.0,
        )
        if r.status_code != 200:
            return {"suggestions": []}
        data = r.json()
        names = data.get("data", [])[:limit]
        return {"suggestions": names}
    except Exception:
        return {"suggestions": []}



@app.post("/dashboard/add-wish")
def add_wish(
    request: Request,
    card_name: str = Form(...),
    set_name: str = Form(""),
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    clean_name = card_name.strip()
    clean_set = set_name.strip() or None

    if not clean_name:
        return RedirectResponse(url="/dashboard", status_code=302)

    # 1) Check if user already has this card in their collection
    owned = session.exec(
        select(CardListing).where(
            CardListing.owner_id == current_user.id,
            CardListing.card_name == clean_name,
        )
    ).first()

    if owned:
        # card is already in collection -> don't add to wishlist
        return RedirectResponse(
            url="/dashboard?already_have=" + urllib.parse.quote(clean_name),
            status_code=302,
        )

    # 2) Check if it's already in wishlist
    existing = session.exec(
        select(WishlistItem).where(
            WishlistItem.owner_id == current_user.id,
            WishlistItem.card_name == clean_name,
            WishlistItem.set_name == clean_set,
        )
    ).first()

    if existing:
        # already there, just tell the user
        return RedirectResponse(
            url="/dashboard?wish_exists=" + urllib.parse.quote(clean_name),
            status_code=302,
        )

    # 3) Not owned and not in wishlist -> create new wish
    scry_img, oracle_text, price_usd, _, _, _ = fetch_scryfall_info(
        clean_name, clean_set
    )
    wish = WishlistItem(
        owner_id=current_user.id,
        card_name=clean_name,
        set_name=clean_set,
        scryfall_image_url=scry_img,
        oracle_text=oracle_text,
        price_usd=price_usd,
    )
    session.add(wish)
    session.commit()

    return RedirectResponse(
        url="/dashboard?wish_added=" + urllib.parse.quote(clean_name),
        status_code=302,
    )

@app.post("/dashboard/delete-wish/{wish_id}")
def delete_wish(request: Request,
                wish_id: int,
                current_user: User = Depends(login_required),
                session: Session = Depends(get_session)):
    wish = session.get(WishlistItem, wish_id)
    if not wish or wish.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Wishlist item not found")
    session.delete(wish)
    session.commit()
    return RedirectResponse(url="/dashboard", status_code=302)

def parse_mana_cost(mana_cost: str | None) -> list[str]:
    """
    Turn "{1}{R}{R}" into ["1", "R", "R"].
    Handles weirdness by just returning what's between {}.
    """
    if not mana_cost:
        return []
    result: list[str] = []
    buf = ""
    inside = False
    for ch in mana_cost:
        if ch == "{":
            inside = True
            buf = ""
        elif ch == "}":
            if inside and buf:
                result.append(buf)
            inside = False
            buf = ""
        else:
            if inside:
                buf += ch
    return result

@app.post("/dashboard/import-wishlist")
def import_wishlist(
    request: Request,
    deck_text: str = Form(...),
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    lines = [l.strip() for l in deck_text.splitlines() if l.strip()]

    # 1) Parse lines into {card_name -> total_qty_in_deck}
    import_counts: dict[str, int] = {}
    # also remember a set code per card name if present
    import_sets: dict[str, Optional[str]] = {}

    for line in lines:
        low = line.lower()

        # skip obvious non-card lines (EDHREC/Moxfield style)
        if low.startswith("#") or low.startswith("//") or "sideboard" in low:
            continue
        if low.startswith("commander") or low.startswith("companion"):
            continue

        # Try "1 Card Name" or "1x Card Name"
        m = re.match(r"^\s*(\d+)\s*x?\s*(.+)$", line)
        if m:
            qty = int(m.group(1))
            raw_name = m.group(2).strip()
        else:
            qty = 1
            raw_name = line

        if not raw_name:
            continue

        # Parse 'Destiny Spinner (PLST) THB-168', etc.
        name, set_code = parse_name_and_set(raw_name, None)
        if not name:
            continue

        import_counts[name] = import_counts.get(name, 0) + qty
        if set_code and name not in import_sets:
            import_sets[name] = set_code

    # how many 'slots' vs distinct cards
    total_slots = sum(import_counts.values())
    distinct_cards = len(import_counts)
    duplicates_in_import = max(total_slots - distinct_cards, 0)

    added: list[str] = []                 # new wishlist entries created now
    already_owned_names: set[str] = set() # cards where you already have in collection
    already_in_wishlist: list[str] = []   # cards that were already on wishlist

    for name, total_qty in import_counts.items():
        # Do you already own this card in your collection?
        owned = session.exec(
            select(CardListing).where(
                CardListing.owner_id == current_user.id,
                CardListing.card_name == name,
            )
        ).first()

        if owned:
            already_owned_names.add(name)

        # Is it already on your wishlist?
        existing = session.exec(
            select(WishlistItem).where(
                WishlistItem.owner_id == current_user.id,
                WishlistItem.card_name == name,
            )
        ).first()

        if existing:
            already_in_wishlist.append(name)
            continue

        set_for_fetch = import_sets.get(name)

        # Not on wishlist yet -> create a new entry
        scry_img, oracle_text, price_usd, _, _, _ = fetch_scryfall_info(name, set_for_fetch)

        wish = WishlistItem(
            owner_id=current_user.id,
            card_name=name,
            set_name=set_for_fetch,
            scryfall_image_url=scry_img,
            oracle_text=oracle_text,
            price_usd=price_usd,
        )
        session.add(wish)
        added.append(name)

    session.commit()

    params = {
        "wish_import_added": len(added),
        "wish_import_already_owned": len(already_owned_names),
        "wish_import_existing": len(already_in_wishlist),
        "wish_import_duplicates": duplicates_in_import,
    }
    qs = urllib.parse.urlencode(params)
    return RedirectResponse(url="/dashboard?" + qs, status_code=302)



@app.get("/collection")
def collection_page(
    request: Request,
    q: str = "",
    listed: str = "all",
    color: str = "any",
    card_type: str = "any",
    sort: str = "name_asc",
    page: int = 1,
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    # base query: all cards in this user's collection
    query = select(CardListing).where(CardListing.owner_id == current_user.id)

    # text search by card name
    if q:
        query = query.where(CardListing.card_name.contains(q))

    # filter by listed status
    if listed == "listed":
        query = query.where(CardListing.is_for_trade == True)
    elif listed == "not_listed":
        query = query.where(CardListing.is_for_trade == False)

    # filter by color (color_identity string like "R", "UG", etc.)
    if color != "any":
        # for "colorless" we want cards with no colors_str
        if color == "C":
            query = query.where(
                (CardListing.colors == None) | (CardListing.colors == "")
            )
        else:
            query = query.where(CardListing.colors.contains(color))

    # filter by card type
    if card_type != "any":
        query = query.where(CardListing.type_line.contains(card_type))

    # sorting
    if sort == "name_asc":
        query = query.order_by(CardListing.card_name)
    elif sort == "name_desc":
        query = query.order_by(CardListing.card_name.desc())
    elif sort == "price_desc":
        query = query.order_by(CardListing.price_usd.desc().nullslast())
    elif sort == "price_asc":
        query = query.order_by(CardListing.price_usd.nullsfirst())
    elif sort == "set_asc":
        query = query.order_by(CardListing.set_name, CardListing.card_name)

    # fetch all matching, then slice for pagination (simple and ok for a few thousand)
    all_cards = session.exec(query).all()
    total = len(all_cards)

    page_size = 100
    max_page = max(1, math.ceil(total / page_size)) if total else 1
    page = max(1, min(page, max_page))

    start = (page - 1) * page_size
    end = start + page_size
    cards = all_cards[start:end]

    # card names currently on your wishlist
    wish_rows = session.exec(
        select(WishlistItem.card_name).where(WishlistItem.owner_id == current_user.id)
    ).all()
    wishlist_names = {row[0] if isinstance(row, tuple) else row for row in wish_rows}

    # build view models with parsed mana symbols for the template
    view_cards = []
    for c in cards:
        symbols = parse_mana_cost(c.mana_cost)
        view_cards.append({"card": c, "mana": symbols})


    return templates.TemplateResponse(
        "collection.html",
        {
            "request": request,
            "current_user": current_user,
            "cards": cards,
            "view_cards": view_cards,
            "q": q,
            "listed": listed,
            "color": color,
            "card_type": card_type,
            "sort": sort,
            "page": page,
            "max_page": max_page,
            "total": total,
            "wishlist_names": wishlist_names,
        },
    )

@app.post("/collection/add-card")
def add_collection_card(
    request: Request,
    card_name: str = Form(...),
    set_name: str = Form(""),
    quantity: int = Form(1),
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    clean_name = card_name.strip()
    clean_set = set_name.strip() or None
    qty = quantity or 1
    if qty < 1:
        qty = 1

    if not clean_name:
        return RedirectResponse(url="/collection", status_code=302)

    # 1) check if this card (same name + set) is already in the collection
    existing = session.exec(
        select(CardListing).where(
            CardListing.owner_id == current_user.id,
            CardListing.card_name == clean_name,
            CardListing.set_name == clean_set,
        )
    ).first()

    if existing:
        existing.quantity = (existing.quantity or 0) + qty
        session.add(existing)
        status_param = "added_existing"
    else:
        # 2) new card entry: fetch Scryfall info
        image_url, oracle_text, price_usd, colors, type_line, mana_cost = fetch_scryfall_info(
            clean_name, clean_set
        )

        new_card = CardListing(
            owner_id=current_user.id,
            card_name=clean_name,
            set_name=clean_set,
            quantity=qty,
            condition="NM",
            foil=False,
            is_for_trade=True,
            scryfall_image_url=image_url,
            oracle_text=oracle_text,
            price_usd=price_usd,
            colors=colors,
            type_line=type_line,
            mana_cost=mana_cost,
        )
        session.add(new_card)
        status_param = "added_new"

    session.commit()

    return RedirectResponse(
        url=f"/collection?{status_param}=" + urllib.parse.quote(clean_name),
        status_code=302,
    )

from fastapi import Form  # you already import this above for other handlers

@app.post("/collection/delete/{card_id}")
def delete_collection_card(
    card_id: int,
    request: Request,
    remove_quantity: int = Form(1),
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    # Make sure this card belongs to the current user
    card = session.get(CardListing, card_id)
    if not card or card.owner_id != current_user.id:
        # Just go back silently – nothing to delete
        return RedirectResponse(url="/collection", status_code=302)

    # Normalize quantity
    try:
        qty = int(remove_quantity)
    except (TypeError, ValueError):
        qty = 1
    if qty < 1:
        qty = 1

    # Decrease quantity or remove the row entirely
    if card.quantity <= qty:
        session.delete(card)
    else:
        card.quantity = card.quantity - qty

    session.commit()

    return RedirectResponse(
        url="/collection?deleted_card=1",
        status_code=302,
    )


@app.post("/collection/delete-card")
def delete_collection_card(
    card_id: int = Form(...),
    quantity: int = Form(1),
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    card = session.get(CardListing, card_id)
    if not card or card.owner_id != current_user.id:
        return RedirectResponse(url="/collection", status_code=302)

    # how many to remove (at least 1)
    remove_qty = quantity or 1
    if remove_qty < 1:
        remove_qty = 1

    current_qty = card.quantity or 0
    removed_all = False

    # store name before possible delete
    card_name = card.card_name

    if remove_qty >= current_qty:
        # remove the whole row
        removed_qty = current_qty
        session.delete(card)
        removed_all = True
    else:
        # just reduce quantity
        card.quantity = current_qty - remove_qty
        session.add(card)
        removed_qty = remove_qty

    session.commit()

    # build a nice message
    params = {
        "removed_name": card_name,
        "removed_qty": removed_qty,
    }
    if removed_all:
        params["removed_all"] = "1"

    qs = urllib.parse.urlencode(params)
    return RedirectResponse(url="/collection?" + qs, status_code=302)



# Browse & matches

@app.get("/cards")
def browse_cards(
    request: Request,
    q: str = "",
    group_id: Optional[int] = None,
    session: Session = Depends(get_session),
    current_user: Optional[User] = Depends(get_current_user),
):
    # base query: all tradeable cards with their owners
    query = (
        select(CardListing, User)
        .join(User, CardListing.owner_id == User.id)
        .where(CardListing.is_for_trade == True)
    )

    # text search
    if q:
        query = query.where(CardListing.card_name.contains(q))

    groups_for_user: List[FriendGroup] = []
    allowed_user_ids: set[int] = set()

    if current_user:
        # groups the current user belongs to
        mships = session.exec(
            select(GroupMember).where(GroupMember.user_id == current_user.id)
        ).all()
        gid_list = [m.group_id for m in mships]

        if gid_list:
            groups_for_user = session.exec(
                select(FriendGroup).where(FriendGroup.id.in_(gid_list))
            ).all()

            # all members of any of the user's groups – but NOT yourself
            gm_all = session.exec(
                select(GroupMember).where(GroupMember.group_id.in_(gid_list))
            ).all()
            for gm in gm_all:
                if gm.user_id != current_user.id:
                    allowed_user_ids.add(gm.user_id)

        # if a specific group filter is selected, restrict to that group only
        if group_id:
            gm_group = session.exec(
                select(GroupMember).where(GroupMember.group_id == group_id)
            ).all()
            group_member_ids = {gm.user_id for gm in gm_group if gm.user_id != current_user.id}

            if allowed_user_ids:
                allowed_user_ids = allowed_user_ids.intersection(group_member_ids)
            else:
                allowed_user_ids = group_member_ids

        # apply allowed_user_ids restriction
        if allowed_user_ids:
            query = query.where(CardListing.owner_id.in_(list(allowed_user_ids)))
        else:
            # no allowed users → no results
            query = query.where(CardListing.owner_id == -1)
    else:
        # not logged in → don't show any cards
        query = query.where(CardListing.owner_id == -1)

    results = session.exec(query).all()
    cards: List[dict] = [{"card": c, "owner": u} for c, u in results]

    return templates.TemplateResponse(
        "cards.html",
        {
            "request": request,
            "current_user": current_user,
            "cards": cards,
            "q": q,
            "groups": groups_for_user,
            "group_id": group_id,
        },
    )


@app.get("/matches")
def matches_page(
    request: Request,
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    # All wishlist items for current user
    wishes = session.exec(
        select(WishlistItem).where(WishlistItem.owner_id == current_user.id)
    ).all()

    owned_rows = session.exec(
        select(CardListing.card_name).where(CardListing.owner_id == current_user.id)
    ).all()
    owned_names = {row[0] if isinstance(row, tuple) else row for row in owned_rows}

    for w in wishes:
        if w.card_name in owned_names:
            continue  # skip cards you already own when searching matches
        # find friends' listings with w.card_name


    # All open claims created by current user -> card ids to skip
    claimed_card_ids = set(
        session.exec(
            select(TradeClaim.card_listing_id).where(
                TradeClaim.requester_id == current_user.id,
                TradeClaim.status == "open",
            )
        ).all()
    )

    # Group-based visibility: only see cards from people in your groups
    allowed_user_ids: set[int] = set()
    mships = session.exec(
        select(GroupMember).where(GroupMember.user_id == current_user.id)
    ).all()
    gid_list = [m.group_id for m in mships]
    if gid_list:
        gm_all = session.exec(
            select(GroupMember).where(GroupMember.group_id.in_(gid_list))
        ).all()
        for gm in gm_all:
            if gm.user_id != current_user.id:
                allowed_user_ids.add(gm.user_id)

    matches: list[dict] = []

    for wish in wishes:
        q = (
            select(CardListing, User)
            .join(User, CardListing.owner_id == User.id)
            .where(
                CardListing.card_name == wish.card_name,
                CardListing.owner_id != current_user.id,
                CardListing.is_for_trade == True,
            )
        )

        if allowed_user_ids:
            q = q.where(CardListing.owner_id.in_(list(allowed_user_ids)))

        results = session.exec(q).all()

        offers = []
        for c, u in results:
            # skip cards you've already claimed
            if c.id in claimed_card_ids:
                continue
            offers.append({"card": c, "owner": u})

        if offers:
            matches.append({"wish": wish, "offers": offers})

    return templates.TemplateResponse(
        "matches.html",
        {
            "request": request,
            "current_user": current_user,
            "matches": matches,
        },
    )

@app.get("/groups")
def groups_page(
    request: Request,
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    # find groups current_user is a member of
    memberships = session.exec(
        select(GroupMember).where(GroupMember.user_id == current_user.id)
    ).all()
    group_ids = [m.group_id for m in memberships]

    groups: List[FriendGroup] = []
    members_by_group: dict[int, List[User]] = {}
    invites_by_group: dict[int, List[GroupInvite]] = {}

    if group_ids:
        # groups
        groups = session.exec(
            select(FriendGroup).where(FriendGroup.id.in_(group_ids))
        ).all()

        # members for each group
        pairs = session.exec(
            select(GroupMember, User)
            .join(User, GroupMember.user_id == User.id)
            .where(GroupMember.group_id.in_(group_ids))
        ).all()
        for gm, u in pairs:
            members_by_group.setdefault(gm.group_id, []).append(u)

        # invites for each group
        invites = session.exec(
            select(GroupInvite).where(GroupInvite.group_id.in_(group_ids))
        ).all()
        for inv in invites:
            invites_by_group.setdefault(inv.group_id, []).append(inv)

    return templates.TemplateResponse(
        "groups.html",
        {
            "request": request,
            "current_user": current_user,
            "groups": groups,
            "members_by_group": members_by_group,
            "invites_by_group": invites_by_group,
        },
    )

@app.post("/claims/{claim_id}/complete")
def complete_claim(
    claim_id: int,
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    # 1) Load the claim
    claim = session.get(TradeClaim, claim_id)
    if not claim:
        return RedirectResponse(url="/trade-plan?error=claim_not_found", status_code=302)

    # Only someone involved in the trade can mark it as done
    if current_user.id not in (claim.requester_id, claim.owner_id):
        return RedirectResponse(url="/trade-plan?error=not_allowed", status_code=302)

    # 2) Load the card listing (owned by claim.owner_id)
    card = session.get(CardListing, claim.card_listing_id)
    if not card:
        # listing gone; just delete claim
        session.delete(claim)
        session.commit()
        return RedirectResponse(url="/trade-plan?error=card_missing", status_code=302)

    if card.owner_id != claim.owner_id:
        # something got out of sync (ownership changed)
        session.delete(claim)
        session.commit()
        return RedirectResponse(url="/trade-plan?error=owner_mismatch", status_code=302)

    from_user_id = claim.owner_id       # who is giving the card
    to_user_id = claim.requester_id     # who is receiving the card
    move_qty = claim.quantity or 1

    # 3) Decrease quantity for the owner
    current_qty = card.quantity or 0
    if current_qty <= 0:
        session.delete(claim)
        session.commit()
        return RedirectResponse(url="/trade-plan?error=no_quantity", status_code=302)

    # if claim.quantity > available, just move what they have left
    actual_move = move_qty if move_qty <= current_qty else current_qty

    if current_qty == actual_move:
        session.delete(card)
    else:
        card.quantity = current_qty - actual_move
        session.add(card)

    # 4) Add / increment the card in the receiver's collection
    existing_target = session.exec(
        select(CardListing).where(
            CardListing.owner_id == to_user_id,
            CardListing.card_name == card.card_name,
            CardListing.set_name == card.set_name,
        )
    ).first()

    if existing_target:
        existing_target.quantity = (existing_target.quantity or 0) + actual_move
        session.add(existing_target)
    else:
        new_card = CardListing(
            owner_id=to_user_id,
            card_name=card.card_name,
            set_name=card.set_name,
            condition=card.condition,
            foil=card.foil,
            quantity=actual_move,
            scryfall_image_url=card.scryfall_image_url,
            oracle_text=card.oracle_text,
            is_for_trade=False,  # new owner hasn't listed it yet
            price_usd=card.price_usd,
            colors=card.colors,
            type_line=card.type_line,
            mana_cost=card.mana_cost,
        )
        session.add(new_card)

    # 5) Update wishlist ONLY for the receiver: they now have this card
    session.exec(
        delete(WishlistItem).where(
            WishlistItem.owner_id == to_user_id,
            WishlistItem.card_name == card.card_name,
        )
    )

    # 6) Remove the claim (trade finished)
    session.delete(claim)

    session.commit()

    return RedirectResponse(url="/trade-plan?completed=1", status_code=302)


@app.post("/claims/{claim_id}/cancel")
def cancel_claim(
    request: Request,
    claim_id: int,
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    claim = session.get(TradeClaim, claim_id)
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")

    if current_user.id not in (claim.requester_id, claim.owner_id):
        raise HTTPException(status_code=403, detail="Not allowed")

    claim.status = "cancelled"
    session.add(claim)
    session.commit()
    return RedirectResponse(url="/trade-plan", status_code=302)


@app.get("/trade-plan")
def trade_plan(
    request: Request,
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    # all open claims where current_user is requester OR owner
    claims = session.exec(
        select(TradeClaim).where(
            TradeClaim.status == "open",
        ).where(
            (TradeClaim.requester_id == current_user.id) |
            (TradeClaim.owner_id == current_user.id)
        )
    ).all()

    friends: dict[int, dict] = {}

    for claim in claims:
        if claim.requester_id == current_user.id:
            # I should receive from owner
            other_id = claim.owner_id
            direction = "receive"
        else:
            # I should give to requester
            other_id = claim.requester_id
            direction = "give"

        if other_id not in friends:
            other = session.get(User, other_id)
            friends[other_id] = {
                "friend": other,
                "receive": [],
                "give": [],
            }

        card = session.get(CardListing, claim.card_listing_id)
        friends[other_id][direction].append({"claim": claim, "card": card})

    # compute totals per friend
    friend_blocks = []
    for data in friends.values():
        total_receive = 0.0
        total_give = 0.0

        for item in data["receive"]:
            c = item["card"]
            cl = item["claim"]
            if c and c.price_usd:
                total_receive += c.price_usd * cl.quantity

        for item in data["give"]:
            c = item["card"]
            cl = item["claim"]
            if c and c.price_usd:
                total_give += c.price_usd * cl.quantity

        data["total_receive"] = total_receive
        data["total_give"] = total_give
        friend_blocks.append(data)

    return templates.TemplateResponse(
        "trade_plan.html",
        {
            "request": request,
            "current_user": current_user,
            "friends": friend_blocks,
        },
    )

@app.post("/trade-plan/complete")
def complete_trade(
    claim_id: int = Form(...),
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    # 1) Load the claim
    claim = session.get(TradeClaim, claim_id)
    if not claim:
        return RedirectResponse(url="/trade-plan?error=claim_not_found", status_code=302)

    # Only someone involved in the trade can complete it
    if current_user.id not in (claim.requester_id, claim.owner_id):
        return RedirectResponse(url="/trade-plan?error=not_allowed", status_code=302)

    # 2) Load the card listing (owned by claim.owner_id)
    card = session.get(CardListing, claim.card_listing_id)
    if not card:
        # card listing vanished; just delete the claim
        session.delete(claim)
        session.commit()
        return RedirectResponse(url="/trade-plan?error=card_missing", status_code=302)

    # Sanity: ensure ownership matches the claim
    if card.owner_id != claim.owner_id:
        # Ownership mismatch, something went wrong; don't move the card
        session.delete(claim)
        session.commit()
        return RedirectResponse(url="/trade-plan?error=owner_mismatch", status_code=302)

    from_user_id = claim.owner_id       # giving the card
    to_user_id = claim.requester_id     # receiving the card

    # 3) Move ONE copy from owner to requester
    current_qty = card.quantity or 0
    if current_qty <= 0:
        # weird, nothing left; just delete the claim
        session.delete(claim)
        session.commit()
        return RedirectResponse(url="/trade-plan?error=no_quantity", status_code=302)

    # Decrease quantity for the owner
    if current_qty == 1:
        session.delete(card)
    else:
        card.quantity = current_qty - 1
        session.add(card)

    # 4) Add/increment same card in the receiver's collection
    existing_to = session.exec(
        select(CardListing).where(
            CardListing.owner_id == to_user_id,
            CardListing.card_name == card.card_name,
            CardListing.set_name == card.set_name,
        )
    ).first()

    if existing_to:
        existing_to.quantity = (existing_to.quantity or 0) + 1
        session.add(existing_to)
    else:
        new_card = CardListing(
            owner_id=to_user_id,
            card_name=card.card_name,
            set_name=card.set_name,
            condition=card.condition,
            foil=card.foil,
            quantity=1,
            scryfall_image_url=card.scryfall_image_url,
            oracle_text=card.oracle_text,
            is_for_trade=False,  # new owner hasn't listed it yet
            price_usd=card.price_usd,
            colors=card.colors,
            type_line=card.type_line,
            mana_cost=card.mana_cost,
        )
        session.add(new_card)

    # 5) Update wishlist of the receiver:
    # remove any wishlist entry for this card name (they now have it)
    session.exec(
        delete(WishlistItem).where(
            WishlistItem.owner_id == to_user_id,
            WishlistItem.card_name == card.card_name,
        )
    )

    # 6) Remove the claim itself (trade is done)
    session.delete(claim)

    session.commit()

    return RedirectResponse(
        url="/trade-plan?completed=1", status_code=302
    )


@app.post("/groups/create")
def create_group(
    request: Request,
    name: str = Form(...),
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    clean_name = name.strip()
    if not clean_name:
        return RedirectResponse(url="/groups", status_code=302)

    group = FriendGroup(name=clean_name, owner_id=current_user.id)
    session.add(group)
    session.commit()
    session.refresh(group)

    # owner is automatically a member
    gm = GroupMember(group_id=group.id, user_id=current_user.id)
    session.add(gm)
    session.commit()

    return RedirectResponse(url="/groups", status_code=302)


@app.get("/groups")
def groups_page(
    request: Request,
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    # find groups current_user is a member of
    memberships = session.exec(
        select(GroupMember).where(GroupMember.user_id == current_user.id)
    ).all()
    group_ids = [m.group_id for m in memberships]

    groups: List[FriendGroup] = []
    members_by_group: dict[int, List[User]] = {}
    invites_by_group: dict[int, List[GroupInvite]] = {}

    if group_ids:
        groups = session.exec(
            select(FriendGroup).where(FriendGroup.id.in_(group_ids))
        ).all()

        # members
        pairs = session.exec(
            select(GroupMember, User)
            .join(User, GroupMember.user_id == User.id)
            .where(GroupMember.group_id.in_(group_ids))
        ).all()
        for gm, u in pairs:
            members_by_group.setdefault(gm.group_id, []).append(u)

        # invites
        invites = session.exec(
            select(GroupInvite).where(GroupInvite.group_id.in_(group_ids))
        ).all()
        for inv in invites:
            invites_by_group.setdefault(inv.group_id, []).append(inv)

    return templates.TemplateResponse(
        "groups.html",
        {
            "request": request,
            "current_user": current_user,
            "groups": groups,
            "members_by_group": members_by_group,
            "invites_by_group": invites_by_group,
        },
    )

@app.post("/groups/{group_id}/create-invite")
def create_group_invite(
    request: Request,
    group_id: int,
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    group = session.get(FriendGroup, group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    if group.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only owner can create invite links")

    token = secrets.token_urlsafe(16)

    invite = GroupInvite(
        group_id=group.id,
        token=token,
        created_by=current_user.id,
    )
    session.add(invite)
    session.commit()

    return RedirectResponse(url="/groups", status_code=302)


@app.get("/groups/join/{token}")
def join_group_with_token(
    request: Request,
    token: str,
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    invite = session.exec(
        select(GroupInvite).where(GroupInvite.token == token)
    ).first()
    if not invite:
        raise HTTPException(status_code=404, detail="Invite not found or expired")

    # ensure user is not already a member
    existing = session.exec(
        select(GroupMember).where(
            GroupMember.group_id == invite.group_id,
            GroupMember.user_id == current_user.id,
        )
    ).first()
    if not existing:
        gm = GroupMember(group_id=invite.group_id, user_id=current_user.id)
        session.add(gm)
        session.commit()

    # (Optional) make invites single-use:
    # session.delete(invite)
    # session.commit()

    return RedirectResponse(url="/groups", status_code=302)

@app.post("/groups/{group_id}/add-member")
def add_group_member(
    group_id: int,
    email: str = Form(...),
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    # 1) Load the group
    group = session.get(FriendGroup, group_id)
    if not group:
        # group does not exist
        return RedirectResponse(url="/groups?error=group_not_found", status_code=302)

    # 2) Only the group owner can add members (adjust if you want different rules)
    if group.owner_id != current_user.id:
        return RedirectResponse(url="/groups?error=not_owner", status_code=302)

    # 3) Find the user by email
    email_clean = (email or "").strip().lower()
    user = session.exec(
        select(User).where(User.email == email_clean)
    ).first()

    if not user:
        # No such user account
        return RedirectResponse(
            url=f"/groups?error=user_not_found&group_id={group_id}",
            status_code=302,
        )

    # 4) Check if they are already a member
    existing_membership = session.exec(
        select(GroupMember).where(
            GroupMember.group_id == group_id,
            GroupMember.user_id == user.id,
        )
    ).first()

    if existing_membership:
        return RedirectResponse(
            url=f"/groups?error=already_member&group_id={group_id}",
            status_code=302,
        )

    # 5) Create membership
    membership = GroupMember(
        group_id=group_id,
        user_id=user.id,
    )
    session.add(membership)
    session.commit()

    return RedirectResponse(
        url=f"/groups?added_member=1&group_id={group_id}",
        status_code=302,
    )


@app.post("/groups/{group_id}/remove-member/{user_id}")
def remove_group_member(
    request: Request,
    group_id: int,
    user_id: int,
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    group = session.get(FriendGroup, group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    if group.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only owner can remove members")

    # (optional) prevent removing yourself as owner
    if user_id == current_user.id:
        return RedirectResponse(url="/groups", status_code=302)

    membership = session.exec(
        select(GroupMember).where(
            GroupMember.group_id == group_id,
            GroupMember.user_id == user_id,
        )
    ).first()

    if membership:
        session.delete(membership)
        session.commit()

    return RedirectResponse(url="/groups", status_code=302)


@app.get("/api/card-suggestions")
def card_suggestions(q: str = ""):
    q = q.strip()
    if not q:
        return {"suggestions": []}

    try:
        resp = httpx.get(
            "https://api.scryfall.com/cards/autocomplete",
            params={"q": q},
            timeout=5.0,
        )
        if resp.status_code != 200:
            return {"suggestions": []}
        data = resp.json()
        # Scryfall returns { "data": ["Card Name 1", "Card Name 2", ...] }
        names = data.get("data", [])[:10]
        return {"suggestions": names}
    except Exception:
        return {"suggestions": []}
    
@app.post("/claims/create")
def create_claim(
    request: Request,
    card_id: int = Form(...),
    current_user: User = Depends(login_required),
    session: Session = Depends(get_session),
):
    card = session.get(CardListing, card_id)
    if not card:
        raise HTTPException(status_code=404, detail="Card not found")

    if card.owner_id == current_user.id:
        # you can't claim your own card – just send back where you came from
        return RedirectResponse(url=request.headers.get("referer", "/cards"), status_code=302)

    claim = TradeClaim(
        requester_id=current_user.id,
        owner_id=card.owner_id,
        card_listing_id=card.id,
        quantity=1,
        status="open",
    )
    session.add(claim)
    session.commit()

    return RedirectResponse(url=request.headers.get("referer", "/cards"), status_code=302)



if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
