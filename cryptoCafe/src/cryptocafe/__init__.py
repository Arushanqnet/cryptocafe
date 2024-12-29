import asyncio
import html
import os
import json
import re
import requests
import time

from quart import (
    Quart, request, session, redirect, url_for, render_template, send_from_directory
)
from urllib.parse import urlencode

from sqlalchemy import (
    create_engine, Column, Integer, String, Text, select
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from dotenv import load_dotenv
load_dotenv()

# Initialize OpenAI
from openai import OpenAI
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ---------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------
app = Quart(__name__)
app.secret_key = os.getenv("SECRET_KEY", "super-secret-key")

app.config['SESSION_TYPE'] = 'filesystem'
app.config['ENV'] = 'development'
app.config['DEBUG'] = True

app.static_folder = 'static'
os.makedirs('static/images', exist_ok=True)

# Google CSE
GOOGLE_CSE_API_KEY = os.getenv("GOOGLE_CSE_API_KEY", "")
GOOGLE_CSE_CX = os.getenv("GOOGLE_CSE_CX", "")

# Database for user accounts + their personalized articles
Base = declarative_base()

class User(Base):
    """
    Stores each user's account from Google:
      - google_id -> 'sub' from Google OIDC
      - email
      - name
      - picture
      - topics -> comma-separated topics (onboarding)
      - style  -> string for TTS style
    """
    __tablename__ = "users"

    id        = Column(Integer, primary_key=True)
    google_id = Column(String, unique=True, nullable=False)
    email     = Column(String, nullable=True)
    name      = Column(String, nullable=True)
    picture   = Column(String, nullable=True)
    topics    = Column(String, nullable=True)  # e.g. "BTC,ETH"
    style     = Column(String, nullable=True)  # e.g. "Radio style"


class Article(Base):
    """
    Personalized DB model for user-specific news articles.
    Notice we added 'user_email' so we can filter articles
    by each specific user.
    """
    __tablename__ = "articles"

    id          = Column(Integer, primary_key=True)
    user_email  = Column(String, nullable=True)  # <--- used to link articles to a user
    news_url    = Column(String, nullable=False)
    image_path  = Column(String, nullable=True)
    title       = Column(String, nullable=True)
    text        = Column(Text, nullable=True)
    source_name = Column(String, nullable=True)
    date        = Column(String, nullable=True)
    topics      = Column(String, nullable=True)
    sentiment   = Column(String, nullable=True)
    tickers     = Column(String, nullable=True)
    tts_text    = Column(Text, nullable=True)
    tts_type    = Column(String, nullable=True)

# Connect articles.db
db_file = "sqlite:///articles.db"
engine = create_engine(db_file, echo=False)
SessionLocal = sessionmaker(bind=engine)
Base.metadata.create_all(engine)

# ---------------------------------------------------------------------
# New DB: journals.db
# ---------------------------------------------------------------------
JournalsBase = declarative_base()

class JournalArticle(JournalsBase):
    """
    Stores trending news fetched every 5 minutes.
    (Used as the 'master' list of news.)
    """
    __tablename__ = "journal_articles"

    id          = Column(Integer, primary_key=True)
    news_url    = Column(String, unique=True, nullable=False)
    image_path  = Column(String, nullable=True)
    title       = Column(String, nullable=True)
    text        = Column(Text, nullable=True)
    source_name = Column(String, nullable=True)
    date        = Column(String, nullable=True)
    topics      = Column(String, nullable=True)
    sentiment   = Column(String, nullable=True)
    tickers     = Column(String, nullable=True)
    tts_text    = Column(Text, nullable=True)
    tts_type    = Column(String, nullable=True)
    created_at  = Column(Integer, default=lambda: int(time.time()))

db_journals_file = "sqlite:///journals.db"
journals_engine = create_engine(db_journals_file, echo=False)
SessionLocalJournals = sessionmaker(bind=journals_engine)
JournalsBase.metadata.create_all(journals_engine)


# Predefined trending headings
TRENDING_TOPICS = [
    "Bitcoin (BTC)",         # The original cryptocurrency
    "Ethereum (ETH)",        # Smart contracts & DeFi hub
    "DeFi",                  # Decentralized finance solutions
    "NFTs",                  # Digital collectibles & art
    "Trading",               # Short/long-term strategies
    "Market Insights"        # Daily news & analysis
]

# Google OAuth Endpoints
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"

GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")

# ---------------------------------------------------------------------
# BACKGROUND TASK
# ---------------------------------------------------------------------
background_task_running = False

async def fetch_trending_news_loop():
    """
    Infinite loop that runs every 5 minutes (300s).
    Fetches trending news for each topic in TRENDING_TOPICS,
    upserts them into journals.db, and sleeps 5 mins.
    """
    while True:
        try:
            await fetch_and_update_journals_db()
        except Exception as e:
            print("ERROR in fetch_trending_news_loop:", e)
        await asyncio.sleep(300)  # 5 minutes

async def fetch_and_update_journals_db():
    """
    For each topic in TRENDING_TOPICS, run google search and upsert into JournalArticle.
    """
    j_sess = SessionLocalJournals()
    for topic in TRENDING_TOPICS:
        results = google_cse_search(topic, limit=3)
        for r in results:
            # upsert
            upsert_journal_article(j_sess, r, topics=topic, tts_type="Plain text")
    j_sess.commit()
    j_sess.close()


# ---------------------------------------------------------------------
# OAUTH 2.0 (Manual)
# ---------------------------------------------------------------------
@app.route("/login")
async def login():
    """
    Build Google OAuth URL, redirect user.
    """
    redirect_uri = url_for("auth_callback", _external=True)
    scope = "openid email profile"

    params = {
        "client_id":     GOOGLE_CLIENT_ID,
        "redirect_uri":  redirect_uri,
        "response_type": "code",
        "scope":         scope,
        "access_type":   "offline",
        "prompt":        "consent",
    }
    auth_url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
    return redirect(auth_url)


@app.route("/auth/callback")
async def auth_callback():
    """
    Google calls this with ?code=.
    Exchange code for tokens, get user info, store in DB if new.
    Then start the background fetch if not started already.
    """
    global background_task_running

    code = request.args.get("code")
    if not code:
        return "No code provided in callback.", 400

    redirect_uri = url_for("auth_callback", _external=True)
    data = {
        "code": code,
        "client_id":     GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri":  redirect_uri,
        "grant_type":    "authorization_code",
    }
    try:
        resp = requests.post(GOOGLE_TOKEN_URL, data=data, timeout=5)
        resp.raise_for_status()
        token_data = resp.json()
        access_token = token_data.get("access_token")
        if not access_token:
            return "No access token returned by Google.", 400

        # userinfo
        headers = {"Authorization": f"Bearer {access_token}"}
        userinfo_resp = requests.get(GOOGLE_USERINFO_URL, headers=headers, timeout=5)
        userinfo_resp.raise_for_status()
        user_info = userinfo_resp.json()

        # e.g. user_info has 'sub', 'email', 'name', 'picture'
        google_id = user_info.get("sub")
        email     = user_info.get("email")
        name      = user_info.get("name")
        picture   = user_info.get("picture")

        db_sess = SessionLocal()
        existing_user = db_sess.execute(
            select(User).where(User.google_id == google_id)
        ).scalar_one_or_none()

        if existing_user:
            # update if needed
            existing_user.email   = email
            existing_user.name    = name
            existing_user.picture = picture
            db_sess.commit()
            session["user_id"] = existing_user.id

            # if user has no topics or style => onboarding
            if not existing_user.topics or not existing_user.style:
                db_sess.close()
                # Start background task if not started
                if not background_task_running:
                    background_task_running = True
                    asyncio.create_task(fetch_trending_news_loop())
                return redirect(url_for("onboarding"))
            else:
                db_sess.close()
                # Start background task if not started
                if not background_task_running:
                    background_task_running = True
                    asyncio.create_task(fetch_trending_news_loop())
                return redirect(url_for("index"))
        else:
            # create new user => need onboarding
            new_user = User(
                google_id=google_id,
                email=email,
                name=name,
                picture=picture,
                topics="",  # not set yet
                style="",   # not set yet
            )
            db_sess.add(new_user)
            db_sess.commit()
            session["user_id"] = new_user.id
            db_sess.close()

            # Start background task if not started
            if not background_task_running:
                background_task_running = True
                asyncio.create_task(fetch_trending_news_loop())
            return redirect(url_for("onboarding"))

    except Exception as e:
        return f"Error exchanging code for token: {e}", 500


@app.route("/logout")
async def logout():
    session.pop("user_id", None)
    session.pop("search_results", None)
    return redirect(url_for("index"))


# ---------------------------------------------------------------------
# ONBOARDING & SETTINGS
# ---------------------------------------------------------------------
@app.route("/onboarding")
async def onboarding():
    """
    Show a page that lets user pick topics + style (TTS).
    If user not logged in, redirect to /.
    """
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("index"))
    return await render_template("onboarding.html")


@app.route("/save_onboarding", methods=["POST"])
async def save_onboarding():
    """
    1) Save the user's chosen topics + style.
    2) We'll no longer fetch articles from Google here for each topic.
       Instead, we rely on journals.db for trending. 
       We'll do an immediate check for new articles in journals.db 
       and copy relevant ones to articles.db in user’s style.
    3) Redirect to the homepage.
    """
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("index"))

    form_data = await request.form
    topics_list = form_data.getlist("topics")  # if multiple checkboxes
    style  = form_data.get("style", "").strip()

    # turn topics list -> comma string
    topics_str = ",".join(topics_list)

    db_sess = SessionLocal()
    user = db_sess.execute(
        select(User).where(User.id == user_id)
    ).scalar_one_or_none()
    if user:
        user.topics = topics_str
        user.style  = style
        db_sess.commit()

        # Pull from journals.db => copy relevant into articles.db
        copy_journals_to_user_articles(user)

        db_sess.close()

    return redirect(url_for("index"))


@app.route("/settings")
async def settings():
    """
    Show a form to update topics + style (like onboarding, but user can do it anytime).
    """
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("index"))

    db_sess = SessionLocal()
    user = db_sess.execute(
        select(User).where(User.id == user_id)
    ).scalar_one_or_none()
    db_sess.close()

    return await render_template("settings.html", user=user)


@app.route("/save_settings", methods=["POST"])
async def save_settings():
    """
    Similar to save_onboarding, but for the settings page.
    We'll also do a fresh copy from journals.db => user's articles.
    """
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("index"))

    form_data = await request.form
    topics = form_data.getlist("topics")
    style  = form_data.get("style", "").strip()
    topics_str = ",".join(topics)

    db_sess = SessionLocal()
    user = db_sess.execute(
        select(User).where(User.id == user_id)
    ).scalar_one_or_none()
    if user:
        user.topics = topics_str
        user.style  = style
        db_sess.commit()

        # Also copy new items from journals.db => user
        copy_journals_to_user_articles(user)

    db_sess.close()
    return redirect(url_for("index"))


# ---------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------
def google_cse_search(query: str, limit=10):
    """
    Calls Google Custom Search JSON API for up to 'limit' results.
    Returns a list of dicts in a format that can be inserted as an Article-like record.
    """
    if not GOOGLE_CSE_API_KEY or not GOOGLE_CSE_CX:
        print("Warning: GOOGLE_CSE_API_KEY or GOOGLE_CSE_CX not set.")
        return []

    params = {
        "key": GOOGLE_CSE_API_KEY,
        "cx":  GOOGLE_CSE_CX,
        "q":   query,
        "num": limit,
    }
    url = "https://www.googleapis.com/customsearch/v1?" + urlencode(params)

    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()
        items = data.get("items", [])
        results = []
        for item in items:
            link = item.get("link", "")
            title = item.get("title", "")
            snippet = item.get("snippet", "")

            # Attempt to extract an image from 'pagemap'
            image_url = ""
            pagemap = item.get("pagemap", {})
            cse_image = pagemap.get("cse_image", [])
            if cse_image and isinstance(cse_image, list):
                image_url = cse_image[0].get("src", "")

            results.append({
                "news_url": link.strip(),
                "title":    title.strip(),
                "text":     snippet.strip(),
                "source_name": "Google Search",
                "date": "",
                "image_url": image_url,
                "topics": "",
                "sentiment": "",
                "tickers": ""
            })
        return results
    except Exception as e:
        print("Google CSE error:", e)
        return []


def download_image(image_url: str, filename: str) -> str:
    local_path = f"static/images/{filename}"
    if not os.path.exists(local_path):
        try:
            r = requests.get(image_url, stream=True, timeout=5)
            r.raise_for_status()
            with open(local_path, "wb") as f:
                for chunk in r.iter_content(8192):
                    f.write(chunk)
            print("Downloaded image =>", local_path)
        except Exception as e:
            print("Image download error:", e)
            # fallback to default
            local_path = "static/images/default.jpg"
    return local_path


def upsert_journal_article(session, data: dict, topics: str, tts_type: str = "Plain text"):
    """
    Insert or update a JournalArticle record in DB (journals.db).
    Also downloads image. We store text as is (plain text).
    We won't generate TTS here, to keep it simpler.
    """
    news_url = data.get("news_url", "").strip()
    if not news_url:
        return None

    existing = session.execute(
        select(JournalArticle).where(JournalArticle.news_url == news_url)
    ).scalar_one_or_none()

    if existing:
        article = existing
    else:
        article = JournalArticle(news_url=news_url)
        session.add(article)

    article.title       = data.get("title", "")
    article.text        = data.get("text", "")
    article.source_name = data.get("source_name", "")
    article.date        = data.get("date", "")
    article.topics      = topics
    article.sentiment   = data.get("sentiment", "")
    article.tickers     = data.get("tickers", "")
    article.tts_type    = tts_type

    image_url = data.get("image_url", "https://via.placeholder.com/360x640.png?text=No+Image")
    if image_url:
        filename = f"{abs(hash(image_url))}.jpg"
        local_path = download_image(image_url, filename)
        article.image_path = "/" + local_path
    else:
        article.image_path = "/static/images/default.jpg"

    return article


def copy_journals_to_user_articles(user_obj):
    """
    Fetch all JournalArticle from journals.db.
    Compare topics with user_obj.topics.
    For new matches, convert them to user’s style, store in articles.db with user_email.
    """
    j_sess = SessionLocalJournals()
    db_sess = SessionLocal()

    # Get all from journals.db
    all_journals = j_sess.execute(select(JournalArticle)).scalars().all()
    user_topics = set((user_obj.topics or "").split(","))

    for jart in all_journals:
        # If any overlap in topics => we convert + store
        journal_topics_set = set((jart.topics or "").split(","))
        if user_topics & journal_topics_set:  # intersection
            # Check if already in articles.db for this user
            existing = db_sess.execute(
                select(Article).where(
                    Article.user_email == user_obj.email,
                    Article.news_url == jart.news_url
                )
            ).scalar_one_or_none()
            if not existing:
                # Create new article from jart
                a = Article(
                    user_email  = user_obj.email,
                    news_url    = jart.news_url,
                    image_path  = jart.image_path,
                    title       = jart.title,
                    text        = jart.text,
                    source_name = jart.source_name,
                    date        = jart.date,
                    topics      = jart.topics,
                    sentiment   = jart.sentiment,
                    tickers     = jart.tickers,
                    tts_type    = user_obj.style
                )
                # Generate TTS in user style
                generate_tts_for_db_article(a)
                db_sess.add(a)

    db_sess.commit()
    db_sess.close()
    j_sess.close()


def sanitize(entry: str) -> str:
    sanitized_text = html.escape(entry)
    # Escape backslashes and double quotes
    sanitized_text = sanitized_text.replace('\\', '\\\\').replace('"', '\\"')

    # Remove quotes at the start/end if they exist
    if sanitized_text.startswith('"') and sanitized_text.endswith('"'):
        sanitized_text = sanitized_text[1:-1]

    return sanitized_text


def generate_tts_for_db_article(article_obj: Article):
    """
    Generates TTS text for a user-specific Article object, storing in article_obj.tts_text.
    """
    if article_obj.tts_text:
        return article_obj.tts_text

    raw_text = (article_obj.text or "").strip()
    if not raw_text:
        article_obj.tts_text = "No content to speak."
        return article_obj.tts_text

    style = article_obj.tts_type or "default style"
    prompt = f"""
    Please create a YouTube short reels script (~30-45 seconds) voiceover summarizing
    the following article in a {style}.
    Keep it concise but natural. Include ONLY the voiceover script in your response.

    Article text:
    \"\"\"
    {raw_text}
    \"\"\"
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a News narrator outputting news voiceover scripts as plain text"},
                {"role": "user", "content": prompt}
            ],
        )
        script_output = response.choices[0].message.content.strip()
        article_obj.tts_text = sanitize(script_output)
        return article_obj.tts_text
    except Exception as e:
        print("OpenAI TTS error:", e)
        article_obj.tts_text = "Error generating TTS."

    return article_obj.tts_text


# ---------------------------------------------------------------------
# EPHEMERAL (NON-DB) SEARCH UTILS
# ---------------------------------------------------------------------
def generate_tts_for_ephemeral(article_dict: dict):
    """
    Generates TTS text for a single ephemeral search result (a dict).
    We'll store the result in article_dict["tts_text"].
    """
    if "tts_text" in article_dict and article_dict["tts_text"]:
        return article_dict["tts_text"]

    raw_text = (article_dict.get("text") or "").strip()
    if not raw_text:
        article_dict["tts_text"] = "No content to speak."
        return article_dict["tts_text"]

    style = article_dict.get("tts_type") or "default style"
    prompt = f"""
    Please create a YouTube short reels script (~30-45 seconds) voiceover summarizing
    the following article in a {style}.
    Keep it concise but natural. Include ONLY the voiceover script in your response.

    Article text:
    \"\"\"
    {raw_text}
    \"\"\"
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a News narrator outputting news voiceover scripts as plain text"},
                {"role": "user", "content": prompt}
            ],
        )
        script_output = response.choices[0].message.content.strip()
        article_dict["tts_text"] = sanitize(script_output)
        return article_dict["tts_text"]
    except Exception as e:
        print("OpenAI TTS error:", e)
        article_dict["tts_text"] = "Error generating TTS."
        return article_dict["tts_text"]


# ---------------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------------
@app.route("/")
async def index():
    """
    - If user not logged in => show sign in button (empty article lists).
    - If logged in and missing topics/style => onboard.
    - Otherwise => show custom search results + user-personalized DB articles from articles.db.
      NOTE: We replaced the old "DB fetch by topic" with fetch of user_email-based articles,
            sorted newest-first (id desc or any time-based approach).
    """
    user_id = session.get("user_id")
    if not user_id:
        return await render_template("index.html", user=None, ephemeral_data=[], db_data=[])

    db_sess = SessionLocal()
    db_user = db_sess.execute(
        select(User).where(User.id == user_id)
    ).scalar_one_or_none()

    if not db_user:
        db_sess.close()
        session.pop("user_id", None)
        return await render_template("index.html", user=None, ephemeral_data=[], db_data=[])

    # If user missing topics or style => force onboarding
    if not db_user.topics or not db_user.style:
        db_sess.close()
        return redirect(url_for("onboarding"))

    # If user is returning, check for new journalse again
    copy_journals_to_user_articles(db_user)

    # 1) Pull ephemeral search results from session
    ephemeral_data = session.get("search_results", [])

    # 2) Fetch user's personalized articles from articles.db
    user_articles = db_sess.execute(
        select(Article)
        .where(Article.user_email == db_user.email)
        .order_by(Article.id.desc())  # new news first
    ).scalars().all()
    db_sess.close()

    # 3) Convert to dict
    db_data = []
    for a in user_articles:
        db_data.append({
            "news_url":    a.news_url,
            "image_url":   a.image_path,
            "title":       a.title,
            "text":        a.text,
            "source_name": a.source_name,
            "date":        a.date,
            "topics":      (a.topics or "").split(","),
            "sentiment":   a.sentiment,
            "tickers":     (a.tickers or "").split(","),
            "tts_text":    a.tts_text,
            "tts_type":    a.tts_type,
        })

    return await render_template(
        "index.html",
        user=db_user,
        ephemeral_data=ephemeral_data, 
        db_data=db_data
    )


@app.route("/search", methods=["POST"])
async def do_search():
    """
    - Perform Google search (CSE).
    - Generate ephemeral TTS for each result.
    - Store them in session["search_results"].
    - Do NOT store in DB. Keep custom search as is.
    """
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("index"))

    form_data = await request.form
    query = form_data.get("query", "").strip()
    tts_type = form_data.get("tts_type", "").strip() or ""

    if not query:
        return redirect(url_for("index"))

    # Clear old ephemeral data
    session["search_results"] = []

    results = google_cse_search(query, limit=4)
    ephemeral_articles = []
    for r in results:
        r["tts_type"] = tts_type
        # generate ephemeral TTS
        generate_tts_for_ephemeral(r)

        # download image to local
        image_url = r.get("image_url") or ""
        if image_url:
            filename = f"{abs(hash(image_url))}.jpg"
            local_path = download_image(image_url, filename)
            r["image_url"] = "/" + local_path
        else:
            r["image_url"] = "/static/images/default.jpg"

        ephemeral_articles.append(r)

    # Save ephemeral articles in session
    session["search_results"] = ephemeral_articles
    return redirect(url_for("index"))


@app.route("/reels")
async def reels():
    """
    Shows a reels-style page with combined ephemeral + user-personalized DB articles
    in the exact same order as index.html:
      ephemeral_data first, then db_data
    """
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("index"))

    db_sess = SessionLocal()
    db_user = db_sess.execute(
        select(User).where(User.id == user_id)
    ).scalar_one_or_none()

    if not db_user:
        db_sess.close()
        return redirect(url_for("index"))

    # ephemeral first
    ephemeral_data = session.get("search_results", [])

    # then fetch user's personalized articles
    user_articles = db_sess.execute(
        select(Article)
        .where(Article.user_email == db_user.email)
        .order_by(Article.id.desc())
    ).scalars().all()
    db_sess.close()

    db_data = []
    for a in user_articles:
        db_data.append({
            "news_url":    a.news_url,
            "image_url":   a.image_path,
            "title":       a.title,
            "text":        a.text,
            "source_name": a.source_name,
            "date":        a.date,
            "topics":      (a.topics or "").split(","),
            "sentiment":   a.sentiment,
            "tickers":     (a.tickers or "").split(","),
            "tts_text":    a.tts_text,
            "tts_type":    a.tts_type,
        })

    combined_data = ephemeral_data + db_data

    # get reel index
    article_index = request.args.get("index", 0, type=int)
    return await render_template(
        "reels.html",
        data=combined_data,
        start_index=article_index
    )


@app.route('/static/images/<path:filename>')
async def serve_image(filename):
    return await send_from_directory('static/images', filename)


def run():
    app.run(debug=True)


if __name__ == "__main__":
    asyncio.run(app.run(debug=True))
