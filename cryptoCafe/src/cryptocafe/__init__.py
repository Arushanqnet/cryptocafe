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

# ---------------------------------------------------------------------
# Database #1: articles.db (user-specific storage)
# ---------------------------------------------------------------------
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
# Database #2: journals.db (master trending articles) + public_news
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


class PublicNews(JournalsBase):
    """
    Stores publicly-available news in a 'Journalistic style',
    shown to non-logged-in users.
    """
    __tablename__ = "public_news"

    id          = Column(Integer, primary_key=True)
    news_url    = Column(String, unique=True, nullable=False)
    image_path  = Column(String, nullable=True)
    title       = Column(String, nullable=True)
    text        = Column(Text, nullable=True)  # holds text in a journalistic style
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
    upserts them into journals.db, and also updates public_news.
    Then sleeps 5 mins.
    """
    while True:
        try:
            await fetch_and_update_journals_db()
        except Exception as e:
            print("ERROR in fetch_trending_news_loop:", e)
        await asyncio.sleep(3600)  # 5 minutes

async def fetch_and_update_journals_db():
    """
    For each topic in TRENDING_TOPICS, run google search and upsert into JournalArticle.
    Then also update the public_news table from the new/updated JournalArticle data,
    rewriting the text in 'Journalistic style' via ChatGPT and sanitizing.
    """
    j_sess = SessionLocalJournals()
    for topic in TRENDING_TOPICS:
        results = google_cse_search(topic, limit=3)
        for r in results:
            # upsert into journal_articles
            upsert_journal_article(j_sess, r, topics=topic, tts_type="Plain text")

    j_sess.commit()

    # After updating journal_articles, update public_news
    update_public_news()

    j_sess.close()

def update_public_news():
    """
    Pull all journal_articles, upsert them into public_news
    in a 'Journalistic style' and generate TTS for it.
    """
    j_sess = SessionLocalJournals()
    all_jarts = j_sess.execute(select(JournalArticle)).scalars().all()

    for jart in all_jarts:
        # Check if already exists in public_news
        existing_public = j_sess.execute(
            select(PublicNews).where(PublicNews.news_url == jart.news_url)
        ).scalar_one_or_none()

        text_styled_sanitized = sanitize(jart.text)

        if existing_public is None:
            # Create new PublicNews
            pnews = PublicNews(
                news_url    = jart.news_url,
                image_path  = jart.image_path,
                title       = jart.title,
                source_name = jart.source_name,
                date        = jart.date,
                topics      = jart.topics,
                sentiment   = jart.sentiment,
                tickers     = jart.tickers,
                tts_type    = "Journalistic style",
                text        = text_styled_sanitized
            )
            # Generate TTS for the public news
            public_tts = generate_tts_for_public_news(jart.text)
            pnews.tts_text = sanitize(public_tts)

            j_sess.add(pnews)
        else:
            # Update existing record with latest info
            existing_public.title       = jart.title
            existing_public.image_path  = jart.image_path
            existing_public.source_name = jart.source_name
            existing_public.date        = jart.date
            existing_public.topics      = jart.topics
            existing_public.sentiment   = jart.sentiment
            existing_public.tickers     = jart.tickers
            existing_public.tts_type    = "Journalistic style"
            existing_public.text        = text_styled_sanitized

            # Re-generate TTS for any updated text
            public_tts = generate_tts_for_public_news(jart.text)
            existing_public.tts_text = sanitize(public_tts)

    j_sess.commit()
    j_sess.close()


def generate_journalistic_text(article_text: str) -> str:
    """
    Uses ChatGPT to rewrite `article_text` in a Journalistic style.
    """
    if not article_text.strip():
        return "No content available."

    prompt = f"""
    Please create a youtube short reels script (~30-45 seconds) voiceover summarizing the following article in a Journalistic style.
    Keep it concise but natural. Include ONLY the voiceover script in your response.

    \"\"\"{article_text}\"\"\"
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a News narrator outputting news voiceover scripts as plain text."},
                {"role": "user", "content": prompt},
            ],
        )
        result = response.choices[0].message.content.strip()
        return result
    except Exception as e:
        print("OpenAI Journalistic style error:", e)
        return "Unable to rewrite in Journalistic style."


def generate_tts_for_public_news(journalistic_text: str) -> str:
    """
    Generate a ~30-45 second TTS script (like a reels voiceover) 
    from the already-rewritten journalistic text.
    """
    if not journalistic_text.strip():
        return "No content to speak."

    prompt = f"""
    Please create a short news voiceover (~30-45 seconds) from the text below.
    Keep it concise and engaging. Provide ONLY the voiceover script in your response:

    \"\"\"{journalistic_text}\"\"\"
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a News narrator outputting news voiceover scripts as plain text."},
                {"role": "user", "content": prompt},
            ],
        )
        result = response.choices[0].message.content.strip()
        return result
    except Exception as e:
        print("OpenAI PublicNews TTS error:", e)
        return "Error generating TTS."
    
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
    If user not logged in, redirect to / (home).
    """
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("index"))
    return await render_template("onboarding.html")


@app.route("/save_onboarding", methods=["POST"])
async def save_onboarding():
    """
    1) Save the user's chosen topics + style.
    2) We'll do an immediate check for new articles in journals.db
       and copy relevant ones to articles.db in the user’s style.
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
    If user not logged in, we won't allow access.
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


UNWANTED_ENTITIES_REGEX = re.compile(r'&#x[0-9A-Fa-f]+;')

def sanitize(entry: str) -> str:
    """
    1) Decode HTML entities (e.g. &amp; -> &, &#x27; -> ', etc.).
    2) Remove leftover hex entities (e.g., &#x27;) using one regex pass.
    3) Remove ALL non-ASCII characters (unicode) outside range 0-127.
    4) HTML-escape the result to prevent injection.
    5) Escape backslashes and quotes.
    6) Strip leading/trailing quotes if needed.
    """
    # Step 1: Decode HTML entities
    decoded_text = html.unescape(entry)

    # Step 2: Remove leftover hex entities
    cleaned_text = UNWANTED_ENTITIES_REGEX.sub('', decoded_text)

    # Step 3: Remove all non-ASCII characters (anything outside 0x00-0x7F)
    #         This also removes emojis and other extended Unicode.
    cleaned_text = re.sub(r'[^\x00-\x7F]+', '', cleaned_text)

    # Step 4: HTML-escape (to prevent HTML/script injection)
    escaped_text = html.escape(cleaned_text)

    # Step 5: Escape backslashes and double quotes for safety
    escaped_text = escaped_text.replace('\\', '\\\\').replace('"', '\\"')

    # Step 6: Strip leading/trailing quotes if your use-case requires it
    if escaped_text.startswith('"') and escaped_text.endswith('"'):
        escaped_text = escaped_text[1:-1]

    return escaped_text

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
    1) If user not logged in, show 'public_news' from journals.db (already styled).
       - The search and settings won't work (disabled in HTML).
       - Reels should still work (but will show public_news reels).
    2) If user is logged in:
       - If missing topics/style => onboard
       - Else show ephemeral_data + user-personalized db_data
    """
    user_id = session.get("user_id")
    if not user_id:
        # NON-LOGGED-IN: show public_news
        j_sess = SessionLocalJournals()
        public_articles = j_sess.execute(
            select(PublicNews).order_by(PublicNews.id.desc())
        ).scalars().all()
        j_sess.close()

        # Transform them into a simple list of dict
        public_data = []
        for a in public_articles:
            public_data.append({
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

        return await render_template("index.html",
                                     user=None,
                                     ephemeral_data=[],
                                     db_data=[],      # no user DB data
                                     public_data=public_data)  # pass public news
    else:
        # LOGGED-IN
        db_sess = SessionLocal()
        db_user = db_sess.execute(
            select(User).where(User.id == user_id)
        ).scalar_one_or_none()

        if not db_user:
            # user not found => remove session
            db_sess.close()
            session.pop("user_id", None)
            return redirect(url_for("index"))

        # If user missing topics or style => force onboarding
        if not db_user.topics or not db_user.style:
            db_sess.close()
            return redirect(url_for("onboarding"))

        # If user is returning, copy new journal articles => user articles
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
            db_data=db_data,
            public_data=[]  # no need for public articles if logged in
        )


@app.route("/search", methods=["POST"])
async def do_search():
    """
    - If user is NOT logged in => ignore/redirect (disabled).
    - If user is logged in => do normal search flow.
      1) Store original text in 'normal_text'.
      2) Sanitize 'text' for TTS generation.
    """
    user_id = session.get("user_id")
    if not user_id:
        # Non-logged-in => cannot do search
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
        # 1) Store original text
        r["normal_text"] = r["text"]

        # 2) Sanitize text before TTS
        r["text"] = sanitize(r["text"])
        r["tts_type"] = tts_type

        # 3) Generate ephemeral TTS (which will use the sanitized text)
        generate_tts_for_ephemeral(r)

        # 4) Download image to local
        image_url = r.get("image_url") or ""
        if image_url:
            filename = f"{abs(hash(image_url))}.jpg"
            local_path = download_image(image_url, filename)
            r["image_url"] = "/" + local_path
        else:
            r["image_url"] = "/static/images/default.jpg"

        ephemeral_articles.append(r)

    # Finally, store the entire ephemeral set in the session
    session["search_results"] = ephemeral_articles

    return redirect(url_for("index"))

@app.route("/reels")
async def reels():
    """
    Shows a reels-style page:
      - If user is logged in => ephemeral_data first, then user's DB articles.
      - If user is NOT logged in => show public_news articles.
    """
    user_id = session.get("user_id")
    if not user_id:
        # Non-logged-in => show public_news in reels
        j_sess = SessionLocalJournals()
        public_articles = j_sess.execute(
            select(PublicNews).order_by(PublicNews.id.desc())
        ).scalars().all()
        j_sess.close()

        public_data = []
        for a in public_articles:
            public_data.append({
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
        # non-logged-in => just reels for public_data
        article_index = request.args.get("index", 0, type=int)
        return await render_template(
            "reels.html",
            data=public_data,
            start_index=article_index
        )
    else:
        # Logged in => ephemeral_data + user-personalized articles
        db_sess = SessionLocal()
        db_user = db_sess.execute(
            select(User).where(User.id == user_id)
        ).scalar_one_or_none()

        if not db_user:
            db_sess.close()
            return redirect(url_for("index"))

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
