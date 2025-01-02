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
# Database #1: articles.db (for user accounts only now)
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
      - style  -> the TTS style preference
    """
    __tablename__ = "users"

    id        = Column(Integer, primary_key=True)
    google_id = Column(String, unique=True, nullable=False)
    email     = Column(String, nullable=True)
    name      = Column(String, nullable=True)
    picture   = Column(String, nullable=True)
    topics    = Column(String, nullable=True)  # e.g. "BTC,ETH"
    style     = Column(String, nullable=True)  # e.g. "Journalistic style"

# Connect articles.db
db_file = "sqlite:///users.db"
engine = create_engine(db_file, echo=False)
SessionLocal = sessionmaker(bind=engine)
Base.metadata.create_all(engine)


# ---------------------------------------------------------------------
# Database #2: journals.db (master trending articles) + public_news + search_article
# ---------------------------------------------------------------------
JournalsBase = declarative_base()

class JournalArticle(JournalsBase):
    """
    Stores trending news fetched periodically.
    Now with five TTS columns, one for each style:
      - tts_text_persuasive
      - tts_text_academic
      - tts_text_business
      - tts_text_journalistic
      - tts_text_argumentative
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
    created_at  = Column(Integer, default=lambda: int(time.time()))

    # New columns for each TTS style
    tts_text_persuasive   = Column(Text, nullable=True)
    tts_text_academic     = Column(Text, nullable=True)
    tts_text_business     = Column(Text, nullable=True)
    tts_text_journalistic = Column(Text, nullable=True)
    tts_text_argumentative= Column(Text, nullable=True)


class SearchArticle(JournalsBase):
    """
    Stores search results so we can reuse or quickly re-generate TTS
    (unchanged from original).
    """
    __tablename__ = "search_article"

    id          = Column(Integer, primary_key=True)
    query       = Column(String, nullable=False)
    user_id     = Column(Integer, nullable=True)         # The user who first searched
    news_url    = Column(String, nullable=False)         # Link to the article
    image_path  = Column(String, nullable=True)          
    title       = Column(String, nullable=True)
    text        = Column(Text, nullable=True)            
    source_name = Column(String, nullable=True)
    date        = Column(String, nullable=True)
    tts_text    = Column(Text, nullable=True)
    tts_type    = Column(String, nullable=True)
    created_at  = Column(Integer, default=lambda: int(time.time()))


db_journals_file = "sqlite:///journals.db"
journals_engine = create_engine(db_journals_file, echo=False)
SessionLocalJournals = sessionmaker(bind=journals_engine)
JournalsBase.metadata.create_all(journals_engine)


# Predefined trending headings
TRENDING_TOPICS = [
    "Bitcoin",
    "Ethereum",
    "DeFi",
    "NFTs",
    "Trading",
    "Market Insights"
]

# Google OAuth Endpoints
GOOGLE_AUTH_URL      = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL     = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL  = "https://openidconnect.googleapis.com/v1/userinfo"
GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")

# ---------------------------------------------------------------------
# BACKGROUND TASK
# ---------------------------------------------------------------------
background_task_running = False

async def fetch_trending_news_loop():
    """
    Infinite loop that runs every 60 minutes (3600s).
    Fetches trending news for each topic in TRENDING_TOPICS,
    upserts them into journals.db, generating all TTS variants.
    Then sleeps 1 hour.
    """
    while True:
        try:
            await fetch_and_update_journals_db()
        except Exception as e:
            print("ERROR in fetch_trending_news_loop:", e)
        await asyncio.sleep(3600)  # 1 hour

async def fetch_and_update_journals_db():
    """
    For each topic in TRENDING_TOPICS, run google search and upsert into JournalArticle.
    We'll generate all TTS variants for each new or updated article.
    """
    j_sess = SessionLocalJournals()
    for topic in TRENDING_TOPICS:
        results = google_cse_search(topic, limit=3)
        for r in results:
            # Upsert: store all TTS styles
            upsert_journal_article(j_sess, r, topics=topic)
    j_sess.commit()
    j_sess.close()


# ---------------------------------------------------------------------
# OAUTH 2.0
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

        google_id = user_info.get("sub")
        email     = user_info.get("email")
        name      = user_info.get("name")
        picture   = user_info.get("picture")

        db_sess = SessionLocal()
        existing_user = db_sess.execute(
            select(User).where(User.google_id == google_id)
        ).scalar_one_or_none()

        if existing_user:
            existing_user.email   = email
            existing_user.name    = name
            existing_user.picture = picture
            db_sess.commit()
            session["user_id"] = existing_user.id

            if not existing_user.topics or not existing_user.style:
                db_sess.close()
                if not background_task_running:
                    background_task_running = True
                    asyncio.create_task(fetch_trending_news_loop())
                return redirect(url_for("onboarding"))
            else:
                db_sess.close()
                if not background_task_running:
                    background_task_running = True
                    asyncio.create_task(fetch_trending_news_loop())
                return redirect(url_for("index"))
        else:
            new_user = User(
                google_id=google_id,
                email=email,
                name=name,
                picture=picture,
                topics="",
                style=""
            )
            db_sess.add(new_user)
            db_sess.commit()
            session["user_id"] = new_user.id
            db_sess.close()

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
    """
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("index"))
    return await render_template("onboarding.html")


@app.route("/save_onboarding", methods=["POST"])
async def save_onboarding():
    """
    Save user's chosen topics + style, then redirect to homepage.
    """
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("index"))

    form_data = await request.form
    topics_list = form_data.getlist("topics")
    style  = form_data.get("style", "").strip()
    topics_str = ",".join(topics_list)

    db_sess = SessionLocal()
    user = db_sess.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if user:
        user.topics = topics_str
        user.style  = style
        db_sess.commit()
    db_sess.close()

    return redirect(url_for("index"))


@app.route("/settings")
async def settings():
    """
    Let user update topics + style at any time.
    """
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("index"))

    db_sess = SessionLocal()
    user = db_sess.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    db_sess.close()

    return await render_template("settings.html", user=user)


@app.route("/save_settings", methods=["POST"])
async def save_settings():
    """
    Save updated topics + style for the user.
    """
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("index"))

    form_data = await request.form
    topics_list = form_data.getlist("topics")
    style  = form_data.get("style", "").strip()
    topics_str = ",".join(topics_list)

    db_sess = SessionLocal()
    user = db_sess.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if user:
        user.topics = topics_str
        user.style  = style
        db_sess.commit()
    db_sess.close()

    return redirect(url_for("index"))


# ---------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------
def google_cse_search(query: str, limit=10):
    """
    Calls Google Custom Search JSON API for up to 'limit' results.
    Returns a list of dicts in a format that can be inserted into JournalArticle.
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

            # Attempt to extract an image
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
            local_path = "static/images/default.jpg"
    return local_path


PUNCT_ENTITY_REGEX = re.compile(r'&#x(2E|002E|2C|002C);', re.IGNORECASE)
UNWANTED_ENTITIES_REGEX = re.compile(r'&#x[0-9A-Fa-f]+;')
NON_ASCII_REGEX = re.compile(r'[^\x00-\x7F]+')
# Keep letters, digits, whitespace, and specifically allow '.' and ','
NON_WORDS_REGEX = re.compile(r'[^a-zA-Z0-9\s\.,]+')
MULTI_SPACE_REGEX = re.compile(r'\s+')

def sanitize(entry: str) -> str:
    """
    1) Decode HTML entities
    2) Replace &#x2E; (fullstop) and &#x2C; (comma) with '.' and ',' respectively
    3) Remove leftover hex entities
    4) Remove all non-ASCII
    5) Keep only letters, digits, whitespace, '.', and ','
    6) Collapse multiple spaces, strip
    7) HTML-escape
    8) Escape backslashes and double quotes
    9) If string starts and ends with quotes, remove them
    """

    # Step 1: Decode HTML entities
    decoded_text = html.unescape(entry)

    # Step 2: Replace known punctuation entities ('.' or ',')
    def punct_replacer(match):
        code = match.group(1).lower()
        if code in ['2e', '002e']:
            return '.'
        elif code in ['2c', '002c']:
            return ','
        # Should not happen if we only match above codes, but just in case:
        return ''
    replaced_text = PUNCT_ENTITY_REGEX.sub(punct_replacer, decoded_text)

    # Step 3: Remove leftover hex entities
    cleaned_text = UNWANTED_ENTITIES_REGEX.sub('', replaced_text)

    # Step 4: Remove all non-ASCII
    cleaned_text = NON_ASCII_REGEX.sub('', cleaned_text)

    # Step 5: Keep only letters, digits, whitespace, '.' and ','
    cleaned_text = NON_WORDS_REGEX.sub(' ', cleaned_text)

    # Step 6: Collapse multiple spaces and strip
    cleaned_text = MULTI_SPACE_REGEX.sub(' ', cleaned_text).strip()

    # Step 7: HTML-escape the cleaned text
    escaped_text = html.escape(cleaned_text)

    # Step 8: Escape backslashes and double quotes
    escaped_text = escaped_text.replace('\\', '\\\\').replace('"', '\\"')

    # Step 9: If the string starts and ends with quotes, remove them
    if escaped_text.startswith('"') and escaped_text.endswith('"'):
        escaped_text = escaped_text[1:-1]

    return escaped_text
def generate_tts_text(article_text: str, style: str) -> str:
    """
    Uses ChatGPT to rewrite `article_text` in the specified style.
    """
    if not article_text.strip():
        return "No content available."

    prompt = f"""
    Please create a YouTube short reels script (~30-45 seconds) voiceover summarizing
    the following article in a {style}.
    Keep it concise but natural. Include ONLY the voiceover script in your response.
    Important:- In response don't include any non-ASCII characters or extra punctuation.

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
        return sanitize(result)
    except Exception as e:
        print(f"OpenAI TTS error ({style}):", e)
        return f"Unable to rewrite in {style}."


def upsert_journal_article(session, data: dict, topics: str):
    """
    Insert or update a JournalArticle record in DB (journals.db).
    We now generate all TTS styles for the article.
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

    sanitized_text = sanitize(data.get("text", ""))

    article.title       = data.get("title", "")
    article.text        = sanitized_text
    article.source_name = data.get("source_name", "")
    article.date        = data.get("date", "")
    article.topics      = topics
    article.sentiment   = data.get("sentiment", "")
    article.tickers     = data.get("tickers", "")

    # Generate each TTS style
    article.tts_text_persuasive   = generate_tts_text(sanitized_text, "Persuasive style")
    article.tts_text_academic     = generate_tts_text(sanitized_text, "Academic style")
    article.tts_text_business     = generate_tts_text(sanitized_text, "Business style")
    article.tts_text_journalistic = generate_tts_text(sanitized_text, "Journalistic style")
    article.tts_text_argumentative= generate_tts_text(sanitized_text, "Argumentative style")

    image_url = data.get("image_url", "https://via.placeholder.com/360x640.png?text=No+Image")
    if image_url:
        filename = f"{abs(hash(image_url))}.jpg"
        local_path = download_image(image_url, filename)
        article.image_path = "/" + local_path
    else:
        article.image_path = "/static/images/default.jpg"

    return article


# ---------------------------------------------------------------------
# SEARCH TTS HELPER (UNTOUCHED)
# ---------------------------------------------------------------------
def generate_tts_for_ephemeral(article_dict: dict):
    """
    Generates TTS text for ephemeral search results (kept).
    Uses the user's style if needed. (unchanged)
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
    Landing page:
      - Non-logged-in => show ALL JournalArticle (no topic filter),
                         display .tts_text_journalistic for each article
      - Logged-in => filter JournalArticle by user’s topics,
                     display the user’s selected TTS style column
    """
    user_id = session.get("user_id")
    j_sess = SessionLocalJournals()

    if not user_id:
        # NON-LOGGED-IN => show all articles, journalistic TTS only
        public_articles = j_sess.execute(
            select(JournalArticle).order_by(JournalArticle.id.desc())
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
                # Show journalistic TTS only
                "tts_text":    a.tts_text_journalistic,
                "tts_type":    "Journalistic style",
            })

        return await render_template("index.html",
                                     user=None,
                                     ephemeral_data=[],
                                     db_data=[],     
                                     public_data=public_data)
    else:
        # LOGGED-IN => filter by user topics, show user’s style TTS
        db_sess = SessionLocal()
        db_user = db_sess.execute(select(User).where(User.id == user_id)).scalar_one_or_none()

        if not db_user:
            db_sess.close()
            j_sess.close()
            session.pop("user_id", None)
            return redirect(url_for("index"))

        # If user missing topics or style => onboard
        if not db_user.topics or not db_user.style:
            db_sess.close()
            j_sess.close()
            return redirect(url_for("onboarding"))

        # Filter articles by intersection with user’s topics
        user_topics_set = set((db_user.topics or "").split(","))
        all_j_articles = j_sess.execute(
            select(JournalArticle).order_by(JournalArticle.id.desc())
        ).scalars().all()

        # Build filtered list
        filtered_articles = []
        for a in all_j_articles:
            article_topics_set = set((a.topics or "").split(","))
            if user_topics_set & article_topics_set:
                filtered_articles.append(a)

        ephemeral_data = session.get("search_results", [])
        db_sess.close()
        j_sess.close()

        # We'll build "db_data" from the filtered JournalArticle
        db_data = []
        user_style = db_user.style.lower()
        # Map user style (string) to the actual column in the article
        # We'll handle some fuzzy matching for style to keep it simple
        for a in filtered_articles:
            if "persuasive" in user_style:
                used_tts = a.tts_text_persuasive
                style_label = "Persuasive style"
            elif "academic" in user_style:
                used_tts = a.tts_text_academic
                style_label = "Academic style"
            elif "business" in user_style:
                used_tts = a.tts_text_business
                style_label = "Business style"
            elif "argumentative" in user_style:
                used_tts = a.tts_text_argumentative
                style_label = "Argumentative style"
            else:
                # default => Journalistic
                used_tts = a.tts_text_journalistic
                style_label = "Journalistic style"

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
                "tts_text":    used_tts,
                "tts_type":    style_label,
            })

        return await render_template(
            "index.html",
            user=db_user,
            ephemeral_data=ephemeral_data,
            db_data=db_data,
            public_data=[]
        )


@app.route("/search", methods=["POST"])
async def do_search():
    """
    1) If user not logged in => cannot search.
    2) If user is logged in => always do a fresh Google search,
       upsert into search_article (like before), generate TTS with user style if needed,
       store ephemeral results in session.
    """
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("index"))

    form_data = await request.form
    query = form_data.get("query", "").strip()
    if not query:
        return redirect(url_for("index"))

    # Grab the user from the DB to get their TTS style
    db_sess = SessionLocal()
    db_user = db_sess.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    db_sess.close()
    tts_type = db_user.style or "Journalistic style"

    # Clear old ephemeral data
    session["search_results"] = []
    ephemeral_articles = []

    # Always fetch fresh data from Google
    results = google_cse_search(query, limit=4)

    j_sess = SessionLocalJournals()
    for r in results:
        original_snippet = r["text"]
        sanitized_snippet = sanitize(original_snippet)

        existing_sa = j_sess.execute(
            select(SearchArticle).where(SearchArticle.title == r["title"])
        ).scalars().first()

        image_url = r.get("image_url") or ""
        filename = f"{abs(hash(image_url))}.jpg"
        local_path = download_image(image_url, filename) if image_url else "static/images/default.jpg"
        final_image_path = "/" + local_path

        tts_text_for_this_article = ""
        if not existing_sa:
            ephemeral_dict = {
                "text": sanitized_snippet,
                "tts_type": tts_type
            }
            generate_tts_for_ephemeral(ephemeral_dict)
            tts_text_for_this_article = ephemeral_dict["tts_text"]

            new_search = SearchArticle(
                query=query,
                user_id=user_id,
                news_url=r["news_url"],
                image_path=final_image_path,
                title=r["title"],
                text=sanitized_snippet,
                source_name=r["source_name"],
                date=r["date"],
                tts_text=tts_text_for_this_article,
                tts_type=tts_type
            )
            j_sess.add(new_search)
            j_sess.commit()
        else:
            if existing_sa.tts_type != tts_type:
                ephemeral_dict = {
                    "text": existing_sa.text,
                    "tts_type": tts_type
                }
                generate_tts_for_ephemeral(ephemeral_dict)
                existing_sa.tts_text = ephemeral_dict["tts_text"]
                existing_sa.tts_type = tts_type
                j_sess.commit()

            tts_text_for_this_article = existing_sa.tts_text
            existing_sa.image_path = final_image_path
            j_sess.commit()

        ephemeral_articles.append({
            "news_url":    r["news_url"],
            "image_url":   final_image_path,
            "title":       r["title"],
            "text":        sanitized_snippet,
            "source_name": r["source_name"],
            "date":        r["date"],
            "tts_text":    tts_text_for_this_article,
            "tts_type":    tts_type,
            "normal_text": original_snippet
        })

    j_sess.close()
    session["search_results"] = ephemeral_articles
    return redirect(url_for("index"))


@app.route("/reels")
async def reels():
    """
    Shows a reels-style page:
      - Non-logged-in => show all journal articles (journalistic TTS).
      - Logged-in => filter by user topics, use user’s style TTS, plus ephemeral results.
    """
    user_id = session.get("user_id")
    article_index = request.args.get("index", 0, type=int)
    j_sess = SessionLocalJournals()

    if not user_id:
        # Non-logged-in => show all, journalistic
        public_articles = j_sess.execute(
            select(JournalArticle).order_by(JournalArticle.id.desc())
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
                "tts_text":    a.tts_text_journalistic,
                "tts_type":    "Journalistic style",
            })
        return await render_template("reels.html", data=public_data, start_index=article_index)

    else:
        # Logged in => ephemeral_data + filter by user topics
        db_sess = SessionLocal()
        db_user = db_sess.execute(select(User).where(User.id == user_id)).scalar_one_or_none()

        if not db_user:
            db_sess.close()
            j_sess.close()
            return redirect(url_for("index"))

        ephemeral_data = session.get("search_results", [])

        all_j_articles = j_sess.execute(
            select(JournalArticle).order_by(JournalArticle.id.desc())
        ).scalars().all()
        j_sess.close()

        user_topics_set = set((db_user.topics or "").split(","))
        filtered_articles = []
        for a in all_j_articles:
            article_topics_set = set((a.topics or "").split(","))
            if user_topics_set & article_topics_set:
                filtered_articles.append(a)

        # Determine which TTS column to use
        user_style = db_user.style.lower()
        db_data = []
        for a in filtered_articles:
            if "persuasive" in user_style:
                used_tts = a.tts_text_persuasive
                style_label = "Persuasive style"
            elif "academic" in user_style:
                used_tts = a.tts_text_academic
                style_label = "Academic style"
            elif "business" in user_style:
                used_tts = a.tts_text_business
                style_label = "Business style"
            elif "argumentative" in user_style:
                used_tts = a.tts_text_argumentative
                style_label = "Argumentative style"
            else:
                used_tts = a.tts_text_journalistic
                style_label = "Journalistic style"

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
                "tts_text":    used_tts,
                "tts_type":    style_label,
            })

        db_sess.close()

        combined_data = ephemeral_data + db_data
        return await render_template("reels.html", data=combined_data, start_index=article_index)


@app.route('/static/images/<path:filename>')
async def serve_image(filename):
    return await send_from_directory('static/images', filename)


def run():
    app.run(debug=True)


if __name__ == "__main__":
    asyncio.run(app.run(debug=True))
