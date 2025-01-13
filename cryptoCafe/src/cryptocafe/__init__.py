import asyncio
import html
import os
import json
import re
import requests
import time
from quart import jsonify

from quart import (
    Quart, request, session, redirect, url_for, render_template, send_from_directory
)
from urllib.parse import urlencode

# GOOGLE TTS
# Make sure you install the library:  pip install google-cloud-texttospeech
from google.cloud import texttospeech
from google.oauth2 import service_account

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
os.makedirs('static/audio', exist_ok=True)

# Google CSE
GOOGLE_CSE_API_KEY = os.getenv("GOOGLE_CSE_API_KEY", "")
GOOGLE_CSE_CX      = os.getenv("GOOGLE_CSE_CX", "")

# ---------------------------------------------------------------------
# Database #1: users.db (for user accounts + liked_articles)
# ---------------------------------------------------------------------
Base = declarative_base()

class User(Base):
    """
    Stores each user's Google account + their TTS style & topics.
    """
    __tablename__ = "users"

    id        = Column(Integer, primary_key=True)
    google_id = Column(String, unique=True, nullable=False)
    email     = Column(String, nullable=True)
    name      = Column(String, nullable=True)
    picture   = Column(String, nullable=True)
    topics    = Column(String, nullable=True)  # e.g. "BTC,ETH"
    style     = Column(String, nullable=True)  # e.g. "Journalistic style"

class LikedArticles(Base):
    """
    For each user, store a single comma-separated string of article IDs they liked.
    user_id is the primary key => 1 row per user.
    """
    __tablename__ = "liked_articles"

    user_id           = Column(Integer, primary_key=True)
    liked_article_ids = Column(String, nullable=True)  # e.g. "12,18,22"

db_file = "sqlite:///users.db"
engine = create_engine(db_file, echo=False)
SessionLocal = sessionmaker(bind=engine)
Base.metadata.create_all(engine)

# ---------------------------------------------------------------------
# Database #2: journals.db
# ---------------------------------------------------------------------
JournalsBase = declarative_base()

class JournalArticle(JournalsBase):
    """
    Master table for trending news articles + TTS variants.
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

    # TTS text columns
    tts_text_persuasive    = Column(Text, nullable=True)
    tts_text_academic      = Column(Text, nullable=True)
    tts_text_business      = Column(Text, nullable=True)
    tts_text_journalistic  = Column(Text, nullable=True)
    tts_text_argumentative = Column(Text, nullable=True)

    # TTS mp3 filenames
    mp3_persuasive        = Column(String, nullable=True)
    mp3_academic          = Column(String, nullable=True)
    mp3_business          = Column(String, nullable=True)
    mp3_journalistic      = Column(String, nullable=True)
    mp3_argumentative     = Column(String, nullable=True)

    # NEW: Liked count
    liked_count = Column(Integer, default=0)


class SearchArticle(JournalsBase):
    """
    For ephemeral search results. 
    """
    __tablename__ = "search_article"

    id          = Column(Integer, primary_key=True)
    query       = Column(String, nullable=False)
    user_id     = Column(Integer, nullable=True)
    news_url    = Column(String, nullable=False)
    image_path  = Column(String, nullable=True)
    title       = Column(String, nullable=True)
    text        = Column(Text, nullable=True)
    source_name = Column(String, nullable=True)
    date        = Column(String, nullable=True)
    tts_text    = Column(Text, nullable=True)
    tts_type    = Column(String, nullable=True)
    tts_mp3     = Column(String, nullable=True)
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

# Google OAuth
GOOGLE_AUTH_URL      = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL     = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL  = "https://openidconnect.googleapis.com/v1/userinfo"
GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")

# ---------------------------------------------------------------------
# BACKGROUND TASK
# ---------------------------------------------------------------------
background_task_running = True

async def fetch_trending_news_loop():
    """
    Periodically fetch trending news.
    """
    while True:
        try:
            await fetch_and_update_journals_db()
        except Exception as e:
            print("ERROR in fetch_trending_news_loop:", e)
        await asyncio.sleep(3600)  # 1 hour

async def fetch_and_update_journals_db():
    j_sess = SessionLocalJournals()
    for topic in TRENDING_TOPICS:
        results = google_cse_search(topic, limit=3)
        for r in results:
            upsert_journal_article(j_sess, r, topics=topic)
    j_sess.commit()
    j_sess.close()

# ---------------------------------------------------------------------
# OAUTH 2.0
# ---------------------------------------------------------------------
@app.route("/login")
async def login():
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
        return "No code provided.", 400

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
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("index"))
    return await render_template("onboarding.html")

@app.route("/save_onboarding", methods=["POST"])
async def save_onboarding():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("index"))

    form_data  = await request.form
    topics_list= form_data.getlist("topics")
    style      = form_data.get("style", "").strip()
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
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("index"))

    db_sess = SessionLocal()
    user = db_sess.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    db_sess.close()

    return await render_template("settings.html", user=user)

@app.route("/save_settings", methods=["POST"])
async def save_settings():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("index"))

    form_data  = await request.form
    topics_list= form_data.getlist("topics")
    style      = form_data.get("style", "").strip()
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
        except Exception as e:
            print("Image download error:", e)
            local_path = "static/images/default.jpg"
    return local_path

PUNCT_ENTITY_REGEX = re.compile(r'&#x(2E|002E|2C|002C);', re.IGNORECASE)
UNWANTED_ENTITIES_REGEX = re.compile(r'&#x[0-9A-Fa-f]+;')
NON_ASCII_REGEX = re.compile(r'[^\x00-\x7F]+')
NON_WORDS_REGEX = re.compile(r'[^a-zA-Z0-9\s\.,]+')
MULTI_SPACE_REGEX = re.compile(r'\s+')

def sanitize(entry: str) -> str:
    decoded_text = html.unescape(entry)

    def punct_replacer(match):
        code = match.group(1).lower()
        if code in ['2e', '002e']:
            return '.'
        elif code in ['2c', '002c']:
            return ','
        return ''

    replaced_text = PUNCT_ENTITY_REGEX.sub(punct_replacer, decoded_text)
    cleaned_text = UNWANTED_ENTITIES_REGEX.sub('', replaced_text)
    cleaned_text = NON_ASCII_REGEX.sub('', cleaned_text)
    cleaned_text = NON_WORDS_REGEX.sub(' ', cleaned_text)
    cleaned_text = MULTI_SPACE_REGEX.sub(' ', cleaned_text).strip()

    escaped_text = html.escape(cleaned_text)
    escaped_text = escaped_text.replace('\\', '\\\\').replace('"', '\\"')
    if escaped_text.startswith('"') and escaped_text.endswith('"'):
        escaped_text = escaped_text[1:-1]

    return escaped_text

def generate_tts_text(article_text: str, style: str) -> str:
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
                {
                    "role": "system",
                    "content": "You are a News narrator outputting news voiceover scripts as plain text."
                },
                {
                    "role": "user",
                    "content": prompt
                },
            ],
        )
        result = response.choices[0].message.content.strip()
        return sanitize(result)
    except Exception as e:
        print(f"OpenAI TTS error ({style}):", e)
        return f"Unable to rewrite in {style}."

def generate_google_tts_mp3(text_script: str, base_filename: str) -> str:
    if not text_script.strip():
        return ""
    creds_path = os.path.join(os.getcwd(), "TTS_Crds.json")

    try:
        credentials = service_account.Credentials.from_service_account_file(creds_path)
        client_tts = texttospeech.TextToSpeechClient(credentials=credentials)

        synthesis_input = texttospeech.SynthesisInput(text=text_script)
        voice = texttospeech.VoiceSelectionParams(
            language_code="en-US",
            name="en-US-News-K",
            ssml_gender=texttospeech.SsmlVoiceGender.NEUTRAL
        )
        audio_config = texttospeech.AudioConfig(
            audio_encoding=texttospeech.AudioEncoding.MP3
        )
        response = client_tts.synthesize_speech(
            input=synthesis_input,
            voice=voice,
            audio_config=audio_config
        )

        final_filename = base_filename + ".mp3"
        final_path = os.path.join("static", "audio", final_filename)

        with open(final_path, "wb") as out:
            out.write(response.audio_content)

        return final_filename

    except Exception as e:
        print("Google TTS generation error:", e)
        return ""

def upsert_journal_article(session, data: dict, topics: str):
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

    # Generate TTS for each style
    tts_styles = {
        "persuasive":   "Persuasive style",
        "academic":     "Academic style",
        "business":     "Business style",
        "journalistic": "Journalistic style",
        "argumentative":"Argumentative style"
    }

    for short_key, style_str in tts_styles.items():
        tts_text_val = generate_tts_text(sanitized_text, style_str)
        setattr(article, f"tts_text_{short_key}", tts_text_val)

        mp3_hash = abs(hash(news_url + short_key))
        base_filename = f"{mp3_hash}_{short_key}"
        mp3_filename = generate_google_tts_mp3(tts_text_val, base_filename)
        setattr(article, f"mp3_{short_key}", mp3_filename)

    image_url = data.get("image_url", "https://via.placeholder.com/360x640.png?text=No+Image")
    if image_url:
        filename = f"{abs(hash(image_url))}.jpg"
        local_path = download_image(image_url, filename)
        article.image_path = "/" + local_path
    else:
        article.image_path = "/static/images/default.jpg"

    return article

def generate_tts_for_ephemeral(article_dict: dict):
    if not article_dict.get("text"):
        article_dict["tts_text"] = "No content to speak."
        return

    style = article_dict.get("tts_type") or "Journalistic style"
    raw_text = article_dict["text"].strip()
    if not raw_text:
        article_dict["tts_text"] = "No content to speak."
        return

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
                {
                    "role": "system",
                    "content": "You are a News narrator outputting news voiceover scripts as plain text"
                },
                {
                    "role": "user",
                    "content": prompt
                },
            ],
        )
        script_output = response.choices[0].message.content.strip()
        article_dict["tts_text"] = sanitize(script_output)
    except Exception as e:
        print("OpenAI TTS error:", e)
        article_dict["tts_text"] = "Error generating TTS."

    unique_hash = abs(hash(article_dict.get("news_url", "") + style))
    base_filename = f"search_{unique_hash}"
    mp3_filename  = generate_google_tts_mp3(article_dict["tts_text"], base_filename)
    article_dict["tts_mp3"] = mp3_filename

# ---------------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------------
@app.route("/")
async def index():
    user_id = session.get("user_id")
    j_sess = SessionLocalJournals()

    if not user_id:
        # Non-logged => show all articles with journalistic TTS
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
                "mp3_name":    a.mp3_journalistic,
                "liked_count": a.liked_count
            })

        return await render_template("index.html",
                                     user=None,
                                     ephemeral_data=[],
                                     db_data=[],
                                     public_data=public_data)
    else:
        # Logged-in => filter by user topics + user style TTS
        db_sess = SessionLocal()
        db_user = db_sess.execute(select(User).where(User.id == user_id)).scalar_one_or_none()

        if not db_user:
            db_sess.close()
            j_sess.close()
            session.pop("user_id", None)
            return redirect(url_for("index"))

        if not db_user.topics or not db_user.style:
            db_sess.close()
            j_sess.close()
            return redirect(url_for("onboarding"))

        user_topics_set = set((db_user.topics or "").split(","))

        all_j_articles = j_sess.execute(
            select(JournalArticle).order_by(JournalArticle.id.desc())
        ).scalars().all()

        filtered_articles = []
        for a in all_j_articles:
            article_topics_set = set((a.topics or "").split(","))
            if user_topics_set & article_topics_set:
                filtered_articles.append(a)

        ephemeral_data = session.get("search_results", [])
        db_sess.close()
        j_sess.close()

        db_data = []
        user_style = db_user.style.lower()

        for a in filtered_articles:
            if "persuasive" in user_style:
                used_tts   = a.tts_text_persuasive
                used_mp3   = a.mp3_persuasive
                style_label= "Persuasive style"
            elif "academic" in user_style:
                used_tts   = a.tts_text_academic
                used_mp3   = a.mp3_academic
                style_label= "Academic style"
            elif "business" in user_style:
                used_tts   = a.tts_text_business
                used_mp3   = a.mp3_business
                style_label= "Business style"
            elif "argumentative" in user_style:
                used_tts   = a.tts_text_argumentative
                used_mp3   = a.mp3_argumentative
                style_label= "Argumentative style"
            else:
                used_tts   = a.tts_text_journalistic
                used_mp3   = a.mp3_journalistic
                style_label= "Journalistic style"

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
                "mp3_name":    used_mp3,
                "liked_count": a.liked_count
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
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("index"))

    form_data = await request.form
    query = form_data.get("query", "").strip()
    if not query:
        return redirect(url_for("index"))

    db_sess = SessionLocal()
    db_user = db_sess.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    db_sess.close()
    tts_type = db_user.style or "Journalistic style"

    session["search_results"] = []
    ephemeral_articles = []

    results = google_cse_search(query, limit=4)

    j_sess = SessionLocalJournals()
    for r in results:
        original_snippet   = r["text"]
        sanitized_snippet  = sanitize(original_snippet)
        existing_sa = j_sess.execute(
            select(SearchArticle).where(SearchArticle.title == r["title"])
        ).scalars().first()

        image_url = r.get("image_url") or ""
        filename = f"{abs(hash(image_url))}.jpg"
        local_path = download_image(image_url, filename) if image_url else "static/images/default.jpg"
        final_image_path = "/" + local_path

        tts_text_for_this_article = ""
        tts_mp3_for_this_article  = ""

        if not existing_sa:
            ephemeral_dict = {
                "text": sanitized_snippet,
                "tts_type": tts_type,
                "news_url": r["news_url"]
            }
            generate_tts_for_ephemeral(ephemeral_dict)
            tts_text_for_this_article = ephemeral_dict["tts_text"]
            tts_mp3_for_this_article  = ephemeral_dict["tts_mp3"]

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
                tts_type=tts_type,
                tts_mp3=tts_mp3_for_this_article
            )
            j_sess.add(new_search)
            j_sess.commit()
        else:
            if existing_sa.tts_type != tts_type:
                ephemeral_dict = {
                    "text": existing_sa.text,
                    "tts_type": tts_type,
                    "news_url": existing_sa.news_url
                }
                generate_tts_for_ephemeral(ephemeral_dict)
                existing_sa.tts_text = ephemeral_dict["tts_text"]
                existing_sa.tts_mp3  = ephemeral_dict["tts_mp3"]
                existing_sa.tts_type = tts_type
                j_sess.commit()

            existing_sa.image_path = final_image_path
            j_sess.commit()

            tts_text_for_this_article = existing_sa.tts_text
            tts_mp3_for_this_article  = existing_sa.tts_mp3

        ephemeral_articles.append({
            "news_url":    r["news_url"],
            "image_url":   final_image_path,
            "title":       r["title"],
            "text":        sanitized_snippet,
            "source_name": r["source_name"],
            "date":        r["date"],
            "tts_text":    tts_text_for_this_article,
            "tts_type":    tts_type,
            "mp3_name":    tts_mp3_for_this_article,
            "normal_text": original_snippet
        })

    j_sess.close()
    session["search_results"] = ephemeral_articles
    return redirect(url_for("index"))

@app.route("/reels")
async def reels():
    user_id = session.get("user_id")
    article_index = request.args.get("index", 0, type=int)
    j_sess = SessionLocalJournals()

    if not user_id:
        # Non-logged-in => all journalistic
        public_articles = j_sess.execute(
            select(JournalArticle).order_by(JournalArticle.id.desc())
        ).scalars().all()
        j_sess.close()

        public_data = []
        for a in public_articles:
            public_data.append({
                "id":          a.id,
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
                "mp3_name":    a.mp3_journalistic,
                "liked_count": a.liked_count
            })

        # Non-logged-in => No liked_ids
        return await render_template(
            "reels.html",
            data=public_data,
            start_index=article_index,
            liked_ids_json="[]"
        )

    else:
        # Logged-in => Filter by user topics + style, also get liked article IDs
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

        user_style = db_user.style.lower()
        db_data = []
        for a in filtered_articles:
            if "persuasive" in user_style:
                used_tts   = a.tts_text_persuasive
                used_mp3   = a.mp3_persuasive
                style_label= "Persuasive style"
            elif "academic" in user_style:
                used_tts   = a.tts_text_academic
                used_mp3   = a.mp3_academic
                style_label= "Academic style"
            elif "business" in user_style:
                used_tts   = a.tts_text_business
                used_mp3   = a.mp3_business
                style_label= "Business style"
            elif "argumentative" in user_style:
                used_tts   = a.tts_text_argumentative
                used_mp3   = a.mp3_argumentative
                style_label= "Argumentative style"
            else:
                used_tts   = a.tts_text_journalistic
                used_mp3   = a.mp3_journalistic
                style_label= "Journalistic style"

            db_data.append({
                "id":          a.id,
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
                "mp3_name":    used_mp3,
                "liked_count": a.liked_count,
                "options":     True
            })

        # Fetch the liked articles for this user from LikedArticles table
        liked_entry = db_sess.execute(
            select(LikedArticles).where(LikedArticles.user_id == user_id)
        ).scalar_one_or_none()

        if liked_entry and liked_entry.liked_article_ids:
            liked_ids_list = liked_entry.liked_article_ids.split(",")
        else:
            liked_ids_list = []

        db_sess.close()
        # Combine ephemeral + filtered
        combined_data = ephemeral_data + db_data
        # Pass liked_ids to the template in JSON form
        return await render_template(
            "reels.html",
            data=combined_data,
            start_index=article_index,
            liked_ids_json=liked_ids_list
        )
# NEW ROUTE: /like_article
@app.route("/like_article", methods=["POST"])
async def like_article():
    """
    1) Expects JSON: {"article_id": <some_int>}
    2) Increments liked_count for JournalArticle
    3) Appends article_id to user's LikedArticles row
    4) Returns JSON with success + updated liked_count
    """
    try:
        user_id = session.get("user_id")
        if not user_id:
            # Return JSON error + 401
            return jsonify({"error": "User not logged in"}), 401

        # Must do await request.get_json() or await request.json with Quart
        data = await request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        article_id = data.get("article_id")
        if not article_id:
            return jsonify({"error": "Missing article_id"}), 400

        # 1) Increment liked_count in journals.db
        j_sess = SessionLocalJournals()
        article = j_sess.execute(
            select(JournalArticle).where(JournalArticle.id == article_id)
        ).scalar_one_or_none()

        if not article:
            j_sess.close()
            return jsonify({"error": "Article not found"}), 404

        article.liked_count += 1
        j_sess.commit()
        updated_count = article.liked_count
        j_sess.close()

        # 2) Update or create LikedArticles row in users.db
        db_sess = SessionLocal()
        liked_entry = db_sess.execute(
            select(LikedArticles).where(LikedArticles.user_id == user_id)
        ).scalar_one_or_none()

        if liked_entry:
            existing_ids = (liked_entry.liked_article_ids or "").split(",")
            if str(article_id) not in existing_ids:
                existing_ids.append(str(article_id))
                liked_entry.liked_article_ids = ",".join(filter(None, existing_ids))
                db_sess.commit()
        else:
            new_liked = LikedArticles(
                user_id=user_id,
                liked_article_ids=str(article_id)
            )
            db_sess.add(new_liked)
            db_sess.commit()

        db_sess.close()

        # 3) Return JSON so front-end can parse success
        return jsonify({"success": True, "liked_count": updated_count})

    except Exception as e:
        print("Error in /like_article route:", e)
        # Return JSON with error message
        return jsonify({"error": str(e)}), 500

@app.route("/dislike_article", methods=["POST"])
async def dislike_article():
    """
    1) Expects JSON: {"article_id": <some_int>}
    2) Decrements liked_count for JournalArticle (down to a minimum of 0).
    3) Removes article_id from user's LikedArticles row.
    4) Returns JSON with success + updated liked_count
    """
    try:
        user_id = session.get("user_id")
        if not user_id:
            return jsonify({"error": "User not logged in"}), 401

        data = await request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        article_id = data.get("article_id")
        if not article_id:
            return jsonify({"error": "Missing article_id"}), 400

        # 1) Decrement liked_count in journals.db
        j_sess = SessionLocalJournals()
        article = j_sess.execute(
            select(JournalArticle).where(JournalArticle.id == article_id)
        ).scalar_one_or_none()

        if not article:
            j_sess.close()
            return jsonify({"error": "Article not found"}), 404

        # Ensure we don't go below zero
        if article.liked_count > 0:
            article.liked_count -= 1

        j_sess.commit()
        updated_count = article.liked_count
        j_sess.close()

        # 2) Remove from LikedArticles row in users.db
        db_sess = SessionLocal()
        liked_entry = db_sess.execute(
            select(LikedArticles).where(LikedArticles.user_id == user_id)
        ).scalar_one_or_none()

        if liked_entry and liked_entry.liked_article_ids:
            existing_ids = (liked_entry.liked_article_ids or "").split(",")
            if str(article_id) in existing_ids:
                existing_ids.remove(str(article_id))
                liked_entry.liked_article_ids = ",".join(filter(None, existing_ids))
                db_sess.commit()

        db_sess.close()

        # 3) Return final JSON
        return jsonify({"success": True, "liked_count": updated_count})

    except Exception as e:
        print("Error in /dislike_article route:", e)
        return jsonify({"error": str(e)}), 500

@app.route('/static/images/<path:filename>')
async def serve_image(filename):
    return await send_from_directory('static/images', filename)

@app.route('/static/audio/<path:filename>')
async def serve_audio(filename):
    return await send_from_directory('static/audio', filename)

def run():
    app.run(debug=True)

if __name__ == "__main__":
    asyncio.run(app.run(debug=True))
