import asyncio
import html
import os
import json
import re
import requests

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

# Database
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
    Example DB model for news articles.
    """
    __tablename__ = "articles"

    id          = Column(Integer, primary_key=True)
    news_url    = Column(String, unique=True, nullable=False)
    image_path  = Column(String, nullable=True)
    title       = Column(String, nullable=True)
    text        = Column(Text, nullable=True)
    source_name = Column(String, nullable=True)
    date        = Column(String, nullable=True)
    topics      = Column(String, nullable=True)   # e.g. "BTC,ETH"
    sentiment   = Column(String, nullable=True)
    tickers     = Column(String, nullable=True)
    tts_text    = Column(Text, nullable=True)
    tts_type    = Column(String, nullable=True)

db_file = "sqlite:///articles.db"
engine = create_engine(db_file, echo=False)
SessionLocal = sessionmaker(bind=engine)
Base.metadata.create_all(engine)

# Google OAuth Endpoints
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"

GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")

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
    """
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
                return redirect(url_for("onboarding"))
            else:
                db_sess.close()
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
            return redirect(url_for("onboarding"))

    except Exception as e:
        return f"Error exchanging code for token: {e}", 500


@app.route("/logout")
async def logout():
    session.pop("user_id", None)
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
    2) For each chosen topic, fetch articles via Google CSE.
    3) Upsert them into DB with TTS text.
    4) Redirect to the homepage.
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

        # 2) For each topic, fetch articles from Google CSE
        #    You can decide how many articles per topic you want to fetch:
        for topic in topics_list:
            # skip empty
            if not topic.strip():
                continue
            
            # fetch e.g. 3-5 articles for each topic
            results = google_cse_search(topic.strip(), limit=3)
            # upsert them
            for r in results:
                upsert_article(db_sess, r, topics=user.topics, tts_type=user.style)

        db_sess.commit()
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
    (Optionally, you could also fetch new articles here if topics change.)
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

        # If desired, refetch or update articles on settings change as well.
        # (Omitted by default.)
    db_sess.close()

    return redirect(url_for("index"))


# ---------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------
def google_cse_search(query: str, limit=10):
    """
    Calls Google Custom Search JSON API for up to 'limit' results.
    Returns a list of dicts in a format that can be inserted as "Article".
    """
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
                "news_url": link,
                "title":    title,
                "text":     snippet,
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


def upsert_article(session, data: dict, topics: str, tts_type: str = "default"):
    """
    Insert or update an Article record.
    Download its image (if needed) and generate TTS text.
    """
    news_url = data.get("news_url", "").strip()
    if not news_url:
        return None

    existing = session.execute(
        select(Article).where(Article.news_url == news_url)
    ).scalar_one_or_none()

    if existing:
        article = existing
    else:
        article = Article(news_url=news_url)
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

    generate_tts(article)
    return article


def article_to_dict(article: Article):
    """
    Convert an Article object to a dict,
    splitting topics/tickers into lists for convenience.
    """
    return {
        "news_url":    article.news_url,
        "image_url":   article.image_path,
        "title":       article.title,
        "text":        article.text,
        "source_name": article.source_name,
        "date":        article.date,
        "topics":      (article.topics or "").split(","),
        "sentiment":   article.sentiment,
        "tickers":     (article.tickers or "").split(","),
        "tts_text":    article.tts_text,
        "tts_type":    article.tts_type,
    }


def filter_articles_by_topics(articles, user_topics):
    """
    If user has some comma-separated topics, let's only show articles
    that match at least one of those topics.
    This is naive; refine if needed.
    """
    if not user_topics.strip():
        return articles  # no filtering

    topic_list = [t.strip().lower() for t in user_topics.split(",") if t.strip()]
    if not topic_list:
        return articles

    filtered = []
    for a in articles:
        article_topic_list = [t.strip().lower() for t in (a.topics or "").split(",") if t.strip()]
        # if there's any overlap
        if set(topic_list).intersection(set(article_topic_list)):
            filtered.append(a)
    return filtered

# def generate_tts(article_obj: Article):
#     """
#     Generates a TTS script by calling OpenAI with the user-defined style.
#     If 'tts_text' is already set, returns it.
#     Otherwise, uses the article text to produce a short TTS summary.
#     """
#     if article_obj.tts_text:
#         return article_obj.tts_text

#     raw_text = (article_obj.text or "").strip()
#     if not raw_text:
#         article_obj.tts_text = "No content to speak."
#         return article_obj.tts_text

#     style = article_obj.tts_type or "How it influences current market prices"
#     prompt = f"""
#             Please create a youtube short reels (~30-45 seconds) voiceover summarizing the following article in a {style}.
#             Keep it concise but natural. Include ONLY the voiceover script in your response.

#             Article text:
#             \"\"\"
#             {raw_text}
#             \"\"\"
#                 """
#     try:
#         response = openai.ChatCompletion.create(
#             model="gpt-4",
#             messages=[
#                 {"role": "system", "content": "You are a youtube short reels News narrator outputting a news voiceover as plain text."},
#                 {"role": "user", "content": prompt}
#             ],
           
#         )
#         article_obj.tts_text = response.choices[0].message.content.strip()
#     except Exception as e:
#         print("OpenAI TTS error:", e)
#         article_obj.tts_text = "Error generating TTS."

#     return article_obj.tts_text
def sanitize(entry):       
    sanitized_text = html.escape(entry)
    
    # Remove unnecessary quotes at the start and end
    if sanitized_text.startswith('"') and sanitized_text.endswith('"'):
        sanitized_text = sanitized_text[1:-1]
    
    # Update the entry with sanitized text
    entry = sanitized_text
    return entry

def generate_tts(article_obj: Article):
    """
    Generates a TTS script by calling OpenAI with the user-defined style.
    If 'tts_text' is already set, returns it.
    Otherwise, uses the article text to produce a short TTS summary.
    """
    if article_obj.tts_text:
        return article_obj.tts_text

    raw_text = (article_obj.text or "").strip()
    if not raw_text:
        article_obj.tts_text = "No content to speak."
        return article_obj.tts_text

    style = article_obj.tts_type or "How it influences current market rates"
    prompt = f"""
            Please create a youtube short reels script (~30-45 seconds) voiceover summarizing the following article in a {style}.
            Keep it concise but natural. Include ONLY the voiceover script in your response.

            Article text:
            \"\"\"
            {raw_text}
            \"\"\"
                """
    try:
        response =  client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "You are a News narrator outputing news voiceover scripts"},
            {"role": "user", "content": prompt}
        ],
    )
        # FIX: Extract content string and strip it
        ssml_output = response.choices[0].message.content.strip()
        # e.g. if you had GPT:
        # prompt = f"Please create a {style} TTS script for the following article: {raw_text}"
        # response = ...
        article_obj.tts_text = sanitize(ssml_output)

        # For demonstration:

        return article_obj.tts_text
    except Exception as e:
        print("OpenAI TTS error:", e)
        article_obj.tts_text = "Error generating TTS."

    return article_obj.tts_text


# ---------------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------------
@app.route("/")
async def index():
    """
    If user not logged in => show sign in button
    If user logged in => 
       - if user missing topics/style => redirect to /onboarding
       - else => show articles & search
    """
    user_id = session.get("user_id")
    if not user_id:
        return await render_template("index.html", user=None, data=[])

    db_sess = SessionLocal()
    db_user = db_sess.execute(
        select(User).where(User.id == user_id)
    ).scalar_one_or_none()

    if not db_user:
        # no user found => log them out
        db_sess.close()
        session.pop("user_id", None)
        return await render_template("index.html", user=None, data=[])

    # if user has no topics or style => onboard them
    if not db_user.topics or not db_user.style:
        db_sess.close()
        return redirect(url_for("onboarding"))

    # If they do have topics/style, fetch articles
    user_topics = set(db_user.topics.split(","))
    all_articles = db_sess.execute(select(Article)).scalars().all()
    db_sess.close()

    # filter articles that match at least one of the user topics
    filtered = []
    for a in all_articles:
        art_topics = set((a.topics or "").split(","))
        if user_topics & art_topics:
            filtered.append(a)

    display_data = [article_to_dict(a) for a in filtered]
    return await render_template("index.html", user=db_user, data=display_data)


@app.route("/search", methods=["POST"])
async def do_search():
    """
    1) Check that the user is logged in
    2) Get the query from form
    3) Call google CSE
    4) Upsert top results into DB
    5) Return to home
    """
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("index"))

    form_data = await request.form
    query    = form_data.get("query", "").strip()
    tts_type = form_data.get("tts_type", "").strip()

    if not query:
        return redirect(url_for("index"))

    db_sess = SessionLocal()
    db_user = db_sess.execute(
        select(User).where(User.id == user_id)
    ).scalar_one_or_none()

    # If user didn't pick a new TTS style, fallback to what's in DB
    final_tts_style = tts_type or (db_user.style or "default")

    # Google search
    results = google_cse_search(query, limit=4)

    for r in results:
        upsert_article(db_sess, r, topics=db_user.topics, tts_type=final_tts_style)

    db_sess.commit()
    db_sess.close()

    return redirect(url_for("index"))


@app.route("/reels")
async def reels():
    """
    Reels-based view: read from DB, optional ?index= param
    Just a sample page that can show a reel-like UI
    """
    article_index = request.args.get("index", 0, type=int)
    db_sess = SessionLocal()
    all_articles = db_sess.execute(select(Article)).scalars().all()
    db_sess.close()

    data = [article_to_dict(a) for a in all_articles]
    return await render_template("reels.html", data=data, start_index=article_index)


@app.route('/static/images/<path:filename>')
async def serve_image(filename):
    return await send_from_directory('static/images', filename)


def run():
    app.run(debug=True)


if __name__ == "__main__":
    # Using asyncio.run(...) for Quart
    asyncio.run(app.run(debug=True))
