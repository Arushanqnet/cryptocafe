QUART + POETRY APPLICATION DOCUMENTATION
----------------------------------------

TABLE OF CONTENTS
-----------------
1. Overview
2. File Imports and Environment Setup
3. Application Configuration
4. Database Models (articles.db)
5. Database Models (journals.db)
6. Global Constants
7. Background Task (Trending News Fetch)
8. OAuth2 Flow (Google Sign-In)
9. Onboarding and Settings
10. Search-Related Utility Functions
11. TTS Generation Functions
12. Routes
13. How to Run

--------------------------------------------------------------------------------
1. OVERVIEW
--------------------------------------------------------------------------------
This application is built using the Quart framework, an async variant of Flask,
and integrates with Google OAuth for user login. It maintains user profiles,
saves personalized articles fetched from a trending news background task, and 
provides ephemeral custom search with TTS (Text-To-Speech) generation using 
OpenAI's API.

The following main features are present:
- Google Sign-In (manual OAuth2 flow)
- Onboarding and settings for user-selected topics and TTS style
- Background task fetching trending news every 5 minutes
- Separate databases: one for the trending journal articles, and another for
  user-personalized articles
- Ephemeral (session-based) search with TTS
- Basic UI rendering (index, onboarding, settings, reels)

--------------------------------------------------------------------------------
2. FILE IMPORTS AND ENVIRONMENT SETUP
--------------------------------------------------------------------------------

Line by line (grouped) documentation:

1-6:  
```python
import asyncio
import html
import os
import json
import re
import requests
import time
asyncio: Used to schedule background tasks, run async code in Quart.
html: Provides utility functions (like html.escape()) to sanitize text.
os: For accessing environment variables and filesystem operations.
json: For JSON serialization/deserialization.
re: Regular expressions (not heavily used but imported for potential text processing).
requests: For making HTTP requests to Google OAuth, Google CSE, and images.
time: For timestamps (used in the journals DB to record creation times).
8-14:

python
Copy code
from quart import (
    Quart, request, session, redirect, url_for, render_template, send_from_directory
)
from urllib.parse import urlencode
Quart is the main framework class and submodules used for:
request: Accessing incoming request data
session: Managing user session data (cookies)
redirect, url_for: Utility to create redirects and construct URLs
render_template: Render HTML templates
send_from_directory: Serve static files
urlencode: For building query strings (used in OAuth flows, Google CSE calls)
16-20:

python
Copy code
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, select
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
SQLAlchemy modules for database access and ORM:
create_engine: Creates an engine bound to a database (SQLite in this case)
Column, Integer, String, Text: Data types for model fields
select: SQLAlchemy 1.4+ style for building queries
declarative_base: Creates base class for our model definitions
sessionmaker: Factory to create database sessions
22-23:

python
Copy code
from dotenv import load_dotenv
load_dotenv()
load_dotenv() loads environment variables from a .env file if present (like OPENAI_API_KEY, GOOGLE_CLIENT_ID, etc.).
25-26:

python
Copy code
# Initialize OpenAI
from openai import OpenAI
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
Imports OpenAI’s Python library (a simplified approach as shown).
Instantiates the client with an API key from the environment variable.
APPLICATION CONFIGURATION
28:

python
Copy code
app = Quart(__name__)
Creates a Quart application instance.
29:

python
Copy code
app.secret_key = os.getenv("SECRET_KEY", "super-secret-key")
Sets the secret key for sessions. Uses an env var or fallback default.
31-33:

python
Copy code
app.config['SESSION_TYPE'] = 'filesystem'
app.config['ENV'] = 'development'
app.config['DEBUG'] = True
Configures the app to use filesystem-based sessions, sets environment to development, and enables debug mode.
35:

python
Copy code
app.static_folder = 'static'
Tells Quart that the static folder is where static files (CSS, JS, images) live.
36:

python
Copy code
os.makedirs('static/images', exist_ok=True)
Ensures that static/images folder exists to store downloaded images.
38-39:

python
Copy code
# Google CSE
GOOGLE_CSE_API_KEY = os.getenv("GOOGLE_CSE_API_KEY", "")
GOOGLE_CSE_CX = os.getenv("GOOGLE_CSE_CX", "")
Pulls Google CSE credentials from environment variables or defaults to empty.
DATABASE MODELS (articles.db)
41:

python
Copy code
Base = declarative_base()
Creates a base class for our primary models.
43-60: Definition of the User model

python
Copy code
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
This table stores user-related data.
The docstring explains each column's usage.
google_id is unique so we can identify the user properly.
62-82: Definition of the Article model

python
Copy code
class Article(Base):
    """
    Personalized DB model for user-specific news articles.
    Notice we added 'user_email' so we can filter articles
    by each specific user.
    """
    __tablename__ = "articles"

    id          = Column(Integer, primary_key=True)
    user_email  = Column(String, nullable=True)
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
This table stores articles personalized for each user (linked by user_email).
Additional metadata: news_url, image_path, title, etc.
tts_text stores the generated TTS script for that article, tts_type is the style used.
84-88:

python
Copy code
# Connect articles.db
db_file = "sqlite:///articles.db"
engine = create_engine(db_file, echo=False)
SessionLocal = sessionmaker(bind=engine)
Base.metadata.create_all(engine)
Defines the SQLite connection for the articles.db.
echo=False means no verbose SQL logs.
Creates the necessary tables if they don't already exist.
DATABASE MODELS (journals.db)
90:

python
Copy code
JournalsBase = declarative_base()
A second declarative base, specifically for the journals database.
92-113: Definition of the JournalArticle model

python
Copy code
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
This model is for the "master list" of trending articles.
topics is used to mark the general category (like "Bitcoin (BTC)").
tts_text and tts_type can be used if we want to store TTS for these master articles, but typically we generate TTS for user-personalized articles.
115-119:

python
Copy code
db_journals_file = "sqlite:///journals.db"
journals_engine = create_engine(db_journals_file, echo=False)
SessionLocalJournals = sessionmaker(bind=journals_engine)
JournalsBase.metadata.create_all(journals_engine)
Creates a second engine/connection for journals.db.
Creates journal_articles table if not existing.
GLOBAL CONSTANTS
121-129:

python
Copy code
TRENDING_TOPICS = [
    "Bitcoin (BTC)",
    "Ethereum (ETH)",
    "DeFi",
    "NFTs",
    "Trading",
    "Market Insights"
]

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
TRENDING_TOPICS is a list of default topics we fetch in the background loop.
Google OAuth URLs used during manual OAuth2 flow.
131-132:

python
Copy code
GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
Pulled from environment variables for the OAuth flow.
BACKGROUND TASK (TRENDING NEWS FETCH)
134:

python
Copy code
background_task_running = False
A global flag to prevent multiple background tasks from starting simultaneously.
136-146:

python
Copy code
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
This function runs in an endless loop (when started) to periodically call fetch_and_update_journals_db().
Waits 5 minutes between iterations.
148-161:

python
Copy code
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
Loops over each topic in TRENDING_TOPICS, fetches up to 3 Google CSE results, then uses upsert_journal_article to either insert or update them in journal_articles.
Commits changes to journals.db once done for all topics.
OAUTH2 FLOW (GOOGLE SIGN-IN)
163-177:

python
Copy code
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
When user hits /login, we build the Google authorization URL with required parameters and redirect the user to Google.
179-254:

python
Copy code
@app.route("/auth/callback")
async def auth_callback():
    """
    Google calls this with ?code=.
    Exchange code for tokens, get user info, store in DB if new.
    Then start the background fetch if not started already.
    """
    ...
This route is the callback that Google calls after the user grants permission.
We read the code parameter, exchange it for an access_token at GOOGLE_TOKEN_URL.
We then fetch user info (sub, email, name, picture) from Google’s userinfo endpoint.
We store/update user in articles.db:
If the user already exists, update their record.
If they don’t exist, create new with empty topics and style.
Finally, if the user is missing topics or style, we redirect to /onboarding, otherwise we go to /.
We also ensure the background task is started only once (background_task_running flag).
256-260:

python
Copy code
@app.route("/logout")
async def logout():
    session.pop("user_id", None)
    session.pop("search_results", None)
    return redirect(url_for("index"))
Clears the session data for the user (including ephemeral search results), then redirects to homepage.
ONBOARDING AND SETTINGS
262-272:

python
Copy code
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
If user not logged in, we redirect them away.
Otherwise, render an HTML template with topics selection and style input.
274-299:

python
Copy code
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
    ...
Reads topics and style from POST form data.
Updates the user record in the DB.
Calls copy_journals_to_user_articles(user) to replicate relevant trending articles from journals.db.
Redirects user to the homepage.
301-315:

python
Copy code
@app.route("/settings")
async def settings():
    """
    Show a form to update topics + style (like onboarding, but user can do it anytime).
    """
    ...
Similar logic as onboarding but for an existing user who might want to update their preferences.
317-336:

python
Copy code
@app.route("/save_settings", methods=["POST"])
async def save_settings():
    """
    Similar to save_onboarding, but for the settings page.
    We'll also do a fresh copy from journals.db => user
    """
    ...
Same pattern: read form data, update user.topics and user.style, then copy new items from journals.db.
SEARCH-RELATED UTILITY FUNCTIONS
338-384:

python
Copy code
def google_cse_search(query: str, limit=10):
    """
    Calls Google Custom Search JSON API for up to 'limit' results.
    Returns a list of dicts in a format that can be inserted as an Article-like record.
    """
    ...
Builds the query string for Google CSE with key, cx, q, and num.
Sends a GET request to Google’s Custom Search.
Parses the JSON response, extracting link, title, snippet, and image if present.
Returns a list of dictionaries suitable for insertion into a DB or ephemeral usage.
386-405:

python
Copy code
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
Given an image URL and a filename, downloads the image to static/images.
If download fails, fallback is static/images/default.jpg.
407-442:

python
Copy code
def upsert_journal_article(session, data: dict, topics: str, tts_type: str = "Plain text"):
    """
    Insert or update a JournalArticle record in DB (journals.db).
    Also downloads image. We store text as is (plain text).
    We won't generate TTS here, to keep it simpler.
    """
    ...
Takes a SQLAlchemy session and the data dictionary (like from google_cse_search).
Checks if the news_url already exists in journal_articles.
If it does, updates it. Otherwise, creates a new record.
Downloads the image locally, sets image_path.
Returns the article object.
444-487:

python
Copy code
def copy_journals_to_user_articles(user_obj):
    """
    Fetch all JournalArticle from journals.db.
    Compare topics with user_obj.topics.
    For new matches, convert them to user’s style, store in articles.db with user_email.
    """
    ...
Gathers all JournalArticle records from journals.db.
Compares each record’s topics with the user’s topics. If overlap, we create a new Article in articles.db for that user — but only if it doesn’t already exist.
Calls generate_tts_for_db_article(a) to generate TTS script, then saves.
489-506:

python
Copy code
def sanitize(entry: str) -> str:
    sanitized_text = html.escape(entry)
    ...
    return sanitized_text
Utility to escape HTML, backslashes, quotes in text to keep it safe for storing/using in JSON or HTML contexts.
508-537:

python
Copy code
def generate_tts_for_db_article(article_obj: Article):
    """
    Generates TTS text for a user-specific Article object, storing in article_obj.tts_text.
    """
    ...
Builds a prompt referencing the article’s text and the user’s tts_type.
Calls OpenAI’s GPT model with a system message instructing it to produce a voiceover script.
Sanitizes the output via sanitize().
Stores the result in article_obj.tts_text.
TTS GENERATION FUNCTIONS (EPHEMERAL)
539-569:

python
Copy code
def generate_tts_for_ephemeral(article_dict: dict):
    """
    Generates TTS text for a single ephemeral search result (a dict).
    We'll store the result in article_dict["tts_text"].
    """
    ...
Similar logic to generate_tts_for_db_article(), but works on ephemeral dictionaries stored in session instead of DB objects.
ROUTES
571-619: index()

python
Copy code
@app.route("/")
async def index():
    """
    - If user not logged in => show sign in button (empty article lists).
    - If logged in and missing topics/style => onboard.
    - Otherwise => show custom search results + user-personalized DB articles.
    """
    ...
Process:

Checks if user_id is in session.
If not, renders index.html with no user or articles.
If user is found, we load them from the DB.
If they’re missing topics or style, redirect to /onboarding.
Otherwise, we copy the latest journals to the user’s articles (so they're up to date), fetch ephemeral data from session, fetch user’s articles from articles.db, then render the combined results.
621-652: do_search()

python
Copy code
@app.route("/search", methods=["POST"])
async def do_search():
    """
    - Perform Google search (CSE).
    - Generate ephemeral TTS for each result.
    - Store them in session["search_results"].
    """
    ...
Process:

Reads the search query and TTS style from form data.
Calls google_cse_search.
For each result, calls generate_tts_for_ephemeral.
Downloads images locally, sets updated image path in the ephemeral data.
Stores the ephemeral articles in session["search_results"].
Redirects to /.
654-687: reels()

python
Copy code
@app.route("/reels")
async def reels():
    """
    Shows a reels-style page with combined ephemeral + user-personalized DB articles
    in the exact same order as index.html:
      ephemeral_data first, then db_data
    """
    ...
Similar logic to index(), except it merges ephemeral data first, then the user’s DB articles in descending order by ID.
Passes them to a reels.html template with a start_index parameter for stepping through articles like a slideshow.
689-691:

python
Copy code
@app.route('/static/images/<path:filename>')
async def serve_image(filename):
    return await send_from_directory('static/images', filename)
A helper route to serve images from static/images.
693-695:

python
Copy code
def run():
    app.run(debug=True)
Convenience function if you want to run the app from another script by calling run().
697-699:

python
Copy code
if __name__ == "__main__":
    asyncio.run(app.run(debug=True))
If running directly as a script, use asyncio.run() to start the Quart app with debug on.
HOW TO RUN
Make sure you have Python 3.9+ and a virtual environment set up.
pip install -r requirements.txt (or if using Poetry, poetry install).
Create a .env file containing:
makefile
Copy code
OPENAI_API_KEY=your_key_here
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_CSE_API_KEY=your_google_cse_key
GOOGLE_CSE_CX=your_google_cse_cx
SECRET_KEY=a_random_secret_key
Run python main.py (or python <this_file>.py) to start the server.
Visit http://localhost:5000/ in your browser.