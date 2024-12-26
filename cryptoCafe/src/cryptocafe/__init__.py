import asyncio
import requests
import json
import os
from quart import Quart, render_template

app = Quart(__name__)

@app.route("/")
async def index():
    """
    Fetch news data from the Crypto News API (or from local JSON) and render it in card format.
    """
    # Change this to fetch from the API if desired:
    # api_url = (
    #     "https://cryptonews-api.com/api/v1/category"
    #     "?section=alltickers&items=2&page=1&token=YOUR_API_TOKEN"
    # )
    # response = requests.get(api_url)
    # data = response.json()

    # For demonstration, we’re loading from a local 'data.json' file instead:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_path = os.path.join(base_dir, 'data.json')
    with open(data_path, 'r') as f:
        data = json.load(f)

    news_data = data.get("data", [])
    return await render_template("index.html", data=news_data)

@app.route("/reels")
async def reels():
    """
    Fetch the same data, but render the 'reels' experience using Fabric.js and Web Speech Synthesis.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_path = os.path.join(base_dir, 'data.json')
    with open(data_path, 'r') as f:
        data = json.load(f)

    news_data = data.get("data", [])
    return await render_template("reels.html", data=news_data)

def run() -> None:
    """
    Entry point to run the Quart app.
    """
    app.run(debug=True)

if __name__ == "__main__":
    asyncio.run(app.run(debug=True))
