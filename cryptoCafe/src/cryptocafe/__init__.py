import asyncio
import requests
import json
import os
from quart import Quart, render_template,send_from_directory

app = Quart(__name__)

# Ensure the 'static/images' directory exists
os.makedirs('static/images', exist_ok=True)

def download_image(image_url, image_filename):
    image_path = os.path.join('static', 'images', image_filename)
    if not os.path.exists(image_path):
        try:
            response = requests.get(image_url, stream=True)
            response.raise_for_status()
            with open(image_path, 'wb') as out_file:
                for chunk in response.iter_content(chunk_size=8192):
                    out_file.write(chunk)
            print(f'Downloaded image: {image_filename}')
        except Exception as e:
            print(f'Error downloading image {image_url}: {e}')
            # Handle the error, e.g., set a default image
            image_path = os.path.join('static', 'images', 'default.jpg')
    return image_path

@app.route("/")
async def index():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_path = os.path.join(base_dir, 'data.json')
    with open(data_path, 'r') as f:
        data = json.load(f)

    news_data = data.get("data", [])

    # Process the images
    for item in news_data:
        image_url = item.get('image_url', '')
        if image_url:
            image_filename = f"{hash(image_url)}.jpg"
        else:
            image_filename = 'default.jpg'
        
        image_path = download_image(image_url, image_filename)
        item['image_url'] = '/' + image_path

    return await render_template("index.html", data=news_data)

@app.route("/reels")
async def reels():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_path = os.path.join(base_dir, 'data.json')
    with open(data_path, 'r') as f:
        data = json.load(f)

    news_data = data.get("data", [])

    # Process the images
    for item in news_data:
        image_url = item.get('image_url', '')
        if image_url:
            image_filename = f"{hash(image_url)}.jpg"
        else:
            image_filename = 'default.jpg'

        image_path = download_image(image_url, image_filename)
        item['image_url'] = '/' + image_path

    return await render_template("reels3.html", data=news_data)

# Set the static folder
app.static_folder = 'static'


@app.route('/static/images/<path:filename>')
async def serve_image(filename):
    return await send_from_directory('static/images', filename)

def run() -> None:
    """
    Entry point to run the Quart app.
    """
    app.run(debug=True)

if __name__ == "__main__":
    asyncio.run(app.run(debug=True))
