from flask import Flask, request, jsonify
from flask_cors import CORS
from utils.url_analyzer import analyze_url
from utils.email_analyzer import analyze_email
from utils.chat_analyzer import analyze_chat

app = Flask(__name__)
CORS(app)  # Allow all origins for testing

@app.route('/scan/url', methods=['POST'])
def scan_url():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    result = analyze_url(url)
    return jsonify(result)

@app.route('/scan/email', methods=['POST'])
def scan_email():
    data = request.get_json()
    email_text = data.get('email_text', '')
    result = analyze_email(email_text)
    return jsonify(result)

@app.route('/scan/chat', methods=['POST'])
def scan_chat():
    data = request.get_json()
    message = data.get('message', '')
    result = analyze_chat(message)
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)