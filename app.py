from flask import Flask, render_template, request, jsonify
from analyzer import run_scan

app = Flask(__name__)
app.config['DEBUG'] = True  # Force debug on for local development

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.form or request.get_json() or {}
    url = data.get('url') if isinstance(data, dict) else None
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    try:
        results = run_scan(url)
        return jsonify({'ok': True, 'results': results})
    except Exception as e:
        app.logger.exception('Scan failed')
        return jsonify({'ok': False, 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
