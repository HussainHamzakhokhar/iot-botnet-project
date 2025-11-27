from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <h1>🛡️ IoT Botnet Detection Dashboard</h1>
    <button onclick="alert('Working!')">Click Me</button>
    '''

if __name__ == '__main__':
    app.run(debug=True, port=5000)