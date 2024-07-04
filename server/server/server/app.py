from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, FileLog
import config

app = Flask(__name__)
app.config.from_object(config)
db.init_app(app)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Login successful'}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    username = request.form['username']
    # Save file and log the action
    file.save(f"../uploads/{file.filename}")
    new_log = FileLog(username=username, action=f"Uploaded {file.filename}")
    db.session.add(new_log)
    db.session.commit()
    return jsonify({'message': 'File uploaded successfully'}), 201

@app.route('/logs', methods=['GET'])
def get_logs():
    logs = FileLog.query.all()
    return jsonify([{'username': log.username, 'action': log.action, 'timestamp': log.timestamp} for log in logs]), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
