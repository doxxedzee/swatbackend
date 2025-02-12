from flask import Flask, render_template, request, jsonify
import mongo

app = Flask(__name__)

@app.route('/register')
def register_page():
    return render_template('register.html')

# Route to handle registration
@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if password != confirm_password:
        return jsonify(success=False, message='Passwords do not match.')

    existing_user = mongo.db.users.find_one({"username": username})
    if existing_user:
        return jsonify(success=False, message='Username already exists.')

    new_user = {"username": username, "password": password}
    mongo.db.users.insert_one(new_user)

    return jsonify(success=True, message='Registration successful! Please log in.')

if __name__ == '__main__':
    app.run(port=3000)
