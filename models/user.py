from pymongo import MongoClient
from bson.objectid import ObjectId

# Connect to MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['swatting']  # Replace with your actual database name
user_collection = db['users']

class User:
    def __init__(self, username, password, uid=None):
        self.uid = uid
        self.username = username
        self.password = password

    @classmethod
    def create_user(cls, username, password):
        existing_user = user_collection.find_one({'username': username})
        if existing_user:
            raise ValueError("Username already exists.")
        
        # Create new user
        new_uid = user_collection.count_documents({}) + 1  # Generate unique UID
        user_doc = {
            'uid': new_uid,
            'username': username,
            'password': password  # Store password securely in production!
        }
        user_collection.insert_one(user_doc)
        return cls(username=username, password=password, uid=new_uid)

    @classmethod
    def get_user_by_username(cls, username):
        user_doc = user_collection.find_one({'username': username})
        if user_doc:
            return cls(username=user_doc['username'], password=user_doc['password'], uid=user_doc['uid'])
        return None

# Usage
if __name__ == '__main__':
    try:
        new_user = User.create_user('testuser', 'testpassword')
        print(f'User created: {new_user.username} with UID: {new_user.uid}')
    except ValueError as e:
        print(e)
