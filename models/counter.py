from pymongo import MongoClient
from bson.objectid import ObjectId

# Connect to MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['swatting']  # Replace with your actual database name
counter_collection = db['counters']

class Counter:
    def __init__(self):
        # Ensure the counter document exists
        if counter_collection.count_documents({}) == 0:
            counter_collection.insert_one({'uid': 0})  # Initialize counter

    def get_next_uid(self):
        # Increment the counter and return the new UID
        counter_doc = counter_collection.find_one_and_update(
            {},
            {'$inc': {'uid': 1}},
            return_document=True
        )
        return counter_doc['uid']

# Usage
if __name__ == '__main__':
    counter = Counter()
    new_uid = counter.get_next_uid()
    print(f'New UID: {new_uid}')
