import os
from flask import Flask, request, Response

app = Flask(__name__)

ENCFS_MOUNT=os.environ["ENCFS_MOUNT"]

@app.route('/read_file', methods=['GET'])
def read_file():

    file_path = os.path.join(ENCFS_MOUNT, request.args.get("path"))
    if not os.path.exists(file_path):
        return {"error": "File not found"}, 404

    with open(file_path) as f:
        return f.read(), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)