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

@app.route('/write_file', methods=['POST'])
def write_file():

    file_path = os.path.join(ENCFS_MOUNT, request.args.get("path"))
    try:
        with open(file_path, "w") as f:
            f.write(request.data.decode())
        return f'{request.args.get("path")} written to', 200
    except OSError as e:
        return e.strerror, 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)