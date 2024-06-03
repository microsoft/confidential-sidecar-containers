from flask import Flask, request, Response
import requests

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST'])
def proxy(path):
    response = requests.request(
        method=request.method,
        url=f"http://localhost:8080/{path}",
        headers={key: value for (key, value) in request.headers if key != 'Host'},
        data=request.get_data())

    return Response(
        response.content,
        status=response.status_code
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
