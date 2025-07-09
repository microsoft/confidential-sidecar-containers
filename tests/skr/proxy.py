# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

import base64
import json
import subprocess
from flask import Flask, request, Response
import requests

app = Flask(__name__)

def grpc_request(request, method):
    response = subprocess.run([
        "grpcurl",
        "-v", "-plaintext",
        "-d", request,
        "127.0.0.1:50000",
        f"key_provider.KeyProviderService.{method}"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    return Response(
        response.stdout if response.returncode == 0 else response.stderr,
        status=200 if response.returncode == 0 else 500,
    )

@app.route('/say_hello', methods=['GET'])
def grpc_say_hello():
    return grpc_request('{"name":"GRPC interface test!"}', "SayHello")

@app.route('/get_report', methods=['GET'])
def grpc_get_report():
    runtime_data = ""
    try:
        request_json = request.get_json()
        runtime_data = request_json["runtime_data"] or ""
    except Exception as e: ...

    return grpc_request(
        request=f'{{"report_data_hex_string":"{runtime_data}"}}',
        method="GetReport",
    )

@app.route('/get_attestation_data', methods=['GET'])
def grpc_get_attestation_data():
    runtime_data = ""
    try:
        request_json = request.get_json()
        runtime_data = request_json["runtime_data"] or ""
    except Exception as e: ...

    return grpc_request(
        request=f'{{"b64_runtime_data_string":"{runtime_data}"}}',
        method="GetAttestationData",
    )

@app.route('/unwrap_key', methods=['GET'])
def grpc_unwrap_key():
    return grpc_request(
        request=json.dumps({
            "key_provider_key_wrap_protocol_input": base64.b64encode(json.dumps({
                "op": "keyunwrap",
                "keywrapparams": {},
                "keyunwrapparams": {
                    "dc": {
                        "Parameters": {
                            "attestation-agent": [
                                base64.b64encode("skr".encode()).decode()
                            ]
                        }
                    },
                    "annotation": request.get_json()["wrapped_data"]
                },
            }).encode()).decode()
        }),
        method="UnWrapKey",
    )

# For requests which match the HTTP sidecar, just forward them on
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
