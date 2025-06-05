import os
import grpc
from flask import Flask, request, Response

import attestation_container_pb2 as attestation_container
import attestation_container_pb2_grpc as attestation_container_grpc

app = Flask(f"attestation_{__name__}")

@app.route('/get_attestation', methods=['GET'])
def get_attestation():

    report_data = request.args.get("report_data")
    if report_data is None:
        return {"error": "report_data is required"}, 400

    attestation_request = attestation_container.FetchAttestationRequest()
    attestation_request.report_data = report_data.encode("utf-8")

    with grpc.insecure_channel("unix:/mnt/uds/sock") as channel:
        stub = attestation_container_grpc.AttestationContainerStub(channel)
        response = stub.FetchAttestation(attestation_request)
        attestation = response.attestation

    return Response(
        attestation,
        status=200,
        mimetype="application/octet-stream"
    )

@app.route("/get_cert_chain", methods=["GET"])
def get_cert_chain():
    """
    **NEW** implementation – grab the platform certs from the attestation
    container instead of reading the baked-in file.
    """
    # An empty report-data is fine; we only need the certs.
    req = attestation_container.FetchAttestationRequest()
    with grpc.insecure_channel("unix:/mnt/uds/sock") as ch:
        att = attestation_container_grpc.AttestationContainerStub(ch).FetchAttestation(req)

    # platform_certificates is already a base-64-encoded JSON blob
    # exactly what the test harness expects.
    return Response(att.platform_certificates, 200,
                    mimetype="application/octet-stream")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)