Secure Key Release
==================
This tool instantiates a web server ( http://localhost:8080 ) which exposes a REST API so that other containers can retrieve raw attestation via the `attest/raw` POST method and MAA token via the `attest/maa` POST methods as well as release secrets from Azure Key Vault MHSM service via the `key/release` POST method. The latter two APIs require that the server is configured with a certificate cache endpoint during startup. The information for the cerificate cache endpoint is passed as a base64-encoded string and has the following schema:

```json
{
   "certcache": {
      "endpoint": "americas.test.acccache.azure.net",
      "tee_type": "SevSnpVM",
      "api_version": "api-version=2020-10-15-preview"
   }
}
```

The tool can be executed using the script https://github.com/microsoft/confidential-sidecars/blob/master/skr.sh and the base64-encoded string as an optional cert cache endpoint attribute to it.

If the cert cache endpoint is not provided, only the `attest/raw` POST method is available.

API
---

The `status` GET method returns the status of the server. The response carries a `StatusOK` header and a payload of the following format:

```json
{
    "message": "STATUS OK"
}

{
    "message": "STATUS NOT OK"
}
```

The `attest/raw` POST method expects a JSON of the following format:

```json
{
    "runtime_data": "<Base64-encoded blob; the hash digest of the blob will be presented as report data in the raw attestation report>"
}
```

Upon success, the `attest/raw` POST method reponse carries a `StatusOK` header and a payload of the following format:

```json
{
    "report": "<hex format of raw hardware attestation report>"
}
```

Upon error, the `attest/raw` POST method response carries a `BadRequest` or `StatusForbidden` header and a payload of the following format:

```json
{
    "error": "<error message>"
}
```

The `attest/json` POST method expects a JSON of the following format:

```json
{
    "runtime_data": "<Base64-encoded blob that will be presented as ReportData in hardware attestation report>"
}
```

Upon success, the `attest/json` POST method response carries a `StatusOK` header and a payload of the following format:

```json
{
    "report": {
        "version": int,
        "guest_svn": int,
        "policy": int,
        "family_id": string,
        "image_id": string,
        "vmpl": int,
        "signature_algo": int,
        "platform_version": int,
        "platform_info": int,
        "author_key_en": int,
        "reserved1": int,
        "report_data": string,
        "measurement": string,
        "host_data": string,
        "id_key_digest": string,
        "author_key_digest": string,
        "report_id": string,
        "report_id_ma": string,
        "reported_tcb": int,
        "reserved2":string,
        "chip_id": string,
        "committed_svn": int,
        "committed_version": int,
        "launch_svn": int,
        "reserved3": string,
        "signature": string
    }
}
```

Upon error, the `attest/json` POST method response carries a `BadRequest` or `StatusForbidden` header and a payload of the following format:

```json
{
    "error": "<error message>"
}
```

The `attest/maa` POST method expects a JSON of the following format:

```json
{
    "maa_endpoint": "<maa endpoint>",
    "runtime_data": "<Base64-encoded blob whose hash digest will be presented as runtime data in maa token>"
}
```

Upon success, the `attest/maa` POST method reponse carries a `StatusOK` header and a payload of the following format:

```json
{
    "token": "<MAA token formatted in JSON Web Token format>"
}
```

Upon error, the `attest/maa` POST method response carries a `BadRequest` or `StatusForbidden` header and a payload of the following format:

```json
{
    "error": "<error message>"
}
```

The `key/release` POST method expects a JSON of the following format:

```json
{
    "maa_endpoint": "<maa endpoint>",
    "mhsm_endpoint": "<mhsm endpoint>",
    "kid": "<key identifier>",
    "access_token": "optional aad token if the command will run in a resource without proper managed identity assigned"
}
```

Upon success, the `key/release` POST method reponse carries a `StatusOK` header and a payload of the following format:

```json
{
    "key": "<hexstring representation of the key>"
}
```

Upon error, the `key/release` POST method response carries a `StatusForbidden` header and a payload of the following format:

```json
{
    "error": "<error message>"
}
```

