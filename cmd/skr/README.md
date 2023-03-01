The ```skr``` tool instantiates a web server ( http://localhost:<port>) which exposes a REST API so that other containers can retrieve raw attestation via the `attest/raw` POST method and MAA token via the `attest/maa` POST methods as well as release secrets from Azure Key Vault service via the `key/release` POST method. 

The tool can be executed using the script [skr.sh](https://github.com/Microsoft/confidential-sidecar-containers/blob/master/skr.sh). If the port number is not specified, the port will default to 8080.

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
    "akv_endpoint": "<akv endpoint>",
    "kid": "<key identifier>",
    "access_token": "optional aad token if the command will run in a resource without proper managed identity assigned"
}
```

Upon success, the `key/release` POST method reponse carries a `StatusOK` header and a payload of the following format:

```json
{
    "key": "<key in JSON Web Key format>"
}
```

Upon error, the `key/release` POST method response carries a `StatusForbidden` header and a payload of the following format:

```json
{
    "error": "<error message>"
}
```

