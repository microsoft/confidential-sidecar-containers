# Secure Key Release (SKR)

The ```skr``` tool instantiates a web server ( <http://localhost>:<port>) which exposes a REST API so that other containers can retrieve raw attestation via the `attest/raw` POST method and MAA token via the `attest/maa` POST method as well as release secrets from Azure Key Vault service via the `key/release` POST method.

The tool can be executed using the script [skr.sh](https://github.com/Microsoft/confidential-sidecar-containers/blob/main//docker/skr/skr.sh).
If the port number is not specified, the port will default to 8080.
This script take the environment variables `SkrSideCarArgs`, `Port`, `LogFile`, and `LogLevel` and passes them into `/bin/skr` with their corresponding flags.

To use the GRPC server instead of the HTTP server, the tool can be executed using the same script [skr.sh](https://github.com/Microsoft/confidential-sidecar-containers/blob/main//docker/skr/skr.sh).
But instead expecting the environment variables `Port`, `ServerType`, `LogFile`, and `LogLevel` and passes them into `/bin/skr` with their corresponding flags, where `Port` is specified as `50000`.

## HTTP API

The `status` GET method returns the status of the server.
The response carries a `StatusOK` header and a payload of the following format:

```json
{
    "message": "STATUS OK"
}

{
    "message": "STATUS NOT OK"
}
```

The `attest/raw` and `attest/combined` POST methods expect JSON of the following format:

```json
{
    "runtime_data": "<Base64-encoded blob; the hash digest of the blob will be presented as report data in the raw attestation report>"
}
```

`runtime_data` is to guarantee the freshness of the attestation report.
We put the `runtime_data` in the attestation report request and then we can check the whole signed report contains the same data we just put in.
This field is for preventing replay attack.

Upon success, the `attest/raw` POST method response carries a `StatusOK` header and a payload of the following format:

```json
{
    "report": "<hex format of raw hardware attestation report>"
}
```
The `attest/combined` response payload contains all the fields required to support a full key release.

```json
{
	"endorsed_tcb": "64 bit hex encoded TCB field",
	"endorsements": "base64 encoded certificate chain",
	"evidence": "base64 encoded attestation report",
	"uvm_endorsements": "base64 encoded uvm reference info COSESign1 document",
}
```

Upon error, the `attest/raw` and `attest/combined` POST methods response carry a `BadRequest` or `StatusForbidden` header and a payload of the following format:

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

Upon success, the `attest/maa` POST method response carries a `StatusOK` header and a payload of the following format:

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

Upon success, the `key/release` POST method response carries a `StatusOK` header and a payload of the following format:

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

Additionally, the ```skr``` tool instantiates a GRPC server that can be accessed by running grpcurl commands.
The GRPC server exposes the following methods:

## GRPC API

The `<ip:port> list` command lists the services exposed on a specific IP address and port.

```bash
grpcurl -v -plaintext 127.0.0.1:50000 list
```

The `<ip:port> list <service-name>` command lists the exposed APIs under a specific service on a specific IP address and port.

```bash
grpcurl -v -plaintext 127.0.0.1:50000  list key_provider.KeyProviderService
```

The `SayHello` method of the KeyProviderService is used to test whether APIs under KeyProviderService can be reached.

```bash
grpcurl -v -plaintext -d '{"name":"This is a GRPC test!"}' 127.0.0.1:50000  key_provider.KeyProviderService.SayHello
```

The `GetReport` method of the KeyProviderService is used to get the SNP report in hex string format.
Users can optionally provide `report_data_hex_string` and the input will show under report data section of the SNP report.

```bash
grpcurl -v -plaintext -d '{"report_data_hex_string":""}' 127.0.0.1:50000  key_provider.KeyProviderService.GetReport
```

The `GetAttestationData` method of the KeyProviderService is used to get the combined attestation data similar to the HTTP `attest/combined` endpoint.
Users can optionally provide `b64_runtime_data_string` to prevent replay attacks by guaranteeing the freshness of the attestation report.

```bash
grpcurl -v -plaintext -d '{"b64_runtime_data_string":""}' 127.0.0.1:50000  key_provider.KeyProviderService.GetAttestationData
```

The `UnWrapKey` method of the KeyProviderService is used to test whether the key can be released.

```bash
AAA=`printf skr | base64 -w0`

ANNO=`cat wrapped`

REQ=`echo "{\"op\":\"keyunwrap\",\"keywrapparams\":{},\"keyunwrapparams\":{\"dc\":{\"Parameters\":{\"attestation-agent\":[\"${AAA}\"]}},\"annotation\":\"${ANNO}\"}}" | base64 -w0`

grpcurl -plaintext -d "{\"key_provider_key_wrap_protocol_input\":\"${REQ}\"}" 127.0.0.1:50000 key_provider.KeyProviderService.UnWrapKey
```
