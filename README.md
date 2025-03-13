# Kong plugin: `light-oauth2` Authorization Server for ENGIE
The plugin offers a Light OAuth2 Authorization Server enabling following capabilities:
1) Token Instropection
2) Token Revocation (of a single token or of all tokens)
    - The tokens are stored in a `ngx.shared` dictionary. Using Redis storage is essential to have a suitable solution running on multiple DataPlane nodes
3) Token Exchange:
    - Craft a JWT managed by the Light OAuth2 server by copying the input Bearer Authorization JWT
    - Call the `refssi-identites-rattachees` REST API for enrichment of the JWT managed by the Light OAuth2 server
    - Load the private JWK from the plugin's configuration and convert it into a PEM format
    - Sign the JWT with the PEM string for building a JWS
    - Add the JWT managed by the Light OAuth2 server to an HTTP Request Header backend API
    - Note: for the token exchange flow, the plugin `light-oauth2` doesn't check the validity of the input itself neither checking of JWT signature and JWT expiration. So it's **mandatory to use this plugin in conjunction with [OIDC](https://docs.konghq.com/hub/kong-inc/openid-connect/)**

The following endpoints are available:
  - `/auth/engie/.well-known/openid-configuration` used by [OIDC](https://docs.konghq.com/hub/kong-inc/openid-connect/) plugin
  - `/auth/engie/jwks`
  - `/auth/engie/introspect`
  - `/auth/engie/revoke`

The `/.well-known/openid-configuration` and `/jwks` endpoints are public. The `/introspect` and `/revoke` endpoints are protected by a basic Authorization.

Multiple domains can be used for providing segmentation of authorization and JWT tokens management:
- `/auth/engie/.well-known/openid-configuration`
- `/auth/other_domain1/.well-known/openid-configuration`
- `/auth/other_domain2/.well-known/openid-configuration`
- etc.

## `light-oauth2` plugin configuration reference
|FORM PARAMETER                 |DEFAULT          |DESCRIPTION                                                 |
|:------------------------------|:----------------|:-----------------------------------------------------------|
|config.api_idengieb2c_claim|idB2C|The claim name to extract the `idEngieB2C` (from a JWT) for calling `refssi-identites-rattachees` REST API with the right Id|
|config.api_claims_to_copy|listeReferenceSI|Array of JSON properties for extracting values from the `refssi-identites-rattachees` call and for injecting/enriching the JWT managed by the Light OAuth2 server|
|config.api_refssi_identites_rattachees_url|N/A|URL of the `refssi-identites-rattachees` REST API|
config.auth_domain|engie|Domain name of the Light OAuth2 server|
|config.expires_in|1800|Number of seconds for the `exp` (expiration) claim
|config.iss|https://kong-gateway:8443/auth/engie|The `iss` (issuer) claim that identifies the Light OAuth2 server|
|config.jku|https://kong-gateway:8443/auth/engie/jwks|The `jku` (JWK set Url) that points to a Kong Gateway route for delivering the JWKs|
|config.jwt_header_downstream|N/A|The Http header name where to drop the JWT managed by the Light OAuth2 server in the downstream response|
|config.jwt_header_upstream|Authorization|The Http header name where to drop the JWT managed by the Light OAuth2 server in the upstream request. It overrides any existing value. If the value is `Authorization`, the `Bearer` value is added|
|config.private_jwk|{"kty": "RSA","kid": "kong",...<***CHANGE_ME***>}|The JWK private key to sign the JWT managed by the Light OAuth2 server. The format is JSON. RS256, RS512, SH256, SH512 algorithms are supported|
|config.role|tokenExchange|Role of the plugin. Can be `Introspection`, `Recovation`, `tokenExchange`|
|config.verbose|false|Append to the Consumer a detailed message in case of error|

## High level algorithm of `light-oauth2` to craft and sign a JWT managed by the Light OAuth2 server
```lua
-- Try to find one by one an Authentication given by the Consumer
if not "Authorization: Bearer" then
  -- The Consumer's request is blocked
  return "HTTP 401", "You are not authorized to access to this service"
end

-- If the Consumer sends a correct Authentication, we craft the 'light-oauth2' JWT
-- Copy all the content of the AT (given by 'Authorization: Bearer')
light-oauth2.payload = AT.payload

-- Header values
light-oauth2.header.typ = "JWT",
light-oauth2.header.alg = "<JWK.alg>", -- Got from the alg of private JWK
light-oauth2.header.kid = "<JWK.kid>", -- Got from the kid of private JWK
light-oauth2.header.jku = "<jku>" -- Got from the plugin Configuration

-- Common claims
light-oauth2.payload.iss = "<iss>" -- Got from the plugin Configuration
light-oauth2.payload.iat = "<current time>"
light-oauth2.payload.exp = light-oauth2.payload.iat + "<expires_in>"  -- Got from the plugin Configuration
light-oauth2.payload.aud = "<url>" -- the Backend_Api URL
light-oauth2.payload.jti = "<uuid>" -- Generation of a 'Universally unique identifier'

-- Call the 'refssi-identites-rattachees' REST API
-- The Bearer Authorisation header is got from the Request and is added
-- The `idEngieB2C` query parameter is got from the JWT claim
local res, err = httpc:request_uri(plugin_conf.api_refssi_identites_rattachees_url, ...)
if not err then
  -- Add claims retrieved by 'refssi-identites-rattachees' REST API for JWT enrichment
  light-oauth2.payload.api_claims_to_copy = resp(api_claims_to_copy)
else
  -- The Consumer's request is blocked
  return "HTTP 401", "You are not authorized to access to this service"
end
-- Sign the JWT with a private JWK (set in the plugin configuration) for building a JWS 
jws_x_engie_jwt = jwt:sign (light-oauth2, private_jwk)

-- Add the JWT managed by the Light OAuth2 server in an HTTP header to the request's headers before sending the request to the Backend API
kong.service.request.set_header(plugin_conf.jwt_header_upstream, jws_x_engie_jwt)
```
## Deploy and configure the `light-oauth2` plugin for Kong EE/Konnect and the Kong Gateway
### Prerequisites
**In this repo, there is the [kong-light-oauth2.yaml](./decK/kong-light-oauth2.yaml) decK file related to the prerequisites and following examples.** If you prefrer you can do `deck gateway sync` and avoid manual declaration as explained below. Once the `deck gateway sync` is done, set the password of the `admin@engie.com` consumer with this value: `Engie!2025`

1) Prepare the RSA256 JWK for getting the Public and Private Keypair
- You can use the JWK keypair provided in this repo:
  - JWKS Public Keys (JSON Web Key Set) Public Key: [RS256-jwks-public.json](./test-keys/RS256-jwks-public.json)
  - JWK Private Key: [RS256-jwk-private.json](./test-keys/RS256-jwk-private.json)
- **Or** create your own JWK keypair: go for instance to https://mkjwk.org/ site and configure the online tool with following values:
  - key Size: `2048`
  - Key Use: `Signature`
  - Algorithm: `RS256`
  - Key-ID (kid): `kong`
- Click on Generate, copy to clipboard the `Public and Private Keypair` (i.e. Private Key) and the `Public Key`
2) Install [http.ie](https://httpie.io/)
3) For Konnect: create a Control plane called for instance `cp-engie-light-oauth2`
4) For Kong EE and Konnect:
  - Install the [Kong Gateway](https://docs.konghq.com/gateway/latest/install/) (For Konnect: attach the Gateway to the Control Plane)
  - Install the `light-oauth2` plugin by following the documentation, [here](https://docs.konghq.com/konnect/gateway-manager/plugins/add-custom-plugin/)
  - Create the Admin consumer of the Light OAuth2 server
    - Username: `admin@engie.com`
  - Add 3 x credentials to `admin@engie.com`:
    - `ACL` credential: 
      - Group: `admin`
    - `Basic Authentication` credential: 
      - Username: `admin@engie.com`
      - Password: `Engie!2025`
    - `JWT` credential: 
      - Key: `https://kong-gateway:8443/auth/engie` (this should have the same value as the `ìss` claim)
      - Algorithm: `RS256`
      - RSA Public.Key: 
        - Get the content of [RS256-public.pem](./test-keys/RS256-public.pem) **or**
        - Build a PEM file from JWK public key by using the [convert-RSA-JWK-to-PEM.js](test-keys/convert-RSA-JWK-to-PEM.js)  node.js tool:
        ```
        node convert-RSA-JWK-to-PEM.js RS256-jwk-public.json
        ```
        - Put the content in a `.pem` file by including `-----BEGIN PUBLIC KEY-----` and `-----END PUBLIC KEY-----`
      - Note: For HMAC Algorithm:
        - Get the `k` content of [SH256-jwk-symetric-key.json](./test-keys/SH256-jwk-symetric-key.json)
  - Create in the Engie IdP (example: Okta) a Client and a User for testing the `Client Credentials` grant and the `Authorization Code Flow`, for instance `contact@konghq.com`
    
### Create the JWKS route: `/auth/engie/jwks`
Create a Route to deliver the public JWKS:
- The Route has the following properties:
  - name=`light-oauth2-jwks`
  - path=`/auth/engie/jwks`
  - Click on `Save`
- Add the `Request Termination` plugin to the Route with:
  - `config.status_code`=`200`
  - `config.content_type`=`application/json`
  - `config.body`=copy/paste the content of [RS256-jwks-public.json](./test-keys/RS256-jwks-public.json) **Or**
  - `config.body`=**The `Public JWK Key` must be pasted from https://mkjwk.org/ and add `"keys": [` property for having a JWKS**. If needed, adapt the `kid` to a custom value. JWKS Structure:
    ```json
    {
      "keys": [
        {
          *****  CHANGE ME WITH THE PUBLIC JWK *****
        }
      ]
    }
    ```
  - Click on `Save`
- Add the `CORS` plugin to the Route with:
  - config.origins=`*`
  - Click on `Save`

### Create the Introspection route: `/auth/engie/introspect`
Create a Route to introspect the JWT crafted by the Light OAuth2 server:
- The Route has the following properties:
  - name=`light-oauth2-introspect`
  - path=`/auth/engie/introspect`
  - Click on `Save`
- Add the `light-oauth2` plugin to the Route with:
  - Default parameters
  - `config.api_refssi_identites_rattachees_url`=https://kong-gateway:8443 (not used)
  - `config.role`=`introspect`
- Add the `Basic Authentication` plugin to the Route with default parameters
- Add the `ACL` plugin to the Route with:
  - `congig.allow`=`admin`
- Add the `Kong Functions (Pre-Plugins)` plugin to the Route with:
  - `config.access`=
  ```lua
  -- Add 'x-light-oauth2' header from AuthZ header for JWT plugin
  local body, error = kong.request.get_body("application/x-www-form-urlencoded")
  -- If the Body parameters are not set correctly
  if  not error and (not body or (body and body.token == "" or body.token == nil)) then
      error = "Parameters 'token_type_hint' or 'token' not specified"
  end
  if not error then
    kong.service.request.set_header("x-light-oauth2", "Bearer "..body.token)
  else
    kong.log.err("Unable to get the JWT token, err:" .. error)
  end
  ```
- Add the `JWT` plugin to the Route with:
  - `config.claims_to_verify`=`exp`
  - `config.header_names`=`x-light-oauth2`
  - `config.key_claim_name`=`iss`

### Create the Revoke route: `/auth/engie/revoke`
Create a Route to Revoke the JWT crafted by the Light OAuth2 server:
- The Route has the following properties:
  - name=`light-oauth2-revoke`
  - path=`/auth/engie/revoke`
  - Click on `Save`
- Add the `light-oauth2` plugin to the Route with:
  - Default parameters
  - `config.api_refssi_identites_rattachees_url`=https://kong-gateway:8443 (not used)
  - `config.role`=`revoke`
- Add the `Basic Authentication` plugin to the Route with default parameters
- Add the `ACL` plugin to the Route with:
  - `config.allow`=`admin`

### Create the Well-Known route: `/auth/engie/.well-known/openid-configuration`
Create a Route to provide the `/.well-known/openid-configuration` details of the Light OAuth2 server used by [OIDC](https://docs.konghq.com/hub/kong-inc/openid-connect/) plugin:
- The Route has the following properties:
  - name=`light-oauth2-well-known`
  - path=`/auth/engie/.well-known/openid-configuration`
  - Click on `Save`
- Add the `CORS` plugin to the Route with:
  - `config.origins`=`*`
- Add the `Request Termination` plugin to the Route with:
  - `config.status_code`=`200`
  - `config.content_type`=`application/json`
  - `config.body`=
  ```json
  {
    "issuer": "https://kong-gateway:8443/auth/engie",
    "jwks_uri": "https://kong-gateway:8443/auth/engie/jwks",
    "introspection_endpoint": "https://kong-gateway:8443/auth/engie/introspect", "introspection_endpoint_auth_methods_supported": [ 
        "client_secret_basic"
    ],
    "introspection_endpoint_auth_signing_alg_values_supported": [
        "HS256",
        "HS512",
        "RS256",
        "RS512"
    ],
    "revocation_endpoint": "https://kong-gateway:8443/auth/engie/revoke",
    "revocation_endpoint_auth_methods_supported": [
      "client_secret_basic"
    ],
    "revocation_endpoint_auth_signing_alg_values_supported": [
        "HS256",
        "HS512",
        "RS256",
        "RS512"
    ]
  }
  ```
### If needed, mock the `Refssi Identites Rattachees` REST API
1) Create a Route wtih:
  - name=`mocking-RefssiIdentitesRattachees`
  - path=`/refssi-identites-rattachees`
  - Click on `Save`
2) Add the `Mocking` plugin to the Route with:
  - config.api_specification=put this spec: [RefssiIdentitesRattachees.yaml](/RefssiIdentitesRattachees/swagger.yaml)
  - Click on `Save`

### Configure the `light-oauth2` plugin for **Crafting** a new JWT on Token Exchange
1) Create a Gateway Service
- For `httpbin` service, add a Gateway Service with:
  - name=`httpbin-light-oauth2`
  - URL=`http://httpbin.apim.eu/anything` 
  - Click on `Save`
2) Add a Route to the Service with:
  - name=`httpbin-login-lightoauth2` 
  - path=`/light-oauth2/login`
  - Click on `Save`
3) Add `OIDC` plugin to the Route with the properties of the Engie IdP (example: Okta):
  - config.client_id=`<adapt the client_id to your client_id>`
  - config.client_secret=`<adapt the client_id to your client_secret>`
  - config.issuer=`<adapt the URL to your IdP>` (example: https://sso.apim.eu:8443/auth/realms/Jerome/.well-known/openid-configuration)
  - config.auth_methods=`authorization_code`, `client_credentials`, `introspection`
4) Add `light-oauth2` plugin to the Route with:
  - config.api_idengieb2c_claim=`idB2C`
  - config.api_claims_to_copy=`listeReferenceSI` and `listeIdEngieB2CRattachees`
  - config.api_refssi_identites_rattachees_url=`<adapt the URL to your environment>` (example: `https://kong-gateway:8443/refssi-identites-rattachees` for the mocked API created above)
  - config.auth_domain=`engie`
  - config.iss=`<adapt the URL to your environment>` (example: https://kong-gateway:8443/auth/engie)
  - config.jku=`<adapt the URL to your environment>` (example: https://kong-gateway:8443/auth/engie/jwks)
  - config.private_jwk=copy/paste the content of [RS256-jwk-private.json](./test-keys/RS256-jwk-private.json) **Or**
  - config.private_jwk=paste the `Public and Private Keypair` from https://mkjwk.org/. If needed, adapt the `kid` to a custom value; the `kid` value must be the same as defined in `Prerequisites` heading (see the configuration of `Request Termination` plugin)
  - config.verbose=`true`

### Configure the `light-oauth2` plugin for **Validating** the new JWT with OIDC plugin
1) Add a Route to the `httpbin-light-oauth2` Gateway Service with:
  - name=`httpbin-access-lightoauth2` 
  - path=`/light-oauth2/access`
  - Click on `Save`
2) Add `OIDC` plugin to the Route with the properties of the Engie IdP (example: Okta):
  - config.client_id=`admin@engie.com`
  - config.client_secret=`Engie!2025`
  - config.issuer=`https://kong-gateway:8443/auth/engie/.well-known/openid-configuration`
  - config.auth_methods=`introspection`
  - config.introspect_jwt_tokens=`true`
  - introspection_endpoint_auth_method=`client_secret_basic`

## How to test the `light-oauth2` plugin for a Token Exchange and for Client Credentials Grant
- `Request` by using the Client created in ypur IdP:
  ```shell
  http --verify=no -a contact@konghq.com:<**YOUR_PASSWORD**> https://kong-gateway:8443/light-oauth2/login
  ```
  or
  ```shell
  http --verify=no https://kong-gateway:8443/light-oauth2/access Authorization:'Bearer eyJraWQiOiJrb25nIiwiamt1IjoiaHR0cHM6Ly9rb25nLWdhdGV3YXk6ODQ0My9hdXRoL2VuZ2llL2p3a3MiLCJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXAiOiJCZWFyZXIiLCJzdWIiOiJjYzE2M2ZmNS1iZmMxLTRkNmYtYTFjMS02YjAzZTI5NWY2MmYiLCJhY3IiOiIxIiwiY2xpZW50SWQiOiJjb250YWN0QGtvbmdocS5jb20iLCJjbGllbnRIb3N0IjoiOTAuMy42Ni4yMjciLCJjbGllbnRBZGRyZXNzIjoiOTAuMy42Ni4yMjciLCJsaXN0ZVJlZmVyZW5jZVNJIjpbeyJhcHBsaWNhdGlvbiI6IiIsImVudGl0ZSI6Ik1GelVGb1lIOEpTNDJlNk1jQ05uIiwiaWRlbnRpZmlhbnRTSSI6IjBOQnZ3WnVkRDU0NzNDRCJ9XSwiYXpwIjoiY29udGFjdEBrb25naHEuY29tIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwiZGVmYXVsdC1yb2xlcy1qZXJvbWUiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwiaWF0IjoxNzQxODcxMTE5LCJpc3MiOiJodHRwczovL2tvbmctZ2F0ZXdheTo4NDQzL2F1dGgvZW5naWUiLCJleHAiOjE3NDE4NzExNDksInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJqdGkiOiJlYmYwYzI2OS1jZTQzLTQ0YzgtYTRmZS1jNzBlYWViOTZmMmMiLCJhdWQiOiJodHRwOi8vaHR0cGJpbi5hcGltLmV1L2FueXRoaW5nIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwibGlzdGVJZEVuZ2llQjJDUmF0dGFjaGVlcyI6W3siaWRFbmdpZUIyQ0ZpbHMiOiJZZFUyTUFPVHBIdFA5UGt3UzAiLCJkYXRlUmF0dGFjaGVtZW50IjoiMjAyNS0wMy0xM1QxMzowNToxOVoiLCJsaXN0ZVJlZmVyZW5jZVNJIjpbeyJhcHBsaWNhdGlvbiI6InVsTzhWRjJrIiwiZW50aXRlIjoiYWpvR0pvdmF2b1FaczAzUjRkVCIsImlkZW50aWZpYW50U0kiOiJKdUhvZkVoNW5CNU9qcmFUaWEifV19XSwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LWNvbnRhY3RAa29uZ2hxLmNvbSJ9.PG3TxIe2yp4FmizkwuPEMukRQAh76tovQhb7_RXNXKuPX4IxzVn6LLMBsZ4AvU--5xP-t-TzOEzQEfqzn5Edt3IPutbvul8YcHLn4IwQRKteP1Sncy0nwWGXpiruv2m5OczcJFb3rshKngRHD-wCyWzlsac75GGuf1E1G_nihR8mr5Hc4kgkAKpxk5Wgv0G8HJ1tiN9lXgq7iJpzzPV0lvXuVr6R8a9xYvV_TZrwNVvX_yp07uCra2pPxYTLaoJ-ZL5MUzlxgsyVVl8Dg23TSnrrYeRx513TVb3ZtN4uRDSXW5bKeHuo1xJCaMy_mgr-wtTCRSIezHTSWe642-cUZw'
  ```
- `Response`: expected value of `light-oauth2` plugin:
    * Base64 encoded:
    ```
    eyJraWQiOiJrb25nIiwiamt1IjoiaHR0cHM6Ly9rb25nLWdhdGV3YXk6ODQ0My9hdXRoL2VuZ2llL2p3a3MiLCJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXAiOiJCZWFyZXIiLCJzdWIiOiJjYzE2M2ZmNS1iZmMxLTRkNmYtYTFjMS02YjAzZTI5NWY2MmYiLCJhY3IiOiIxIiwiY2xpZW50SWQiOiJjb250YWN0QGtvbmdocS5jb20iLCJjbGllbnRIb3N0IjoiOTAuMy42Ni4yMjciLCJjbGllbnRBZGRyZXNzIjoiOTAuMy42Ni4yMjciLCJsaXN0ZVJlZmVyZW5jZVNJIjpbeyJhcHBsaWNhdGlvbiI6IiIsImVudGl0ZSI6Ik1GelVGb1lIOEpTNDJlNk1jQ05uIiwiaWRlbnRpZmlhbnRTSSI6IjBOQnZ3WnVkRDU0NzNDRCJ9XSwiYXpwIjoiY29udGFjdEBrb25naHEuY29tIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwiZGVmYXVsdC1yb2xlcy1qZXJvbWUiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwiaWF0IjoxNzQxODcxMTE5LCJpc3MiOiJodHRwczovL2tvbmctZ2F0ZXdheTo4NDQzL2F1dGgvZW5naWUiLCJleHAiOjE3NDE4NzExNDksInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJqdGkiOiJlYmYwYzI2OS1jZTQzLTQ0YzgtYTRmZS1jNzBlYWViOTZmMmMiLCJhdWQiOiJodHRwOi8vaHR0cGJpbi5hcGltLmV1L2FueXRoaW5nIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwibGlzdGVJZEVuZ2llQjJDUmF0dGFjaGVlcyI6W3siaWRFbmdpZUIyQ0ZpbHMiOiJZZFUyTUFPVHBIdFA5UGt3UzAiLCJkYXRlUmF0dGFjaGVtZW50IjoiMjAyNS0wMy0xM1QxMzowNToxOVoiLCJsaXN0ZVJlZmVyZW5jZVNJIjpbeyJhcHBsaWNhdGlvbiI6InVsTzhWRjJrIiwiZW50aXRlIjoiYWpvR0pvdmF2b1FaczAzUjRkVCIsImlkZW50aWZpYW50U0kiOiJKdUhvZkVoNW5CNU9qcmFUaWEifV19XSwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LWNvbnRhY3RAa29uZ2hxLmNvbSJ9.PG3TxIe2yp4FmizkwuPEMukRQAh76tovQhb7_RXNXKuPX4IxzVn6LLMBsZ4AvU--5xP-t-TzOEzQEfqzn5Edt3IPutbvul8YcHLn4IwQRKteP1Sncy0nwWGXpiruv2m5OczcJFb3rshKngRHD-wCyWzlsac75GGuf1E1G_nihR8mr5Hc4kgkAKpxk5Wgv0G8HJ1tiN9lXgq7iJpzzPV0lvXuVr6R8a9xYvV_TZrwNVvX_yp07uCra2pPxYTLaoJ-ZL5MUzlxgsyVVl8Dg23TSnrrYeRx513TVb3ZtN4uRDSXW5bKeHuo1xJCaMy_mgr-wtTCRSIezHTSWe642-cUZw
    ```
    * JSON decoded, **pay attention to the new claims added for enrichment `listeReferenceSI` and  `listeIdEngieB2CRattachees`**:
    ```json
    {
      "typ": "Bearer",
      "sub": "cc163ff5-bfc1-4d6f-a1c1-6b03e295f62f",
      "acr": "1",
      "clientId": "contact@konghq.com",
      "clientHost": "90.3.66.227",
      "clientAddress": "90.3.66.227",
      "listeReferenceSI": [
        {
          "application": "",
          "entite": "MFzUFoYH8JS42e6McCNn",
          "identifiantSI": "0NBvwZudD5473CD"
        }
      ],
      "azp": "contact@konghq.com",
      "realm_access": {
        "roles": [
          "offline_access",
          "default-roles-jerome",
          "uma_authorization"
        ]
      },
      "iat": 1741871119,
      "iss": "https://kong-gateway:8443/auth/engie",
      "exp": 1741871149,
      "scope": "openid email profile",
      "jti": "ebf0c269-ce43-44c8-a4fe-c70eaeb96f2c",
      "aud": "http://httpbin.apim.eu/anything",
      "email_verified": false,
      "resource_access": {
        "account": {
          "roles": [
            "manage-account",
            "manage-account-links",
            "view-profile"
          ]
        }
      },
      "listeIdEngieB2CRattachees": [
        {
          "idEngieB2CFils": "YdU2MAOTpHtP9PkwS0",
          "dateRattachement": "2025-03-13T13:05:19Z",
          "listeReferenceSI": [
            {
              "application": "ulO8VF2k",
              "entite": "ajoGJovavoQZs03R4dT",
              "identifiantSI": "JuHofEh5nB5OjraTia"
            }
          ]
        }
      ],
      "preferred_username": "service-account-contact@konghq.com"
    }
    ```

## How to use the `/introspect` and `/revoke` endpoints
### `/introspect`
- `Request`:
```shell
http --verify=no --form -a 'admin@engie.com:Engie!2025' \
POST https://kong-gateway:8443/auth/engie/introspect \
token_type_hint='access_token' \
token='eyJraWQiOiJrb25nIiwiamt1IjoiaHR0cHM6Ly9rb25nLWdhdGV3YXk6ODQ0My9hdXRoL2VuZ2llL2p3a3MiLCJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJwcmVmZXJyZWRfdXNlcm5hbWUiOiJzZXJ2aWNlLWFjY291bnQtY29udGFjdEBrb25naHEuY29tIiwidHlwIjoiQmVhcmVyIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwiZGVmYXVsdC1yb2xlcy1qZXJvbWUiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwic3ViIjoiY2MxNjNmZjUtYmZjMS00ZDZmLWExYzEtNmIwM2UyOTVmNjJmIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJhY3IiOiIxIiwiY2xpZW50SWQiOiJjb250YWN0QGtvbmdocS5jb20iLCJjbGllbnRIb3N0IjoiOTAuMy42Ni4yMjciLCJsaXN0ZVJlZmVyZW5jZVNJIjpbeyJhcHBsaWNhdGlvbiI6IkZvdnhTIiwiZW50aXRlIjoiSWZWNiIsImlkZW50aWZpYW50U0kiOiJBMFdpMDk5MjFMIn1dLCJhenAiOiJjb250YWN0QGtvbmdocS5jb20iLCJjbGllbnRBZGRyZXNzIjoiOTAuMy42Ni4yMjciLCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwiaXNzIjoiaHR0cHM6Ly9rb25nLWdhdGV3YXk6ODQ0My9hdXRoL2VuZ2llIiwiZXhwIjoxNzQxODc2NTI3LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwianRpIjoiMDhiN2ZhNTItNmY2My00OTU4LTljNTYtM2RmMGM5YWY0NzE5IiwiYXVkIjoiaHR0cDovL2h0dHBiaW4uYXBpbS5ldS9hbnl0aGluZyIsImxpc3RlSWRFbmdpZUIyQ1JhdHRhY2hlZXMiOlt7ImlkRW5naWVCMkNGaWxzIjoiSWdoeVltVzQiLCJkYXRlUmF0dGFjaGVtZW50IjoiMjAyNS0wMy0xM1QxNDowNToyN1oiLCJsaXN0ZVJlZmVyZW5jZVNJIjpbeyJhcHBsaWNhdGlvbiI6InVYMiIsImVudGl0ZSI6InBSakM1ZnZiIiwiaWRlbnRpZmlhbnRTSSI6IndBc1dFUnBlV2s0In1dfV0sImlhdCI6MTc0MTg3NDcyN30.f5yATYEj3tzuIBu8GpuJ8o_hHKq2YamTAEPMv0bRt0C3JbOGn8LVnCz_VxIvP5RiFqokPzGOlztM8BhhfvxFpgw9o6RLGtyIDEjB0Cn99QbLgPnHk_pOwWGA6JApghBObgG1JmmWTMIlIpe-84OWQAiQR3-sNEHkizuk-7QdNtEZZUmLqVXX2zH0Qqpo3iHzA7_ajSYsRrvB5562gKKM1t21JdqW5sWEpqq-ujt176rhuEbHt5x5vOxBQapxV0-1qiYmJ0glGU8Fri54y_sa4k8eT2WIu2HYvDlMJ_f6M-Yddc_iu7TBXgIaBwH72MGQUhtfRMY1A_bH3ww9IkXelg'
```
- Ok `Response`: if JWT is valid (and not expired) the JSON of JWT is returned with an extra claim **`"active": true`**
```shell
HTTP/1.1 200 OK
```
```json
{
  "acr": "1",
  "active": true,
  "aud": "http://httpbin.apim.eu/anything",
  "azp": "contact@konghq.com",
  "...etc...": "...etc..."
}
```
- Ko `Response`: if JWT has expired 
```shell
HTTP/1.1 401 Unauthorized
```
```json
{
  "exp": "token expired"
}
```
- Ko `Response`: if JWT has been revoked (and not expired)
```shell
HTTP/1.1 401 Unauthorized
```
```json
{
   "active": false
}
```

### `/revoke`
- `Request`:
```shell
http --verify=no --form -a 'admin@engie.com:Engie!2025' \
POST https://kong-gateway:8443/auth/engie/revoke \
token_type_hint='access_token' \
token='eyJraWQiOiJrb25nIiwiamt1IjoiaHR0cHM6Ly9rb25nLWdhdGV3YXk6ODQ0My9hdXRoL2VuZ2llL2p3a3MiLCJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJwcmVmZXJyZWRfdXNlcm5hbWUiOiJzZXJ2aWNlLWFjY291bnQtY29udGFjdEBrb25naHEuY29tIiwidHlwIjoiQmVhcmVyIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwiZGVmYXVsdC1yb2xlcy1qZXJvbWUiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwic3ViIjoiY2MxNjNmZjUtYmZjMS00ZDZmLWExYzEtNmIwM2UyOTVmNjJmIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJhY3IiOiIxIiwiY2xpZW50SWQiOiJjb250YWN0QGtvbmdocS5jb20iLCJjbGllbnRIb3N0IjoiOTAuMy42Ni4yMjciLCJsaXN0ZVJlZmVyZW5jZVNJIjpbeyJhcHBsaWNhdGlvbiI6IkZvdnhTIiwiZW50aXRlIjoiSWZWNiIsImlkZW50aWZpYW50U0kiOiJBMFdpMDk5MjFMIn1dLCJhenAiOiJjb250YWN0QGtvbmdocS5jb20iLCJjbGllbnRBZGRyZXNzIjoiOTAuMy42Ni4yMjciLCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwiaXNzIjoiaHR0cHM6Ly9rb25nLWdhdGV3YXk6ODQ0My9hdXRoL2VuZ2llIiwiZXhwIjoxNzQxODc2NTI3LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwianRpIjoiMDhiN2ZhNTItNmY2My00OTU4LTljNTYtM2RmMGM5YWY0NzE5IiwiYXVkIjoiaHR0cDovL2h0dHBiaW4uYXBpbS5ldS9hbnl0aGluZyIsImxpc3RlSWRFbmdpZUIyQ1JhdHRhY2hlZXMiOlt7ImlkRW5naWVCMkNGaWxzIjoiSWdoeVltVzQiLCJkYXRlUmF0dGFjaGVtZW50IjoiMjAyNS0wMy0xM1QxNDowNToyN1oiLCJsaXN0ZVJlZmVyZW5jZVNJIjpbeyJhcHBsaWNhdGlvbiI6InVYMiIsImVudGl0ZSI6InBSakM1ZnZiIiwiaWRlbnRpZmlhbnRTSSI6IndBc1dFUnBlV2s0In1dfV0sImlhdCI6MTc0MTg3NDcyN30.f5yATYEj3tzuIBu8GpuJ8o_hHKq2YamTAEPMv0bRt0C3JbOGn8LVnCz_VxIvP5RiFqokPzGOlztM8BhhfvxFpgw9o6RLGtyIDEjB0Cn99QbLgPnHk_pOwWGA6JApghBObgG1JmmWTMIlIpe-84OWQAiQR3-sNEHkizuk-7QdNtEZZUmLqVXX2zH0Qqpo3iHzA7_ajSYsRrvB5562gKKM1t21JdqW5sWEpqq-ujt176rhuEbHt5x5vOxBQapxV0-1qiYmJ0glGU8Fri54y_sa4k8eT2WIu2HYvDlMJ_f6M-Yddc_iu7TBXgIaBwH72MGQUhtfRMY1A_bH3ww9IkXelg'
```
- `Response`: Revoking a token that is invalid, expired, or previously revoked results in a 200 OK status code to avoid disclosing any sensitive information
```shell
HTTP/1.1 200
```
## Use Insomnia collection for testing
See [collection](/insomnia/Insomnia.yaml)

## Check the JWS with https://jwt.io
1) Open https://jwt.io
2) Copy/paste the `light-oauth2` header value
- If everything works correctly the jwt.io sends a `Signature Verified` message
- The public key is downloaded automatically through the `light-oauth2-jwks` route and the `Request Termination` plugin. If it's not the case, open the Browser Developer Tools and see the network tab and console tab. The classic issue is getting the JWKS by using the self-signed Kong certificate (on 8443); it's easy to fix the issue by opening a new tab, going on the `jku` request (i.e. https://kong-gateway:8443/auth/engie/jwks), clicking on Advanced and by clicking on `Proceed to`
- There is a known limitation on jwt.io with `"use": "enc"` the match isn't done correctly and the JWK is not loaded automatically: we simply have to copy/paste the public JWK directly in the `VERIFY SIGNATURE` of the web page. With `"use": "sig"` there is no restriction
![Alt text](/images/1-JWT.io.jpg "jwt.io")