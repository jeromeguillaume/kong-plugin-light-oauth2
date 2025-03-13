local lightOAuth2 = {
    PRIORITY = 1025,
    VERSION = '1.0.0',
  }

local genericErrMsg = "You are not authorized to access to this service"
local cjson         = require "cjson.safe"
local shared        = ngx.shared
local cjson_encode  = cjson.encode
local cjson_decode  = cjson.decode
local shared        = ngx.shared
local dict          = shared['kong']

---------------------------------------------------------------------------------------------------
-- Set JWT in cache
---------------------------------------------------------------------------------------------------
local function setTokenCache(plugin_conf, signedJwt, jti, exp)
  
  local err
  local succ
  local jsonJWT = cjson_encode(signedJwt)
  if not jsonJWT then
    err = "Could not encode signed JWT object jti=" .. jti
  end
  if not err then
    succ, err = dict:set(jti, jsonJWT, exp)
    if err then
      err = "Error set in dict the JWT jti=" .. err
    end
  end
  return err
end

---------------------------------------------------------------------------------------------------
-- Delete JWT from cache
---------------------------------------------------------------------------------------------------
local function deleteTokenCache(plugin_conf, jti)  
  dict:delete(jti)
  return false
end

---------------------------------------------------------------------------------------------------
-- Get JWT in cache
---------------------------------------------------------------------------------------------------
local function getTokenCache(plugin_conf, jti)

  -- check if entry actually exists
  local req_json, err = dict:get(jti)
  if not req_json then
    if not err then
      kong.log.debug("jti=" ..jti.." JWT not in cache")
      return nil, false
    else
      kong.log.error("jti=" ..jti.." JWT cache error: " .. err)
      return nil, true
    end
  end

  -- decode object from JSON to table
  local req_obj = cjson_decode(req_json)
  if not req_json then
    kong.log.error("jti=" ..jti.." JWT cjson_decode error: ")
    return nil, true
  end

  kong.log.debug("jti=" ..jti.." JWT successfully got from cache: "..req_obj)
  return req_obj, false
  
end

---------------------------------------------------------------------------------------------------
-- Enrich the JWT from the 'external-rest-api' REST API
---------------------------------------------------------------------------------------------------
local function enrichFromRefssiIdentitesRattachees(plugin_conf, jwt_payload)
  
  local utils = require "kong.tools.utils"
  local http = require "resty.http"
  local httpc = http.new()
  local errMsg  

  kong.log.debug('plugin_conf.api_id_claim: ' .. plugin_conf.api_id_claim)
  kong.log.debug('jwt_payload[plugin_conf.api_id_claim]: ' .. (jwt_payload[plugin_conf.api_id_claim] or 'nil'))
  kong.log.debug("Send HTTP request to: '" .. 
                  plugin_conf.api_url .. 
                  "' with "..plugin_conf.api_url_query_param.."='"..(jwt_payload[plugin_conf.api_id_claim] or 'nil').."'")
  
  if not jwt_payload[plugin_conf.api_id_claim] then
    return nil, "Unable to find '"..plugin_conf.api_id_claim.."' claim in the input JWT"
  end

  local res, err = httpc:request_uri(plugin_conf.api_url, { 
      method = "GET",
      headers = {
          ["Content-Type"] = "application/json",
          ["Authorisation"] = kong.request.get_header('Authorisation'),
          ["X-Correlation-Id"] = utils.uuid()
      },
      query = { 
        [plugin_conf.api_url_query_param]=jwt_payload[plugin_conf.api_id_claim]
      },
      keepalive_timeout = 10,
      keepalive_pool = 10
      })
  
  if err then
    errMsg = "Response Error url='" .. plugin_conf.api_url .. "', err='".. err .. "'"
  elseif res.status ~= 200 then
    errMsg = "Response Error url='" .. plugin_conf.api_url .. "', httpStatus='".. res.status .. "', body='" .. (res.body or 'nil') .. "'"
  else
    local cjson = require("cjson.safe").new()
    local api_json, err = cjson.decode(res.body)
    -- If we failed to base64 decode
    if err then
      errMsg = "Unable to decode JSON url='" .. plugin_conf.api_url .. "', err='".. err .. "'"
    else
      kong.log.debug("Response Ok url='" .. plugin_conf.api_url .. "', httpStatus='".. res.status .. "', body='" .. (res.body or 'nil') .. "'")
      -- Enrich the JWT claims by using 'external-rest-api" REST API
      for i = 1, #plugin_conf.api_claims_to_copy do
        if api_json[plugin_conf.api_claims_to_copy[i]] then
          jwt_payload [plugin_conf.api_claims_to_copy[i]] = api_json[plugin_conf.api_claims_to_copy[i]]
        else
          errMsg = "Unable to get claim value: '" .. plugin_conf.api_claims_to_copy[i] .. "'"
          break
        end
      end
    end
  end
  return jwt_payload, errMsg
end

---------------------------------------------------------------------------------------------------
-- Craft the JWT 'x-mydomain-jwt' and Sign it having a JWS
---------------------------------------------------------------------------------------------------
local function jwtCrafterSigner(data, plugin_conf)
  
  local jwt   = require("resty.jwt")
  local pkey  = require("resty.openssl.pkey")
  local json  = require("cjson")
  local errFunc = {}
  local error_verbose
  local algorithm
  local signingKey
  local pk
  local err
  local ok
  local privateJwkJson
  local jwt_token
  
  -- Convert Private Key to JSON
  ok, privateJwkJson = pcall(json.decode, plugin_conf.private_jwk)
  -- If there is an error during the JWT signature
  if ok == false then
    err = true
    error_verbose = "Unable to JSON decode the private key, error: '" .. privateJwkJson .. "'"
  end

  -- Convert the private JWK key to a PEM format
  if not err then
    algorithm = privateJwkJson.alg
    if privateJwkJson.alg == 'RS256' or privateJwkJson.alg == 'RS512' then
      pk, err = pkey.new(plugin_conf.private_jwk, {formats = "JWK", type = "*"})
      if err then
        error_verbose = "Unable to load the JWK, error: '" .. err .. "'"
      else
        signingKey, err = pk:tostring("PrivateKey", "PEM", false)
        if err then
          error_verbose = "Unable to output the JWK key to PEM format, error: '" .. err .. "'"
        else
          kong.log.debug("RSA - JWK converted to PEM: " .. signingKey)
        end
      end
    elseif privateJwkJson.alg == 'HS256' or privateJwkJson.alg == 'HS512' then
      signingKey = privateJwkJson.k
      kong.log.debug("HMAC - JWK key: " .. signingKey)
    else
      err = true
      local alg = privateJwkJson.alg or ''
      error_verbose = "Unknown algorithm '" .. alg .. "'"
    end
  end

  if not err then
    local jwt_obj = {}
    jwt_obj.header = {
      typ = "JWT",
      alg = privateJwkJson.alg,
      kid = privateJwkJson.kid,
      jku = plugin_conf.jku
    }
    jwt_obj.payload = data

    -- Sign the JWT for having a JWS
    ok, jwt_token = pcall(jwt.sign, self, signingKey, jwt_obj)

    -- If there is an error during the JWT signature
    if ok == false then
      err = true
      
      if jwt_token and jwt_token.reason then
        error_verbose = jwt_token.reason
      elseif jwt_token then
        error_verbose = jwt_token
      else
        error_verbose = "Unknown JWT signature error"
      end
    end
  end
  -- If there is an error on JWK to PEM conversion
  if err then
    kong.log.err (error_verbose)
    errFunc.error = genericErrMsg
    if plugin_conf.verbose then
      errFunc.error_verbose = error_verbose
    end
    return nil, errFunc
  end
  return jwt_token, errFunc

end

-----------------------------------------------------------------------------------------------
-- Get Payload from an Authorization Token (JWT)
-- The JWT has 3 parts, separated by a dot: Header.Payload.Signature
-----------------------------------------------------------------------------------------------
  local function get_JWT_payload (jwt_auth_token)
  local jwt_payload
  local utils = require "kong.tools.utils"
  local entries = utils.split(jwt_auth_token, ".")

  if #entries == 3 then
    jwt_payload = entries[2]
  else
    local err = "Inconsistent JWT: unable to get the typical structure Header.Payload.Signature"
    return nil, err
  end

  -- bas64 decoding of JWT payload
  local decode_base64 = ngx.decode_base64
  local decoded = decode_base64(jwt_payload)
  local cjson = require("cjson.safe").new()
  local jwt_auth_token_json, err = cjson.decode(decoded)
  -- If we failed to base64 decode
  if err then
    err = "Unable to decode JSON from JWT: '" .. err .. "'"
    return nil, err
  end

  return jwt_auth_token_json, nil
end

---------------------------------------------------------------------------------------------------
-- Prepare the JWT payload
---------------------------------------------------------------------------------------------------
local function prepareJwtPayload(plugin_conf)
  local utils = require "kong.tools.utils"
  local data = {}
  local decode_base64 = ngx.decode_base64
  local entries
  local bearer_token
  local errFunc = {}
  local error_verbose
  
  -- First try to retrieve an Authorization Header from the Request
  local authorization_header = kong.request.get_header ("Authorization")
  
  -- If we found an Authorization Header
  if authorization_header ~= nil then
    -- Try to find an 'Authorization: Bearer'
    entries = utils.split(authorization_header, "Bearer ")
    if #entries == 2 then
      bearer_token = entries[2]
      kong.log.debug("Authenticated Token retrieved successfully: " .. bearer_token)
    else
      kong.log.debug("There is no 'Authorization: Bearer' header")
    end
  else
    kong.log.debug("There is no 'Authorization' header")
  end

  -- If there is no Authorization header
  if not bearer_token then
    error_verbose = "No suitable Authentication method is found: no Bearer token"
  end
  
  -- Copy the entire content of AT to the new JWT
  if not error_verbose then
    local json_token_payload, err = get_JWT_payload (bearer_token)
    if not err then
      data = utils.deep_copy(json_token_payload, true)
    else
      -- Error: Unable to get the 'Auth token' payload
      error_verbose = "Unable to handle the 'Auth token' payload: " .. err
    end
  end

  -- Copy the entire content of AT to the new JWT
  if not error_verbose then
    data, error_verbose = enrichFromRefssiIdentitesRattachees(plugin_conf, data)
  end

  -- If there is a pending error we reject the request
  if error_verbose then
    errFunc.error = genericErrMsg
    kong.log.err(error_verbose)
    if plugin_conf.verbose then
      errFunc.error_verbose = error_verbose
    end
    return nil, errFunc
  end

  -- Set Issuer
  data.iss = plugin_conf.iss
  -- Set 'Issued at' + 'Expires In'
  data.iat = ngx.time()
  data.exp = data.iat + plugin_conf.expires_in

  -- Get API backend URL
  local service = kong.router.get_service()
  local service_port = ""
  -- If the API backend URL doesn't use the default port (80 or 443) we explicitly add it
  if tostring(service.port) ~= '80' and tostring(service.port) ~= '443' then
    service_port = ":" .. service.port
  end
  
  local path = ""
  if service.path then
    path = service.path
  end
  data.aud = service.protocol .. "://" .. service.host .. service_port .. path
  data.jti = utils.uuid()

  return data, errFunc
end

---------------------------------------------------------------------------------------------------
-- Craft a new JWT from an existing JWT and put in the Kong GW Cache
---------------------------------------------------------------------------------------------------
local function createToken(plugin_conf)
  
  local crafted_x_custom_jwt
  local error_verbose

  -- Get the Authentication and Prepare the JWT payload
  local data, errFunc = prepareJwtPayload(plugin_conf)
  if not errFunc.error then
    -- Sign the JWT for having a JWS
    crafted_x_custom_jwt, errFunc = jwtCrafterSigner(data, plugin_conf)
  end

  -- Set the new JWT in the cache    
  if not errFunc.error then
    error_verbose = setTokenCache(plugin_conf, crafted_x_custom_jwt, data.jti, data.exp)
    if error_verbose then
      errFunc.error = genericErrMsg
      kong.log.err(error_verbose)
      if plugin_conf.verbose then
        errFunc.error_verbose = error_verbose
      end
    end
  end
  
  -- Set the new JWT to an Upstream or Downstream HTTP Header
  if not errFunc.error then
    -- Set the new JWT to an Upstream HTTP Header (potentially overwriting the existing header)
    if plugin_conf.jwt_header_upstream then
      -- If HTTP Header is 'Authorization' we add the 'Bearer' type
      if plugin_conf.jwt_header_upstream == "Authorization" then
        crafted_x_custom_jwt = 'Bearer ' .. crafted_x_custom_jwt
      end
      kong.service.request.set_header(plugin_conf.jwt_header_upstream, crafted_x_custom_jwt)
    end

    -- Set the new JWT to a Downstream HTTP Header (potentially overwriting the existing header)
    if plugin_conf.jwt_header_downstream then
      kong.response.set_header(plugin_conf.jwt_header_downstream, crafted_x_custom_jwt)
    end

  end  

  if not errFunc.error then
    kong.log.debug("JWT successfully crafted and Added on Header: '".. (plugin_conf.jwt_header_upstream or 'nil') .. "'"
                    .. " JWT: '" .. crafted_x_custom_jwt .. "'")
  end
  return errFunc
end

---------------------------------------------------------------------------------------------------
-- Introspect the JWT: checking the presence of the JWT in the Kong cache
---------------------------------------------------------------------------------------------------
local function introspectToken(plugin_conf)
  local errFunc = {}
  local error_verbose
  local err
  local json_token_payload
  local jwt_cached
  local response = {}
  local bearer_token
  local utils = require "kong.tools.utils"

  local body, error_verbose = kong.request.get_body("application/x-www-form-urlencoded")

  -- If the Body parameters are not set correctly
  if  not error_verbose and (not body or
      (body and
        (body.token_type_hint ~= "access_token" or
         body.token == "" or body.token == nil)
      )) then
    error_verbose = "Parameters 'token_type_hint' or 'token' not specified"
  end

  -- Get the JWT Payload
  if not error_verbose then
    json_token_payload, err = get_JWT_payload (body.token)
    if err then
      error_verbose = "Unable to handle the 'Authorization Bearer' payload: " .. err
    end
  end

  -- Check the presence of the JWT in the Kong cache
  if not error_verbose then
    jwt_cached, err = getTokenCache(plugin_conf, json_token_payload.jti)

    if err then
      error_verbose = "An unexpected error occurred getting cache JWT with jti: '" .. (json_token_payload.jti or 'nil').."'"
    
    -- Else If the token is found in the cache      
    elseif jwt_cached then
      response = utils.deep_copy(json_token_payload, true)
      -- If JWT in the cache and in the '/introspect' endpoiunt are the same
      if jwt_cached == body.token then
        response.active = true
      else
        -- The JWT is altered in comparison with the one in the cache
        -- Note: normally this code shouln't be executed because the '/introspect' is protected by JWT plugin or OIDC
        response.active = false
      end
      
    else
      -- Token is not found in the cache
      response.active = false
    end

  end

  -- If there is an error
  if error_verbose then
    errFunc.error = genericErrMsg
    kong.log.err(error_verbose)
    if plugin_conf.verbose then
      errFunc.error_verbose = error_verbose
    end
  else
    kong.log.debug("Successful JWT Introspection for '"..plugin_conf.auth_domain.."' domain and jti: '" ..json_token_payload.jti.."'")
  end
  
  return response, errFunc
end

---------------------------------------------------------------------------------------------------
-- Revoke the JWT: remove the JWT in the Kong cache
-- Revoking a token that is invalid, expired, or already revoked returns a 200 OK status code to
-- prevent any information leaks (Okta source)
---------------------------------------------------------------------------------------------------
local function revokeToken(plugin_conf)
  local errFunc = {}
  local error_verbose
  local response = {}
  local json_token_payload
  local err
  local jwt_cached
  local utils = require "kong.tools.utils"
  
  local body, error_verbose = kong.request.get_body("application/x-www-form-urlencoded")
  
  -- If the Body parameters are not set correctly
  if  not error_verbose and (not body or
    (body and
      (body.token_type_hint ~= "access_token" or
      body.token == "" or body.token == nil)
    )) then
    error_verbose = "Parameters 'token_type_hint' or 'token' not specified"
  end
  
  -- Get the JWT Payload
  if not error_verbose then
    json_token_payload, err = get_JWT_payload (body.token)
    if err then
      error_verbose = "Unable to handle the 'Authorization Bearer' payload: " .. err
    end
  end

  -- Remove the JWT from cache
  if not error_verbose then
    local err = deleteTokenCache(plugin_conf, json_token_payload.jti)
    if err then
      kong.log.err ("An unexpected error occurred invalidating cache JWT with jti: '" .. (json_token_payload.jti or 'nil') .. "'")
    else
      kong.log.debug("Token with jti=" ..json_token_payload.jti.." successfully revoked or not present")
    end
  end

  -- If there is an error
  if error_verbose then
    errFunc.error = genericErrMsg
    kong.log.err(error_verbose)
    if plugin_conf.verbose then
      errFunc.error_verbose = error_verbose
    end
  end
  
  return response, errFunc
end

---------------------------------------------------------------------------------------------------
-- Executed for every request from a client and before it is being proxied to the upstream service
---------------------------------------------------------------------------------------------------
function lightOAuth2:access(plugin_conf)
  local errFunc = {}
  local response = {}
  -- Token Exchange
  if plugin_conf.role == "tokenExchange" then
    errFunc = createToken(plugin_conf)
  -- Introspection
  elseif plugin_conf.role == "introspect" then
    response, errFunc = introspectToken(plugin_conf)
    if not errFunc.error then
      return kong.response.exit(200, response, {["Content-Type"] = "application/json"})
    end
  -- Revocation
  elseif plugin_conf.role == "revoke" then
    response, errFunc = revokeToken(plugin_conf)
    if not errFunc.error then
      return kong.response.exit(200, nil, {["Content-Type"] = "application/json"})
    end
  end
  
  -- If there is an error
  if errFunc.error then
    return kong.response.exit(401, errFunc,  {["Content-Type"] = "application/json"})
  end
  
end 

return lightOAuth2