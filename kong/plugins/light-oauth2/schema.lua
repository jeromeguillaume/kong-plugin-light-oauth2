local typedefs = require "kong.db.schema.typedefs"

return {
	name = "light-oauth2",
	fields = {
		{ protocols = typedefs.protocols },
		{ config = {
				type = "record",
				fields = {
					{ api_id_claim = {type = "string", required = true, default = "clientId" }},
					{ api_claims_to_copy = {type = "array", required = true, elements = {type = "string"}, default = {"products"}}},
					{ api_url = typedefs.url({ required = true, default= "https://domain.com/restApi"}) },
					{ api_url_query_param = {type = "string", required = true, default = "paramClientId" }},
					{ auth_domain = {type = "string", required = true, default = "mydomain" }},
					{ expires_in = { type = "number", required = true, default = 1800 }},
					{ iss = typedefs.url({ required = true, default = "https://kong-gateway:8443/auth/mydomain"}) },
					{ jku = typedefs.url({ required = true, default = "https://kong-gateway:8443/auth/mydomain/jwks"}) },
					{ jwt_header_downstream = typedefs.header_name {required = false}},
					{ jwt_header_upstream = typedefs.header_name {required = true, default="Authorization"}},										
					{ private_jwk = {type = "string", required = true, encrypted = true, default = "{\"kty\": \"RSA\",\"kid\": \"kong\",...<***CHANGE_ME***>}"}},
					{ role = {required = true, type = "string", default = "tokenExchange",
						one_of = {
							"tokenExchange",
							"revoke",
							"introspect",
						},
					},},
					{ verbose = { type = "boolean", default = false }},
				},
			},
		}
	}
}