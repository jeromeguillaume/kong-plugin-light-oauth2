local typedefs = require "kong.db.schema.typedefs"

return {
	name = "light-oauth2",
	fields = {
		{ protocols = typedefs.protocols },
		{ config = {
				type = "record",
				fields = {
					{ api_idengieb2c_claim = {type = "string", required = true, default = "idB2C" }},
					{ api_claims_to_copy = {type = "array", required = true, elements = {type = "string"}, default = {"listeReferenceSI"}}},
					{ api_refssi_identites_rattachees_url = typedefs.url({ required = true}) },
					{ auth_domain = {type = "string", required = true, default = "engie" }},
					{ expires_in = { type = "number", required = true, default = 1800 }},
					{ iss = typedefs.url({ required = true, default = "https://kong-gateway:8443/auth/engie"}) },
					{ jku = typedefs.url({ required = true, default = "https://kong-gateway:8443/auth/engie/jwks"}) },
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