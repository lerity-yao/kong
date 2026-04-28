local cjson = require "cjson.safe"
local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local kong_meta = require "kong.meta"


local kong = kong
local tostring = tostring
local type = type


---
-- JWT Claims Header plugin
--
-- This plugin runs AFTER the JWT plugin (PRIORITY 800 < JWT's 1450).
-- It reads the authenticated JWT token stored by the JWT plugin in
-- kong.ctx.shared.authenticated_jwt_token, decodes its claims,
-- and forwards them as upstream request headers.
--
-- Two modes (mutually exclusive, controlled by forward_all_claims switch):
--   1. forward_all_claims = true  → Forward ALL claims as X-JWT-Claims JSON header
--   2. forward_all_claims = false → Forward SPECIFIC claims as individual headers
---
local JwtClaimsHeaderHandler = {
  VERSION = kong_meta.version,
  PRIORITY = 800,  -- Must be < 1450 (JWT plugin) to run after JWT authentication
}


function JwtClaimsHeaderHandler:access(conf)
  -- Read the JWT token stored by the JWT plugin
  local token = kong.ctx.shared.authenticated_jwt_token
  if not token then
    return  -- No JWT token found; JWT plugin may not be enabled or auth failed
  end

  -- Decode the JWT token to extract claims (no signature verification needed,
  -- the JWT plugin already verified it)
  local jwt, err = jwt_decoder:new(token)
  if err then
    kong.log.err("failed to decode JWT token: ", err)
    return
  end

  local claims = jwt.claims
  if not claims or type(claims) ~= "table" then
    return
  end

  -- Mode 1: forward_all_claims switch ON → forward all claims as X-JWT-Claims JSON header
  if conf.forward_all_claims then
    local claims_json, json_err = cjson.encode(claims)
    if json_err then
      kong.log.err("failed to encode JWT claims to JSON: ", json_err)
    else
      kong.service.request.set_header("X-JWT-Claims", claims_json)
    end

  -- Mode 2: forward_all_claims switch OFF → forward specific claims as individual headers
  elseif conf.claims_to_forward and #conf.claims_to_forward > 0 then
    local prefix = conf.header_prefix or "X-JWT-Claim-"
    for _, claim_name in ipairs(conf.claims_to_forward) do
      local claim_value = claims[claim_name]
      if claim_value ~= nil then
        kong.service.request.set_header(prefix .. claim_name, tostring(claim_value))
      end
    end
  end
end


return JwtClaimsHeaderHandler
