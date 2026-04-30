local typedefs = require "kong.db.schema.typedefs"

return {
  name          = "admins",
  primary_key   = { "id" },
  endpoint_key  = "username",
  cache_key     = { "username" },
  dao           = "kong.db.dao.admins",
  generate_admin_api = false,

  fields        = {
    { id = typedefs.uuid },
    { created_at = typedefs.auto_timestamp_s },
    { updated_at = typedefs.auto_timestamp_s },
    { username = { type = "string", required = true, unique = true } },
    { email = { type = "string" } },
    { password_hash = { type = "string" } },           -- bcrypt hash
    { custom_id = { type = "string" } },
    { rbac_token_enabled = { type = "boolean", required = true, default = true } },
    { status = { type = "integer", required = true, default = 1 } },  -- 0=invited, 1=active
    { invite_token = { type = "string", unique = true } },
    { roles = {
        type = "array",
        elements = { type = "foreign", reference = "rbac_roles" },
      },
    },
  },
}
