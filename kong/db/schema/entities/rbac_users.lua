local typedefs = require "kong.db.schema.typedefs"

return {
  name          = "rbac_users",
  primary_key   = { "id" },
  endpoint_key  = "name",
  cache_key     = { "name" },
  dao           = "kong.db.dao.rbac_users",
  generate_admin_api = false,  -- custom route control

  fields        = {
    { id = typedefs.uuid },
    { created_at = typedefs.auto_timestamp_s },
    { updated_at = typedefs.auto_timestamp_s },
    { name = { type = "string", required = true, unique = true } },
    { comment = { type = "string" } },
    { user_token = { type = "string", required = true, unique = true } },
    { enabled = { type = "boolean", required = true, default = true } },
    { roles = {
        type = "array",
        elements = { type = "foreign", reference = "rbac_roles" },
      },
    },
  },
}
