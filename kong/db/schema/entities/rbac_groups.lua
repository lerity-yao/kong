local typedefs = require "kong.db.schema.typedefs"

return {
  name          = "rbac_groups",
  primary_key   = { "id" },
  endpoint_key  = "name",
  cache_key     = { "name" },
  dao           = "kong.db.dao.rbac_groups",
  generate_admin_api = false,

  fields        = {
    { id = typedefs.uuid },
    { created_at = typedefs.auto_timestamp_s },
    { updated_at = typedefs.auto_timestamp_s },
    { name = { type = "string", required = true, unique = true } },
    { comment = { type = "string" } },
    { roles = {
        type = "array",
        elements = { type = "foreign", reference = "rbac_roles" },
      },
    },
  },
}
