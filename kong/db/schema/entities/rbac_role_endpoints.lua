local typedefs = require "kong.db.schema.typedefs"

return {
  name          = "rbac_role_endpoints",
  primary_key   = { "id" },
  dao           = "kong.db.dao.rbac_role_endpoints",
  generate_admin_api = false,

  fields        = {
    { id = typedefs.uuid },
    { created_at = typedefs.auto_timestamp_s },
    { updated_at = typedefs.auto_timestamp_s },
    { role = { type = "foreign", reference = "rbac_roles", required = true, on_delete = "cascade" } },
    { workspace = { type = "string", default = ngx.null } },  -- null = all workspaces
    { endpoint = { type = "string", required = true } },      -- e.g. "/*", "/services/*"
    { actions = { type = "array", elements = { type = "string" }, required = true, default = { "*" } } },
    { negative = { type = "boolean", required = true, default = false } },  -- true = deny rule
  },
}
