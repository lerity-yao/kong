local typedefs = require "kong.db.schema.typedefs"

return {
  name          = "rbac_role_entities",
  primary_key   = { "id" },
  dao           = "kong.db.dao.rbac_role_entities",
  generate_admin_api = false,

  fields        = {
    { id = typedefs.uuid },
    { created_at = typedefs.auto_timestamp_s },
    { updated_at = typedefs.auto_timestamp_s },
    { role = { type = "foreign", reference = "rbac_roles", required = true, on_delete = "cascade" } },
    { entity_id = { type = "string", required = true } },
    { entity_type = { type = "string", required = true } },   -- e.g. "services", "routes"
    { actions = { type = "array", elements = { type = "string" }, required = true, default = { "*" } } },
    { negative = { type = "boolean", required = true, default = false } },
  },
}
