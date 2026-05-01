local typedefs = require "kong.db.schema.typedefs"


return {
  name = "api_docs",
  primary_key = { "id" },
  workspaceable = false,  -- API Docs is a global resource, workspace is just a filter
  endpoint_key = "name",
  dao = "kong.db.dao.api_docs",
  generate_admin_api = false,  -- custom routes in api/routes/api_docs.lua

  fields = {
    { id           = typedefs.uuid },
    { created_at   = typedefs.auto_timestamp_s },
    { updated_at   = typedefs.auto_timestamp_s },
    { name         = { type = "string", required = true, unique = true } },
    { version      = { type = "string", required = true } },
    { spec_content = { type = "string", required = true, len_max = 5242880 } },  -- 5MB limit
    { service      = { type = "foreign", reference = "services",
                       on_delete = "null" } },
    { is_current   = { type = "boolean", default = true } },
    { ws_id        = { type = "string", uuid = true } },  -- workspace filter, manually managed
  },

  -- Composite unique constraint (name, version) is enforced at DB level
  -- via migration 027_api_docs: CONSTRAINT "api_docs_name_version_unique" UNIQUE ("name", "version")
}
