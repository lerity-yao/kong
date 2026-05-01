local api_docs = {
  name = "027_api_docs",
  postgres = {
    up = [[
      CREATE TABLE IF NOT EXISTS "api_docs" (
        "id"           UUID                       PRIMARY KEY,
        "ws_id"        UUID                       REFERENCES "workspaces" ("id") ON DELETE CASCADE,
        "name"         TEXT                       NOT NULL,
        "version"      TEXT                       NOT NULL,
        "spec_content" TEXT                       NOT NULL,
        "service_id"   UUID                       REFERENCES "services" ("id") ON DELETE SET NULL,
        "is_current"   BOOLEAN                    NOT NULL DEFAULT TRUE,
        "created_at"   TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() AT TIME ZONE 'UTC'),
        "updated_at"   TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() AT TIME ZONE 'UTC'),
        CONSTRAINT "api_docs_name_version_unique" UNIQUE ("name", "version")
      );

      CREATE INDEX IF NOT EXISTS "idx_api_docs_name" ON "api_docs" ("name");
      CREATE INDEX IF NOT EXISTS "idx_api_docs_service_id" ON "api_docs" ("service_id");
      CREATE INDEX IF NOT EXISTS "idx_api_docs_is_current" ON "api_docs" ("name", "is_current") WHERE "is_current" = TRUE;
      CREATE INDEX IF NOT EXISTS "idx_api_docs_ws_id" ON "api_docs" ("ws_id");

      -- Migrate RBAC endpoints: /workspaces/*/api-docs → /api-docs
      -- api_docs is a global resource, workspace is just a query param
      UPDATE "rbac_role_endpoints"
        SET "endpoint" = '/api-docs'
        WHERE "endpoint" LIKE '/workspaces/%/api-docs';
    ]],
  },
}

return api_docs
