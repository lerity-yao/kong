return {
  postgres = {
    up = [[
      -- 1. rbac_users (API Token users for programmatic access)
      CREATE TABLE IF NOT EXISTS "rbac_users" (
        "id"          UUID                       PRIMARY KEY,
        "created_at"  TIMESTAMP WITH TIME ZONE   DEFAULT (CURRENT_TIMESTAMP(3) AT TIME ZONE 'UTC'),
        "updated_at"  TIMESTAMP WITH TIME ZONE   DEFAULT (CURRENT_TIMESTAMP(3) AT TIME ZONE 'UTC'),
        "name"        TEXT                       NOT NULL UNIQUE,
        "comment"     TEXT,
        "user_token"  TEXT                       UNIQUE,
        "enabled"     BOOLEAN                    NOT NULL DEFAULT TRUE
      );

      -- 2. rbac_roles
      CREATE TABLE IF NOT EXISTS "rbac_roles" (
        "id"          UUID                       PRIMARY KEY,
        "created_at"  TIMESTAMP WITH TIME ZONE   DEFAULT (CURRENT_TIMESTAMP(3) AT TIME ZONE 'UTC'),
        "updated_at"  TIMESTAMP WITH TIME ZONE   DEFAULT (CURRENT_TIMESTAMP(3) AT TIME ZONE 'UTC'),
        "name"        TEXT                       NOT NULL UNIQUE,
        "comment"     TEXT,
        "is_default"  BOOLEAN                    NOT NULL DEFAULT FALSE
      );

      -- 3. rbac_role_endpoints (endpoint-level permissions)
      CREATE TABLE IF NOT EXISTS "rbac_role_endpoints" (
        "id"          UUID                       PRIMARY KEY,
        "created_at"  TIMESTAMP WITH TIME ZONE   DEFAULT (CURRENT_TIMESTAMP(3) AT TIME ZONE 'UTC'),
        "updated_at"  TIMESTAMP WITH TIME ZONE   DEFAULT (CURRENT_TIMESTAMP(3) AT TIME ZONE 'UTC'),
        "role_id"     UUID                       NOT NULL REFERENCES "rbac_roles" ("id") ON DELETE CASCADE,
        "workspace"   TEXT,
        "endpoint"    TEXT                       NOT NULL,
        "actions"     TEXT[]                     NOT NULL DEFAULT '{"*"}',
        "negative"    BOOLEAN                    NOT NULL DEFAULT FALSE
      );
      CREATE INDEX IF NOT EXISTS "rbac_role_endpoints_role_idx" ON "rbac_role_endpoints" ("role_id");

      -- 4. rbac_role_entities (entity-level permissions)
      CREATE TABLE IF NOT EXISTS "rbac_role_entities" (
        "id"           UUID                       PRIMARY KEY,
        "created_at"   TIMESTAMP WITH TIME ZONE   DEFAULT (CURRENT_TIMESTAMP(3) AT TIME ZONE 'UTC'),
        "updated_at"   TIMESTAMP WITH TIME ZONE   DEFAULT (CURRENT_TIMESTAMP(3) AT TIME ZONE 'UTC'),
        "role_id"      UUID                       NOT NULL REFERENCES "rbac_roles" ("id") ON DELETE CASCADE,
        "entity_id"    TEXT                       NOT NULL,
        "entity_type"  TEXT                       NOT NULL,
        "actions"      TEXT[]                     NOT NULL DEFAULT '{"*"}',
        "negative"     BOOLEAN                    NOT NULL DEFAULT FALSE
      );
      CREATE INDEX IF NOT EXISTS "rbac_role_entities_role_idx" ON "rbac_role_entities" ("role_id");

      -- 5. rbac_groups (local user groups)
      CREATE TABLE IF NOT EXISTS "rbac_groups" (
        "id"          UUID                       PRIMARY KEY,
        "created_at"  TIMESTAMP WITH TIME ZONE   DEFAULT (CURRENT_TIMESTAMP(3) AT TIME ZONE 'UTC'),
        "updated_at"  TIMESTAMP WITH TIME ZONE   DEFAULT (CURRENT_TIMESTAMP(3) AT TIME ZONE 'UTC'),
        "name"        TEXT                       NOT NULL UNIQUE,
        "comment"     TEXT
      );

      -- 6. admins (GUI administrators)
      CREATE TABLE IF NOT EXISTS "admins" (
        "id"                  UUID                       PRIMARY KEY,
        "created_at"          TIMESTAMP WITH TIME ZONE   DEFAULT (CURRENT_TIMESTAMP(3) AT TIME ZONE 'UTC'),
        "updated_at"          TIMESTAMP WITH TIME ZONE   DEFAULT (CURRENT_TIMESTAMP(3) AT TIME ZONE 'UTC'),
        "username"            TEXT                       NOT NULL UNIQUE,
        "email"               TEXT,
        "password_hash"       TEXT,
        "custom_id"           TEXT,
        "rbac_token_enabled"  BOOLEAN                    NOT NULL DEFAULT TRUE,
        "status"              INTEGER                    NOT NULL DEFAULT 1,
        "invite_token"        TEXT                       UNIQUE
      );

      -- 7. rbac_user_roles (many-to-many: rbac_users <-> rbac_roles)
      CREATE TABLE IF NOT EXISTS "rbac_user_roles" (
        "user_id"     UUID                       NOT NULL REFERENCES "rbac_users" ("id") ON DELETE CASCADE,
        "role_id"     UUID                       NOT NULL REFERENCES "rbac_roles" ("id") ON DELETE CASCADE,
        PRIMARY KEY ("user_id", "role_id")
      );

      -- 8. admin_roles (many-to-many: admins <-> rbac_roles)
      CREATE TABLE IF NOT EXISTS "admin_roles" (
        "admin_id"    UUID                       NOT NULL REFERENCES "admins" ("id") ON DELETE CASCADE,
        "role_id"     UUID                       NOT NULL REFERENCES "rbac_roles" ("id") ON DELETE CASCADE,
        PRIMARY KEY ("admin_id", "role_id")
      );

      -- 9. group_roles (many-to-many: rbac_groups <-> rbac_roles)
      CREATE TABLE IF NOT EXISTS "group_roles" (
        "group_id"    UUID                       NOT NULL REFERENCES "rbac_groups" ("id") ON DELETE CASCADE,
        "role_id"     UUID                       NOT NULL REFERENCES "rbac_roles" ("id") ON DELETE CASCADE,
        PRIMARY KEY ("group_id", "role_id")
      );

      -- 10. group_members (many-to-many: rbac_groups <-> admins)
      CREATE TABLE IF NOT EXISTS "group_admins" (
        "group_id"    UUID                       NOT NULL REFERENCES "rbac_groups" ("id") ON DELETE CASCADE,
        "admin_id"    UUID                       NOT NULL REFERENCES "admins" ("id") ON DELETE CASCADE,
        PRIMARY KEY ("group_id", "admin_id")
      );

      -- 11. group_rbac_users (many-to-many: rbac_groups <-> rbac_users)
      CREATE TABLE IF NOT EXISTS "group_rbac_users" (
        "group_id"       UUID                    NOT NULL REFERENCES "rbac_groups" ("id") ON DELETE CASCADE,
        "rbac_user_id"   UUID                    NOT NULL REFERENCES "rbac_users" ("id") ON DELETE CASCADE,
        PRIMARY KEY ("group_id", "rbac_user_id")
      );

      -- ============================================
      -- Seed data
      -- ============================================

      -- Built-in roles
      INSERT INTO "rbac_roles" ("id", "name", "comment", "is_default")
        VALUES ('11111111-1111-1111-1111-111111111111', 'super-admin', 'Full access to all endpoints across all workspaces', TRUE)
        ON CONFLICT DO NOTHING;
      INSERT INTO "rbac_roles" ("id", "name", "comment", "is_default")
        VALUES ('22222222-2222-2222-2222-222222222222', 'admin', 'Read/write access to most endpoints', TRUE)
        ON CONFLICT DO NOTHING;
      INSERT INTO "rbac_roles" ("id", "name", "comment", "is_default")
        VALUES ('33333333-3333-3333-3333-333333333333', 'read-only', 'Read access to all endpoints', TRUE)
        ON CONFLICT DO NOTHING;

      -- super-admin: /* all actions
      INSERT INTO "rbac_role_endpoints" ("id", "role_id", "endpoint", "actions")
        VALUES ('44444444-4444-4444-4444-444444444444', '11111111-1111-1111-1111-111111111111', '/*', '{"*"}')
        ON CONFLICT DO NOTHING;

      -- admin: /* all actions
      INSERT INTO "rbac_role_endpoints" ("id", "role_id", "endpoint", "actions")
        VALUES ('55555555-5555-5555-5555-555555555555', '22222222-2222-2222-2222-222222222222', '/*', '{"*"}')
        ON CONFLICT DO NOTHING;

      -- read-only: /* read only
      INSERT INTO "rbac_role_endpoints" ("id", "role_id", "endpoint", "actions")
        VALUES ('66666666-6666-6666-6666-666666666666', '33333333-3333-3333-3333-333333333333', '/*', '{"read"}')
        ON CONFLICT DO NOTHING;

      -- Default admin user and admin_roles association
      -- will be created in teardown with bcrypt hash
      -- from admin_gui_default_password config (default: "admin")
    ]],

    teardown = function(connector)
      -- Use bcrypt to hash the default admin password at migration time
      -- This ensures a real bcrypt hash instead of a hardcoded placeholder
      local bcrypt = require "kong.tools.bcrypt"
      local password = kong.configuration.admin_gui_default_password or "admin"
      local hash, err = bcrypt.hash(password)
      if err then
        return nil, "failed to hash default admin password: " .. err
      end

      -- Insert admin user first (admin_roles depends on it via FK)
      local sql = string.format(
        [[INSERT INTO "admins" ("id", "username", "email", "password_hash", "status")
           VALUES ('77777777-7777-7777-7777-777777777777', 'kong_admin', 'admin@example.com', '%s', 1)
           ON CONFLICT DO NOTHING]],
        hash:gsub("'", "''")  -- escape single quotes in hash
      )

      local _, qerr = connector:query(sql)
      if qerr then
        return nil, "failed to insert default admin: " .. tostring(qerr)
      end

      -- Now insert admin_roles association (FK constraint satisfied)
      local role_sql = [[INSERT INTO "admin_roles" ("admin_id", "role_id")
        VALUES ('77777777-7777-7777-7777-777777777777', '11111111-1111-1111-1111-111111111111')
        ON CONFLICT DO NOTHING]]

      local _, rerr = connector:query(role_sql)
      if rerr then
        return nil, "failed to insert admin_roles: " .. tostring(rerr)
      end

      -- Insert rbac_user for kong_admin (with auto-generated user_token)
      -- This is needed for token-based authentication via Kong-Admin-Token header
      local resty_random = require "resty.random"
      local to_hex = require "resty.string".to_hex
      local token_bytes = resty_random.bytes(16)
      local user_token = to_hex(token_bytes)

      local rbac_user_sql = string.format(
        [[INSERT INTO "rbac_users" ("id", "name", "user_token", "enabled")
           VALUES ('88888888-8888-8888-8888-888888888888', 'kong_admin', '%s', TRUE)
           ON CONFLICT DO NOTHING]],
        user_token
      )

      local _, uerr = connector:query(rbac_user_sql)
      if uerr then
        return nil, "failed to insert rbac_user: " .. tostring(uerr)
      end

      -- Associate rbac_user with super-admin role
      local rbac_role_sql = [[INSERT INTO "rbac_user_roles" ("user_id", "role_id")
        VALUES ('88888888-8888-8888-8888-888888888888', '11111111-1111-1111-1111-111111111111')
        ON CONFLICT DO NOTHING]]

      local _, urerr = connector:query(rbac_role_sql)
      if urerr then
        return nil, "failed to insert rbac_user_roles: " .. tostring(urerr)
      end

      return true
    end
  },
}
