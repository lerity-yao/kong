-- RBAC Admin API routes
-- Custom CRUD for rbac_users, rbac_roles, rbac_role_endpoints, rbac_role_entities,
-- rbac_groups, and admins entities.
--
-- NOTE: These custom tables (admins, rbac_users, rbac_roles, etc.) are NOT registered
-- in Kong's DAO system. We must use kong.db.connector:query() with raw SQL,
-- just like auth.lua. Using db.rbac_users / db.admins etc. returns nil and causes 500.

local cjson = require "cjson.safe".new()
cjson.encode_number_precision(16)

local utils = require "kong.tools.utils"


-- Helper: generate a random token
local function generate_token()
  return utils.uuid()
end


-- Helper: exit with JSON
local function exit_json(status, data)
  return kong.response.exit(status, data)
end


-- Helper: query DB via connector
local function query(sql)
  return kong.db.connector:query(sql, "read")
end

local function exec(sql)
  return kong.db.connector:query(sql, "write")
end


-- Helper: escape single quotes for SQL
local function esc(s)
  if s == nil then return "" end
  return tostring(s):gsub("'", "''")
end


-- Helper: is a string a valid UUID pattern?
local function is_uuid(s)
  if type(s) ~= "string" then return false end
  return s:match("^" .. string.rep("%x", 8) .. "%-"
    .. string.rep("%x", 4) .. "%-"
    .. string.rep("%x", 4) .. "%-"
    .. string.rep("%x", 4) .. "%-"
    .. string.rep("%x", 12) .. "$") ~= nil
end


-- Helper: find rbac_user by name or id
local function find_rbac_user(name_or_id)
  local sql
  if is_uuid(name_or_id) then
    sql = string.format(
      [[SELECT id, name, comment, user_token, enabled, created_at, updated_at FROM rbac_users WHERE id = '%s'::uuid]],
      name_or_id
    )
  else
    sql = string.format(
      [[SELECT id, name, comment, user_token, enabled, created_at, updated_at FROM rbac_users WHERE name = '%s']],
      esc(name_or_id)
    )
  end
  local res = query(sql)
  if res and #res > 0 then
    local user = res[1]
    -- Fetch roles
    local roles = query(string.format(
      [[SELECT r.id, r.name, r.comment FROM rbac_roles r
        JOIN rbac_user_roles ur ON ur.role_id = r.id
        WHERE ur.user_id = '%s'::uuid]],
      user.id
    ))
    user.roles = roles or {}
    return user
  end
  return nil
end


-- Helper: find rbac_role by name or id
local function find_rbac_role(name_or_id)
  local sql
  if is_uuid(name_or_id) then
    sql = string.format(
      [[SELECT id, name, comment, is_default, created_at, updated_at FROM rbac_roles WHERE id = '%s'::uuid]],
      name_or_id
    )
  else
    sql = string.format(
      [[SELECT id, name, comment, is_default, created_at, updated_at FROM rbac_roles WHERE name = '%s']],
      esc(name_or_id)
    )
  end
  local res = query(sql)
  if res and #res > 0 then
    return res[1]
  end
  return nil
end


-- Helper: find admin by name or id
local function find_admin(name_or_id)
  local sql
  if is_uuid(name_or_id) then
    sql = string.format(
      [[SELECT id, username, email, password_hash, status, created_at, updated_at FROM admins WHERE id = '%s'::uuid]],
      name_or_id
    )
  else
    sql = string.format(
      [[SELECT id, username, email, password_hash, status, created_at, updated_at FROM admins WHERE username = '%s']],
      esc(name_or_id)
    )
  end
  local res = query(sql)
  if res and #res > 0 then
    local admin = res[1]
    -- Fetch roles
    local roles = query(string.format(
      [[SELECT r.id, r.name, r.comment FROM rbac_roles r
        JOIN admin_roles ar ON ar.role_id = r.id
        WHERE ar.admin_id = '%s'::uuid]],
      admin.id
    ))
    admin.roles = roles or {}
    return admin
  end
  return nil
end


-- ============================================================
-- RBAC Users
-- ============================================================

local rbac_users_routes = {
  ["/rbac/users"] = {
    GET = function(self, db)
      local size = tonumber(self.params.size) or 100
      local offset = self.params.offset
      local sql = [[SELECT id, name, comment, user_token, enabled, created_at, updated_at FROM rbac_users ORDER BY created_at DESC]]
      if offset and offset ~= "" then
        sql = sql .. string.format([[ OFFSET %s]], esc(offset))
      end
      sql = sql .. string.format([[ LIMIT %d]], size)
      local rows = query(sql) or {}
      -- Attach roles for each user
      for _, user in ipairs(rows) do
        local roles = query(string.format(
          [[SELECT r.id, r.name, r.comment FROM rbac_roles r
            JOIN rbac_user_roles ur ON ur.role_id = r.id
            WHERE ur.user_id = '%s'::uuid]],
          user.id
        ))
        user.roles = roles or {}
      end
      return exit_json(200, { data = rows, next = nil })
    end,
    POST = function(self, db)
      local params = self.params
      local name = params.name
      if not name then
        return exit_json(400, { message = "name is required" })
      end
      local token = params.user_token or generate_token()
      local comment = params.comment or ""
      local enabled = params.enabled
      if enabled == nil then enabled = true end
      local sql = string.format(
        [[INSERT INTO rbac_users (id, name, comment, user_token, enabled, created_at, updated_at)
           VALUES ('%s'::uuid, '%s', '%s', '%s', %s, NOW(), NOW())
           RETURNING id, name, comment, user_token, enabled, created_at, updated_at]],
        utils.uuid(), esc(name), esc(comment), esc(token), enabled and "true" or "false"
      )
      local res = exec(sql)
      if not res or #res == 0 then
        return exit_json(400, { message = "Failed to create RBAC user" })
      end
      local user = res[1]
      -- Bind roles if provided
      local roles_param = params.roles
      if roles_param and type(roles_param) == "table" then
        for _, role_name in ipairs(roles_param) do
          local role = find_rbac_role(role_name)
          if role then
            exec(string.format(
              [[INSERT INTO rbac_user_roles (user_id, role_id) VALUES ('%s'::uuid, '%s'::uuid) ON CONFLICT DO NOTHING]],
              user.id, role.id
            ))
          end
        end
      end
      -- Fetch actual roles
      local roles = query(string.format(
        [[SELECT r.id, r.name, r.comment FROM rbac_roles r
          JOIN rbac_user_roles ur ON ur.role_id = r.id
          WHERE ur.user_id = '%s'::uuid]],
        user.id
      ))
      user.roles = roles or {}
      return exit_json(201, user)
    end,
  },
  ["/rbac/users/:name_or_id"] = {
    GET = function(self, db)
      local user = find_rbac_user(self.params.name_or_id)
      if not user then
        return exit_json(404, { message = "Not found" })
      end
      return exit_json(200, user)
    end,
    PATCH = function(self, db)
      local name_or_id = self.params.name_or_id
      local user = find_rbac_user(name_or_id)
      if not user then
        return exit_json(404, { message = "Not found" })
      end
      local sets = {}
      if self.params.comment ~= nil then
        table.insert(sets, string.format("comment = '%s'", esc(self.params.comment)))
      end
      if self.params.enabled ~= nil then
        table.insert(sets, string.format("enabled = %s", self.params.enabled and "true" or "false"))
      end
      if self.params.user_token ~= nil then
        table.insert(sets, string.format("user_token = '%s'", esc(self.params.user_token)))
      end
      table.insert(sets, "updated_at = NOW()")
      if #sets == 0 then
        return exit_json(200, user)
      end
      local sql = string.format(
        [[UPDATE rbac_users SET %s WHERE id = '%s'::uuid
           RETURNING id, name, comment, user_token, enabled, created_at, updated_at]],
        table.concat(sets, ", "), user.id
      )
      local res = exec(sql)
      if res and #res > 0 then
        res[1].roles = user.roles
        return exit_json(200, res[1])
      end
      return exit_json(400, { message = "Failed to update RBAC user" })
    end,
    DELETE = function(self, db)
      local user = find_rbac_user(self.params.name_or_id)
      if not user then
        return exit_json(404, { message = "Not found" })
      end
      -- Prevent deleting users that have super-admin role
      for _, r in ipairs(user.roles or {}) do
        if r.name == "super-admin" then
          return exit_json(403, { message = "Cannot delete RBAC user with super-admin role" })
        end
      end
      exec(string.format([[DELETE FROM rbac_user_roles WHERE user_id = '%s'::uuid]], user.id))
      exec(string.format([[DELETE FROM rbac_users WHERE id = '%s'::uuid]], user.id))
      return exit_json(204)
    end,
  },
  ["/rbac/users/:name_or_id/roles"] = {
    GET = function(self, db)
      local user = find_rbac_user(self.params.name_or_id)
      if not user then
        return exit_json(404, { message = "RBAC user not found" })
      end
      return exit_json(200, { data = user.roles or {} })
    end,
    POST = function(self, db)
      local user = find_rbac_user(self.params.name_or_id)
      if not user then
        return exit_json(404, { message = "RBAC user not found" })
      end
      local roles = self.params.roles
      if not roles then
        return exit_json(400, { message = "roles field is required" })
      end
      for _, role_name in ipairs(roles) do
        local role = find_rbac_role(role_name)
        if role then
          exec(string.format(
            [[INSERT INTO rbac_user_roles (user_id, role_id) VALUES ('%s'::uuid, '%s'::uuid) ON CONFLICT DO NOTHING]],
            user.id, role.id
          ))
        end
      end
      -- Return updated user
      local updated = find_rbac_user(self.params.name_or_id)
      return exit_json(200, updated)
    end,
  },
  ["/rbac/users/:name_or_id/roles/:role_name_or_id"] = {
    DELETE = function(self, db)
      local user = find_rbac_user(self.params.name_or_id)
      if not user then
        return exit_json(404, { message = "RBAC user not found" })
      end
      local role = find_rbac_role(self.params.role_name_or_id)
      if not role then
        return exit_json(404, { message = "Role not found" })
      end
      exec(string.format(
        [[DELETE FROM rbac_user_roles WHERE user_id = '%s'::uuid AND role_id = '%s'::uuid]],
        user.id, role.id
      ))
      local updated = find_rbac_user(self.params.name_or_id)
      return exit_json(200, updated)
    end,
  },
}


-- ============================================================
-- RBAC Roles
-- ============================================================

local rbac_roles_routes = {
  ["/rbac/roles"] = {
    GET = function(self, db)
      local size = tonumber(self.params.size) or 100
      local offset = self.params.offset
      local sql = [[SELECT id, name, comment, is_default, created_at, updated_at FROM rbac_roles ORDER BY name]]
      if offset and offset ~= "" then
        sql = sql .. string.format([[ OFFSET %s]], esc(offset))
      end
      sql = sql .. string.format([[ LIMIT %d]], size)
      local rows = query(sql) or {}
      return exit_json(200, { data = rows, next = nil })
    end,
    POST = function(self, db)
      local params = self.params
      local name = params.name
      if not name then
        return exit_json(400, { message = "name is required" })
      end
      local comment = params.comment or ""
      local is_default = params.is_default
      if is_default == nil then is_default = false end
      local sql = string.format(
        [[INSERT INTO rbac_roles (id, name, comment, is_default, created_at, updated_at)
           VALUES ('%s'::uuid, '%s', '%s', %s, NOW(), NOW())
           RETURNING id, name, comment, is_default, created_at, updated_at]],
        utils.uuid(), esc(name), esc(comment), is_default and "true" or "false"
      )
      local res = exec(sql)
      if not res or #res == 0 then
        return exit_json(400, { message = "Failed to create RBAC role" })
      end
      return exit_json(201, res[1])
    end,
  },
  ["/rbac/roles/:name_or_id"] = {
    GET = function(self, db)
      local role = find_rbac_role(self.params.name_or_id)
      if not role then
        return exit_json(404, { message = "Not found" })
      end
      return exit_json(200, role)
    end,
    PATCH = function(self, db)
      local name_or_id = self.params.name_or_id
      local role = find_rbac_role(name_or_id)
      if not role then
        return exit_json(404, { message = "Not found" })
      end
      local sets = {}
      if self.params.comment ~= nil then
        table.insert(sets, string.format("comment = '%s'", esc(self.params.comment)))
      end
      if self.params.is_default ~= nil then
        table.insert(sets, string.format("is_default = %s", self.params.is_default and "true" or "false"))
      end
      table.insert(sets, "updated_at = NOW()")
      if #sets == 0 then
        return exit_json(200, role)
      end
      local sql = string.format(
        [[UPDATE rbac_roles SET %s WHERE id = '%s'::uuid
           RETURNING id, name, comment, is_default, created_at, updated_at]],
        table.concat(sets, ", "), role.id
      )
      local res = exec(sql)
      if res and #res > 0 then
        return exit_json(200, res[1])
      end
      return exit_json(400, { message = "Failed to update RBAC role" })
    end,
    DELETE = function(self, db)
      local role = find_rbac_role(self.params.name_or_id)
      if not role then
        return exit_json(404, { message = "Not found" })
      end
      -- Prevent deleting super-admin role
      if role.name == "super-admin" then
        return exit_json(403, { message = "Cannot delete super-admin role" })
      end
      exec(string.format([[DELETE FROM rbac_role_endpoints WHERE role_id = '%s'::uuid]], role.id))
      exec(string.format([[DELETE FROM admin_roles WHERE role_id = '%s'::uuid]], role.id))
      exec(string.format([[DELETE FROM rbac_user_roles WHERE role_id = '%s'::uuid]], role.id))
      exec(string.format([[DELETE FROM rbac_roles WHERE id = '%s'::uuid]], role.id))
      return exit_json(204)
    end,
  },
  ["/rbac/roles/:name_or_id/endpoints"] = {
    GET = function(self, db)
      local role = find_rbac_role(self.params.name_or_id)
      if not role then
        return exit_json(404, { message = "RBAC role not found" })
      end
      local rows = query(string.format(
        [[SELECT id, role_id, endpoint, actions, negative, workspace, created_at, updated_at
          FROM rbac_role_endpoints WHERE role_id = '%s'::uuid]],
        role.id
      )) or {}
      return exit_json(200, { data = rows, next = nil })
    end,
    POST = function(self, db)
      local role = find_rbac_role(self.params.name_or_id)
      if not role then
        return exit_json(404, { message = "RBAC role not found" })
      end
      local params = self.params
      local endpoint = params.endpoint or "/*"
      -- Convert actions to PostgreSQL text[] literal: {"read","write"}
      local actions = params.actions or {"*"}
      local pg_actions
      if type(actions) == "table" then
        local parts = {}
        for _, a in ipairs(actions) do
          table.insert(parts, string.format('"%s"', esc(tostring(a))))
        end
        pg_actions = "{" .. table.concat(parts, ",") .. "}"
      else
        pg_actions = tostring(actions)
      end
      local negative = params.negative or false
      local ws = params.workspace or "*"
      local sql = string.format(
        [[INSERT INTO rbac_role_endpoints (id, role_id, endpoint, actions, negative, workspace, created_at, updated_at)
           VALUES ('%s'::uuid, '%s'::uuid, '%s', '%s', %s, '%s', NOW(), NOW())
           RETURNING id, role_id, endpoint, actions, negative, workspace, created_at, updated_at]],
        utils.uuid(), role.id, esc(endpoint), esc(pg_actions), negative and "true" or "false", esc(ws)
      )
      local res, err = exec(sql)
      if not res or #res == 0 then
        ngx.log(ngx.ERR, "RBAC endpoint insert failed: sql=", sql, " err=", tostring(err), " res=", tostring(res))
        return exit_json(400, { message = "Failed to create endpoint permission", detail = tostring(err) })
      end
      return exit_json(201, res[1])
    end,
  },
  ["/rbac/roles/:name_or_id/endpoints/:endpoint_id"] = {
    PATCH = function(self, db)
      local sets = {}
      if self.params.endpoint ~= nil then
        table.insert(sets, string.format("endpoint = '%s'", esc(self.params.endpoint)))
      end
      if self.params.actions ~= nil then
        local actions = self.params.actions
        local pg_actions
        if type(actions) == "table" then
          local parts = {}
          for _, a in ipairs(actions) do
            table.insert(parts, string.format('"%s"', esc(tostring(a))))
          end
          pg_actions = "{" .. table.concat(parts, ",") .. "}"
        else
          pg_actions = tostring(actions)
        end
        table.insert(sets, string.format("actions = '%s'", esc(pg_actions)))
      end
      if self.params.negative ~= nil then
        table.insert(sets, string.format("negative = %s", self.params.negative and "true" or "false"))
      end
      if self.params.workspace ~= nil then
        table.insert(sets, string.format("workspace = '%s'", esc(self.params.workspace)))
      end
      table.insert(sets, "updated_at = NOW()")
      if #sets == 0 then
        return exit_json(200, { message = "No fields to update" })
      end
      local sql = string.format(
        [[UPDATE rbac_role_endpoints SET %s WHERE id = '%s'::uuid
           RETURNING id, role_id, endpoint, actions, negative, workspace, created_at, updated_at]],
        table.concat(sets, ", "), esc(self.params.endpoint_id)
      )
      local res = exec(sql)
      if not res or #res == 0 then
        return exit_json(404, { message = "Endpoint not found" })
      end
      return exit_json(200, res[1])
    end,
    DELETE = function(self, db)
      local res = exec(string.format(
        [[DELETE FROM rbac_role_endpoints WHERE id = '%s'::uuid RETURNING id]],
        esc(self.params.endpoint_id)
      ))
      if not res or #res == 0 then
        return exit_json(404, { message = "Endpoint not found" })
      end
      return exit_json(204)
    end,
  },
  ["/rbac/roles/:name_or_id/entities"] = {
    GET = function(self, db)
      local role = find_rbac_role(self.params.name_or_id)
      if not role then
        return exit_json(404, { message = "RBAC role not found" })
      end
      local rows = query(string.format(
        [[SELECT * FROM rbac_role_entities WHERE role_id = '%s'::uuid]],
        role.id
      )) or {}
      return exit_json(200, { data = rows, next = nil })
    end,
    POST = function(self, db)
      local role = find_rbac_role(self.params.name_or_id)
      if not role then
        return exit_json(404, { message = "RBAC role not found" })
      end
      local params = self.params
      local entity_id = params.entity_id or ""
      local entity_type = params.entity_type or ""
      -- Convert actions to PostgreSQL text[] literal: {"read","write"}
      local actions = params.actions or {"*"}
      local pg_actions
      if type(actions) == "table" then
        local parts = {}
        for _, a in ipairs(actions) do
          table.insert(parts, string.format('"%s"', esc(tostring(a))))
        end
        pg_actions = "{" .. table.concat(parts, ",") .. "}"
      else
        pg_actions = tostring(actions)
      end
      local negative = params.negative or false
      local sql = string.format(
        [[INSERT INTO rbac_role_entities (id, role_id, entity_id, entity_type, actions, negative, created_at, updated_at)
           VALUES ('%s'::uuid, '%s'::uuid, '%s', '%s', '%s', %s, NOW(), NOW())
           RETURNING *]],
        utils.uuid(), role.id, esc(entity_id), esc(entity_type), esc(pg_actions), negative and "true" or "false"
      )
      local res = exec(sql)
      if not res or #res == 0 then
        return exit_json(400, { message = "Failed to create entity permission" })
      end
      return exit_json(201, res[1])
    end,
  },
  ["/rbac/roles/:name_or_id/entities/:entity_id"] = {
    DELETE = function(self, db)
      local res = exec(string.format(
        [[DELETE FROM rbac_role_entities WHERE id = '%s'::uuid RETURNING id]],
        esc(self.params.entity_id)
      ))
      if not res or #res == 0 then
        return exit_json(404, { message = "Entity permission not found" })
      end
      return exit_json(204)
    end,
  },
}


-- ============================================================
-- RBAC Groups
-- ============================================================

local rbac_groups_routes = {
  ["/rbac/groups"] = {
    GET = function(self, db)
      local size = tonumber(self.params.size) or 100
      local offset = self.params.offset
      local sql = [[SELECT id, name, comment, created_at, updated_at FROM rbac_groups ORDER BY name]]
      if offset and offset ~= "" then
        sql = sql .. string.format([[ OFFSET %s]], esc(offset))
      end
      sql = sql .. string.format([[ LIMIT %d]], size)
      local rows = query(sql) or {}
      -- Attach roles for each group
      for _, group in ipairs(rows) do
        local roles = query(string.format(
          [[SELECT r.id, r.name, r.comment FROM rbac_roles r
            JOIN rbac_group_roles gr ON gr.role_id = r.id
            WHERE gr.group_id = '%s'::uuid]],
          group.id
        ))
        group.roles = roles or {}
      end
      return exit_json(200, { data = rows, next = nil })
    end,
    POST = function(self, db)
      local params = self.params
      local name = params.name
      if not name then
        return exit_json(400, { message = "name is required" })
      end
      local comment = params.comment or ""
      local sql = string.format(
        [[INSERT INTO rbac_groups (id, name, comment, created_at, updated_at)
           VALUES ('%s'::uuid, '%s', '%s', NOW(), NOW())
           RETURNING id, name, comment, created_at, updated_at]],
        utils.uuid(), esc(name), esc(comment)
      )
      local res = exec(sql)
      if not res or #res == 0 then
        return exit_json(400, { message = "Failed to create group" })
      end
      res[1].roles = {}
      return exit_json(201, res[1])
    end,
  },
  ["/rbac/groups/:name_or_id"] = {
    GET = function(self, db)
      local name_or_id = self.params.name_or_id
      local sql
      if is_uuid(name_or_id) then
        sql = string.format([[SELECT id, name, comment, created_at, updated_at FROM rbac_groups WHERE id = '%s'::uuid]], name_or_id)
      else
        sql = string.format([[SELECT id, name, comment, created_at, updated_at FROM rbac_groups WHERE name = '%s']], esc(name_or_id))
      end
      local rows = query(sql)
      if not rows or #rows == 0 then
        return exit_json(404, { message = "Not found" })
      end
      local group = rows[1]
      local roles = query(string.format(
        [[SELECT r.id, r.name, r.comment FROM rbac_roles r
          JOIN rbac_group_roles gr ON gr.role_id = r.id
          WHERE gr.group_id = '%s'::uuid]],
        group.id
      ))
      group.roles = roles or {}
      return exit_json(200, group)
    end,
    PATCH = function(self, db)
      local name_or_id = self.params.name_or_id
      -- Find group first
      local find_sql
      if is_uuid(name_or_id) then
        find_sql = string.format([[SELECT id FROM rbac_groups WHERE id = '%s'::uuid]], name_or_id)
      else
        find_sql = string.format([[SELECT id FROM rbac_groups WHERE name = '%s']], esc(name_or_id))
      end
      local found = query(find_sql)
      if not found or #found == 0 then
        return exit_json(404, { message = "Not found" })
      end
      local group_id = found[1].id
      local sets = {}
      if self.params.comment ~= nil then
        table.insert(sets, string.format("comment = '%s'", esc(self.params.comment)))
      end
      table.insert(sets, "updated_at = NOW()")
      if #sets == 0 then
        return exit_json(200, found[1])
      end
      local sql = string.format(
        [[UPDATE rbac_groups SET %s WHERE id = '%s'::uuid
           RETURNING id, name, comment, created_at, updated_at]],
        table.concat(sets, ", "), group_id
      )
      local res = exec(sql)
      if res and #res > 0 then
        return exit_json(200, res[1])
      end
      return exit_json(400, { message = "Failed to update group" })
    end,
    DELETE = function(self, db)
      local name_or_id = self.params.name_or_id
      local find_sql
      if is_uuid(name_or_id) then
        find_sql = string.format([[SELECT id FROM rbac_groups WHERE id = '%s'::uuid]], name_or_id)
      else
        find_sql = string.format([[SELECT id FROM rbac_groups WHERE name = '%s']], esc(name_or_id))
      end
      local found = query(find_sql)
      if not found or #found == 0 then
        return exit_json(404, { message = "Not found" })
      end
      exec(string.format([[DELETE FROM rbac_group_roles WHERE group_id = '%s'::uuid]], found[1].id))
      exec(string.format([[DELETE FROM rbac_groups WHERE id = '%s'::uuid]], found[1].id))
      return exit_json(204)
    end,
  },
  ["/rbac/groups/:name_or_id/roles"] = {
    GET = function(self, db)
      local name_or_id = self.params.name_or_id
      local find_sql
      if is_uuid(name_or_id) then
        find_sql = string.format([[SELECT id FROM rbac_groups WHERE id = '%s'::uuid]], name_or_id)
      else
        find_sql = string.format([[SELECT id FROM rbac_groups WHERE name = '%s']], esc(name_or_id))
      end
      local found = query(find_sql)
      if not found or #found == 0 then
        return exit_json(404, { message = "Group not found" })
      end
      local roles = query(string.format(
        [[SELECT r.id, r.name, r.comment FROM rbac_roles r
          JOIN rbac_group_roles gr ON gr.role_id = r.id
          WHERE gr.group_id = '%s'::uuid]],
        found[1].id
      ))
      return exit_json(200, { data = roles or {} })
    end,
    POST = function(self, db)
      local name_or_id = self.params.name_or_id
      local find_sql
      if is_uuid(name_or_id) then
        find_sql = string.format([[SELECT id FROM rbac_groups WHERE id = '%s'::uuid]], name_or_id)
      else
        find_sql = string.format([[SELECT id FROM rbac_groups WHERE name = '%s']], esc(name_or_id))
      end
      local found = query(find_sql)
      if not found or #found == 0 then
        return exit_json(404, { message = "Group not found" })
      end
      local group_id = found[1].id
      local roles = self.params.roles
      if not roles then
        return exit_json(400, { message = "roles field is required" })
      end
      for _, role_name in ipairs(roles) do
        local role = find_rbac_role(role_name)
        if role then
          exec(string.format(
            [[INSERT INTO rbac_group_roles (group_id, role_id) VALUES ('%s'::uuid, '%s'::uuid) ON CONFLICT DO NOTHING]],
            group_id, role.id
          ))
        end
      end
      local roles_res = query(string.format(
        [[SELECT r.id, r.name, r.comment FROM rbac_roles r
          JOIN rbac_group_roles gr ON gr.role_id = r.id
          WHERE gr.group_id = '%s'::uuid]],
        group_id
      ))
      return exit_json(200, { data = roles_res or {} })
    end,
  },
  ["/rbac/groups/:name_or_id/roles/:role_name_or_id"] = {
    DELETE = function(self, db)
      local name_or_id = self.params.name_or_id
      local find_sql
      if is_uuid(name_or_id) then
        find_sql = string.format([[SELECT id FROM rbac_groups WHERE id = '%s'::uuid]], name_or_id)
      else
        find_sql = string.format([[SELECT id FROM rbac_groups WHERE name = '%s']], esc(name_or_id))
      end
      local found = query(find_sql)
      if not found or #found == 0 then
        return exit_json(404, { message = "Group not found" })
      end
      local role = find_rbac_role(self.params.role_name_or_id)
      if not role then
        return exit_json(404, { message = "Role not found" })
      end
      exec(string.format(
        [[DELETE FROM rbac_group_roles WHERE group_id = '%s'::uuid AND role_id = '%s'::uuid]],
        found[1].id, role.id
      ))
      local roles_res = query(string.format(
        [[SELECT r.id, r.name, r.comment FROM rbac_roles r
          JOIN rbac_group_roles gr ON gr.role_id = r.id
          WHERE gr.group_id = '%s'::uuid]],
        found[1].id
      ))
      return exit_json(200, { data = roles_res or {} })
    end,
  },
}


-- ============================================================
-- Admins
-- ============================================================

local admins_routes = {
  ["/admins"] = {
    GET = function(self, db)
      local size = tonumber(self.params.size) or 100
      local offset = self.params.offset
      local sql = [[SELECT id, username, email, status, created_at, updated_at FROM admins ORDER BY username]]
      if offset and offset ~= "" then
        sql = sql .. string.format([[ OFFSET %s]], esc(offset))
      end
      sql = sql .. string.format([[ LIMIT %d]], size)
      local rows = query(sql) or {}
      -- Attach roles for each admin
      for _, admin in ipairs(rows) do
        local roles = query(string.format(
          [[SELECT r.id, r.name, r.comment FROM rbac_roles r
            JOIN admin_roles ar ON ar.role_id = r.id
            WHERE ar.admin_id = '%s'::uuid]],
          admin.id
        ))
        admin.roles = roles or {}
      end
      return exit_json(200, { data = rows, next = nil })
    end,
    POST = function(self, db)
      local bcrypt = require "kong.tools.bcrypt"
      local params = self.params
      local username = params.username
      if not username then
        return exit_json(400, { message = "username is required" })
      end
      local email = params.email or ""
      local password_hash
      local status
      if params.password then
        password_hash = bcrypt.hash(params.password)
        status = 1
      else
        password_hash = ""
        status = 0
      end
      local sql = string.format(
        [[INSERT INTO admins (id, username, email, password_hash, status, created_at, updated_at)
           VALUES ('%s'::uuid, '%s', '%s', '%s', %d, NOW(), NOW())
           RETURNING id, username, email, status, created_at, updated_at]],
        utils.uuid(), esc(username), esc(email), esc(password_hash), status
      )
      local res = exec(sql)
      if not res or #res == 0 then
        return exit_json(400, { message = "Failed to create admin" })
      end
      res[1].roles = {}
      -- Assign roles if provided
      if params.roles then
        for _, role_name in ipairs(params.roles) do
          local role = find_rbac_role(role_name)
          if role then
            exec(string.format(
              [[INSERT INTO admin_roles (admin_id, role_id) VALUES ('%s'::uuid, '%s'::uuid) ON CONFLICT DO NOTHING]],
              res[1].id, role.id
            ))
          end
        end
        res[1].roles = query(string.format(
          [[SELECT r.id, r.name, r.comment FROM rbac_roles r
            JOIN admin_roles ar ON ar.role_id = r.id
            WHERE ar.admin_id = '%s'::uuid]],
          res[1].id
        )) or {}
      end
      return exit_json(201, res[1])
    end,
  },
  ["/admins/:name_or_id"] = {
    GET = function(self, db)
      local admin = find_admin(self.params.name_or_id)
      if not admin then
        return exit_json(404, { message = "Not found" })
      end
      return exit_json(200, admin)
    end,
    PATCH = function(self, db)
      local name_or_id = self.params.name_or_id
      local admin = find_admin(name_or_id)
      if not admin then
        return exit_json(404, { message = "Not found" })
      end
      local sets = {}
      if self.params.email ~= nil then
        table.insert(sets, string.format("email = '%s'", esc(self.params.email)))
      end
      if self.params.status ~= nil then
        table.insert(sets, string.format("status = %d", tonumber(self.params.status) or 0))
      end
      -- Password change
      if self.params.password then
        local bcrypt = require "kong.tools.bcrypt"
        local hash = bcrypt.hash(self.params.password)
        table.insert(sets, string.format("password_hash = '%s'", esc(hash)))
      end
      table.insert(sets, "updated_at = NOW()")
      if #sets == 0 then
        return exit_json(200, admin)
      end
      local sql = string.format(
        [[UPDATE admins SET %s WHERE id = '%s'::uuid
           RETURNING id, username, email, status, created_at, updated_at]],
        table.concat(sets, ", "), admin.id
      )
      local res = exec(sql)
      if res and #res > 0 then
        res[1].roles = admin.roles
        return exit_json(200, res[1])
      end
      return exit_json(400, { message = "Failed to update admin" })
    end,
    DELETE = function(self, db)
      local admin = find_admin(self.params.name_or_id)
      if not admin then
        return exit_json(404, { message = "Not found" })
      end
      -- Prevent deleting super-admin
      for _, r in ipairs(admin.roles or {}) do
        if r.name == "super-admin" then
          return exit_json(403, { message = "Cannot delete super-admin" })
        end
      end
      exec(string.format([[DELETE FROM admin_roles WHERE admin_id = '%s'::uuid]], admin.id))
      exec(string.format([[DELETE FROM admins WHERE id = '%s'::uuid]], admin.id))
      return exit_json(204)
    end,
  },
  ["/admins/:name_or_id/roles"] = {
    GET = function(self, db)
      local admin = find_admin(self.params.name_or_id)
      if not admin then
        return exit_json(404, { message = "Admin not found" })
      end
      return exit_json(200, { data = admin.roles or {} })
    end,
    POST = function(self, db)
      local admin = find_admin(self.params.name_or_id)
      if not admin then
        return exit_json(404, { message = "Admin not found" })
      end
      local roles = self.params.roles
      if not roles then
        return exit_json(400, { message = "roles field is required" })
      end
      for _, role_name in ipairs(roles) do
        local role = find_rbac_role(role_name)
        if role then
          exec(string.format(
            [[INSERT INTO admin_roles (admin_id, role_id) VALUES ('%s'::uuid, '%s'::uuid) ON CONFLICT DO NOTHING]],
            admin.id, role.id
          ))
        end
      end
      local updated = find_admin(self.params.name_or_id)
      return exit_json(200, updated)
    end,
  },
  ["/admins/:name_or_id/roles/:role_name_or_id"] = {
    DELETE = function(self, db)
      local admin = find_admin(self.params.name_or_id)
      if not admin then
        return exit_json(404, { message = "Admin not found" })
      end
      local role = find_rbac_role(self.params.role_name_or_id)
      if not role then
        return exit_json(404, { message = "Role not found" })
      end
      exec(string.format(
        [[DELETE FROM admin_roles WHERE admin_id = '%s'::uuid AND role_id = '%s'::uuid]],
        admin.id, role.id
      ))
      local updated = find_admin(self.params.name_or_id)
      return exit_json(200, updated)
    end,
  },
  ["/admins/:name_or_id/workspaces"] = {
    GET = function(self, db)
      local admin = find_admin(self.params.name_or_id)
      if not admin then
        return exit_json(404, { message = "Admin not found" })
      end
      local rows = query([[SELECT id, name, comment, created_at, updated_at FROM workspaces ORDER BY name]]) or {}
      return exit_json(200, { data = rows, next = nil })
    end,
  },
}


-- ============================================================
-- Available Endpoints (dynamic introspection)
-- ============================================================

local available_endpoints_routes = {
  ["/rbac/available-endpoints"] = {
    GET = function(self, db)
      -- Introspect ALL registered Lapis routes via each_route,
      -- then normalize to RBAC endpoint patterns (/* wildcard form).
      -- This is the same source of truth that /endpoints uses.
      local each_route = require("lapis.application.route_group").each_route
      local application = require("kong.api")

      local raw_patterns = {}
      each_route(application, true, function(path)
        if type(path) == "table" then
          path = next(path)
        end
        if path and not raw_patterns[path] then
          raw_patterns[path] = true
        end
      end)

      local seen = {}
      local endpoints = {}

      -- 1. Catch-all wildcard
      endpoints[1] = { value = "*", label = "* (all endpoints)" }
      seen["*"] = true

      -- 2. Normalize each route pattern
      -- /services/:services → /services/*
      -- /workspaces/:workspaces/services → /workspaces/*/services  (KEEP!)
      -- /schemas/:name → /schemas/*
      for pattern, _ in pairs(raw_patterns) do
        if type(pattern) == "string" then
          -- Replace :param with * for RBAC wildcard semantics
          local normalized = pattern:gsub(":[%w_]+", "*")

          if normalized and #normalized > 1 and not seen[normalized] then
            seen[normalized] = true
            table.insert(endpoints, { value = normalized, label = normalized })
          end
        end
      end

      -- 3. Sort: * first, then segment-based alphabetical
      table.sort(endpoints, function(a, b)
        if a.value == "*" then return true end
        if b.value == "*" then return false end
        return a.value:gsub("/", string.char(0)) < b.value:gsub("/", string.char(0))
      end)

      -- 4. Derive entity types from endpoints (for entity-level permissions)
      -- Only top-level entity names, no nested paths
      local entity_types = {}
      local seen_types = {}
      for _, ep in ipairs(endpoints) do
        -- "/services/*" → "services", "/rbac/users" → "rbac_users"
        local base = ep.value:gsub("^/", ""):gsub("/%*+$", ""):gsub("/", "_")
        -- Only include simple entity names (no nested paths like services_plugins)
        if base ~= "*" and not base:match("_") and not seen_types[base] then
          seen_types[base] = true
          table.insert(entity_types, base)
        end
      end
      -- Add special composite entity types that use _ in name
      local extra_types = {
        "ca_certificates", "rbac_users", "rbac_roles", "rbac_groups",
        "key_sets", "filter_chains", "consumer_groups",
      }
      for _, t in ipairs(extra_types) do
        if not seen_types[t] then
          seen_types[t] = true
          table.insert(entity_types, t)
        end
      end
      table.sort(entity_types)

      return exit_json(200, {
        data = endpoints,
        entity_types = entity_types,
      })
    end,
  },
}


-- Merge all routes
local all_routes = {}
for pattern, data in pairs(rbac_users_routes) do
  all_routes[pattern] = data
end
for pattern, data in pairs(rbac_roles_routes) do
  all_routes[pattern] = data
end
for pattern, data in pairs(rbac_groups_routes) do
  all_routes[pattern] = data
end
for pattern, data in pairs(admins_routes) do
  all_routes[pattern] = data
end
for pattern, data in pairs(available_endpoints_routes) do
  all_routes[pattern] = data
end

return all_routes
