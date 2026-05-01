local cjson = require "cjson"
local kong = kong
local fmt = string.format
local sub  = string.sub
local find = string.find


-- Generate version timestamp: YYYYMMDDHHmmss
local function generate_version()
  return os.date("!%Y%m%d%H%M%S")
end


-- Resolve workspace param to ws_id UUID
local function resolve_ws_id(workspace_name)
  if not workspace_name or workspace_name == "" then
    return nil
  end
  local ws = kong.db.workspaces:select_by_name(workspace_name)
  if ws then
    return ws.id
  end
  return nil
end


-- Flip is_current: set old versions to false when uploading a new version
local function flip_is_current(name, ws_id)
  local where = { fmt("name = %s", kong.db.connector:escape_literal(name)) }
  if ws_id then
    table.insert(where, fmt("ws_id = %s", kong.db.connector:escape_literal(ws_id)))
  end
  local qs = fmt(
    "UPDATE api_docs SET is_current = FALSE WHERE %s AND is_current = TRUE;",
    table.concat(where, " AND "))
  return kong.db.connector:query(qs, "write")
end


-- Promote the latest remaining version as current after deletion
local function promote_latest_version(name, ws_id)
  local where = { fmt("name = %s", kong.db.connector:escape_literal(name)) }
  local sub_where = { fmt("name = %s", kong.db.connector:escape_literal(name)) }
  if ws_id then
    table.insert(where, fmt("ws_id = %s", kong.db.connector:escape_literal(ws_id)))
    table.insert(sub_where, fmt("ws_id = %s", kong.db.connector:escape_literal(ws_id)))
  end
  local qs = fmt(
    [[UPDATE api_docs SET is_current = TRUE
      WHERE %s AND version = (
        SELECT MAX(version) FROM api_docs WHERE %s
      );]],
    table.concat(where, " AND "),
    table.concat(sub_where, " AND "))
  kong.db.connector:query(qs, "write")
end


---------------------------------------------------------------------------
-- Swagger path matching helpers
---------------------------------------------------------------------------

local function swagger_path_to_pattern(swagger_path)
  return swagger_path:gsub("%{[^}]+%}", "[^/]+")
end

local function path_matches_route(swagger_path, route_path)
  if sub(route_path, 1, 1) == "~" then
    local rx = sub(route_path, 2)
    local sp = swagger_path_to_pattern(swagger_path)
    local ok, _ = pcall(function() return sp:match(rx) end)
    if ok and sp:match(rx) then return true end
    if find(sp, rx, 1, true) then return true end
    return false
  end
  local rp = route_path:gsub("/+$", "")
  local sp = swagger_path
  if sp == rp then return true end
  if sub(sp, 1, #rp + 1) == rp .. "/" then return true end
  return false
end

local function filter_spec_by_paths(spec, route_paths)
  if not spec or not spec.paths or not route_paths or #route_paths == 0 then
    return spec
  end
  local filtered_paths = {}
  local any_match = false
  for swagger_path, ops in pairs(spec.paths) do
    for _, route_path in ipairs(route_paths) do
      if path_matches_route(swagger_path, route_path) then
        filtered_paths[swagger_path] = ops
        any_match = true
        break
      end
    end
  end
  if not any_match then return spec end
  local new_spec = {}
  for k, v in pairs(spec) do
    if k ~= "paths" then new_spec[k] = v end
  end
  new_spec.paths = filtered_paths
  return new_spec
end


---------------------------------------------------------------------------
-- Entity-level RBAC helpers
---------------------------------------------------------------------------

local function get_entity_allowed_names()
  local session = require "resty.session"
  local s = session.new({
    cookie_name = "session",
    secret = (kong.configuration.admin_gui_session_conf and
      require("cjson.safe").new().decode(kong.configuration.admin_gui_session_conf).secret) or "kong",
    audience = "default",
    cookie_path = "/",
    cookie_http_only = true,
    cookie_same_site = "Lax",
  })
  local ok, _ = pcall(s.open, s)
  local user_data = s.data and s.data[s.data_index] and s.data[s.data_index][1]
  local user_id = user_data and user_data.id
  local user_type = user_data and user_data.user_type

  if not user_id or user_type == "admin" then
    return nil
  end

  local role_ids = {}
  local role_res, _ = kong.db.connector:query(
    fmt([[SELECT role_id FROM rbac_user_roles WHERE user_id = %s::uuid]],
      kong.db.connector:escape_literal(user_id)),
    "read"
  )
  if not role_res or #role_res == 0 then return nil end
  for _, r in ipairs(role_res) do
    table.insert(role_ids, fmt("%s::uuid", kong.db.connector:escape_literal(r.role_id)))
  end

  local entity_res, _ = kong.db.connector:query(
    fmt([[SELECT entity_id, negative FROM rbac_role_entities
          WHERE role_id IN (%s) AND entity_type = 'api_docs']],
        table.concat(role_ids, ",")),
    "read"
  )
  if not entity_res or #entity_res == 0 then return nil end

  local allowed = {}
  local has_positive = false
  for _, e in ipairs(entity_res) do
    if not e.negative then
      allowed[e.entity_id] = true
      has_positive = true
    else
      allowed[e.entity_id] = false
    end
  end
  if not has_positive then return nil end
  return allowed
end

local function filter_by_entity(docs)
  local allowed = get_entity_allowed_names()
  if not allowed then return docs end
  local filtered = {}
  for _, doc in ipairs(docs) do
    if allowed[doc.name] then
      table.insert(filtered, doc)
    end
  end
  return filtered
end


---------------------------------------------------------------------------
-- Build clean insert body (only schema-recognized fields)
---------------------------------------------------------------------------
local function clean_insert_body(params)
  local body = {
    name = params.name,
    spec_content = params.spec_content,
  }
  -- Optional: service association
  if params.service_id then
    if params.service_id == "" or params.service_id == ngx.null then
      body.service = ngx.null
    else
      body.service = { id = params.service_id }
    end
  end
  -- Optional: workspace filter
  if params.workspace then
    local ws_id = resolve_ws_id(params.workspace)
    if ws_id then
      body.ws_id = ws_id
    end
  end
  return body
end


---------------------------------------------------------------------------
-- Routes
---------------------------------------------------------------------------

return {
  -- GET /api-docs — list with filters
  -- Query params: workspace, service_id, name, is_current, size, offset
  ["/api-docs"] = {
    GET = function(self, db, helpers)
      local opts = {
        size = self.params.size or 100,
        offset = self.params.offset,
      }
      local ws_id = resolve_ws_id(self.params.workspace)

      local filter_is_current = true
      if self.params.is_current == "false" then
        filter_is_current = false
      end

      local docs, err, err_t, offset
      if self.params.service_id then
        docs, err = db.api_docs:select_by_service_id(self.params.service_id, ws_id)
      elseif self.params.name and filter_is_current then
        docs, err, err_t, offset = db.api_docs:select_versions_by_name(self.params.name, opts.size, opts.offset, ws_id)
      elseif filter_is_current then
        docs, err, err_t, offset = db.api_docs:page_current(opts.size, opts.offset, { ws_id = ws_id })
      else
        docs, err, err_t, offset = db.api_docs:page_current(opts.size, opts.offset, { ws_id = ws_id, all = true })
      end

      if err then
        return kong.response.exit(500, { message = "Failed to list API docs: " .. tostring(err) })
      end

      docs = filter_by_entity(docs or {})

      -- Enrich docs with ws_name by batch-resolving ws_id → workspace name
      local ws_cache = {}
      for _, doc in ipairs(docs) do
        if doc.ws_id and doc.ws_id ~= ngx.null then
          if not ws_cache[doc.ws_id] then
            local ws = kong.db.workspaces:select({ id = doc.ws_id })
            ws_cache[doc.ws_id] = ws and ws.name or nil
          end
          doc.ws_name = ws_cache[doc.ws_id] or nil
        end
      end

      return kong.response.exit(200, {
        data = docs,
        next = offset,
      })
    end,

    -- POST /api-docs — create with auto version
    POST = function(self, db, helpers)
      local params = self.params

      if not params.name or params.name == "" then
        return kong.response.exit(400, { message = "name is required" })
      end
      if not params.spec_content or params.spec_content == "" then
        return kong.response.exit(400, { message = "spec_content is required" })
      end

      local ws_id = resolve_ws_id(params.workspace)

      -- Flip old is_current for same name
      flip_is_current(params.name, ws_id)

      -- Build clean body with only schema fields
      local body = clean_insert_body(params)
      body.version = generate_version()
      body.is_current = true

      local doc, err, err_t = db.api_docs:insert(body)
      if err then
        return kong.response.exit(500, { message = "Failed to create API doc: " .. tostring(err_t or err) })
      end

      return kong.response.exit(201, doc)
    end,
  },

  -- GET /api-docs/:name — get current version by name
  ["/api-docs/:name"] = {
    GET = function(self, db, helpers)
      local ws_id = resolve_ws_id(self.params.workspace)
      local doc, err = db.api_docs:select_current_by_name(self.params.name, ws_id)
      if err then
        return kong.response.exit(500, { message = "Failed to get API doc: " .. tostring(err) })
      end
      if not doc then
        return kong.response.exit(404, { message = "API doc not found" })
      end
      return kong.response.exit(200, doc)
    end,

    -- PATCH /api-docs/:name — update metadata
    PATCH = function(self, db, helpers)
      local ws_id = resolve_ws_id(self.params.workspace)
      local doc, err = db.api_docs:select_current_by_name(self.params.name, ws_id)
      if err then
        return kong.response.exit(500, { message = "Failed to find API doc: " .. tostring(err) })
      end
      if not doc then
        return kong.response.exit(404, { message = "API doc not found" })
      end

      local updates = {}
      if self.params.service_id ~= nil then
        if self.params.service_id == "" or self.params.service_id == ngx.null then
          updates.service = ngx.null
        else
          updates.service = { id = self.params.service_id }
        end
      end

      -- Support changing workspace
      if self.params.new_workspace ~= nil and self.params.new_workspace ~= "" then
        local new_ws_id = resolve_ws_id(self.params.new_workspace)
        if new_ws_id then
          updates.ws_id = new_ws_id
        end
      end

      if next(updates) then
        updates.id = doc.id
        local updated, err, err_t = db.api_docs:update(updates)
        if err then
          return kong.response.exit(500, { message = "Failed to update API doc: " .. tostring(err_t or err) })
        end
        return kong.response.exit(200, updated)
      end

      return kong.response.exit(200, doc)
    end,

    -- DELETE /api-docs/:name — delete current version
    DELETE = function(self, db, helpers)
      local ws_id = resolve_ws_id(self.params.workspace)
      local doc, err = db.api_docs:select_current_by_name(self.params.name, ws_id)
      if err then
        return kong.response.exit(500, { message = "Failed to find API doc: " .. tostring(err) })
      end
      if not doc then
        return kong.response.exit(404, { message = "API doc not found" })
      end

      local _, err = db.api_docs:delete({ id = doc.id })
      if err then
        return kong.response.exit(500, { message = "Failed to delete API doc: " .. tostring(err) })
      end

      promote_latest_version(doc.name, ws_id)
      return kong.response.exit(204)
    end,
  },

  -- GET /api-docs/:name/versions — list all versions
  ["/api-docs/:name/versions"] = {
    GET = function(self, db, helpers)
      local ws_id = resolve_ws_id(self.params.workspace)
      local docs, err, err_t, offset = db.api_docs:select_versions_by_name(
        self.params.name, self.params.size or 100, self.params.offset, ws_id)
      if err then
        return kong.response.exit(500, { message = "Failed to list versions: " .. tostring(err) })
      end
      return kong.response.exit(200, {
        data = docs or {},
        next = offset,
      })
    end,
  },

  -- GET /api-docs/:name/versions/:version — get/delete specific version
  ["/api-docs/:name/versions/:version"] = {
    GET = function(self, db, helpers)
      local ws_id = resolve_ws_id(self.params.workspace)
      local docs, err = db.api_docs:select_versions_by_name(self.params.name, 1000, nil, ws_id)
      if err then
        return kong.response.exit(500, { message = "Failed to get version: " .. tostring(err) })
      end

      if docs then
        for _, doc in ipairs(docs) do
          if doc.version == self.params.version then
            return kong.response.exit(200, doc)
          end
        end
      end

      return kong.response.exit(404, { message = "Version not found" })
    end,

    DELETE = function(self, db, helpers)
      local ws_id = resolve_ws_id(self.params.workspace)
      local docs, err = db.api_docs:select_versions_by_name(self.params.name, 1000, nil, ws_id)
      if err then
        return kong.response.exit(500, { message = "Failed to find version: " .. tostring(err) })
      end

      if not docs or #docs == 0 then
        return kong.response.exit(404, { message = "API doc not found" })
      end

      for _, doc in ipairs(docs) do
        if doc.version == self.params.version then
          local _, err = db.api_docs:delete({ id = doc.id })
          if err then
            return kong.response.exit(500, { message = "Failed to delete version: " .. tostring(err) })
          end

          if doc.is_current then
            promote_latest_version(doc.name, ws_id)
          end

          return kong.response.exit(204)
        end
      end

      return kong.response.exit(404, { message = "Version not found" })
    end,
  },

  -- GET /api-docs/by-route/:route_id
  ["/api-docs/by-route/:route_id"] = {
    GET = function(self, db, helpers)
      local route_id = self.params.route_id
      if not route_id or route_id == "" then
        return kong.response.exit(400, { message = "route_id is required" })
      end

      local route, err = db.routes:select({ id = route_id })
      if err then
        return kong.response.exit(500, { message = "Failed to lookup route: " .. tostring(err) })
      end
      if not route then
        return kong.response.exit(404, { message = "Route not found" })
      end

      local service_id
      if route.service then
        service_id = route.service.id
      end
      if not service_id then
        return kong.response.exit(200, { data = {}, message = "Route has no associated service" })
      end

      local docs, err = db.api_docs:select_by_service_id(service_id)
      if err then
        return kong.response.exit(500, { message = "Failed to lookup API docs: " .. tostring(err) })
      end

      if not docs or #docs == 0 then
        return kong.response.exit(200, { data = {}, message = "No API docs found for this service" })
      end

      local route_paths = route.paths or {}
      local result = {}
      for _, doc in ipairs(docs) do
        local entry = {
          id = doc.id,
          name = doc.name,
          version = doc.version,
          is_current = doc.is_current,
          service = doc.service,
          created_at = doc.created_at,
        }

        if doc.spec_content then
          local ok, spec = pcall(cjson.decode, doc.spec_content)
          if ok and spec then
            entry.spec = filter_spec_by_paths(spec, route_paths)
            entry.path_count = spec.paths and #kong.table.keys(spec.paths) or 0
            entry.matched_path_count = entry.spec.paths and #kong.table.keys(entry.spec.paths) or 0
          else
            entry.spec = nil
            entry.parse_error = true
          end
        end

        local allowed = get_entity_allowed_names()
        if not allowed or allowed[doc.name] then
          table.insert(result, entry)
        end
      end

      return kong.response.exit(200, {
        data = result,
        route = {
          id = route.id,
          name = route.name,
          paths = route.paths,
          hosts = route.hosts,
        },
      })
    end,
  },
}
