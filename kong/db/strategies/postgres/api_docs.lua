local kong = kong
local fmt  = string.format

local ApiDocs = {}

---------------------------------------------------------------------------
-- Helper: resolve workspace name to ws_id UUID
---------------------------------------------------------------------------
local function resolve_ws_id(workspace_name)
  if not workspace_name or workspace_name == "" then
    return nil
  end
  local ws, err = kong.db.workspaces:select_by_name(workspace_name)
  if ws then
    return ws.id
  end
  return nil
end

---------------------------------------------------------------------------
-- Select the current version of an api_doc by name
-- workspace_name: optional filter
---------------------------------------------------------------------------
function ApiDocs:select_current_by_name(name, ws_id)
  local qs
  if ws_id then
    qs = fmt(
      "SELECT * FROM api_docs WHERE ws_id = %s AND name = %s AND is_current = TRUE LIMIT 1;",
      kong.db.connector:escape_literal(ws_id),
      kong.db.connector:escape_literal(name))
  else
    qs = fmt(
      "SELECT * FROM api_docs WHERE name = %s AND is_current = TRUE LIMIT 1;",
      kong.db.connector:escape_literal(name))
  end

  local rows, err = kong.db.connector:query(qs, "read")
  if err then
    return nil, err
  end

  if not rows or #rows == 0 then
    return nil
  end

  return rows[1]
end

---------------------------------------------------------------------------
-- Select current api_docs by service_id
-- ws_id: optional workspace filter
---------------------------------------------------------------------------
function ApiDocs:select_by_service_id(service_id, ws_id)
  local qs
  if ws_id then
    qs = fmt(
      "SELECT * FROM api_docs WHERE ws_id = %s AND service_id = %s AND is_current = TRUE;",
      kong.db.connector:escape_literal(ws_id),
      kong.db.connector:escape_literal(service_id))
  else
    qs = fmt(
      "SELECT * FROM api_docs WHERE service_id = %s AND is_current = TRUE;",
      kong.db.connector:escape_literal(service_id))
  end

  return kong.db.connector:query(qs, "read")
end

---------------------------------------------------------------------------
-- Select all versions of an api_doc by name (paginated)
-- ws_id: optional workspace filter
---------------------------------------------------------------------------
function ApiDocs:select_versions_by_name(name, size, offset, ws_id)
  local limit = (size or 100) + 1

  local where_clauses = {}
  table.insert(where_clauses, fmt("name = %s", kong.db.connector:escape_literal(name)))

  if ws_id then
    table.insert(where_clauses, fmt("ws_id = %s", kong.db.connector:escape_literal(ws_id)))
  end

  if offset and offset ~= "" then
    local decoded = ngx.decode_base64(offset)
    if decoded then
      local cjson = require "cjson.safe"
      local tok = cjson.decode(decoded)
      if tok and tok[1] then
        table.insert(where_clauses, fmt("id > %s", kong.db.connector:escape_literal(tok[1])))
      end
    end
  end

  local where_sql = " WHERE " .. table.concat(where_clauses, " AND ")
  local qs = fmt("SELECT * FROM api_docs%s ORDER BY version DESC LIMIT %d;", where_sql, limit)

  local rows, err = kong.db.connector:query(qs, "read")
  if err then
    return nil, tostring(err)
  end

  rows = rows or {}
  local next_offset
  if #rows == limit then
    rows[limit] = nil
    local cjson = require "cjson"
    next_offset = ngx.encode_base64(cjson.encode({rows[#rows].id}))
  end

  return rows, nil, nil, next_offset
end

---------------------------------------------------------------------------
-- Page current api_docs with optional workspace filter
-- options.ws_id: optional workspace UUID filter
-- options.all: if true, don't filter by is_current
---------------------------------------------------------------------------
function ApiDocs:page_current(size, offset, options)
  local ws_id = options and options.ws_id or nil
  local filter_current = true
  if options and options.all then
    filter_current = false
  end

  local limit = (size or 100) + 1
  local where_clauses = {}

  if filter_current then
    table.insert(where_clauses, "is_current = TRUE")
  end

  if ws_id then
    table.insert(where_clauses, fmt("ws_id = %s", kong.db.connector:escape_literal(ws_id)))
  end

  if offset and offset ~= "" then
    local decoded = ngx.decode_base64(offset)
    if decoded then
      local cjson = require "cjson.safe"
      local tok = cjson.decode(decoded)
      if tok and tok[1] then
        table.insert(where_clauses, fmt("id > %s", kong.db.connector:escape_literal(tok[1])))
      end
    end
  end

  local where_sql = ""
  if #where_clauses > 0 then
    where_sql = " WHERE " .. table.concat(where_clauses, " AND ")
  end

  local qs = fmt("SELECT * FROM api_docs%s ORDER BY id LIMIT %d;", where_sql, limit)

  local rows, err = kong.db.connector:query(qs, "read")
  if err then
    return nil, tostring(err)
  end

  rows = rows or {}
  local next_offset
  if #rows == limit then
    rows[limit] = nil
    local cjson = require "cjson"
    next_offset = ngx.encode_base64(cjson.encode({rows[#rows].id}))
  end

  return rows, nil, nil, next_offset
end

return ApiDocs
