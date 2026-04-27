-- Custom workspaces API route: supports ?counter=true parameter
-- When counter=true, each workspace includes a "counters" field
-- with entity counts (services, routes, consumers, plugins, etc.)

local COUNTER_ENTITIES = {
  "services",
  "routes",
  "consumers",
  "plugins",
  "upstreams",
  "certificates",
  "snis",
  "vaults",
  "keys",
  "key_sets",
}


local function get_entity_count(db, ws_id, entity_name)
  local dao = db[entity_name]
  if not dao then
    return 0
  end

  -- Temporarily set workspace context
  local old_ws = ngx.ctx.workspace
  ngx.ctx.workspace = ws_id

  local count = 0
  local ok, err = pcall(function()
    -- dao:page(size, offset, options)
    -- Pass workspace in options to ensure correct ws_id filtering
    local opts = { workspace = ws_id, pagination = { page_size = 1000 } }
    local offset
    repeat
      local res, err2 = dao:page(1000, offset, opts)
      if err2 then
        return
      end
      local rows = res.data or res
      for _ in ipairs(rows) do
        count = count + 1
      end
      offset = res.next
    until not offset
  end)

  ngx.ctx.workspace = old_ws

  if not ok then
    return 0
  end
  return count
end


return {
  ["/workspaces"] = {
    GET = function(self, db, helpers, parent)
      local counter = self.params.counter

      -- If no counter param, fall through to auto-generated handler
      if not counter then
        return parent()
      end

      -- Fetch workspaces using DAO directly
      local workspaces_data, err = db.workspaces:page()
      if err then
        return kong.response.exit(500, { message = "Failed to fetch workspaces: " .. tostring(err) })
      end

      -- Build response with counters
      local result = {}
      local rows = workspaces_data.data or workspaces_data

      for _, ws in ipairs(rows) do
        local ws_data = {
          id = ws.id,
          name = ws.name,
          comment = ws.comment,
          created_at = ws.created_at,
          updated_at = ws.updated_at,
          meta = ws.meta,
          config = ws.config,
        }

        local counters = {}
        for _, entity_name in ipairs(COUNTER_ENTITIES) do
          counters[entity_name] = get_entity_count(db, ws.id, entity_name)
        end
        ws_data.counters = counters

        table.insert(result, ws_data)
      end

      return kong.response.exit(200, {
        data = result,
        next = workspaces_data.next,
      })
    end,
  },
}
