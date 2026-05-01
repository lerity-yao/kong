
local ApiDocs = {}

-- Custom query: select current version by name
-- ws_id: optional workspace UUID filter
function ApiDocs:select_current_by_name(name, ws_id)
  local doc, err = self.strategy:select_current_by_name(name, ws_id)
  if err then
    return nil, err
  end
  return self:row_to_entity(doc), nil
end

-- Custom query: select by service_id
-- ws_id: optional workspace UUID filter
function ApiDocs:select_by_service_id(service_id, ws_id)
  local docs, err = self.strategy:select_by_service_id(service_id, ws_id)
  if err then
    return nil, err
  end
  return self:rows_to_entities(docs), nil
end

-- Custom query: select all versions by name (paginated)
-- ws_id: optional workspace UUID filter
function ApiDocs:select_versions_by_name(name, size, offset, ws_id)
  local rows, err, err_t, next_offset = self.strategy:select_versions_by_name(name, size, offset, ws_id)
  if err then
    return nil, err, err_t
  end
  local entities, err2, err_t2 = self:rows_to_entities(rows)
  if not entities then
    return nil, err2, err_t2
  end
  return entities, nil, nil, next_offset
end

-- Custom query: page current docs with optional workspace filter
-- options.ws_id: optional workspace UUID filter
-- options.all: if true, don't filter by is_current
function ApiDocs:page_current(size, offset, options)
  local rows, err, err_t, next_offset = self.strategy:page_current(size, offset, options)
  if err then
    return nil, err, err_t
  end
  local entities, err2, err_t2 = self:rows_to_entities(rows, options)
  if not entities then
    return nil, err2, err_t2
  end
  return entities, nil, nil, next_offset
end

return ApiDocs
