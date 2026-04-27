local cjson = require "cjson.safe".new()
local utils = require "kong.tools.utils"


-- 支持的语言和模块
local SUPPORTED_LOCALES = {
  ["en-US"] = true,
  ["zh-CN"] = true,
}

local SUPPORTED_MODULES = {
  Global         = true,
  Workspaces     = true,
  Overview       = true,
  About          = true,
  Services       = true,
  Routes         = true,
  Consumers      = true,
  Plugins        = true,
  Upstreams      = true,
  Certificates   = true,
  Vaults         = true,
  Keys           = true,
  Teams          = true,
  RBAC          = true,
}


-- 语言包缓存（启动时加载，避免每次请求读文件）
local locale_cache = nil


-- 从文件系统加载语言包
local function load_locales()
  if locale_cache then
    return locale_cache
  end

  locale_cache = {}

  for lang, _ in pairs(SUPPORTED_LOCALES) do
    locale_cache[lang] = {}
    for mod, _ in pairs(SUPPORTED_MODULES) do
      local path = "kong/locales/" .. lang .. "/" .. mod .. ".json"
      local file, err = io.open(path, "r")
      if file then
        local content = file:read("*a")
        file:close()
        local data = cjson.decode(content)
        if data then
          locale_cache[lang][mod] = data
        end
      else
        ngx.log(ngx.DEBUG, "locale file not found: ", path, " err: ", err)
      end
    end
  end

  return locale_cache
end


-- GET /locales/:lang/:module
-- 支持 /locales/en-US/Global 和 /locales/en-US/Global.json 两种格式
local function get_locale_module(self)
  local lang = self.params.lang
  local mod = self.params.module

  -- 去掉 .json 后缀
  if mod and mod:sub(-5) == ".json" then
    mod = mod:sub(1, -6)
  end

  if not lang or not SUPPORTED_LOCALES[lang] then
    return kong.response.exit(404, { message = "Unsupported locale: " .. tostring(lang) })
  end

  if not mod or not SUPPORTED_MODULES[mod] then
    return kong.response.exit(404, { message = "Unsupported module: " .. tostring(mod) })
  end

  local cache = load_locales()
  local data = cache[lang] and cache[lang][mod]

  if not data then
    return kong.response.exit(404, { message = "Locale not found: " .. lang .. "/" .. mod })
  end

  return kong.response.exit(200, data)
end


-- GET /locales
-- 返回支持的语言列表
local function list_locales()
  local cache = load_locales()
  local result = {}
  for lang, modules in pairs(cache) do
    local available = {}
    for mod, _ in pairs(modules) do
      table.insert(available, mod)
    end
    table.insert(result, {
      locale = lang,
      modules = available,
    })
  end

  table.sort(result, function(a, b) return a.locale < b.locale end)

  return kong.response.exit(200, { locales = result })
end


return {
  ["/locales/:lang/:module"] = {
    GET = get_locale_module,
  },

  ["/locales"] = {
    GET = list_locales,
  },
}
