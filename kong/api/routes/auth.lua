-- Authentication API routes
-- Handles login, logout, session management, and admin registration.

local cjson = require "cjson.safe".new()
cjson.encode_number_precision(16)

local bcrypt = require "kong.tools.bcrypt"


-- Helper: exit with JSON
local function exit_json(status, data)
  return kong.response.exit(status, data)
end


-- Helper: parse admin_gui_session_conf from kong config
local function get_session_conf()
  local conf_str = kong.configuration.admin_gui_session_conf
  if not conf_str or conf_str == "" then
    return { secret = "kong", cookie_lifetime = 86400 }
  end
  local ok, conf = pcall(cjson.decode, conf_str)
  if not ok or type(conf) ~= "table" then
    return { secret = "kong", cookie_lifetime = 86400 }
  end
  return conf
end


-- Helper: open a session using lua-resty-session
local function open_session()
  local session = require "resty.session"
  local conf = get_session_conf()
  local opts = {
    cookie_name = "session",
    secret = conf.secret or "kong",
    audience = "default",
    cookie_path = "/",
    cookie_http_only = true,
    cookie_same_site = "Lax",
    cookie_lifetime = conf.cookie_lifetime or 86400,
  }
  return session.new(opts)
end


-- Helper: store user data in session
local function set_session_data(s, user_type, user_data, roles)
  -- session.data format: {{userdata, audience, subject}, ...}
  -- We must preserve the array structure, only set fields on data[data_index][1]
  local data_index = s.data_index or 1
  if not s.data[data_index] then
    s.data[data_index] = {}
  end
  if not s.data[data_index][1] then
    s.data[data_index][1] = {}
  end
  local d = s.data[data_index][1]
  d.user_type = user_type     -- "admin" or "rbac_user"
  d.id = user_data.id
  d.username = user_data.username or user_data.name
  d.roles = roles or {}
end


-- Helper: get roles for an admin (from admin_roles join table)
local function get_admin_roles(db, admin_id)
  local roles = {}
  local res = kong.db.connector:query(
    string.format(
      [[SELECT r.id, r.name, r.comment
        FROM rbac_roles r
        JOIN admin_roles ar ON ar.role_id = r.id
        WHERE ar.admin_id = '%s'::uuid]],
      admin_id
    ),
    "read"
  )
  if res then
    for _, r in ipairs(res) do
      table.insert(roles, { id = r.id, name = r.name, comment = r.comment })
    end
  end
  return roles
end


-- Helper: get roles for an rbac_user
local function get_rbac_user_roles(db, user_id)
  local roles = {}
  local res = kong.db.connector:query(
    string.format(
      [[SELECT r.id, r.name, r.comment
        FROM rbac_roles r
        JOIN rbac_user_roles ur ON ur.role_id = r.id
        WHERE ur.user_id = '%s'::uuid]],
      user_id
    ),
    "read"
  )
  if res then
    for _, r in ipairs(res) do
      table.insert(roles, { id = r.id, name = r.name, comment = r.comment })
    end
  end
  return roles
end


return {
  ["/auth/login"] = {
    POST = function(self, db)
      local params = self.params
      local username = params.username
      local password = params.password

      if not username or not password then
        return exit_json(400, { message = "username and password are required" })
      end

      -- Look up admin by username via direct SQL
      local res, err = kong.db.connector:query(
        string.format(
          [[SELECT id, username, email, password_hash, status FROM admins WHERE username = '%s' LIMIT 1]],
          username:gsub("'", "''")
        ),
        "read"
      )
      if err then
        return exit_json(500, { message = "Internal error" })
      end
      local admin = res and res[1]
      if not admin then
        return exit_json(401, { message = "Invalid credentials" })
      end

      -- Check if admin is active
      if admin.status ~= 1 then
        return exit_json(401, { message = "Account not activated" })
      end

      -- Verify password
      if not admin.password_hash then
        return exit_json(401, { message = "Invalid credentials" })
      end
      local ok = bcrypt.verify(password, admin.password_hash)
      if not ok then
        return exit_json(401, { message = "Invalid credentials" })
      end

      -- Get roles
      local roles = get_admin_roles(db, admin.id)

      -- Create session
      local s = open_session()
      set_session_data(s, "admin", admin, roles)
      s:save()

      return exit_json(200, {
        id = admin.id,
        username = admin.username,
        email = admin.email,
        roles = roles,
      })
    end,
  },

  ["/auth/logout"] = {
    POST = function(self, db)
      local s = open_session()
      local ok, err = s:open()
      if ok then
        s:destroy()
      end
      return exit_json(200, { message = "Logged out" })
    end,
  },

  ["/auth/me"] = {
    GET = function(self, db)
      local s = open_session()
      local started, err = s:open()
      -- Get user data from session: data[data_index][1] holds the actual user data
      local user_data = s.data and s.data[s.data_index] and s.data[s.data_index][1]
      if not started or not user_data or not user_data.id then
        -- Also check Kong-Admin-Token header
        local token = kong.request.get_header("Kong-Admin-Token")
        if token and token ~= "" then
          -- Try to find rbac_user by token via direct SQL
          local res = kong.db.connector:query(
            string.format(
              [[SELECT * FROM rbac_users WHERE user_token = '%s' AND enabled = true LIMIT 1]],
              token:gsub("'", "''")
            ),
            "read"
          )
          if res and #res > 0 then
            local user = res[1]
            local roles = get_rbac_user_roles(db, user.id)
            return exit_json(200, {
              id = user.id,
              username = user.name,
              roles = roles,
            })
          end
        end
        return exit_json(401, { message = "Not authenticated" })
      end

      -- Refresh roles from DB
      local roles = {}
      if user_data.user_type == "admin" then
        roles = get_admin_roles(db, user_data.id)
      elseif user_data.user_type == "rbac_user" then
        roles = get_rbac_user_roles(db, user_data.id)
      end

      return exit_json(200, {
        id = user_data.id,
        username = user_data.username,
        roles = roles,
      })
    end,
  },

  ["/auth/token"] = {
    POST = function(self, db)
      local params = self.params
      local name = params.name
      local user_token = params.user_token

      if not name or not user_token then
        return exit_json(400, { message = "name and user_token are required" })
      end

      -- Look up rbac_user by name via direct SQL
      local res, err = kong.db.connector:query(
        string.format(
          [[SELECT * FROM rbac_users WHERE name = '%s' AND enabled = true LIMIT 1]],
          name:gsub("'", "''")
        ),
        "read"
      )
      if err then
        return exit_json(500, { message = "Internal error" })
      end
      local user = res and res[1]
      if not user then
        return exit_json(401, { message = "Invalid credentials" })
      end
      if not user.enabled then
        return exit_json(401, { message = "User is disabled" })
      end

      -- Verify token
      if user.user_token ~= user_token then
        return exit_json(401, { message = "Invalid credentials" })
      end

      -- Get roles
      local roles = get_rbac_user_roles(db, user.id)

      -- Create session
      local s = open_session()
      set_session_data(s, "rbac_user", user, roles)
      s:save()

      return exit_json(200, {
        id = user.id,
        username = user.name,
        roles = roles,
      })
    end,
  },

  ["/auth/permissions"] = {
    GET = function(self, db)
      local s = open_session()
      local started, err = s:open()
      local user_data = s.data and s.data[s.data_index] and s.data[s.data_index][1]
      local user_id
      local user_type

      if started and user_data and user_data.id then
        user_id = user_data.id
        user_type = user_data.user_type
      else
        -- Also check Kong-Admin-Token header
        local token = kong.request.get_header("Kong-Admin-Token")
        if token and token ~= "" then
          local res = kong.db.connector:query(
            string.format(
              [[SELECT id FROM rbac_users WHERE user_token = '%s' AND enabled = true LIMIT 1]],
              token:gsub("'", "''")
            ),
            "read"
          )
          if res and #res > 0 then
            user_id = res[1].id
            user_type = "rbac_user"
          end
        end
      end

      if not user_id then
        return exit_json(401, { message = "Not authenticated" })
      end

      -- Admin users have unrestricted access
      if user_type == "admin" then
        return exit_json(200, {
          user_type = "admin",
          endpoints = {{ endpoint = "*", actions = { "*" }, negative = false, workspace = "*" }},
        })
      end

      -- For rbac_user: collect all endpoint permissions from all roles
      local role_res = kong.db.connector:query(
        string.format(
          [[SELECT r.id, r.name FROM rbac_roles r
            JOIN rbac_user_roles ur ON ur.role_id = r.id
            WHERE ur.user_id = '%s'::uuid]],
          user_id
        ),
        "read"
      )

      local all_endpoints = {}
      local is_super_admin = false

      if role_res then
        for _, role in ipairs(role_res) do
          if role.name == "super-admin" then
            is_super_admin = true
            break
          end
          local eps = kong.db.connector:query(
            string.format(
              [[SELECT endpoint, actions, negative, workspace FROM rbac_role_endpoints WHERE role_id = '%s'::uuid]],
              role.id
            ),
            "read"
          )
          if eps then
            for _, ep in ipairs(eps) do
              table.insert(all_endpoints, {
                endpoint = ep.endpoint,
                actions = ep.actions or { "*" },
                negative = ep.negative or false,
                workspace = ep.workspace or "*",
              })
            end
          end
        end
      end

      if is_super_admin then
        return exit_json(200, {
          user_type = "rbac_user",
          endpoints = {{ endpoint = "*", actions = { "*" }, negative = false, workspace = "*" }},
        })
      end

      return exit_json(200, {
        user_type = "rbac_user",
        endpoints = all_endpoints,
      })
    end,
  },

  ["/admins/register"] = {
    POST = function(self, db)
      local params = self.params
      local invite_token = params.invite_token
      local username = params.username
      local password = params.password

      if not invite_token or not username or not password then
        return exit_json(400, { message = "invite_token, username, and password are required" })
      end

      -- Find admin by invite_token with status=0 (invited)
      local res, err = kong.db.connector:query(
        [[SELECT * FROM admins WHERE invite_token = ? AND status = 0 LIMIT 1]],
        { invite_token }
      )
      if err then
        return exit_json(500, { message = "Internal error" })
      end
      if not res or #res == 0 then
        return exit_json(404, { message = "Invalid or expired invite token" })
      end

      local admin = res[1]

      -- Update admin: set username, hash password, activate
      local password_hash = bcrypt.hash(password)
      local update_res, update_err = kong.db.connector:query([[
        UPDATE admins
        SET username = ?, password_hash = ?, status = 1, invite_token = NULL, updated_at = NOW() AT TIME ZONE 'UTC'
        WHERE id = ?::uuid
        RETURNING *
      ]], { username, password_hash, admin.id })

      if update_err then
        return exit_json(400, { message = "Failed to register: " .. tostring(update_err) })
      end

      return exit_json(200, { message = "Registration successful" })
    end,
  },
}
