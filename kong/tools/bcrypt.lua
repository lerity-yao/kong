--- bcrypt utility for hashing and verifying passwords.
-- Uses POSIX crypt() via FFI (libcrypt) for bcrypt support.
-- @module kong.tools.bcrypt

local ffi = require "ffi"


ffi.cdef [[
  char *crypt(const char *key, const char *salt);
]]


local _M = {}


--- Generate a bcrypt salt with default cost factor 10.
-- @return string bcrypt salt string like "$2a$10$..."
function _M.gensalt()
  local random = require "resty.random"
  local to_hex = require "resty.string".to_hex
  -- 16 bytes of random data for bcrypt salt
  local r = random.bytes(16)
  return "$2a$10$" .. to_hex(r):sub(1, 22)
end


--- Hash a password using bcrypt.
-- @param password string The plain-text password
-- @return string The bcrypt hash
function _M.hash(password)
  local salt = _M.gensalt()
  local c_hash = ffi.C.crypt(password, salt)
  if c_hash == nil then
    return nil, "bcrypt hash failed"
  end
  return ffi.string(c_hash)
end


--- Verify a password against a bcrypt hash.
-- @param password string The plain-text password
-- @param hash string The bcrypt hash to verify against
-- @return boolean true if password matches
function _M.verify(password, hash)
  local c_hash = ffi.C.crypt(password, hash)
  if c_hash == nil then
    return false
  end
  return ffi.string(c_hash) == hash
end


return _M
