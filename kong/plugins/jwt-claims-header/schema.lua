local typedefs = require "kong.db.schema.typedefs"
local validate_header_name = require("kong.tools.http").validate_header_name


local function validate_header(val)
  if validate_header_name(val) == nil then
    return nil, tostring(val) .. " is not a valid header name"
  end
  return true
end


return {
  name = "jwt-claims-header",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { forward_all_claims = {
              description = "开关：打开后，将 JWT 所有 claims 打包为 JSON 放入 X-JWT-Claims Header 转发给上游。"
                         .. "打开时逐字段转发（claims_to_forward）不可用；关闭时可逐个配置要转发的字段。",
              type = "boolean",
              required = true,
              default = false,
          }, },
          { claims_to_forward = {
              description = "逐字段转发：需要转发给上游的 JWT claim 名称列表。"
                         .. "每个 claim 会以独立 Header 形式转发，格式为：<header_prefix><claim_name>。"
                         .. "例如填写 sub,role，后端将收到 X-JWT-Claim-sub 和 X-JWT-Claim-role 两个 Header。"
                         .. "仅在 forward_all_claims 关闭时生效。",
              type = "set",
              elements = { type = "string" },
              required = false,
              default = {},
          }, },
          { header_prefix = {
              description = "逐字段转发时的 Header 前缀（配合 claims_to_forward 使用）。"
                         .. "例如前缀为 X-JWT-Claim-，sub 字段变为 X-JWT-Claim-sub Header。"
                         .. "仅在 forward_all_claims 关闭时生效。",
              type = "string",
              required = false,
              default = "X-JWT-Claim-",
              custom_validator = validate_header,
          }, },
        },
      },
    },
  },
}
