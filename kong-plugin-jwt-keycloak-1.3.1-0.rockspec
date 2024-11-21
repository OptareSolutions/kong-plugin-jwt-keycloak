package = "kong-plugin-jwt-keycloak"

version = "1.3.1-0"

local pluginName = package:match("^kong%-plugin%-(.+)$")  -- "jwt-keycloak"
supported_platforms = {"linux", "macosx"}

local github_account_name = "OptareSolutions"
local github_repo_name = "kong-plugin-jwt-keycloak"
local github_tag = version -- we should push a tag matching the version

source = {
    url = "git://github.com/"..github_account_name.."/"..github_repo_name,
    tag = github_tag,
    dir = github_repo_name
}
description = {
  summary = "A Kong plugin that will validate tokens issued by keycloak",
  homepage = "https://github.com/"..github_account_name.."/"..github_repo_name,
  license = "Apache 2.0"
}
dependencies = {
  "lua ~> 5"
}
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.jwt-keycloak.validators.issuers"] = "src/validators/issuers.lua",
    ["kong.plugins.jwt-keycloak.validators.roles"] = "src/validators/roles.lua",
    ["kong.plugins.jwt-keycloak.validators.scope"] = "src/validators/scope.lua",
    ["kong.plugins.jwt-keycloak.handler"] = "src/handler.lua",
    ["kong.plugins.jwt-keycloak.key_conversion"] = "src/key_conversion.lua",
    ["kong.plugins.jwt-keycloak.keycloak_keys"] = "src/keycloak_keys.lua",
    ["kong.plugins.jwt-keycloak.schema"]  = "src/schema.lua",
  }
}