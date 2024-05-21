local constants = require "kong.constants"
local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local cjson = require("cjson")
local socket = require "socket"
local keycloak_keys = require("kong.plugins.jwt-keycloak.keycloak_keys")

local validate_issuer = require("kong.plugins.jwt-keycloak.validators.issuers").validate_issuer
local validate_scope = require("kong.plugins.jwt-keycloak.validators.scope").validate_scope
local validate_roles = require("kong.plugins.jwt-keycloak.validators.roles").validate_roles
local validate_realm_roles = require("kong.plugins.jwt-keycloak.validators.roles").validate_realm_roles
local validate_client_roles = require("kong.plugins.jwt-keycloak.validators.roles").validate_client_roles

local re_gmatch = ngx.re.gmatch

local JwtKeycloakHandler = {
    VERSION = "1.2.1"
  }

local priority_env_var = "JWT_KEYCLOAK_PRIORITY"
local priority
if os.getenv(priority_env_var) then
    priority = tonumber(os.getenv(priority_env_var))
else
    priority = 950
end
kong.log.debug('JWT_KEYCLOAK_PRIORITY: ' .. priority)

JwtKeycloakHandler.PRIORITY = priority

function table_to_string(tbl)
    local result = ""
    for k, v in pairs(tbl) do
        -- Check the key type (ignore any numerical keys - assume its an array)
        if type(k) == "string" then
            result = result .. "[\"" .. k .. "\"]" .. "="
        end

        -- Check the value type
        if type(v) == "table" then
            result = result .. table_to_string(v)
        elseif type(v) == "boolean" then
            result = result .. tostring(v)
        else
            result = result .. "\"" .. v .. "\""
        end
        result = result .. ","
    end
    -- Remove leading commas from the result
    if result ~= "" then
        result = result:sub(1, result:len() - 1)
    end
    return result
end

local function retrieve_token_payload(internal_request_headers)
    if internal_request_headers == nil or table.getn(internal_request_headers) == 0 then
        return nil
    end
    kong.log.info('Calling retrieve_token_payload(). Getting token_payload which had been saved by other Kong plugins')

    local authenticated_consumer = ngx.ctx.authenticated_consumer
    if authenticated_consumer then
        kong.log.debug('retrieve_token_payload() authenticated_consumer: ' .. authenticated_consumer)
    end

    local jwt_keycloak_token = kong.ctx.shared.jwt_keycloak_token
    if jwt_keycloak_token then
        kong.log.debug('retrieve_token_payload() jwt_keycloak_token: ' .. jwt_keycloak_token)
    end

    local shared_authenticated_jwt_token = kong.ctx.shared.authenticated_jwt_token
    if shared_authenticated_jwt_token then
        kong.log.debug('retrieve_token_payload() shared_authenticated_jwt_token: ' .. shared_authenticated_jwt_token)
    end

    local authenticated_jwt_token = ngx.ctx.authenticated_jwt_token
    if authenticated_jwt_token then
        kong.log.debug('retrieve_token_payload() authenticated_jwt_token: ' .. authenticated_jwt_token)
    end


    --     local userinfo_header = kong.request.get_header("X-Userinfo")
    --     kong.log.debug('retrieve_token_payload() X-Userinfo header: ' .. userinfo_header)
    --     kong.log.debug('retrieve_token_payload() X-Userinfo header decoded: ' .. ngx.decode_base64(userinfo_header))

    --     local tokenStr = kong.request.get_header("X-ID-Token")
    --     local accessToken = kong.request.get_header("X-Access-Token")

    for _, kong_header in pairs(internal_request_headers) do
        kong.log.debug('retrieve_token_payload() retrieving kong.request header: ' .. kong_header)
        local kong_header_value = kong.request.get_header(kong_header)
        if kong_header_value then
            kong.log.debug('retrieve_token_payload() header[' .. kong_header .. ']=' .. kong_header_value)

            -- split access token into parts
            if kong_header == 'X-Access-Token' then
                -- First part is header
                -- Second part is access token payload
                -- Third part is signature
                local accessTokenParts = {}
                for match in string.gmatch(kong_header_value, "[^%.]+") do
                    table.insert(accessTokenParts, match)
                end
                -- !!! Lua begins indexes from 1 !!!
                kong_header_value = accessTokenParts[2];
                kong.log.debug('retrieve_token_payload() retrieved access token payload: ' .. kong_header_value)

            end

            local decoded_kong_header_value = ngx.decode_base64(kong_header_value)
            kong.log.debug('retrieve_token_payload() retrieved decoded value: ' .. decoded_kong_header_value)

            local token_payload = cjson.decode(decoded_kong_header_value)

            return token_payload
        end
    end
end

--- Retrieve a JWT in a request.
-- Checks for the JWT in URI parameters, then in cookies, and finally
-- in the `Authorization` header.
-- @param request ngx request object
-- @param conf Plugin configuration
-- @return token JWT token contained in request (can be a table) or nil
-- @return err
local function retrieve_token(conf)
    kong.log.debug('Calling retrieve_token()')

    local args = kong.request.get_query()
    for _, v in ipairs(conf.uri_param_names) do
        if args[v] then
            kong.log.debug('retrieve_token() args[v]: ' .. args[v])
            return args[v]
        end
    end

    local var = ngx.var
    for _, v in ipairs(conf.cookie_names) do
        kong.log.debug('retrieve_token() checking cookie: ' .. v)
        local cookie = var["cookie_" .. v]
        if cookie and cookie ~= "" then
            kong.log.debug('retrieve_token() cookie value: ' .. cookie)
            return cookie
        end
    end

    local authorization_header = kong.request.get_header("authorization")
    if authorization_header then
        kong.log.debug('retrieve_token() authorization_header: ' .. authorization_header)
        local iterator, iter_err = re_gmatch(authorization_header, "\\s*[Bb]earer\\s+(.+)")
        if not iterator then
            return nil, iter_err
        end

        local m, err = iterator()
        if err then
            return nil, err
        end

        if m and #m > 0 then
            return m[1]
        end
    end
end


local function load_consumer(consumer_id, anonymous)
    local result, err = kong.db.consumers:select { id = consumer_id }
    if not result then
        if anonymous and not err then
            err = 'anonymous consumer "' .. consumer_id .. '" not found'
        end
        return nil, err
    end
    kong.log.debug('load_consumer(): ' .. result)
    return result
end

local function load_consumer_by_custom_id(custom_id)
    local result, err = kong.db.consumers:select_by_custom_id(custom_id)
    if not result then
        return nil, err
    end
    kong.log.debug('load_consumer_by_custom_id(): ' .. result)
    return result
end

local function set_consumer(consumer, credential, token)
    kong.log.debug('Calling set_consumer()' .. credential)

    local set_header = kong.service.request.set_header
    local clear_header = kong.service.request.clear_header

    if consumer and consumer.id then
        set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
    else
        clear_header(constants.HEADERS.CONSUMER_ID)
    end

    if consumer and consumer.custom_id then
        set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
    else
        clear_header(constants.HEADERS.CONSUMER_CUSTOM_ID)
    end

    if consumer and consumer.username then
        set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
    else
        clear_header(constants.HEADERS.CONSUMER_USERNAME)
    end

    kong.client.authenticate(consumer, credential)

    if credential then
        kong.ctx.shared.authenticated_jwt_token = token -- TODO: wrap in a PDK function?
        ngx.ctx.authenticated_jwt_token = token  -- backward compatibilty only

        if credential.username then
            set_header(constants.HEADERS.CREDENTIAL_USERNAME, credential.username)
        else
            clear_header(constants.HEADERS.CREDENTIAL_USERNAME)
        end

        clear_header(constants.HEADERS.ANONYMOUS)

    else
        clear_header(constants.HEADERS.CREDENTIAL_USERNAME)
        set_header(constants.HEADERS.ANONYMOUS, true)
    end
end

local function get_keys(well_known_endpoint)
    kong.log.debug('Getting public keys from keycloak...')
    local keys, err = keycloak_keys.get_issuer_keys(well_known_endpoint)
    if err then
        return nil, err
    end

    local decoded_keys = {}
    for i, key in ipairs(keys) do
        key = key:gsub("+", "-"):gsub("/", "_")
        decoded_keys[i] = jwt_decoder:base64_decode(key)
    end

    kong.log.debug('Number of keys retrieved: ' .. table.getn(decoded_keys))
    return {
        keys = decoded_keys,
        updated_at = socket.gettime(),
    }
end

local function validate_signature(conf, jwt, second_call)
    kong.log.debug('Calling validate_signature()')
    --     kong.log.debug('validate_signature() jwt: ' .. table_to_string(jwt))
    local issuer_cache_key = 'issuer_keys_' .. jwt.claims.iss
    local well_known_endpoint
    if conf.public_keys_url then
        well_known_endpoint = conf.public_keys_url
    else
        well_known_endpoint = keycloak_keys.get_wellknown_endpoint(conf.well_known_template, jwt.claims.iss)
    end
    kong.log.debug("Using well-known endpoint: " .. well_known_endpoint)
    -- Retrieve public keys
    local public_keys, err = kong.cache:get(issuer_cache_key, nil, get_keys, well_known_endpoint, true)


    if not public_keys then
        if err then
            kong.log.err(err)
        end
        return kong.response.exit(403, { message = "Unable to get public key for issuer" })
    end

    -- Verify signatures
    for _, k in ipairs(public_keys.keys) do
        if jwt:verify_signature(k) then
            kong.log.debug('JWT signature verified')
            return nil
        end
    end

    -- We could not validate signature, try to get a new keyset?
    local since_last_update = socket.gettime() - public_keys.updated_at
    if not second_call and since_last_update > conf.iss_key_grace_period then
        kong.log.debug('Could not validate signature. Keys updated last ' .. since_last_update .. ' seconds ago')
        kong.cache:invalidate_local(issuer_cache_key)
        return validate_signature(conf, jwt, true)
    end

    kong.log.err('Invalid token signature: ')
    return kong.response.exit(401, { message = "Invalid token signature" })
end

local function match_consumer(conf, jwt)
    kong.log.debug('Calling match_consumer()')
    local consumer, err
    local consumer_id = jwt.claims[conf.consumer_match_claim]

    if conf.consumer_match_claim_custom_id then
        consumer_cache_key = "custom_id_key_" .. consumer_id
        consumer, err = kong.cache:get(consumer_cache_key, nil, load_consumer_by_custom_id, consumer_id, true)
    else
        consumer_cache_key = kong.db.consumers:cache_key(consumer_id)
        consumer, err = kong.cache:get(consumer_cache_key, nil, load_consumer, consumer_id, true)
    end

    if err then
        kong.log.err(err)
    end

    if not consumer and not conf.consumer_match_ignore_not_found then
        return false, { status = 401, message = "Unable to find consumer for token" }
    end

    kong.log.debug('match_consumer() consumer=' .. consumer)
    if consumer then
        set_consumer(consumer, nil, nil)
    end

    return true
end

local function do_authentication(conf)
    kong.log.debug('Calling do_authentication()')
    -- Retrieve token
    local token, err = retrieve_token(conf)
    if err then
        kong.log.err(err)
        return kong.response.exit(500, { message = "An unexpected error occurred" })
    end

    if token then
        kong.log.debug('do_authentication() retrieved token: ' .. token)
    end

    local jwt_claims

    local token_type = type(token)
    kong.log.debug('do_authentication() token_type: ' .. token_type)
    if token_type ~= "string" then
        if token_type == "nil" then
            -- Retrieve token payload
            jwt_claims = retrieve_token_payload(conf.internal_request_headers)
            if not jwt_claims then
                return false, { status = 401, message = "Unauthorized" }
            end
            kong.log.debug('do_authentication() token_payload retrieved successfully')
        elseif token_type == "table" then
            return false, { status = 401, message = "Multiple tokens provided" }
        else
            return false, { status = 401, message = "Unrecognizable token" }
        end
    end



    -- Decode token
    local jwt, err
    if token then
        jwt, err = jwt_decoder:new(token)
        if err then
            return false, { status = 401, message = "Bad token; " .. tostring(err) }
        end
    end



    -- Verify algorithim
    if jwt then
        kong.log.debug('do_authentication() Verify token...')
        jwt_claims = jwt.claims

        if jwt.header.alg ~= (conf.algorithm or "HS256") then
            return false, { status = 403, message = "Invalid algorithm" }
        end

        err = validate_signature(conf, jwt)
        if err ~= nil then
            return false, err
        end

        -- Verify the JWT registered claims
        kong.log.debug('do_authentication() Verify the JWT registered claims...')
        local ok_claims, errors = jwt:verify_registered_claims(conf.claims_to_verify)
        if not ok_claims then
            return false, { status = 401, message = "Token claims invalid: " .. table_to_string(errors) }
        end

        -- Verify maximum expiration
        kong.log.debug('do_authentication() Verify maximum expiration...')
        if conf.maximum_expiration ~= nil and conf.maximum_expiration > 0 then
            local ok, errors = jwt:check_maximum_expiration(conf.maximum_expiration)
            if not ok then
                return false, { status = 403, message = "Token claims invalid: " .. table_to_string(errors) }
            end
        end

    end



    -- Verify that the issuer is allowed
    kong.log.debug('do_authentication() Verify that the issuer is allowed...')
    if not validate_issuer(conf.allowed_iss, jwt_claims) then
        return false, { status = 401, message = "Token issuer not allowed" }
    end


    -- Match consumer
    if conf.consumer_match and jwt then
        kong.log.debug('do_authentication() Match consumer...')
        ok, err = match_consumer(conf, jwt)
        if not ok then
            return ok, err
        end
    end

    -- Verify roles or scopes
    kong.log.debug('do_authentication() Verify roles or scopes...')
    local ok, err = validate_scope(conf.scope, jwt_claims)

    if ok then
        ok, err = validate_realm_roles(conf.realm_roles, jwt_claims)
    end

    if ok then
        ok, err = validate_roles(conf.roles, jwt_claims)
    end

    if ok then
        ok, err = validate_client_roles(conf.client_roles, jwt_claims)
    end

    if ok then
        if jwt then
            kong.ctx.shared.jwt_keycloak_token = jwt
        end
        return true
    end

    return false, { status = 403, message = "Access token does not have the required scope/role: " .. err }
end

function JwtKeycloakHandler:access(conf)
    kong.log.debug('Calling access()')
    -- check if preflight request and whether it should be authenticated
    if not conf.run_on_preflight and kong.request.get_method() == "OPTIONS" then
        return
    end

    if conf.anonymous and kong.client.get_credential() then
        -- we're already authenticated, and we're configured for using anonymous,
        -- hence we're in a logical OR between auth methods and we're already done.
        return
    end

    local ok, err = do_authentication(conf)
    if not ok then
        kong.log.warn('do_authentication() returned False')
        if conf.anonymous then
            -- get anonymous user
            local consumer_cache_key = kong.db.consumers:cache_key(conf.anonymous)
            local consumer, err = kong.cache:get(consumer_cache_key, nil,
                    load_consumer,
                    conf.anonymous, true)
            if err then
                kong.log.err(err)
                return kong.response.exit(500, { message = "An unexpected error occurred" })
            end

            set_consumer(consumer, nil, nil)
        else
            kong.log.err('do_authentication() error: ' .. err.message)

            if conf.redirect_after_authentication_failed_uri then
                local scheme = kong.request.get_scheme()
                local host = kong.request.get_host()
                local port = kong.request.get_port()
                local url = scheme .. "://" .. host .. ":" .. port .. conf.redirect_after_authentication_failed_uri

                kong.response.set_header("Location", url)
                kong.log.debug('do_authentication() exit: ' .. url)
                return ngx.redirect(url)
            end

            return kong.response.exit(err.status, err.errors or { message = err.message })
        end
    end
end

return JwtKeycloakHandler
