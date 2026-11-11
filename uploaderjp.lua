local urlparse = require("socket.url")
local https = require("ssl.https")
local cjson = require("cjson")
local utf8 = require("utf8")
local html_entities = require("htmlEntities")
local openssl_digest = require("openssl.digest")
local basexx = require("basexx")
local zlib = require("zlib")

local item_dir = os.getenv("item_dir")
local warc_file_base = os.getenv("warc_file_base")
local passwords = cjson.decode(os.getenv("passwords"))
local item_type = nil
local item_name = nil
local item_key = nil
local item_value = nil

local url_count = 0
local tries = 0
local downloaded = {}
local addedtolist = {}
local abortgrab = false
local killgrab = false
local logged_response = false
local status_code = 0

local discovered_outlinks = {}
local discovered_items = {}
local discovered_stash = {}
local bad_items = {}
local ids = {}

local retry_url = false
local context = {}
local warc_digests = {}

local item_patterns = {
  ["^https?://(u[a-zA-Z0-9]*%.getuploader%.com/[^/%?#]+/download/[0-9]+)$"] = "file",
  ["^https?://(u[a-zA-Z0-9]*%.getuploader%.com/[^/%?#]+/download/[0-9]+)[/%?][^#]+$"] = "file",
  ["^https?://(d[a-zA-Z0-9]*%.getuploader%.com/g/[^#]+)$"] = "file",
  ["^https?://(www[0-9]+%.uploader%.jp/p/[^/%?#]+/[0-9]+/?)$"] = "file",
  ["^https?://(www[0-9]+%.uploader%.jp/dl/[^/%?#]+/[^/%?#]+_uljp[0-9]+%.[^/%?#]+)$"] = "file",
  ["^https?://(u[a-zA-Z0-9]*%.getuploader%.com/[^/%?#]+)/?$"] = "uploader",
  ["^https?://(u[a-zA-Z0-9]*%.getuploader%.com/[^/%?#]+)/rss$"] = "uploader",
  ["^https?://(u[a-zA-Z0-9]*%.getuploader%.com/[^/%?#]+)/search$"] = "uploader",
  ["^https?://(u[a-zA-Z0-9]*%.getuploader%.com/[^/%?#]+)/thumbnail$"] = "uploader",
  ["^https?://(u[a-zA-Z0-9]*%.getuploader%.com/[^/%?#]+)/ranking$"] = "uploader",
  ["^https?://(u[a-zA-Z0-9]*%.getuploader%.com/[^/%?#]+)/ranking/[a-z]+$"] = "uploader",
  ["^https?://(www[0-9]+%.uploader%.jp/home/[^/%?#]+/)$"] = "uploader",
  ["^https?://(download[a-zA-Z0-9]*%.getuploader%.com/t/[^#]+)$"] = "asset",
  ["^https?://(r%.getuploader%.com/[^#]+)$"] = "asset",
}

abort_item = function(item)
  abortgrab = true
  if not item then
    item = item_name
  end
  if not bad_items[item] then
    io.stdout:write("Aborting item " .. item .. ".\n")
    io.stdout:flush()
    bad_items[item] = true
  end
end

kill_grab = function(item)
  io.stdout:write("Aborting crawling.\n")
  io.stdout:flush()
  killgrab = true
end

read_file = function(file)
  if file then
    local f = assert(io.open(file, "rb"))
    local body = f:read("*all")
    f:close()
    return body
  else
    return ""
  end
end

processed = function(url)
  if downloaded[url] or addedtolist[url] then
    return true
  end
  return false
end

discover_item = function(target, item)
  if item ~= item_key and not target[item] then
    target[item] = true
    return true
  end
  return false
end

percent_encode_url = function(newurl)
  newurl = string.gsub(newurl, "(.)", function(c)
    local b = string.byte(c)
    if b < 32 or b > 126 then
      return string.format("%%%02X", b)
    end
    return c
  end)
  return newurl
end

encode_field = function(value)
  value = string.gsub(value, "([^a-zA-Z0-9_%.~%-])", function(c)
    return string.format("%%%02X", string.byte(c))
  end)
  return value
end

encode_nickname = function(nickname)
  nickname = string.gsub(urlparse.unescape(nickname), "%+", " ")
  return encode_field(nickname)
end

find_item = function(url)
  url = string.gsub(url, "^(https?://)ux%.getuploader%.com/", "%1uu.getuploader.com/")
  url = string.gsub(url, "^(https?://)www%.uploader%.jp/", "%1www1.uploader.jp/")
  for pattern, type_ in pairs(item_patterns) do
    local value = string.match(url, pattern)
    if value then
      if type_ == "file" then
        local server, nickname, file_id = string.match(value, "^(u[a-zA-Z0-9]*)%.getuploader%.com/([^/]+)/download/([0-9]+)$")
        if not server then
          for _, pattern in ipairs({
            "^www([0-9]+)%.uploader%.jp/p/([^/%?#]+)/([0-9]+)/?$",
            "^www([0-9]+)%.uploader%.jp/dl/([^/%?#]+)/[^/%?#]+_uljp([0-9]+)%.[^/%?#]+$"
          }) do
            server, nickname, file_id = string.match(value, pattern)
            if server then
              break
            end
          end
          if server then
            server = "u" .. server
            file_id = string.match(file_id, "^0*([0-9]+)$")
          else
            local path = string.match(value, "^([^%?]+)")
            for _, pattern in ipairs({
              "/g/[^/]+/([^/]+)/([0-9]+)/[^/]+$",
              "/g/([^/]+)/([0-9]+)/[^/]+$",
              "/g/([^/]+)/([0-9]+)/?$"
            }) do
              nickname, file_id = string.match(path, pattern)
              if nickname then
                break
              end
            end
            if not nickname then
              return nil
            end
            nickname = string.gsub(nickname, "%%7[cC]", "|")
            local number, name = string.match(nickname, "^([0-9]+)|(.+)$")
            server = "uu"
            if number then
              server = "u" .. number
              nickname = name
            end
          end
        end
        value = string.lower(server) .. ":" .. encode_field(encode_nickname(nickname)) .. ":" .. file_id
      elseif type_ == "uploader" then
        local server, uploader = string.match(value, "^www([0-9]+)%.uploader%.jp/home/([^/%?#]+)/$")
        if server then
          server = "u" .. server
        else
          server, uploader = string.match(value, "^(u[a-zA-Z0-9]*)%.getuploader%.com/([^/%?#]+)$")
        end
        value = string.lower(server) .. ":" .. encode_field(encode_nickname(uploader))
      elseif type_ == "asset" then
        value = string.gsub(value, "|", "%%7C")
      end
      return {
        ["value"]=percent_encode_url(value),
        ["type"]=type_
      }
    end
  end
  local value = string.match(url, "^https?://(u[a-zA-Z0-9]*%.getuploader%.com/[^/%?#]+/[^#]+)$")
  if value then
    return {
      ["value"]=percent_encode_url(value),
      ["type"]="page"
    }
  end
  return nil
end

finish_item = function()
  if item_name then
    for _, checked in pairs(context["digests"]) do
      if checked ~= true and not warc_digests[checked] then
        error("WARC digest does not match downloaded data.")
      end
    end
  end
  if item_name and item_type == "file" and not abortgrab then
    if not next(context["digests"]) and not context["missing"] then
      print("No file found.")
      abort_item()
    end
  end
end

set_item = function(url)
  if ids[url] then
    return nil
  end
  local found = find_item(url)
  if found then
    local new_item_type = found["type"]
    local new_item_value = found["value"]
    local new_item_key = new_item_type .. ":" .. new_item_value
    if new_item_key ~= item_key then
      finish_item()
      ids = {}
      context = {
        ["digests"]={},
        ["last_file_ids"]={}
      }
      item_key = new_item_key
      item_name = item_key
      if passwords[item_key] then
        item_name = item_name .. ":" .. passwords[item_key]
      end
      item_value = new_item_value
      item_type = new_item_type
      ids[url] = true
      abortgrab = false
      tries = 0
      retry_url = false
      print("Archiving item " .. item_name)
    end
  end
end

allowed = function(url, parent)
  local lower = string.lower(url)
  if ids[url] then
    return true
  end

  for _, pattern in pairs({
    "^https?://[^/]+%.getuploader%.com/cdn%-cgi/",
    "^https?://u[a-z0-9]*%.getuploader%.com/[^/]+/upload",
    "^https?://u[a-z0-9]*%.getuploader%.com/[^/]+/edit/",
    "^https?://u[a-z0-9]*%.getuploader%.com/[^/]+/inquire",
    "^https?://r%.getuploader%.com/js/adframe%.js",
    "^https?://r%.getuploader%.com/js/doubleserve%.js",
    "^https?://[^/]*amazon%-adsystem%.com/",
    "^https?://m%.media%-amazon%.com/",
    "^https?://[^/]*adingo%.jp/",
    "^https?://[^/]*microad%.net/",
    "^https?://omt%.shinobi%.jp/",
    "^https?://static%.cloudflareinsights%.com/",
    "^https?://[^/]*googletagmanager%.com/",
    "^https?://[^/]*googleadservices%.com/",
    "^https?://[^/]*google%-analytics%.com/",
    "^https?://[^/]*gstatic%.com/prose/",
    "^https?://twitter%.com/intent/",
    "^https?://[^/]*facebook%.com/sharer/"
  }) do
    if string.match(lower, pattern) then
      return false
    end
  end

  local found = find_item(url)
  if found then
    local new_item = found["type"] .. ":" .. found["value"]
    local old_file = found["type"] == "file" and string.match(url, "^https?://www[0-9]*%.uploader%.jp/")
    if old_file
      or (
        new_item ~= item_key
        and string.match(url, "^https?://d[a-zA-Z0-9]*%.getuploader%.com/g/[^/]+/[0-9]+/?$")
      ) then
      discover_item(discovered_outlinks, percent_encode_url(url))
    end
    if new_item ~= item_key then
      if found["type"] == "page"
        and string.match(found["value"], "^[^/]+/[^/]+/search%?") then
        return false
      end
      discover_item(discovered_items, percent_encode_url(new_item))
      if found["type"] == "file" then
        local prefix, file_id = string.match(new_item, "^(file:[^:]+:[^:]+:)([0-9]+)$")
        file_id = tonumber(file_id)
        for candidate = file_id - 1, (context["last_file_ids"][prefix] or 0) + 1, -1 do
          discover_item(discovered_items, prefix .. tostring(candidate))
        end
        context["last_file_ids"][prefix] = math.max(context["last_file_ids"][prefix] or 0, file_id)
      end
      return false
    end
    return not old_file
  end

  if string.match(lower, "^https?://d[a-zA-Z0-9]*%.getuploader%.com/g/")
    or not (
      string.match(lower, "^https?://getuploader%.com/")
      or string.match(lower, "^https?://[^/]+%.getuploader%.com/")
    ) then
    discover_item(discovered_outlinks, string.match(percent_encode_url(url), "^([^%s]+)"))
    return false
  end

  return false
end

wget.callbacks.download_child_p = function(urlpos, parent, depth, start_url_parsed, iri, verdict, reason)
  return false
end

decode_codepoint = function(newurl)
  newurl = string.gsub(
    newurl, "\\[uU]([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F])",
    function(s)
      return utf8.char(tonumber(s, 16))
    end
  )
  return newurl
end

decode_html = function(text)
  text = string.gsub(text, "&#37;", "%%")
  text = string.gsub(text, "&percnt;", "%%")
  return html_entities.decode(text)
end

age_confirmation = function(html)
  return string.match(html, "<title>年齢確認 | uploader%.jp</title>")
    and string.match(html, "<form[^>]+method=\"POST\"[^>]*>.-<input type=\"hidden\" name=\"q\" value=\"age_confirmation\"[^>]*>.-</form>")
end

wget.callbacks.get_urls = function(file, url, is_css, iri)
  local urls = {}
  local html = nil

  downloaded[url] = true

  if abortgrab then
    return {}
  end

  local function fix_case(newurl)
    if not string.match(newurl, "^https?://[^/]") then
      return newurl
    end
    if string.match(newurl, "^https?://[^/]+$") then
      newurl = newurl .. "/"
    end
    local a, b = string.match(newurl, "^(https?://[^/]+/)(.*)$")
    return string.lower(a) .. b
  end

  local function check(newurl, body_data)
    if not newurl then
      newurl = ""
    end
    newurl = decode_html(decode_codepoint(newurl))
    newurl = string.gsub(newurl, "\\/", "/")
    newurl = string.match(newurl, "^%s*(.-)%s*$")
    newurl = string.gsub(newurl, " ", "%%20")
    newurl = fix_case(newurl)
    newurl = string.gsub(newurl, "^http://([^/]+%.getuploader%.com/)", "https://%1")
    newurl = string.gsub(newurl, "^http://(www[0-9]*%.uploader%.jp/)", "https://%1")
    newurl = string.gsub(newurl, "^(https?://u[a-zA-Z0-9]*%.getuploader%.com/)([^/%?#]+)", function(base, nickname)
      return base .. encode_field(urlparse.unescape(nickname))
    end)
    newurl = string.gsub(percent_encode_url(newurl), "|", "%%7C")
    if not string.match(newurl, "^https?://[^/%s%?#]+") or string.match(newurl, "[%s\\\"<>]") then
      return nil
    end
    local url = string.match(newurl, "^([^#]+)")
    local url_ = url
    while string.match(url_, "&amp;") do
      url_ = string.gsub(url_, "&amp;", "&")
    end
    local key = (body_data and "POST" or "GET") .. "\0" .. url_ .. "\0" .. (body_data or "")
    if not processed(key)
      and (body_data or not processed(url_))
      and allowed(url_) then
      local url_data = {
        url=url_,
        headers={}
      }
      if body_data then
        url_data["body_data"] = body_data
        url_data["method"] = "POST"
        url_data["headers"]["Content-Type"]="application/x-www-form-urlencoded"
      end
      table.insert(urls, url_data)
      addedtolist[key] = true
      if not body_data then
        addedtolist[url_] = true
        addedtolist[url] = true
      end
      return true
    end
  end

  local function checknewurl(newurl)
    if not newurl then
      newurl = ""
    end
    newurl = decode_codepoint(newurl)
    if string.match(newurl, "['\"><]") then
      return nil
    end
    if string.match(newurl, "^https?:////") then
      check((string.gsub(newurl, ":////", "://")))
    elseif string.match(newurl, "^https?://") then
      check(newurl)
    elseif string.match(newurl, "^https?:\\/\\?/") then
      check((string.gsub(newurl, "\\", "")))
    elseif string.match(newurl, "^\\/\\/") then
      checknewurl((string.gsub(newurl, "\\", "")))
    elseif string.match(newurl, "^//") then
      check(urlparse.absolute(url, newurl))
    elseif string.match(newurl, "^\\/") then
      checknewurl((string.gsub(newurl, "\\", "")))
    elseif string.match(newurl, "^/") then
      check(urlparse.absolute(url, newurl))
    elseif string.match(newurl, "^%.%./") then
      if string.match(url, "^https?://[^/]+/[^/]+/") then
        check(urlparse.absolute(url, newurl))
      else
        checknewurl(string.match(newurl, "^%.%.(/.+)$"))
      end
    elseif string.match(newurl, "^%./") then
      check(urlparse.absolute(url, newurl))
    end
  end

  local function checknewshorturl(newurl)
    newurl = decode_codepoint(newurl)
    if string.match(newurl, "['\"><]") then
      return nil
    end
    newurl = string.gsub(newurl, " ", "%%20")
    if string.match(newurl, "^%?") then
      check(urlparse.absolute(url, newurl))
    elseif not (
      string.match(newurl, "^https?:\\?/\\?//?/?")
      or string.match(newurl, "^[/\\]")
      or string.match(newurl, "^%./")
      or string.match(newurl, "^[jJ]ava[sS]cript:")
      or string.match(newurl, "^[mM]ail[tT]o:")
      or string.match(newurl, "^vine:")
      or string.match(newurl, "^android%-app:")
      or string.match(newurl, "^ios%-app:")
      or string.match(newurl, "^data:")
      or string.match(newurl, "^irc:")
      or string.match(newurl, "^%${")
    ) then
      check(urlparse.absolute(url, newurl))
    end
  end

  if allowed(url)
    and status_code < 300 then
    if item_type ~= "asset"
      and not string.match(url, "^https?://d[a-zA-Z0-9]*%.getuploader%.com/g/") then
      html = read_file(file)
      local base, path = string.match(url, "^(https?://[^/]+/[^/%?#]+)(.*)$")
      if age_confirmation(html) then
        os.execute("sleep 5")
        check(url, "q=age_confirmation")
        return urls
      elseif item_type == "file" then
        local form = string.match(html, "<form[^>]+name=\"agree\"[^>]*>(.-)</form>")
        local body_data = nil
        if form then
          local token = string.match(form, "name=\"token\" value=\"([^\"]+)\"")
          if string.match(form, "<input[^>]+name=\"password\"") then
            body_data = "password=" .. urlparse.escape(urlparse.unescape(passwords[item_key]))
          elseif token then
            body_data = "token=" .. urlparse.escape(decode_html(token))
          end
        end
        if body_data then
          os.execute("sleep 5")
          check(url, body_data)
        else
          local download_url = string.match(html, "<a href=\"([^\"]+)\"[^>]*>Download Now</a>")
          if download_url then
            check(download_url)
            --[[
            if not context["others"] then
              context["others"] = true
              local path = string.match(download_url, "^https?://[^/]+(/.+)$")
              for _, host in ipairs({"download1.getuploader.com", "dl1.getuploader.com"}) do
                check("https://" .. host .. path)
              end
            end
            --]]
          end
        end
        --[[
        local filename = encode_field(decode_html(string.match(html, "<th[^>]*>ファイル</th>%s*<td>([^<]+)</td>")))
        local base, server, nickname, file_id = string.match(url, "^(https?://(u[a-zA-Z0-9]*)%.getuploader%.com/([^/]+)/download/([0-9]+))")
        check(base .. "/" .. filename)
        local number = string.match(server, "^u([0-9]+)$")
        if number then
          nickname = number .. "%7C" .. nickname
        end
        local path = "/g/" .. nickname .. "/" .. file_id .. "/" .. filename
        for _, host in ipairs({
          "download1.getuploader.com",
          "dl1.getuploader.com"
        }) do
          check("https://" .. host .. path)
        end
        --]]
      elseif path == "" or path == "/" or path == "/thumbnail" then
        local count = tonumber(string.match(html, "<th>ファイル</th>%s*<td>([0-9]+) ファイル</td>"))
        local per_page = 15
        local prefix = "/index/date/desc/"
        if path == "/thumbnail" then
          per_page = 20
          prefix = "/thumbnail/index/desc/"
        end
        if per_page == 15 then
          local server, uploader = string.match(base, "^https?://u([0-9]+)%.getuploader%.com/([^/%?#]+)$")
          if server then
            if server == "1" then
              server = ""
            end
            local old = "https://www" .. server .. ".uploader.jp/home/" .. uploader .. "/"
            check(old)
          end
          context["pages"] = math.ceil(count / per_page)
        end
        for page = 1, math.ceil(count / per_page) do
          check(base .. prefix .. tostring(page))
        end
      elseif item_type == "uploader"
        and (
          path == "/ranking"
          or string.match(path, "^/ranking/[a-z]+$")
        )
        and context["pages"] > 0 then
        local period = string.match(path, "^/ranking/([a-z]+)$") or "weekly"
        for page = 1, context["pages"] do
          check(base .. "/ranking/" .. period .. "/" .. tostring(page))
        end
      end
    end

    if html then
      for quote, quoted in pairs({
        ["\""]=string.gsub(html, "&[qQ][uU][oO][tT];", "\""),
        ["'"]=string.gsub(html, "&#039;", "'")
      }) do
        for newurl in string.gmatch(quoted, "([^" .. quote .. "]+)") do
          checknewurl(newurl)
        end
        for _, attribute in pairs({"href", "src", "data-src"}) do
          for newurl in string.gmatch(html, "[^%-]" .. string.gsub(attribute, "%-", "%%-") .. "=" .. quote .. "([^" .. quote .. "]+)" .. quote) do
            checknewshorturl(newurl)
          end
        end
      end
      for newurl in string.gmatch(html, "url%(%s*(.-)%s*%)") do
        newurl = string.gsub(decode_html(newurl), "^[\"'](.-)[\"']$", "%1")
        checknewurl(newurl)
        checknewshorturl(newurl)
      end
      for newurl in string.gmatch(html, "<link>(.-)</link>") do
        check(string.match(newurl, "^%s*<!%[CDATA%[(.-)%]%]>%s*$") or newurl)
      end
      html = string.gsub(html, "&gt;", ">")
      html = string.gsub(html, "&lt;", "<")
      for text in string.gmatch(html, ">([^<]+)") do
        checknewurl(string.match(text, "^%s*([^%s]+)"))
        for newurl in string.gmatch(text, "(https?://[^%s<>\"']+)") do
          checknewurl(newurl)
        end
        for host, nickname in string.gmatch(decode_html(text), "([a-zA-Z0-9][a-zA-Z0-9%.%-]*)/([^/%s<>\"'`%?#]+)") do
          if string.match(string.lower(host), "^u[a-z0-9]*%.getuploader%.com$") then
            check("https://" .. host .. "/" .. nickname .. "/")
          end
        end
      end
    end
  end

  if item_type ~= "asset"
    and string.match(url, "^https://u[ux]%.getuploader%.com/") then
    check((string.gsub(url, "^https://(u[ux])%.", {uu="https://ux.", ux="https://uu."})))
  end

  return urls
end

wget.callbacks.dedup_response = function(url, digest)
  if context["digests"][url] then
    if digest ~= context["digests"][url] then
      error("WARC digest does not match downloaded data.")
    end
    context["digests"][url] = true
  end
  warc_digests[digest] = true
end

wget.callbacks.write_to_warc = function(url, http_stat)
  local headers = http_stat["response_headers"]["headers"]
  status_code = http_stat["statcode"]
  local content_type = headers["content-type"] and string.lower(headers["content-type"][1]) or ""
  set_item(url["url"])

  url_count = url_count + 1
  io.stdout:write(url_count .. "=" .. status_code .. " " .. url["url"] .. " \n")
  io.stdout:flush()

  logged_response = true
  if not item_name then
    error("No item name found.")
  end

  if abortgrab then
    print("Not writing to WARC.")
    return false
  end

  if status_code == 404
    and not (
      item_type == "file"
      and string.match(url["url"], "^https?://u[a-zA-Z0-9]*%.getuploader%.com/[^/%?#]+/download/[0-9]+$")
    ) then
    abort_item()
    return false
  end

  if http_stat["res"] < 0 then
    return false
  end

  local redirect = false
  if headers["location"]
    and (status_code == 301 or status_code == 302) then
    local location = urlparse.absolute(url["url"], headers["location"][1])
    local target = find_item(location)
    if target
      and target["type"] == item_type
      and target["value"] == item_value then
      if item_type == "file" then
        redirect = status_code == 302
          and string.match(location, "^https://u[a-zA-Z0-9]*%.getuploader%.com/[^/]+/download/[0-9]+$")
      elseif status_code == 301
        and item_type == "uploader"
        and string.match(url["url"], "^https://www[0-9]*%.uploader%.jp/home/[^/%?#]+/$") then
        redirect = string.match(location, "^https://u[a-zA-Z0-9]*%.getuploader%.com/[^/%?#]+/?$")
      end
    end
  end

  if not (
    (
      status_code == 200
      and not string.match(url["url"], "^https?://www[0-9]*%.uploader%.jp/home/[^/%?#]+/$")
    )
    or redirect
    or status_code == 404
  ) then
    retry_url = true
    return false
  end

  if http_stat["contlen"] >= 0 and http_stat["len"] ~= http_stat["contlen"] then
    retry_url = true
    return false
  end

  if status_code == 200 then
    if item_type == "file"
      and string.match(url["url"], "^https?://d[a-zA-Z0-9]*%.getuploader%.com/g/") then
      if not context["md5"] then
        retry_url = true
        return false
      end
      local sha1 = openssl_digest.new("sha1")
      local md5 = openssl_digest.new("md5")
      local file = assert(io.open(http_stat["local_file"], "rb"))
      while true do
        local data = file:read(1024 * 1024)
        if not data then
          break
        end
        sha1:update(data)
        md5:update(data)
      end
      file:close()
      if basexx.to_hex(md5:final()) ~= string.upper(context["md5"]) then
        print("MD5 does not match.")
        retry_url = true
        return false
      end
      context["digests"][url["url"]] = "sha1:" .. basexx.to_base32(sha1:final())
    elseif item_type == "asset" then
      if http_stat["len"] == 0
        or (
          string.match(url["url"], "^https?://download[a-zA-Z0-9]*%.getuploader%.com/t/")
          and not string.match(content_type, "^image/")
        ) then
        retry_url = true
        return false
      end
    else
      local html = read_file(http_stat["local_file"])
      local request_body = http_stat["request_body"] or ""
      if string.match(html, "name=\"q\" value=\"security_auth\"") then
        print("Uploader password required.")
        abort_item()
        return false
      end
      if age_confirmation(html) then
        if request_body == "q=age_confirmation" then
          print("Age confirmation failed.")
          abort_item()
          return false
        end
      elseif item_type == "file" then
        local md5 = string.match(html, "MD5</label>%s*<input[^>]+value=\"([0-9a-fA-F]+)\"")
        local filename = string.match(html, "<th[^>]*>ファイル</th>%s*<td>([^<]+)</td>")
        local canonical = string.match(html, "<link rel=\"canonical\" href=\"([^\"]+)\"")
        local identity = canonical and find_item(decode_html(canonical))
        local og_url = string.match(html, "<meta property=\"og:url\" content=\"([^\"]+)\"")
        local form = string.match(html, "<form[^>]+name=\"agree\"[^>]*>(.-)</form>")
        local download_url = string.match(html, "<a href=\"([^\"]+)\"[^>]*>Download Now</a>")
        if not md5
          or string.len(md5) ~= 32
          or not filename
          or (context["md5"] and string.lower(md5) ~= context["md5"])
          or not identity
          or identity["value"] ~= item_value
          or not og_url
          or percent_encode_url(decode_html(og_url)) ~= url["url"] then
          retry_url = true
          return false
        end
        if form then
          local token = string.match(form, "name=\"token\" value=\"([^\"]+)\"")
          local protected = string.match(form, "<input[^>]+name=\"password\"")
          if not (token or protected or download_url) then
            retry_url = true
            return false
          end
          if protected then
            discovered_stash[item_name] = {
              ["title"]=string.match(html, "<title[^>]*>(.-)</title>") or cjson.null,
              ["description"]=string.match(html, "<meta name=\"description\" content=\"([^\"]*)\"") or cjson.null,
              ["uploader_description"]=string.match(html, "<h3 class=\"lead\">(.-)</h3>") or cjson.null
            }
            if not passwords[item_key] then
              print("Password required.")
              abort_item()
              return false
            end
            if string.match(request_body, "^password=") then
              print("Password use failed.")
              abort_item()
              return false
            end
          end
          if (token or protected) and string.match(request_body, "^token=") then
            print("Token use failed.")
            abort_item()
            return false
          end
        elseif not download_url then
          retry_url = true
          return false
        end
        if download_url then
          download_url = decode_html(download_url)
          local owner = find_item(download_url)
          if not owner
            or owner["value"] ~= item_value
            or not (
              string.match(download_url, "^https://download[a-zA-Z0-9]*%.getuploader%.com/g/[^/]+/[^/]+/[0-9]+/[^/]+$")
              or string.match(download_url, "^https://download[a-zA-Z0-9]*%.getuploader%.com/g/[^/]+/[0-9]+/[^/]+$")
            ) then
            retry_url = true
            return false
          end
        end
        context["md5"] = string.lower(md5)
        context["missing"] = nil
      elseif string.match(url["url"], "^https?://u[a-zA-Z0-9]*%.getuploader%.com/[^/%?#]+/rss$") then
        local link = string.match(html, "<channel>.-<link>([^<]+)</link>")
        local identity = link and find_item(decode_html(link))
        if not string.match(html, "<rss version=\"2%.0\">")
          or not identity
          or identity["value"] ~= item_value
          or not string.match(html, "</rss>") then
          retry_url = true
          return false
        end
      elseif item_type == "uploader" or item_type == "page" then
        local normalized_url = string.gsub(url["url"], "^(https?://)ux%.getuploader%.com/", "%1uu.getuploader.com/")
        local nickname, path = string.match(normalized_url, "^https?://[^/]+/([^/%?#]+)(.*)$")
        if path == "" then
          normalized_url = normalized_url .. "/"
        end
        local canonical = string.match(html, "<link rel=\"canonical\" href=\"([^\"]+)\"")
        if canonical then
          canonical = string.gsub(decode_html(canonical), "^(https?://)ux%.getuploader%.com/", "%1uu.getuploader.com/")
          local base, name, canonical_path = string.match(canonical, "^(https?://u[a-zA-Z0-9]*%.getuploader%.com/)([^/%?#]+)(.*)$")
          if name and encode_nickname(name) == encode_nickname(nickname) then
            canonical = base .. nickname .. canonical_path
          end
        end
        local og_url = string.match(html, "<meta property=\"og:url\" content=\"([^\"]+)\"")
        if og_url then
          og_url = decode_html(og_url)
        end
        local parent = nil
        for _, pattern in ipairs({
          "^(https?://[^/]+/[^/]+/ranking)/[a-z]+$",
          "^(https?://[^/]+/[^/]+/ranking)/[a-z]+/1$",
          "^(https?://[^/]+/[^/]+/)index/[a-z]+/[a-z]+/1$",
          "^(https?://[^/]+/[^/]+/thumbnail)/index/[a-z]+/1$"
        }) do
          parent = string.match(normalized_url, pattern)
          if parent then
            break
          end
        end
        local search = path == "/search" or string.match(path, "^/search%?")
        if not string.match(html, "<title>[^<]+ | uploader%.jp</title>")
          or (not canonical and not search)
          or (canonical and canonical ~= (parent or normalized_url))
          or (
            (path == "" or parent or search)
            and og_url ~= url["url"]
          ) then
          retry_url = true
          return false
        end
        if search then
          local action = string.match(html, "<form[^>]+method=\"GET\"[^>]+action=\"([^\"]+)\"")
          if not action then
            retry_url = true
            return false
          end
          local owner = find_item(decode_html(action))
          local base = find_item(string.match(normalized_url, "^([^%?]+)"))
          if not owner
            or owner["value"] ~= base["value"]
            or not string.match(action, "^https://u[a-zA-Z0-9]*%.getuploader%.com/[^/%?#]+/search$")
            or not string.match(html, "<input[^>]+name=\"q\"") then
            retry_url = true
            return false
          end
        end
        if (path == "" or path == "/" or path == "/thumbnail")
          and not string.match(html, "<th>ファイル</th>%s*<td>[0-9]+ ファイル</td>") then
          retry_url = true
          return false
        end
        if item_type == "uploader"
          and (
            path == "/ranking"
            or string.match(path, "^/ranking/[a-z]+$")
          )
          and context["pages"] > 0 then
          local period = string.match(path, "^/ranking/([a-z]+)$") or "weekly"
          local found = false
          for link in string.gmatch(html, "[\"']([^\"']*ranking/[a-z]+/[0-9]+[^\"']*)[\"']") do
            local base, value = string.match(urlparse.absolute(url["url"], decode_html(link)), "^(https?://u[a-zA-Z0-9]*%.getuploader%.com/[^/%?#]+)/ranking/([a-z]+)/[0-9]+")
            if base and value == period and find_item(base)["value"] == item_value then
              found = true
              break
            end
          end
          if not found then
            retry_url = true
            return false
          end
        end
      end
    end
  elseif status_code == 404 then
    local html = read_file(http_stat["local_file"])
    if not (
      (
        string.match(html, "<title>404 Not Found | uploader%.jp</title>")
        and string.match(html, "<p>あなたが要求したファイルは存在しません。削除されたか、アドレスが間違っています。</p>")
      )
      or (
        string.match(html, "<title>ユーザーが存在しません | uploader%.jp</title>")
        and string.match(html, "<p>アドレスが間違っているか、ユーザーが存在しないため、アクセスできません。</p>")
      )
    ) then
      retry_url = true
      return false
    end
    if not context["md5"] then
      context["missing"] = true
    end
  end

  retry_url = false
  tries = 0
  return true
end

wget.callbacks.httploop_result = function(url, err, http_stat)
  status_code = http_stat["statcode"]
  set_item(url["url"])

  if not logged_response then
    url_count = url_count + 1
    io.stdout:write(url_count .. "=" .. status_code .. " " .. url["url"] .. " \n")
    io.stdout:flush()
    retry_url = true
  end
  logged_response = false

  if killgrab then
    return wget.actions.ABORT
  end

  if not item_name then
    error("No item name found.")
  end

  if abortgrab then
    abort_item()
    return wget.actions.EXIT
  end

  local newloc = nil
  if status_code >= 300 and status_code <= 399 then
    if http_stat["newloc"] then
      newloc = urlparse.absolute(url["url"], http_stat["newloc"])
    end
  end

  if status_code == 0 or http_stat["res"] < 0 or retry_url then
    io.stdout:write("Server returned bad response. ")
    io.stdout:flush()
    tries = tries + 1
    local maxtries = 5
    if tries > maxtries then
      io.stdout:write(" Skipping.\n")
      io.stdout:flush()
      tries = 0
      abort_item()
      return wget.actions.EXIT
    end
    local sleep_time = math.max(5, math.random(
      math.floor(math.pow(2, tries-0.5)),
      math.floor(math.pow(2, tries))
    ))
    io.stdout:write("Sleeping " .. sleep_time .. " seconds.\n")
    io.stdout:flush()
    os.execute("sleep " .. sleep_time)
    return wget.actions.CONTINUE
  else
    downloaded[url["url"]] = true
  end

  if newloc then
    if processed(newloc) or not allowed(newloc, url["url"]) then
      tries = 0
      return wget.actions.EXIT
    end
  end

  tries = 0

  return wget.actions.NOTHING
end

wget.callbacks.finish = function(start_time, end_time, wall_time, numurls, total_downloaded_bytes, total_download_time)
  finish_item()
  local function submit_backfeed(items, key)
    local tries = 0
    local maxtries = 5
    while tries < maxtries do
      if killgrab then
        return false
      end
      local body, code, headers, status = https.request(
        "https://legacy-api.arpa.li/backfeed/legacy/" .. key,
        items .. "\0"
      )
      if code == 200 and body ~= nil and cjson.decode(body)["status_code"] == 200 then
        io.stdout:write(string.match(body, "^(.-)%s*$") .. "\n")
        io.stdout:flush()
        return nil
      end
      io.stdout:write("Failed to submit discovered URLs." .. tostring(code) .. tostring(body) .. "\n")
      io.stdout:flush()
      os.execute("sleep " .. math.floor(math.pow(2, tries)))
      tries = tries + 1
    end
    kill_grab()
    error()
  end

  local file = io.open(item_dir .. "/" .. warc_file_base .. "_bad-items.txt", "w")
  for url, _ in pairs(bad_items) do
    file:write(url .. "\n")
  end
  file:close()
  for key, data in pairs({
    ["uploaderjp-fa26640b9c47249a"] = discovered_items,
    ["uploaderjp-stash-passwords-6ee08a012b032221?shard=stash"] = discovered_stash,
    ["urls-8e798ec63c36ac1a"] = discovered_outlinks
  }) do
    print("queuing for", string.match(key, "^(.+)%-"))
    local items = nil
    local count = 0
    for item, value in pairs(data) do
      print("found item", item)
      if data == discovered_stash then
        local compressed = zlib.deflate()(cjson.encode(value), "finish")
        item = item .. ":" .. basexx.to_base64(compressed)
        if string.len(item) + 1 > 256 * 1024 then
          error("Data too big.")
        end
      end
      if items == nil then
        items = item
      else
        items = items .. "\0" .. item
      end
      count = count + 1
      if count == 1000 then
        submit_backfeed(items, key)
        items = nil
        count = 0
      end
    end
    if items ~= nil then
      submit_backfeed(items, key)
    end
  end
end

wget.callbacks.before_exit = function(exit_status, exit_status_string)
  if killgrab then
    return wget.exits.IO_FAIL
  end
  if abortgrab then
    abort_item()
  end
  return exit_status
end
