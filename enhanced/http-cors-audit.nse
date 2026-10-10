local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enhancement 2 of http-headers. Actively tests the target's CORS policy by
sending forged Origin headers: an arbitrary attacker origin, the "null"
origin, and prefix/suffix bypass origins derived from the target's own name
(which defeat naive startswith/endswith validation). A preflight (OPTIONS)
request checks whether dangerous methods are granted to a foreign origin.
Each finding is graded INFO to CRITICAL, with extra weight when credentials are
allowed or when 'Vary: Origin' is missing.
]]

author = "Misthi Pandey"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({80, 443, 8000, 8080}, {"http", "http-alt", "https"})

local SEV = {INFO = 1, LOW = 2, MEDIUM = 3, HIGH = 4, CRITICAL = 5}
local SEV_NAME = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

local function probe(host, port, path, origin)
  local r = http.get(host, port, path, {header = {Origin = origin}, no_cache = true})
  if not r or not r.status then return nil end
  return {
    acao = r.header["access-control-allow-origin"],
    acac = r.header["access-control-allow-credentials"],
    vary = r.header["vary"],
  }
end

local function evaluate(origin, res)
  local acao = res.acao
  if not acao then
    return nil, "rejected (no Access-Control-Allow-Origin)"
  end
  local creds = res.acac and res.acac:lower() == "true"
  local has_vary = res.vary and res.vary:lower():find("origin", 1, true)

  if acao == origin then
    local sev, msg
    if creds then
      sev, msg = SEV.CRITICAL, "origin reflected WITH credentials allowed"
    else
      sev, msg = SEV.MEDIUM, "origin reflected (credentials not allowed)"
    end
    if not has_vary then
      msg = msg .. "; missing 'Vary: Origin' (cache poisoning risk)"
    end
    return sev, msg
  elseif acao == "*" then
    if creds then
      return SEV.LOW, "wildcard '*' with credentials (invalid configuration)"
    end
    return SEV.INFO, "wildcard '*' (public data only)"
  end
  return nil, "fixed origin '" .. acao .. "' (not reflected)"
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"

  local target = host.targetname or host.ip
  if not target or target == "" then target = host.ip end

  local evil = "https://evil-attacker.example"
  local tests = {
    {"arbitrary-origin", evil},
    {"null-origin", "null"},
    {"prefix-bypass", "http://" .. target .. ".evil-attacker.example"},
    {"suffix-bypass", "http://evil-" .. target},
  }

  local findings = stdnse.output_table()
  local worst = 0
  local function record(label, sev, msg)
    if sev then
      findings[label] = "[" .. SEV_NAME[sev] .. "] " .. msg
      if sev > worst then worst = sev end
    else
      findings[label] = "OK - " .. msg
    end
  end

  local reached = false
  for _, t in ipairs(tests) do
    local res = probe(host, port, path, t[2])
    if res then
      reached = true
      record(t[1], evaluate(t[2], res))
    end
  end
  if not reached then return nil end

  local pre = http.generic_request(host, port, "OPTIONS", path, {
    header = {
      Origin = evil,
      ["Access-Control-Request-Method"] = "PUT",
      ["Access-Control-Request-Headers"] = "authorization",
    },
    no_cache = true,
  })
  if pre and pre.status then
    local acao = pre.header["access-control-allow-origin"]
    local acam = pre.header["access-control-allow-methods"]
    local acah = pre.header["access-control-allow-headers"]
    local acac = pre.header["access-control-allow-credentials"]
    local creds = acac and acac:lower() == "true"
    if acao and (acao == evil or acao == "*") and acam then
      local risky = {}
      for _, m in ipairs({"PUT", "DELETE", "PATCH"}) do
        if acam:upper():find(m, 1, true) then risky[#risky + 1] = m end
      end
      if #risky > 0 then
        local sev = (acao == evil and creds) and SEV.HIGH or SEV.MEDIUM
        record("preflight", sev, "foreign origin may use " .. table.concat(risky, "/") ..
               " (allowed headers: " .. (acah or "none") .. ")")
      else
        record("preflight", nil, "foreign origin limited to safe methods")
      end
    else
      record("preflight", nil, "foreign origin rejected")
    end
  end

  local out = stdnse.output_table()
  out.verdict = (worst > 0) and SEV_NAME[worst] or "PASS - foreign origins rejected"
  out.findings = findings
  return out
end
