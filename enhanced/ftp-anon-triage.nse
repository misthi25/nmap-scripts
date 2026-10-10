local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enhancement 1 of ftp-anon. Logs in anonymously, lists the root directory over
a passive data connection and triages every entry: private keys, environment
secrets, database dumps, configuration files, backups and archives are flagged
with a severity, and an overall 0-100 exposure score is calculated. Read-only:
only USER, PASS, PASV, LIST and QUIT are sent.
]]

---
-- @usage
-- nmap -p 21 --script ./ftp-anon-triage.nse <target>
-- @args ftp-anon-triage.maxlist Maximum directory entries to analyse. Default: 100
--
-- @output
-- | ftp-anon-triage:
-- |   login: anonymous login allowed (230)
-- |   entries_listed: 6
-- |   exposure_score: 100/100 (SEVERE)
-- |   sensitive_findings:
-- |     [CRITICAL] id_rsa - SSH private key
-- |_    [HIGH] customers_backup.sql - database dump

author = "Misthi Pandey"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({21, 2121}, "ftp")

local POINTS = {CRITICAL = 30, HIGH = 15, MEDIUM = 7, LOW = 2}
local RANK = {CRITICAL = 4, HIGH = 3, MEDIUM = 2, LOW = 1}

-- first matching rule wins, so the most severe rules come first
local RULES = {
  {"^id_rsa", "CRITICAL", "SSH private key"},
  {"^id_dsa", "CRITICAL", "SSH private key"},
  {"^id_ecdsa", "CRITICAL", "SSH private key"},
  {"^id_ed25519", "CRITICAL", "SSH private key"},
  {"%.pem$", "CRITICAL", "PEM key/certificate material"},
  {"%.key$", "CRITICAL", "private key file"},
  {"%.ppk$", "CRITICAL", "PuTTY private key"},
  {"%.kdbx$", "CRITICAL", "password vault"},
  {"^%.env", "CRITICAL", "environment secrets"},
  {"%.env$", "CRITICAL", "environment secrets"},
  {"^%.htpasswd$", "CRITICAL", "HTTP credentials file"},
  {"^passwd$", "CRITICAL", "system account file"},
  {"^shadow$", "CRITICAL", "system password hashes"},
  {"^%.git$", "HIGH", "exposed Git repository"},
  {"%.sql$", "HIGH", "database dump"},
  {"%.sqlite3?$", "HIGH", "database file"},
  {"%.dump$", "HIGH", "data dump"},
  {"^wp%-config", "HIGH", "CMS configuration"},
  {"^web%.config$", "HIGH", "web server configuration"},
  {"^config%.", "HIGH", "configuration file"},
  {"%.bak$", "MEDIUM", "backup copy (may expose source/config)"},
  {"%.old$", "MEDIUM", "old copy (may expose source/config)"},
  {"%.orig$", "MEDIUM", "original copy (may expose source/config)"},
  {"~$", "MEDIUM", "editor backup file"},
  {"%.zip$", "MEDIUM", "archive (may contain source/data)"},
  {"%.tar$", "MEDIUM", "archive (may contain source/data)"},
  {"%.tar%.gz$", "MEDIUM", "archive (may contain source/data)"},
  {"%.tgz$", "MEDIUM", "archive (may contain source/data)"},
  {"%.7z$", "MEDIUM", "archive (may contain source/data)"},
  {"%.rar$", "MEDIUM", "archive (may contain source/data)"},
  {"^backups?$", "MEDIUM", "backup directory"},
  {"^private$", "MEDIUM", "private directory"},
  {"^admin$", "MEDIUM", "admin directory"},
  {"%.log$", "LOW", "log file"},
}

-- Read one complete FTP reply (handles multi-line replies). Returns code, text.
local function read_reply(sock)
  local acc = ""
  while true do
    local status, data = sock:receive_lines(1)
    if not status then
      if acc == "" then return nil end
      break
    end
    acc = acc .. data
    local code = acc:match("^(%d%d%d)")
    if code then
      local sep = acc:sub(4, 4)
      if sep == " " then break end
      if sep == "-" and acc:find("\n" .. code .. " ", 1, true) then break end
    end
  end
  return tonumber(acc:match("^(%d%d%d)")), acc
end

local function cmd(sock, text)
  sock:send(text .. "\r\n")
  return read_reply(sock)
end

action = function(host, port)
  local maxlist = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".maxlist")) or 100

  local sock = nmap.new_socket()
  sock:set_timeout(8000)
  if not sock:connect(host, port) then return nil end

  local code = read_reply(sock)
  if code ~= 220 then sock:close(); return nil end

  code = cmd(sock, "USER anonymous")
  if code == 331 then code = cmd(sock, "PASS anonymous@example.com") end
  if code ~= 230 then
    stdnse.debug1("anonymous login refused (code %s)", tostring(code))
    sock:close()
    return nil
  end

  -- Passive data connection (always to the scanned IP, ignoring the advertised one)
  local pcode, ptext = cmd(sock, "PASV")
  local p1, p2 = nil, nil
  if pcode == 227 then
    p1, p2 = ptext:match("%d+,%d+,%d+,%d+,(%d+),(%d+)")
  end
  if not p1 then
    sock:close()
    return "Anonymous login allowed, but PASV failed - cannot list files"
  end
  local dport = tonumber(p1) * 256 + tonumber(p2)

  local dsock = nmap.new_socket()
  dsock:set_timeout(8000)
  if not dsock:connect(host.ip, dport) then
    sock:close()
    return "Anonymous login allowed, but data connection failed"
  end

  sock:send("LIST\r\n")
  local lcode = read_reply(sock)
  local listing = ""
  if lcode == 125 or lcode == 150 then
    while true do
      local st, d = dsock:receive_lines(1)
      if not st then break end
      listing = listing .. d
      if #listing > 200000 then break end
    end
  end
  dsock:close()
  if lcode == 125 or lcode == 150 then read_reply(sock) end
  sock:send("QUIT\r\n")
  sock:close()

  -- Parse and triage the listing
  local entries, findings, dirs = 0, {}, {}
  local score = 10   -- base penalty: anonymous access is allowed at all
  for line in listing:gmatch("[^\r\n]+") do
    if entries >= maxlist then break end
    if not line:match("^total") then
      local perm, name = line:match("^(%S+)%s+%d+%s+%S+%s+%S+%s+%d+%s+%a+%s+%d+%s+%S+%s+(.+)$")
      if not perm then
        perm = line:sub(1, 1)
        name = line:match("(%S+)%s*$")
      end
      if name and name ~= "." and name ~= ".." then
        entries = entries + 1
        if perm:sub(1, 1) == "d" then dirs[#dirs + 1] = name end
        local lname = name:lower()
        if not lname:match("%.pub$") then
          for _, rule in ipairs(RULES) do
            if lname:match(rule[1]) then
              findings[#findings + 1] = {name = name, sev = rule[2], why = rule[3]}
              score = score + POINTS[rule[2]]
              break
            end
          end
        end
      end
    end
  end

  if entries == 0 then
    return "Anonymous login allowed, but the root directory is empty or unreadable"
  end

  table.sort(findings, function(x, y)
    if RANK[x.sev] ~= RANK[y.sev] then return RANK[x.sev] > RANK[y.sev] end
    return x.name < y.name
  end)
  if score > 100 then score = 100 end
  local rating = "LOW"
  if score >= 70 then rating = "SEVERE"
  elseif score >= 40 then rating = "HIGH"
  elseif score >= 15 then rating = "MODERATE" end

  local lines = {}
  for _, f in ipairs(findings) do
    lines[#lines + 1] = string.format("[%s] %s - %s", f.sev, f.name, f.why)
  end

  local out = stdnse.output_table()
  out.login = "anonymous login allowed (230)"
  out.entries_listed = entries
  out.exposure_score = string.format("%d/100 (%s)", score, rating)
  if #dirs > 0 then out.directories = dirs end
  out.sensitive_findings = (#lines > 0) and lines or "None - listing looks clean"
  return out
end
