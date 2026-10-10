local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Enhancement 2 of ftp-anon. Builds an exposure profile of an FTP service:
(1) correlates the version banner with known high-impact vulnerabilities,
(2) checks via FEAT whether AUTH TLS is offered (otherwise credentials travel
in cleartext), (3) detects passive-mode (PASV) replies that leak an internal
address, and (4) grades information disclosure from the banner and SYST.
The result is a findings list and an A-F grade. No files are read or written.
]]

---
-- @usage
-- nmap -n -p 21 --script ./ftp-exposure-profile.nse <target>
--
-- @output
-- | ftp-exposure-profile:
-- |   grade: F (15/100)
-- |   banner: ProFTPD 1.3.5 Server (Lab Debian) ready.
-- |   findings:
-- |     [CRITICAL] ...
-- |_    [HIGH] ...

author = "Misthi Pandey"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({21, 2121}, "ftp")

-- Small built-in table (banner is lowercased before matching)
local KNOWN = {
  {pat = "vsftpd 2%.3%.4", msg = "vsFTPd 2.3.4 - backdoored release (CVE-2011-2523)"},
  {pat = "proftpd 1%.3%.5", msg = "ProFTPD 1.3.5 - mod_copy unauthenticated file copy (CVE-2015-3306)"},
}

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

local function is_private(a, b)
  return a == 10 or a == 127 or (a == 172 and b >= 16 and b <= 31)
      or (a == 192 and b == 168) or (a == 169 and b == 254)
end

action = function(host, port)
  local sock = nmap.new_socket()
  sock:set_timeout(8000)
  if not sock:connect(host, port) then return nil end

  local code, btext = read_reply(sock)
  if code ~= 220 then sock:close(); return nil end
  local banner = btext:gsub("^%d%d%d[ %-]", ""):gsub("[\r\n]+$", "")

  local findings = {}
  local score = 100
  local function add(sev, msg, penalty)
    findings[#findings + 1] = string.format("[%s] %s", sev, msg)
    score = score - (penalty or 0)
  end

  -- FEAT (before login), then anonymous login (needed to trigger PASV)
  local fcode, ftext = cmd(sock, "FEAT")
  local c = cmd(sock, "USER anonymous")
  if c == 331 then c = cmd(sock, "PASS anonymous@example.com") end
  local logged = (c == 230)
  if fcode ~= 211 and logged then fcode, ftext = cmd(sock, "FEAT") end

  local scode, stext = cmd(sock, "SYST")

  local pcode, ptext
  if logged then pcode, ptext = cmd(sock, "PASV") end
  sock:send("QUIT\r\n")
  sock:close()

  -- 1) Banner -> known risks
  local lower = banner:lower()
  local matched = false
  for _, k in ipairs(KNOWN) do
    if lower:match(k.pat) then
      add("CRITICAL", "banner matches " .. k.msg .. " (verify: banners can be spoofed)", 40)
      matched = true
    end
  end
  if not matched then
    findings[#findings + 1] = "[INFO] banner matches no entry in the built-in vulnerability table"
  end

  -- 2) Cleartext transport
  local feat = (ftext or ""):lower()
  if feat:find("auth tls", 1, true) or feat:find("auth ssl", 1, true) then
    findings[#findings + 1] = "[OK] AUTH TLS offered - encrypted login is possible"
  else
    add("HIGH", "no AUTH TLS/SSL in FEAT - credentials and data travel in cleartext", 25)
  end

  -- 3) PASV internal address leak
  if not logged then
    findings[#findings + 1] = "[INFO] PASV leak test skipped (anonymous login refused)"
  elseif pcode == 227 then
    local a, b, cc, d = ptext:match("(%d+),(%d+),(%d+),(%d+),%d+,%d+")
    if a then
      local adv = string.format("%d.%d.%d.%d", a, b, cc, d)
      if adv ~= host.ip then
        if is_private(tonumber(a), tonumber(b)) then
          add("MEDIUM", string.format("PASV leaks internal address %s (scanned via %s)", adv, host.ip), 15)
        else
          add("LOW", string.format("PASV advertises a different address %s (NAT/misconfiguration)", adv), 5)
        end
      else
        findings[#findings + 1] = "[OK] PASV advertises the scanned address"
      end
    end
  else
    findings[#findings + 1] = "[INFO] PASV test inconclusive (reply " .. tostring(pcode) .. ")"
  end

  -- 4) Information disclosure
  if banner:match("%d+%.%d+") then
    add("LOW", "banner discloses software version", 5)
  end
  if scode == 215 and stext then
    local sys = stext:gsub("^215 ", ""):gsub("[\r\n]+$", "")
    findings[#findings + 1] = "[INFO] SYST reveals: " .. sys
  end

  if score < 0 then score = 0 end
  local grade = "F"
  if score >= 90 then grade = "A"
  elseif score >= 75 then grade = "B"
  elseif score >= 60 then grade = "C"
  elseif score >= 40 then grade = "D" end

  local out = stdnse.output_table()
  out.grade = string.format("%s (%d/100)", grade, score)
  out.banner = banner
  out.anonymous_login = logged and "allowed" or "refused"
  out.findings = findings
  return out
end
