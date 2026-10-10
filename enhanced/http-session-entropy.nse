local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local math = require "math"

description = [[
Enhancement 1 of http-headers. Instead of just printing headers, this script
requests the page several times, collects every Set-Cookie value and
statistically analyses how unpredictable each token is: Shannon entropy over
the variable character positions, constant-position detection, sequential
(incrementing) ID detection and timestamp-derived token detection. Each cookie
gets a verdict (CRITICAL / WEAK / MODERATE / STRONG).
]]

---
-- @usage
-- nmap -p 8000 --script ./http-session-entropy.nse 127.0.0.1
-- @args http-session-entropy.path Path to request. Default: /
-- @args http-session-entropy.samples Number of requests (5-100). Default: 20
--
-- @output
-- | http-session-entropy:
-- |   SESSIONID:
-- |     verdict: CRITICAL
-- |     reason: sequential (constant step of 1) - guessable
-- |_    ...

author = "Misthi Pandey"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local function log2(x) return math.log(x) / math.log(2) end

local function all_match(values, pattern)
  for _, v in ipairs(values) do
    if not v:match(pattern) then return false end
  end
  return true
end

local function charset(values)
  if all_match(values, "^%d+$") then return "decimal"
  elseif all_match(values, "^%x+$") then return "hex"
  elseif all_match(values, "^[%w%-_]+$") then return "alphanumeric/base64url"
  elseif all_match(values, "^[%w%+/=]+$") then return "base64"
  end
  return "mixed"
end

-- Shannon entropy over only the character positions that actually vary,
-- scaled to the average number of varying characters per token.
local function entropy_estimate(values)
  local minlen = math.huge
  for _, v in ipairs(values) do minlen = math.min(minlen, #v) end

  local is_var, const = {}, 0
  for i = 1, minlen do
    local first = values[1]:sub(i, i)
    is_var[i] = false
    for j = 2, #values do
      if values[j]:sub(i, i) ~= first then is_var[i] = true; break end
    end
    if not is_var[i] then const = const + 1 end
  end

  local counts, total = {}, 0
  for _, v in ipairs(values) do
    for i = 1, #v do
      if i > minlen or is_var[i] then
        local ch = v:sub(i, i)
        counts[ch] = (counts[ch] or 0) + 1
        total = total + 1
      end
    end
  end
  if total == 0 then return 0, const end

  local h = 0
  for _, n in pairs(counts) do
    local p = n / total
    h = h - p * log2(p)
  end
  return h * (total / #values), const
end

local function numeric_values(values)
  if not all_match(values, "^%d+$") then return nil end
  local nums = {}
  for _, v in ipairs(values) do
    if #v > 15 then return nil end
    nums[#nums + 1] = tonumber(v)
  end
  return nums
end

local function looks_like_timestamp(nums)
  local now, year = os.time(), 31536000
  local secs, ms = true, true
  for _, n in ipairs(nums) do
    if math.abs(n - now) > year then secs = false end
    if math.abs(n - now * 1000) > year * 1000 then ms = false end
  end
  if secs then return "seconds" elseif ms then return "milliseconds" end
  return nil
end

local function sequential(nums)
  local diffs, freq = {}, {}
  for i = 2, #nums do
    local d = nums[i] - nums[i - 1]
    diffs[#diffs + 1] = d
    freq[d] = (freq[d] or 0) + 1
  end
  local best_d, best_n = 0, 0
  for d, n in pairs(freq) do
    if n > best_n then best_d, best_n = d, n end
  end
  if best_d ~= 0 and best_n / #diffs >= 0.8 then
    return "constant step of " .. best_d
  end
  for _, d in ipairs(diffs) do
    if d <= 0 or d > 1000 then return nil end
  end
  return "monotonic increase with small steps"
end

-- Collect (name, value) pairs from one response.
-- Primary source: raw Set-Cookie header lines. Fallback: Nmap's parsed cookies.
local function extract_cookies(response)
  local found = {}
  if response.rawheader then
    for _, line in ipairs(response.rawheader) do
      local name, value = line:match("^[Ss]et%-[Cc]ookie:%s*([^=;%s]+)=([^;]*)")
      if name then found[#found + 1] = {name, value} end
    end
  end
  if #found == 0 and response.cookies then
    for _, c in ipairs(response.cookies) do
      if c.name then found[#found + 1] = {c.name, c.value or ""} end
    end
  end
  return found
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  local samples = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".samples")) or 20
  samples = math.max(5, math.min(samples, 100))

  -- 1) Collect Set-Cookie values over N fresh requests
  local jar, order = {}, {}
  local ok_requests = 0
  for i = 1, samples do
    local response = http.get(host, port, path, {no_cache = true})
    if response and response.status then
      ok_requests = ok_requests + 1
      local cookies = extract_cookies(response)
      stdnse.debug1("request %d: HTTP %d, %d cookie(s)", i, response.status, #cookies)
      for _, c in ipairs(cookies) do
        local name, value = c[1], c[2]
        if not jar[name] then jar[name] = {}; order[#order + 1] = name end
        table.insert(jar[name], value)
      end
    else
      stdnse.debug1("request %d: no response", i)
    end
  end

  if ok_requests == 0 then
    stdnse.debug1("no successful HTTP responses from %s:%d", host.ip, port.number)
    return nil
  end
  if #order == 0 then
    return string.format("No Set-Cookie headers seen in %d requests to %s", ok_requests, path)
  end

  -- 2) Analyse each cookie
  local out = stdnse.output_table()
  local analysed = 0
  for _, name in ipairs(order) do
    local values = jar[name]
    if #values >= 3 then
      local seen, unique = {}, 0
      local lmin, lmax = math.huge, 0
      for _, v in ipairs(values) do
        if not seen[v] then seen[v] = true; unique = unique + 1 end
        lmin = math.min(lmin, #v)
        lmax = math.max(lmax, #v)
      end

      local verdict, reason
      local bits, const = 0, 0
      if unique == 1 then
        verdict = "INFO"
        reason = "static value, not rotated per request (fixed or login-only token)"
      else
        bits, const = entropy_estimate(values)
        local nums = numeric_values(values)
        local ts = nums and looks_like_timestamp(nums)
        local seq = nums and sequential(nums)
        if ts then
          verdict, reason = "CRITICAL", "timestamp-derived (" .. ts .. ") - predictable"
        elseif seq then
          verdict, reason = "CRITICAL", "sequential (" .. seq .. ") - guessable"
        elseif bits < 64 then
          verdict = "WEAK"
          reason = string.format("~%.0f bits of entropy, below the 64-bit minimum", bits)
        elseif bits < 96 then
          verdict = "MODERATE"
          reason = string.format("~%.0f bits of entropy, acceptable but not generous", bits)
        else
          verdict = "STRONG"
          reason = string.format("~%.0f bits of entropy, looks cryptographically random", bits)
        end
      end

      local res = stdnse.output_table()
      res.verdict = verdict
      res.reason = reason
      res.samples = #values
      res.unique_values = unique
      res.length = (lmin == lmax) and tostring(lmin) or (lmin .. "-" .. lmax)
      res.charset = charset(values)
      res.constant_positions = const
      res.est_entropy_bits = string.format("%.1f", bits)
      out[name] = res
      analysed = analysed + 1
    else
      stdnse.debug1("cookie %s: only %d sample(s), skipped", name, #values)
    end
  end

  if analysed == 0 then
    return "Cookies seen but too few samples to analyse"
  end
  return out
end
