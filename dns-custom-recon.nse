description = [[
  Custom DNS Multi-Record Fingerprint & Infrastructure Discovery Scanner.
  Performs discovery across target DNS servers for:
    - IPv4 Address (A Record)
    - IPv6 Address (AAAA Record)
    - Name Server Delegation (NS Record)
    - Start of Authority (SOA Record)
    - Mail Exchange Gateway (MX Record)
    - DNSSEC Validation Feature Support
]]
author = "Manjushree"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local dns = require "dns"
local shortport = require "shortport"
local stdnse = require "stdnse"

portrule = shortport.portnumber(53, {"udp", "tcp"})

action = function(host, port)
  local results = {}

  table.insert(results, "==================================================================")
  table.insert(results, "        CUSTOM DNS RECONNAISSANCE SCAN REPORT                     ")
  table.insert(results, "==================================================================")

  -- 1. IPv4 Address (A Record)
  local a_status, a_resp = dns.query("google.com", { host = host.ip, port = port.number, proto = port.protocol, dtype = "A" })
  if a_status and a_resp then
    table.insert(results, "[+] IPv4 Address (A Record)      : FOUND")
  else
    table.insert(results, "[-] IPv4 Address (A Record)      : NOT FOUND")
  end

  -- 2. IPv6 Address (AAAA Record)
  local aaaa_status, aaaa_resp = dns.query("google.com", { host = host.ip, port = port.number, proto = port.protocol, dtype = "AAAA" })
  if aaaa_status and aaaa_resp then
    table.insert(results, "[+] IPv6 Address (AAAA Record)   : FOUND")
  else
    table.insert(results, "[-] IPv6 Address (AAAA Record)   : NOT FOUND")
  end

  -- 3. Name Servers (NS Record)
  local ns_status, ns_resp = dns.query("google.com", { host = host.ip, port = port.number, proto = port.protocol, dtype = "NS" })
  if ns_status and ns_resp then
    table.insert(results, "[+] Name Servers (NS)            : FOUND")
  else
    table.insert(results, "[-] Name Servers (NS)            : NOT FOUND")
  end

  -- 4. SOA Record
  local soa_status, soa_resp = dns.query("google.com", { host = host.ip, port = port.number, proto = port.protocol, dtype = "SOA" })
  if soa_status and soa_resp then
    table.insert(results, "[+] SOA Record                   : FOUND")
  else
    table.insert(results, "[-] SOA Record                   : NOT FOUND")
  end

  -- 5. Mail Servers (MX Record)
  local mx_status, mx_resp = dns.query("google.com", { host = host.ip, port = port.number, proto = port.protocol, dtype = "MX" })
  if mx_status and mx_resp then
    table.insert(results, "[+] Mail Servers (MX)            : FOUND")
  else
    table.insert(results, "[-] Mail Servers (MX)            : NOT FOUND")
  end

  -- 6. DNSSEC Status
  local dnssec_status = dns.query("google.com", { host = host.ip, port = port.number, proto = port.protocol, dnssec = true })
  if dnssec_status then
    table.insert(results, "[+] DNSSEC Validation            : ACTIVE / SUPPORTED")
  else
    table.insert(results, "[-] DNSSEC Validation            : NOT DETECTED")
  end

  table.insert(results, "==================================================================")
  return stdnse.format_output(true, results)
end
