SCRIPT FIREWALL DEDSEC (EVASÃO DE FIREWALL)
---
----
local packet = require 'packet'
local nmap = require "nmap"
local vulns = require "vulns"
local stdnse = require "stdnse"
local shortport = require "shortport"

categories = {"discovery", "vuln"}

portrule = shortport.port_or_service({22, 80, 443}, {"ssh", "http", "https"})

rule = function()
 return {
    host = {
      -- Match all hosts
     },
     port = portrule
    }
  end

--
function evasion_firewall(host, port)
  local pkt = packet.Packet:new()
  pkt:push("eth")
  pkt:push("ip")
  pkt:push("tcp")
  pkt.ip.src = host.ip
  pkt.ip.dst = host.ip
  pkt.ip.id = math.random(0, 65535)
  pkt.ip.len = 40
  pkt.ip.ttl = 64
  pkt.tcp.src = math.random(1, 65535)
  pkt.tcp.dst = math.random(1, 65535)
  pkt.tcp.flags = "S"

  local status, response = stdnse.send_receive(host, "evasion_firewall", pkt, {
    evasion_firewall = function(p)
      if p:get_flags() == "SA" then
        return true
       end
      end
    })
    return status
  end

action = function(host, port)
  local result = {}

  local firewall_status = evasion_firewall(host, port)
  if firewall_status then
    table.insert(result, "Evasão de firewall bem-sucedida")
  else
    table.insert(result, "Evasão de firewall falhou")
  end

  local vulns_result = vulns.scan_port(host, port)
   for _, vuln in ipairs(vulns_result) do
    if vuln.id == "VULN1" then
      table.insert(result, "Vulnerabilidade 1 encontrada")
    elseif vuln.id == "VULN2" then
      table.insert(result, "Vulnerabilidade 2 encontrada")
    elseif vuln.id == "VULN3" then
      table.insert(result, "Vulnerabilidade 3 encontrada")
    else
      table.insert(result, "Nenhuma vulnerabilidade encontrada")
    end
  end

  return stdnse.format_output(true, result)
end
