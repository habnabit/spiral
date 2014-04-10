local curvecp = Proto('curvecp', 'CurveCP')

local curvecp_packet_type = ProtoField.new('Packet type', 'packet.type', ftypes.STRING)
local curvecp_client_extension = ProtoField.new('Client extension', 'client.extension', ftypes.BYTES)
local curvecp_server_extension = ProtoField.new('Server extension', 'server.extension', ftypes.BYTES)
local curvecp_client_short_pubkey = ProtoField.new('Client short-term public key', 'client.short_pubkey', ftypes.BYTES)
local curvecp_nonce = ProtoField.new('Nonce', 'packet.nonce', ftypes.BYTES)
local curvecp_cookie = ProtoField.new('Cookie', 'packet.cookie', ftypes.BYTES)
local curvecp_payload = ProtoField.new('Payload', 'packet.payload', ftypes.BYTES)

curvecp.fields = {
   curvecp_packet_type,
   curvecp_client_extension,
   curvecp_server_extension,
   curvecp_client_short_pubkey,
   curvecp_nonce,
   curvecp_cookie,
   curvecp_payload,
}

local packet_types = {
   ['QvnQ5XlH'] = 'Client Hello',
   ['RL3aNMXK'] = 'Server Cookie',
   ['QvnQ5XlI'] = 'Client Initiate',
   ['RL3aNMXM'] = 'Server Message',
   ['QvnQ5XlM'] = 'Client Message',
}

function curvecp.dissector(tvbuf, pktinfo, root)
   pktinfo.cols.protocol:set('CurveCP')
   local pktlen = tvbuf:reported_length_remaining()
   local tree = root:add(curvecp, tvbuf:range(0, pktlen))

   local packet_type = tvbuf:raw(0, 8)
   local packet_type_name = packet_types[packet_type]
   tree:add(curvecp_packet_type, tvbuf:range(0, 8), packet_type_name)
   pktinfo.cols.info:set(packet_type_name .. ' (' .. pktlen .. ' bytes)')

   local direction = tvbuf:raw(0, 1)
   if direction == 'Q' then
      tree:add(curvecp_server_extension, tvbuf:range(8, 16))
      tree:add(curvecp_client_extension, tvbuf:range(24, 16))
      tree:add(curvecp_client_short_pubkey, tvbuf:range(40, 32))
   elseif direction == 'R' then
      tree:add(curvecp_client_extension, tvbuf:range(8, 16))
      tree:add(curvecp_server_extension, tvbuf:range(24, 16))
   end

   if packet_type == 'QvnQ5XlH' then
      tree:add(curvecp_nonce, tvbuf:range(136, 8))
      tree:add(curvecp_payload, tvbuf:range(144, 80))
   elseif packet_type == 'RL3aNMXK' then
      tree:add(curvecp_nonce, tvbuf:range(40, 16))
      tree:add(curvecp_payload, tvbuf:range(56, 144))
   elseif packet_type == 'QvnQ5XlI' then
      tree:add(curvecp_cookie, tvbuf:range(72, 96))
      tree:add(curvecp_nonce, tvbuf:range(168, 8))
      tree:add(curvecp_payload, tvbuf:range(176, pktlen - 176))
   elseif packet_type == 'RL3aNMXM' then
      tree:add(curvecp_nonce, tvbuf:range(40, 16))
      tree:add(curvecp_payload, tvbuf:range(56, pktlen - 56))
   elseif packet_type == 'QvnQ5XlM' then
      tree:add(curvecp_nonce, tvbuf:range(72, 8))
      tree:add(curvecp_payload, tvbuf:range(80, pktlen - 80))
   end

   return pktlen
end

local function heur_dissect_curvecp(tvbuf, pktinfo, root)
   local l = tvbuf:len()
   if l < 80 or l > 1184 then
      return false
   end
   local packet_type = tvbuf:raw(0, 8)
   if not packet_types[packet_type] then
      return false
   end
   curvecp.dissector(tvbuf, pktinfo, root)
   pktinfo.conversation = curvecp
   return true
end

curvecp:register_heuristic('udp', heur_dissect_curvecp)
