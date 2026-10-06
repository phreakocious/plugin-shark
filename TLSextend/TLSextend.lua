-- Vendored from https://github.com/syn-bit/TLSextend (a09ab33). Modified 2026-10-05: bit32 -> bit for Lua 5.4+.
-- An (initial) Wireshark LUA script to keep TLS state
--
--     Copyright (C) 2022  Sake Blok
-- 
--     This program is free software: you can redistribute it and/or modify
--     it under the terms of the GNU General Public License as published by
--     the Free Software Foundation, either version 3 of the License, or
--     (at your option) any later version.
-- 
--     This program is distributed in the hope that it will be useful,
--     but WITHOUT ANY WARRANTY; without even the implied warranty of
--     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--     GNU General Public License for more details.
-- 
--     You should have received a copy of the GNU General Public License
--     along with this program.  If not, see [http://www.gnu.org/licenses/].
-- 
--
-- Written as an answer to a question on ask.wireshark.org:
-- https://ask.wireshark.org/question/26618/filter-tls-with-no-server-hello/
--
-- Version  1.0
-- Source   https://github.com/syn-bit/TLSextend
--
-- Generated from: https://github.com/gaddman/wireshark-TCPextend

-- declare some fields to be read
local f_tcp_stream              = Field.new("tcp.stream")
local f_tls_handshake_type      = Field.new("tls.handshake.type")

-- declare (pseudo) protocol
local p_TLSextend = Proto("TLSextend","Extended TLS information")

-- create the fields for this "protocol". These probably shouldn't all be 32 bit integers.
local F_state = ProtoField.int32("TLSextend.state","TLS state")

-- add the fields to the protocol
p_TLSextend.fields = {F_state}

-- variables to persist across all packets
local stream_data = {} -- indexed per stream

local function reset_stats()
	-- clear stats for a new dissection
	stream_data = {}	-- declared already outside this function for persistence across packets

	-- define/clear variables per stream
	stream_data.state = {}	-- timestamp for this frame
end

function p_TLSextend.init()
	reset_stats()
end
   
-- function to "postdissect" each frame
function p_TLSextend.dissector(buffer,pinfo,tree)

	local tcp_stream = f_tcp_stream()
	if tcp_stream then    -- seems like it should filter out TCP traffic. Maybe there's a way like taps to register the dissector with a filter?
		tcp_stream = tcp_stream.value

        -- set initial values if this stream not seen before            
        if not stream_data.state[tcp_stream] then
            stream_data.state[tcp_stream] = 0
        end

		if not pinfo.visited then

            local tls_handshake_type = f_tls_handshake_type()
            if tls_handshake_type then
                tls_handshake_type = tls_handshake_type.value

                if tls_handshake_type == 1 then
                    stream_data.state[tcp_stream] = bit.bor(stream_data.state[tcp_stream],1)
                end -- if tls_handshake_type == 1

                if tls_handshake_type == 2 then
                    stream_data.state[tcp_stream] = bit.bor(stream_data.state[tcp_stream],2)
                end -- if tls_handshake_type == 2

            end -- if tls_handshake_type
	
		end	-- if not pinfo.visited 
		
		if pinfo.visited then
			-- packet processed, output to tree
			local subtree = tree:add(p_TLSextend,"TLS extended info")
			subtree:add(F_state,stream_data.state[tcp_stream]):set_generated()
		end -- if pinfo.visited
		
	end	-- if tcp_stream
end

-- register protocol as a postdissector
register_postdissector(p_TLSextend)
