-- A Wireshark LUA script to display some additional TCP information.
-- This is a post-dissector script which adds a new tree to the Wireshark view, _TCP extended info_.
--
-- All statistics, except ACK related (delta & ack_sz), are referenced to a single node, usually the sender, and displayed on both sent and received packets.
-- bif:			bytes in flight. This will normally equal the built-in tcp.analysis.bytes_in_flight, however it is 
-- 				also displayed on the ACK packets.
-- max_tx:		maximum size packet the server can send, equal to the client's receive window minus the server's bytes in flight.
-- bsp:			bytes sent since the last push flag. Same as the builtin (since v2.2) tcp.analysis.push_bytes_sent, except this displays for all packets in the flow
-- pba:			number of packets between this ACK and the packet it ACKs (equal to the builtin frame.number minus tcp.analysis.acks_frame)
-- 				TODO: this should be count of how many data packets were received, it is currently everything, even non-TCP.
-- ack_frame:	frame number which ACKs this packet. Basically the inverse of the builtin tcp.analysis.acks_frame
-- delta:		time since the previous packet was transmitted. Unlike the builtin time delta which is relative to the previous displayed packet,
--				this is relative to the previous packet from the matching sender.
-- ack_sz:		size of the segment(s) this ACK is ACKing
-- ip_inc:		incremental value of the IP ID field, ie how much bigger (or smaller) than the previous packet. Useful for spotting out of order packets
--				in situations where the IP ID increments by 1 each packet. If Large Segment Offload is running on the server then expect to see frequent
--				large negative values.
--
-- Chris Gadd
-- https://github.com/gaddman/wireshark-tcpextend
-- v1.2-20170206
--
-- Known limitiations:
-- PBA counts all packets, not just TCP packets

-- declare some fields to be read
local f_tcp_len = Field.new("tcp.len")
local f_tcp_ack = Field.new("tcp.ack")
local f_tcp_push = Field.new("tcp.flags.push")
local f_tcp_seq = Field.new("tcp.seq")
local f_tcp_stream = Field.new("tcp.stream")
local f_tcp_win = Field.new("tcp.window_size")
local f_tcp_src = Field.new("tcp.srcport")
local f_tcp_dst = Field.new("tcp.dstport")
local f_tcp_acks_frm = Field.new("tcp.analysis.acks_frame")
local f_ip_id = Field.new("ip.id")

-- declare (pseudo) protocol
local p_TCPextend = Proto("TCPextend","Extended TCP information")
-- create the fields for this "protocol". These probably shouldn't all be 32 bit integers.
local F_bif = ProtoField.int32("TCPextend.bif","Bytes in Flight")
local F_max_tx = ProtoField.int32("TCPextend.max_tx","Max tx bytes")
local F_bsp = ProtoField.int32("TCPextend.bsp","Bytes since PSH")
local F_pba = ProtoField.int32("TCPextend.pba","Packets before ACK")
local F_ack_frame = ProtoField.int32("TCPextend.ack_frame","Frame number which ACKs this packet")
local F_delta = ProtoField.relative_time("TCPextend.delta","Time delta")
local F_ack_sz = ProtoField.int32("TCPextend.ack_sz","Size of segment ACKd")
local F_ip_inc = ProtoField.int32("TCPextend.ip_inc","IP ID increment")
-- add the fields to the protocol
p_TCPextend.fields = {F_bif, F_max_tx, F_bsp, F_pba, F_ack_frame, F_ack_sz, F_delta, F_ip_inc}
-- variables to persist across all packets
local stm_data = {} -- indexed per stream
local pkt_data = {} -- indexed per packet

local function reset_stats()
	-- clear stats for a new dissection
	stm_data = {}	-- declared already outside this function for persistence across packets
	pkt_data = {}	-- declared already outside this function for persistence across packets
	-- define/clear variables per packet
	pkt_data.bif = {}
	pkt_data.max_tx = {}
	pkt_data.bsp = {}
	pkt_data.pba = {}
	pkt_data.ack_frame = {}
	pkt_data.delta = {}
	pkt_data.ack_sz = {}
	pkt_data.ip_inc = {}
	-- define/clear variables per stream
	stm_data.client_time = {}	-- timestamp for this frame
	stm_data.server_time = {}
	stm_data.client_port = {}	-- tcp port
	stm_data.server_port = {}
	stm_data.client_win = {}	-- window size
	stm_data.server_win = {}
	stm_data.client_bsp = {}	-- bytes since push
	stm_data.server_bsp = {}
	stm_data.client_pseq = {}	-- sequence number at last push flag (at end of packet, ie tcp.seq + tcp.len - 1)
	stm_data.server_pseq = {}
	stm_data.client_ack = {}	-- last ACK value
	stm_data.server_ack = {}
	stm_data.client_seq = {}	-- last SEQ value (actually SEQ+LEN-1)
	stm_data.server_seq = {}
	stm_data.client_id = {}		-- IP id
	stm_data.server_id = {}
end

function p_TCPextend.init()
	reset_stats()
end
   
-- function to "postdissect" each frame
function p_TCPextend.dissector(buffer,pinfo,tree)

	local tcp_len = f_tcp_len()
	if tcp_len then    -- seems like it should filter out TCP traffic. Maybe there's a way like taps to register the dissector with a filter?
		tcp_len = tcp_len.value
		local pkt_no = pinfo.number -- warning, this will become a large array (of 32bit integers) if lots of packets
		local frame_time = pinfo.rel_ts
		local tcp_stream = f_tcp_stream().value
		local tcp_ack = f_tcp_ack().value
		local tcp_lseq = f_tcp_seq().value + tcp_len - 1
		local tcp_push = f_tcp_push().value
		local tcp_win = f_tcp_win().value
		local tcp_srcport = f_tcp_src().value
		local tcp_dstport = f_tcp_dst().value
		local ip_id = f_ip_id().value

		if not pinfo.visited then
	
			-- set initial values if this stream not seen before            
			if not stm_data.client_port[tcp_stream] then
				stm_data.client_port[tcp_stream] = tcp_srcport  -- assuming first packet we see is client to server
				stm_data.server_port[tcp_stream] = tcp_dstport
				stm_data.client_win[tcp_stream] = 0
				stm_data.server_win[tcp_stream] = 0
				stm_data.client_bsp[tcp_stream] = 0
				stm_data.server_bsp[tcp_stream] = 0
				stm_data.client_pseq[tcp_stream] = 0
				stm_data.server_pseq[tcp_stream] = 0
				stm_data.client_ack[tcp_stream] = 0
				stm_data.server_ack[tcp_stream] = 0
				stm_data.client_seq[tcp_stream] = 0
				stm_data.server_seq[tcp_stream] = 0
				stm_data.client_id[tcp_stream] = 0
				stm_data.server_id[tcp_stream] = 0
				stm_data.client_time[tcp_stream] = 0
				stm_data.server_time[tcp_stream] = 0
			end
			-- declare variables local to this packet
			local cbsp = 0
			local sbsp = 0
			local cbif = 0
			local sbif = 0
			local cmax_tx = 0
			local smax_tx = 0
			local cdelta = 0
			local sdelta = 0
			local cack_sz = 0
			local sack_sz = 0
			local req_frm = 0
			
			-- calculate depending on which direction this packet is going
			if tcp_srcport == stm_data.server_port[tcp_stream] then
				-- from server
				-- calculate time since last packet from this endpoint, and store as NStime (seconds,nanoseconds)
				sdelta = frame_time - stm_data.server_time[tcp_stream]
				local secs, frac = math.modf(sdelta)
				pkt_data.delta[pkt_no] = NSTime(secs, frac * 10^9)
				-- set current, and then calculate new bytes since last push
				sbsp = tcp_lseq - stm_data.server_pseq[tcp_stream]
				cbsp = stm_data.client_bsp[tcp_stream]
				if tcp_push == true then
					stm_data.server_bsp[tcp_stream] = 0
					stm_data.server_pseq[tcp_stream] = tcp_lseq
				else
					-- rather than just add the length, calculate from seq in case we have OOO or retransmitted pkts
					stm_data.server_bsp[tcp_stream] = tcp_lseq - stm_data.server_pseq[tcp_stream]
				end
                -- ack_sz = current ACK - previous ACK
                pkt_data.ack_sz[pkt_no] = tcp_ack - stm_data.server_ack[tcp_stream]
				-- max_tx = receive window - _current_ BiF
				smax_tx = stm_data.client_win[tcp_stream] - (stm_data.server_seq[tcp_stream] - stm_data.client_ack[tcp_stream] + 1)
				cmax_tx = stm_data.server_win[tcp_stream] - (stm_data.client_seq[tcp_stream] - stm_data.server_ack[tcp_stream] + 1)
                -- ip_inc = how much bigger is this IP ID than previous packet
				if stm_data.server_id[tcp_stream]>0 then
					-- not the first packet
					pkt_data.ip_inc[pkt_no] = ip_id - stm_data.server_id[tcp_stream]
				end
				-- set/calculate new persistent values
				stm_data.server_time[tcp_stream] = frame_time
				stm_data.server_seq[tcp_stream] = tcp_lseq
				stm_data.server_ack[tcp_stream] = tcp_ack
				stm_data.server_win[tcp_stream] = tcp_win
				stm_data.server_id[tcp_stream] = ip_id
			elseif tcp_srcport == stm_data.client_port[tcp_stream] then
				-- from client
				-- calculate time since last packet from this endpoint, and store as NStime (seconds,nanoseconds)
				cdelta = frame_time - stm_data.client_time[tcp_stream]
				local secs, frac = math.modf(cdelta)
				pkt_data.delta[pkt_no] = NSTime(secs, frac * 10^9)
				-- set current, and then calculate new bytes since last push
				cbsp = tcp_lseq - stm_data.client_pseq[tcp_stream]
				sbsp = stm_data.server_bsp[tcp_stream]
				if tcp_push == true then
					stm_data.client_bsp[tcp_stream] = 0
					stm_data.client_pseq[tcp_stream] = tcp_lseq
				else
					-- rather than just add the length, calculate from seq in case we have OOO or retransmitted pkts
					stm_data.client_bsp[tcp_stream] = tcp_lseq - stm_data.client_pseq[tcp_stream]
				end
                -- ack_sz = current ACK - previous ACK
                pkt_data.ack_sz[pkt_no] = tcp_ack - stm_data.client_ack[tcp_stream]
				-- max_tx = receive window - _current_ BiF
				cmax_tx = stm_data.server_win[tcp_stream] - (stm_data.client_seq[tcp_stream] - stm_data.server_ack[tcp_stream] + 1)
				smax_tx = stm_data.client_win[tcp_stream] - (stm_data.server_seq[tcp_stream] - stm_data.client_ack[tcp_stream] + 1)
                -- ip_inc = how much bigger is this IP ID than previous packet
				if stm_data.client_id[tcp_stream]>0 then
					-- not the first packet
					pkt_data.ip_inc[pkt_no] = ip_id - stm_data.client_id[tcp_stream]
				end
				-- set/calculate new persistent values
				stm_data.client_time[tcp_stream] = frame_time
				stm_data.client_seq[tcp_stream] = tcp_lseq
				stm_data.client_ack[tcp_stream] = tcp_ack
				stm_data.client_win[tcp_stream] = tcp_win
				stm_data.client_id[tcp_stream] = ip_id
			end			
			
			-- calculate new bytes in flight
			cbif = stm_data.client_seq[tcp_stream] - stm_data.server_ack[tcp_stream] + 1
			sbif = stm_data.server_seq[tcp_stream] - stm_data.client_ack[tcp_stream] + 1
			
			-- try to guess which node is the sender, and display some stats based on that
			-- the '=' comparison in case they're both 0 favours download traffic
			if sbif >= cbif then
				-- server is sending data in this stream
				pkt_data.bif[pkt_no] = sbif
				pkt_data.bsp[pkt_no] = sbsp
				pkt_data.max_tx[pkt_no] = smax_tx
			else
				-- client is sending data in this stream
				pkt_data.bif[pkt_no] = cbif
				pkt_data.bsp[pkt_no] = cbsp
				pkt_data.max_tx[pkt_no] = cmax_tx
			end
			
            -- f_tcp_acks_frm not always available, even if an ACK. If so then pba will be null and not added to the tree
			-- TODO: calculate from SEQ/ACK instead of using Wireshark's builtin tcp.analysis.acks_frame
			req_frm = f_tcp_acks_frm().value
			pkt_data.pba[pkt_no] = pkt_no - req_frm
			-- update the request packet for this ACK response
			pkt_data.ack_frame[req_frm] = pkt_no

		end	-- if packet not visited
		
		if pinfo.visited then
			-- packet processed, output to tree
			local subtree = tree:add(p_TCPextend,"TCP extended info")
			subtree:add(F_delta,pkt_data.delta[pkt_no]):set_generated()
			subtree:add(F_bsp,pkt_data.bsp[pkt_no]):set_generated()
			subtree:add(F_bif,pkt_data.bif[pkt_no]):set_generated()
			subtree:add(F_max_tx,pkt_data.max_tx[pkt_no]):set_generated()
			if pkt_data.ack_frame[pkt_no] then
				subtree:add(F_ack_frame,pkt_data.ack_frame[pkt_no]):set_generated()
			end
			if pkt_data.pba[pkt_no] then
				subtree:add(F_pba,pkt_data.pba[pkt_no]):set_generated()
			end
			if tcp_ack then
				subtree:add(F_ack_sz,pkt_data.ack_sz[pkt_no]):set_generated()
			end
			if pkt_data.ip_inc[pkt_no] then
				ip_id = subtree:add(F_ip_inc,pkt_data.ip_inc[pkt_no]):set_generated()
				if (pkt_data.ip_inc[pkt_no]>1) or (pkt_data.ip_inc[pkt_no]<0) then -- this may be a bad assumption
					ip_id:add_expert_info(PI_SEQUENCE,PI_WARN,"This packet may be out of order")
				end
			end
		end
		
	end	-- if a TCP packet
end

-- register protocol as a postdissector
register_postdissector(p_TCPextend)