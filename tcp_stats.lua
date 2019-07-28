-- ** TCP Statistics **
-- Description: Usual TCP performance issues (low TCP window, high TCP delta times, long iRTT, etc.)
-- Author: Silvio Gissi <silvio.gissi@gmail.com>
--
-- Invoke via tshark: tshark -o tcp.calculate_timestamps:TRUE -q -n -X lua_script:tcp_stats.lua -r captured_file.pcapng
-- Optionally add filter by adding -X lua_script1:'ip.src==192.168.123.123', any display filter is acceptable as long as it doesn't filter out parts of the TCP stream

-- Arguments, first one is used for filtering
args = {...}

tcp_stats={}
-- src, dst: Source and destination
-- src_port, dst_port: Source and destination
-- high_delta: Highest TCP time delta (RST/FIN packets discarded)
-- high_delta_frame: Frame number of time above
-- low_window: Lowest value of the TCP window
-- low_window_frame: Frame number of low window above
-- hs_src_mss / hs_dst_mss: TCP handshake MSS from both sides
-- hs_src_sack / hs_dst_sack: TCP handshake SACK support from both sides
-- hs_src_ws / hs_dst_ws: TCP handshake Window Scaling factor from both sides
-- hs_irtt: TCP initial handshake RTT

-- Check if a filter was given
filter="tcp"
if args[1] then
	filter="("..filter..") && ("..args[1]..")"
end
tap_tcp = Listener.new(nil,filter)

tcp_stream=Field.new("tcp.stream")
tcp_ws=Field.new("tcp.window_size")
tcp_f_syn=Field.new("tcp.flags.syn")
tcp_f_ack=Field.new("tcp.flags.ack")
tcp_f_rst=Field.new("tcp.flags.reset")
tcp_f_fin=Field.new("tcp.flags.fin")
tcp_irtt=Field.new("tcp.analysis.initial_rtt")
tcp_hs_mss=Field.new("tcp.options.mss_val")
tcp_hs_ws=Field.new("tcp.options.wscale.multiplier")
tcp_hs_sack=Field.new("tcp.options.sack_perm")
tcp_delta=Field.new("tcp.time_delta")

function tap_tcp.packet(pinfo)
	-- TCP stream numbers
	stream=tcp_stream().value
	-- TCP SYN, RST and FIN flags
	syn=tcp_f_syn().value
	rst=tcp_f_rst().value
	fin=tcp_f_fin().value
	-- Frame number
	fnum=pinfo.number

	-- New stream, first packet must be SYN
	if not tcp_stats[stream] then
		-- Not pure SYN, ignore. Likely existing connection prior to capture start
		if (not tcp_f_syn().value) or tcp_f_ack().value then
			return
		end
		-- Initialize tcp_stats table
		tcp_stats[stream]={}
	end

	-- SYN packet, store handshake
	if syn then
		mss = tcp_hs_mss().value
		-- Check if Window Scaling factor is present
		ws = tcp_hs_ws()
		if ws then
			ws=tostring(ws)
		else
			ws="not supported"
		end

		-- Check if SACK option is present and true
		sack = tcp_hs_sack()
		if sack and sack.value then
			sack="Yes"
		else
			sack="No"
		end

		-- First packet, source handshake
		if not tcp_f_ack().value then
			tcp_stats[stream]["hs_src_mss"]=mss
			tcp_stats[stream]["hs_src_ws"]=ws
			tcp_stats[stream]["hs_src_sack"]=sack
			tcp_stats[stream]["src"]=tostring(pinfo.src)
			tcp_stats[stream]["src_port"]=pinfo.src_port
			tcp_stats[stream]["dst"]=tostring(pinfo.dst)
			tcp_stats[stream]["dst_port"]=pinfo.dst_port
		else
			tcp_stats[stream]["hs_dst_mss"]=tcp_hs_mss().value
			tcp_stats[stream]["hs_dst_ws"]=ws
			tcp_stats[stream]["hs_dst_sack"]=sack
		end
	end

	-- **** Initial Round Trip Time (iRTT)


	-- Check if not stored yet and if iRTT is calculated already (aro3rd packet)
	irtt=tcp_irtt()
	if not tcp_stats[stream]["hs_irtt"] and irtt then
		tcp_stats[stream]["hs_irtt"]=tonumber(tostring(irtt))
	end

	-- **** Highest TCP time delta (time between TCP packets in the same stream)

	delta = tcp_delta()
	if delta then
		delta=tonumber(tostring(delta))
	end
	-- Check if delta exists and is higher than current (if any)
	if delta and (not tcp_stats[stream]["high_delta"] or delta > tcp_stats[stream]["high_delta"]) then
		-- Ignore high deltas on RST or FIN packets
		if not rst and not fin then
			tcp_stats[stream]["high_delta"]=delta
			tcp_stats[stream]["high_delta_frame"]=fnum
		end
	end

	-- **** Lowest calculated window size
	ws = tcp_ws()
	-- Check if WS field is present and get value
	if ws then
		ws=ws.value
	end
	if ws and (not tcp_stats[stream]["low_ws"] or ws < tcp_stats[stream]["low_ws"]) then
		-- Ignore low window on RST or FIN packets
		if not rst and not fin then
			tcp_stats[stream]["low_ws"]=ws
			tcp_stats[stream]["low_ws_frame"]=fnum
		end
	end

end

-- Called at the end of TShark capture but frequently by Wireshark
function tap_tcp.draw()
	print "TCP Stats"

	for stream,st in pairs(tcp_stats) do
		print("Stream " .. stream .. " Src "..st["src"]..":"..st["src_port"].." (MSS " .. st["hs_src_mss"] .. " WS "..st["hs_src_ws"].." SACK "..st["hs_src_sack"]..") -> Dst "..st["dst"]..":"..st["dst_port"].." (MSS " .. st["hs_dst_mss"].." WS "..st["hs_dst_ws"].." SACK "..st["hs_dst_sack"]..") iRTT "..string.format("%.0f",st["hs_irtt"]*1000).."ms Highest Delta "..st["high_delta"].."("..st["high_delta_frame"]..") Lowest Window Size "..st["low_ws"].."("..st["low_ws_frame"]..")")
	end
end

function tap_tcp.reset()
	print "Resetting counters"
	tcp_conn_stats={}
	tcp_stats={}
end
