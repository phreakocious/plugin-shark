----------------------------------------------------------------------------------------------------------------------
-- Name: Microsoft Lync / Skype for Business Wireshark Plugin
-- Version: v2.0.0 (20/3/2016)
-- Date: 1/5/2014
-- Created By: James Cussen
-- Web Site: http://www.myskypelab.com
-- Notes: For more information on this plugin visit http://www.myskypelab.com/2014/05/microsoft-lync-wireshark-plugin.html
-- Feedback: If you have feedback on the plugin you can send it to mylynclab<at>gmail<dot>com 
--
-- Copyright: Copyright (c) 2016, James Cussen (www.myskypelab.com) All rights reserved.
-- Licence: 	Redistribution and use of script, source and binary forms, with or without modification, are permitted provided that the following conditions are met:
--				1) Redistributions of script code must retain the above copyright notice, this list of conditions and the following disclaimer.
--				2) Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
--				3) Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
--				4) This license does not include any resale or commercial use of this software.
--				5) Any portion of this software may not be reproduced, duplicated, copied, sold, resold, or otherwise exploited for any commercial purpose without express written consent of James Cussen.
--			THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; LOSS OF GOODWILL OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
--
-- Protocol Documentation:	[MS-TURNBWM] http://msdn.microsoft.com/en-us/library/ff595670.aspx
-- 							[MS-TURN] http://msdn.microsoft.com/en-us/library/cc431507.aspx
--							[MS-RTP] http://msdn.microsoft.com/en-us/library/cc431492.aspx
--							[MS-SRTP] http://msdn.microsoft.com/en-us/library/cc431516.aspx
--							[MS-RTASPF] http://msdn.microsoft.com/en-us/library/cc308725.aspx
-- 							[MS-RTPDT] http://msdn.microsoft.com/en-us/library/cc485841.aspx
--							[MS-ICE] http://msdn.microsoft.com/en-us/library/dd922095.aspx
--							[MS-ICE2] http://msdn.microsoft.com/en-us/library/cc431504.aspx
--							ICE RFC5245 - https://tools.ietf.org/html/rfc5245
--							STUN RFC5389 - http://tools.ietf.org/html/rfc5389
--							ICE-19 - http://tools.ietf.org/html/draft-ietf-mmusic-ice-19
--							RTP / RTCP - http://tools.ietf.org/html/rfc3550
--							
-- Release Notes:
-- 1.00 Initial Release.
--		- This Wireshark plugin is designed to dissect Lync AV Edge and Internal Edge AV traffic. Captures can be taken on the Edge server (Capturing AV Edge External traffic, and Internal Interface traffic), or it can also be used on the client side for decoding STUN and RTP/RTCP traffic.
--		- This Wireshark plugin dissects STUN/TURN traffic on Microsoft Lync Edge port 3478 (STUN, RTCP, RTP)
--		- This Wireshark plugin dissects traffic on Microsoft Lync Edge port 443 (STUN, RTCP, RTP)
--		- This Wireshark plugin dissects dynamically assigned RTP and RTCP traffic by using ports allocated in STUN requests.
--		- Dissector can be turned on/off within Wireshark Preferences. (Edit->Preferences->Protocols->LYNC_SKYPE_PLUGIN)
--		- Port numbers can be changed within Wireshark Preferences. (Edit->Preferences->Protocols->LYNC_SKYPE_PLUGIN)
--		- If you enter “lync_skype_plugin” in the Filter bar, only the traffic that is being decoded by the Lync Plugin will be displayed.
--		- To be used with the latest release of Wireshark
--
-- 2.00 Wireshark 2.0 update
--		- Some updates to work with Wireshark 2.0+ (Thank you to Vladimir Vysotsky for feedback)
--		- Changed the naming of the plugin to LYNC_SKYPE_PLUGIN.
--		- Big updates to RTP and STUN classification to fix detection issues.
--		- Added TLS pass-through to the Wireshark default SSL dissector for Hello, Handshaking, and Application data. So now you can have the plugin running all the time and still troubleshoot TLS handshaking issues on port 443. This also makes the plugin better for client side testing.
-- 		- Corrected some issues with decoding 0x0013 Data Attribute encapsulated data.
--		- The decoding of port 443 can have false positive matches for different packet types. The amount of false positive in this version of the plugin has been greatly decreased.
--		- Widened the scope of RTP port classification from 1024-59999 (which was limited for Edge use) to 1024-65535. This makes the plugin work better when testing client side connections. 
--		- And more!
--
-------------------------------------------------------------------------------------------------------------------------

do
	local lync_wrapper_proto = Proto("lync_skype_plugin", "Microsoft Lync Skype Plugin");
	
	--PREFERENCES
	local prefs = lync_wrapper_proto.prefs
	prefs.port3478 = Pref.bool( "Decode UDP Port (Default 3478)", true, "Decode UDP Port (Default 3478)" )
	prefs.port443 = Pref.bool( "Decode Internal TCP Port (Default 443)", true, "Decode Internal TCP Port (Default 443)")
	prefs.portexternal443 = Pref.bool( "Decode External AV TCP Port (Default 443)", true, "Decode External AV TCP Port (Default 443)")
	prefs.port50000 = Pref.bool( "Decode 1024-65535 Dynamic Ports", true, "Decode 1024-65535 Dynamic Ports")
	prefs.udpprotocolport = Pref.uint( "UDP Port (default 3478)", 3478)
	prefs.tcpprotocolport = Pref.uint( "TCP Internal Port (default 443)", 443)
	prefs.tcpexternalprotocolport = Pref.uint( "TCP External AV Port (default 443)", 443)
	prefs.showorginal = Pref.bool( "Show orginal wireshark dissection tree", false, "Show orginal wireshark dissection tree")
	
	-- FIELDS	
	local F_stuntype = ProtoField.string("lync_wrapper_proto.stuntype","Type")
	local F_stunname = ProtoField.string("lync_wrapper_proto.stunname","Name")
	local F_attribute = ProtoField.string("lync_wrapper_proto.attribute","Attribute")
	local F_attribute_sub = ProtoField.string("lync_wrapper_proto.attribute.attribute_sub","AttributeType")
	local f_tcp_srcport = Field.new("tcp.srcport")
    local f_tcp_dstport = Field.new("tcp.dstport")
	local f_udp_srcport = Field.new("udp.srcport")
    local f_udp_dstport = Field.new("udp.dstport")
	

	-- ADD THE FIELDS TO THE PROTOCOL
	lync_wrapper_proto.fields = {F_stuntype, F_stunname, F_attribute, F_attribute_sub}   
    
	-- DECLARE THE FIELDS WE NEED TO READ
    local original_stun_dissector
	
	-- GET THE ORIGINAL SSL DISSECTOR
	local tcp_dissector_table = DissectorTable.get("tcp.port")
	original_ssl_dissector = tcp_dissector_table:get_dissector(443) 
        
	function lync_wrapper_proto.dissector(tvbuffer, pinfo, treeitem)
        
		if tvbuffer:len() > 1 then
		
		-- THIS WILL INCLUDE THE ORIGINAL WIRESHARK DISSECTION TREE IN ADDITION TO THE LYNC EDGE DISSECTOR TREE
		if prefs.showorginal then
			original_stun_dissector:call(tvbuffer, pinfo, treeitem)
		end

		-- CREATE NEW TREE PANE FOR MSSTUN PROTOCOL
		local subtreeitem = treeitem:add(lync_wrapper_proto, tvbuffer)
		
		-- IF THIS IS A TCP PACKET THEN OFFSET THE FRAMING
		tcpOffset = 0
		
		-- MAGIC COOKIE 0x2112A442
		-- TCP FRAMING CHECK STUN
		frameCheck = tvbuffer(0,1):uint()
		if tvbuffer:len() >= 12 then
			magiccookie = tvbuffer:range(8,4):uint()
		else
			magiccookie =  0
		end
		
		stunDataindIcationCheck = tvbuffer:range(4,2):uint()
		
		if frameCheck == 0x02 and magiccookie == 0x2112a442 or stunDataindIcationCheck == 0x0115 then  -- MAGIC COOKIE CHECK
			if f_tcp_srcport() ~= nil and f_tcp_dstport() ~= nil then -- CHECK IF TCP
						tcpOffset = 4
						subtreeitem:add(F_stunname, tvbuffer(0,4), cmd_str)
							:set_text("TCP Framing Bytes - Turn Control Message (4 Bytes)")
			end
		end
		
		-- TCP FRAMING CHECK FOR END-TO-END DATA
		if frameCheck == 0x03 then
			if f_tcp_srcport() ~= nil and f_tcp_dstport() ~= nil then
				packetlength = tvbuffer:len()
				length = tvbuffer(2,2):uint()
				-- CHECK LENGTH
				if (length + 4) == packetlength then
				
					tcpOffset = 6
					
					subtreeitem:add(F_stunname, tvbuffer(0,6), cmd_str)
						:set_text("TCP Framing Bytes - End-to-End Data Message (6 Bytes)")
						
					--Set the Protcol and Info Columns
					pinfo.cols.protocol = "MSSTUN"
					pinfo.cols.info = "STUN END-TO-END DATA (Content Sharing)"	
					
					
					attribute_bytes = tostring(tvbuffer:range(0,1)):upper()
					attributeTree = subtreeitem:add(F_stunname, tvbuffer(0,1), attribute_bytes)
					   attributeTree:set_text("Type: " .. "(0x" .. attribute_bytes .. ")")
					
					attribute_bytes = tostring(tvbuffer:range(1,1)):upper()
					attributeTree = subtreeitem:add(F_stunname, tvbuffer(1,1), attribute_bytes)
					   attributeTree:set_text("Reserved: " .. "(0x" .. attribute_bytes .. ")")
					 
					attribute_bytes = tostring(tvbuffer:range(2,2)):upper()
					attributeTree = subtreeitem:add(F_stunname, tvbuffer(2,2), attribute_bytes)
					   attributeTree:set_text("Payload Length: " .. "(0x" .. attribute_bytes .. ")")
					
					attribute_bytes = tostring(tvbuffer:range(4,2)):upper()
					attributeTree = subtreeitem:add(F_stunname, tvbuffer(4,2), attribute_bytes)
					   attributeTree:set_text("RTP Length: " .. "(0x" .. attribute_bytes .. ")")
					   
										
					attributeTree = subtreeitem:add(F_attribute_sub, tvbuffer(6,tvbuffer:len()-6), cmd_str)
						attributeTree:set_text("End-to-End Data: " .. tostring(tvbuffer(6,tvbuffer:len()-6)))
					
				end
			end
		end

		
		-- TCP FRAMING RTP/RTCP
		--RFC 4571 Section 2	
		--	0                   1                   2                   3
		--0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		-----------------------------------------------------------------
		--|             LENGTH            |  RTP or RTCP packet ...       |
		-----------------------------------------------------------------
		
		frameCheck2 = tvbuffer(0,2):uint()
		totalPacketLength = tvbuffer:len()
		framesize = totalPacketLength - 2
		magiccookie = tvbuffer:range(4+tcpOffset,4)
		if f_tcp_srcport() ~= nil and f_tcp_dstport() ~= nil then -- CHECK IF IT'S TCP TRAFFIC
			if frameCheck2 ~= 0x1603 and frameCheck2 ~= 0x1703 then  -- CHECK THAT IT'S NOT TLS TRAFFIC
				if magiccookie ~= 0x2112a442 then -- CHECK THAT IT'S NOT A STUN PACKET
					if frameCheck2 == framesize then -- 2.0 CHECK - THE FRAMING BITS SHOULD EQUAL THE LENGTH OF THE PACKET
								tcpOffset = 2
								subtreeitem:add(F_stunname, tvbuffer(0,2), cmd_str)
									:set_text("TCP Framing Bytes (2 Byte)")
					end
				end
			end
		end
		
		
		-- GET THE ATTRIBUTE
		attribute = tvbuffer(tcpOffset,2):uint()
			
		-- CHECK IF IT'S A MICROSOFT STUN ATTRIBUTE
		standard_attribute = tvbuffer(tcpOffset,1):uint()
		
		if tvbuffer:len() >= 8 then
			magiccookie = tvbuffer:range(4+tcpOffset,4):uint() -- MAGIC COOKIE
		else
			magiccookie =  0
		end
		
		--MAGICCOOKIE == 0x2112A442
		if attribute ~= 0x0300 and magiccookie == 0x2112a442 or attribute == 0x0115 then
		
			-- CHECK for MS STUN!	
			if standard_attribute == 0x00 or standard_attribute == 0x01 then
					
				cmd = tvbuffer(tcpOffset,2):uint()
							   
				cmd_str = "unknown 0x00 0x01 (Possible incorrect packet classification)"
				
				if cmd == 0x0001 then
						cmd_str = "STUN BINDING REQUEST"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0101 then
						cmd_str = "STUN BINDING RESPONSE"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0111 then
						cmd_str = "STUN BINDING ERROR RESPONSE"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0011 then
						cmd_str = "STUN BINDING INDICATION"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0002 then
						cmd_str = "STUN SHARED SECRET REQUEST - NOT SUPPORTED"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0102 then
						cmd_str = "STUN SHARED SECRET RESPONSE - NOT SUPPORTED"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0112 then
						cmd_str = "STUN SHARED SECRET ERROR RESPONSE - NOT SUPPORTED"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0003 then
						cmd_str = "STUN ALLOCATE REQUEST"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0103 then
						cmd_str = "STUN ALLOCATE RESPONSE"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0113 then
						cmd_str = "STUN ALLOCATE ERROR RESPONSE"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0004 then
						cmd_str = "STUN SEND REQUEST"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0104 then
						cmd_str = "STUN REFRESH RESPONSE - NOT SUPPORTED"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0114 then
						cmd_str = "STUN REFRESH ERROR RESPONSE - NOT SUPPORTED"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0115 then
						cmd_str = "STUN DATA INDICATION"	
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0006 then
						cmd_str = "STUN SET ACTIVE DESTINATION REQUEST"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0016 then
						cmd_str = "STUN SEND INDICATION"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0106 then
						cmd_str = "STUN SET ACTIVE DESTINATION RESPONSE"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0116 then
						cmd_str = "STUN SET ACTIVE DESTINATION ERROR RESPONSE"	
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0017 then
						cmd_str = "STUN DATA INDICATION"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0008 then
						cmd_str = "STUN CREATE PERM REQUEST"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0108 then
						cmd_str = "STUN CREATE PERM RESPONSE"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0118 then
						cmd_str = "STUN CREATE_PERM ERROR RESPONSE"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0009 then
						cmd_str = "STUN CHANNEL BIND REQUEST"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0109 then
						cmd_str = "STUN CHANNEL BIND RESPONSE"
						pinfo.cols.protocol = "MSSTUN"
					elseif cmd == 0x0119 then
						cmd_str = "STUN CHANNEL BIND ERROR RESPONSE"
						pinfo.cols.protocol = "MSSTUN"
					else
						-- NO MATCH
						cmd_str = ""
						--IF IT'S ON PORT 443 THEN ASSUME THEN TRY THE TLS DECODER
						if f_tcp_srcport() ~= nil and f_tcp_dstport() ~= nil then
							if f_tcp_srcport().value == 443 or f_tcp_dstport().value == 443 then
							original_ssl_dissector:call(tvbuffer, pinfo, treeitem)   --DECODE AS TLS
							end
						end
				end
				
				--cmd_str = cmd_str .. " attribute = " .. tostring(attribute):upper() .. " standard_attribute = " .. tostring(standard_attribute):upper() .. " Magic Cookie = " .. tostring(magiccookie):upper()
				
				
				field1_val = tostring(bit.tohex(tvbuffer(tcpOffset,2):uint(),4)):upper()
				subtreeitem:add(F_stunname, tvbuffer(tcpOffset,2), cmd_str)
						   :set_text("Command String: " .. cmd_str .. " (0x" .. field1_val .. ")")
				
				
				attribute_length = string.format("%i", tvbuffer(2+tcpOffset,2):uint())
				subtreeitem:add(F_stunname, tvbuffer(2+tcpOffset,2), attribute_length)
							:set_text("Attribute Length: " .. attribute_length .. " Bytes")
				
				field1_val = tostring(tvbuffer:range(4+tcpOffset,4)):upper()
				subtreeitem:add(F_stunname, tvbuffer(4+tcpOffset,4), cmd_str)
						   :set_text("Magic Cookie: " .. "0x" .. field1_val)
						   

				field1_val = tostring(tvbuffer:range(8+tcpOffset,12)):upper()
				subtreeitem:add(F_stunname, tvbuffer(8+tcpOffset,12), cmd_str)
						   :set_text("Transaction ID: 0x" .. field1_val)
						   
				--SET THE PROTCOL AND INFO COLUMNS
				pinfo.cols.info = cmd_str
				
				offset = 20 + tcpOffset
				relativePosition = 0
				
				-- START READING ATTRIBUTES - LOOK FOR MICROSOFT EXTENSIONS
				while true do
					
					-- POSITION IN PACKET
					local absolutePosition = offset + relativePosition
					
					-- GET THE ATTRIBUTE
					local attribute = tvbuffer(absolutePosition,2):uint()
					
					-- CHECK IF IT'S A MICROSOFT ATTRIBUTE
					local ms_attribute = tvbuffer(absolutePosition,1):uint()

					-- GET THE LENGTH OF THE ATTRIBUTE
					local lengthOfCommand = tvbuffer(absolutePosition+2,2):uint()
					
					-- CALCULATE THE FINAL POSITION
					local finalPosition = absolutePosition + lengthOfCommand + 4
				
					
					--NON MICROSOFT SPECIFIC ATTRIBUTES
					if ms_attribute == 0x00 then
					-- DEFINED IN IETFDRAFT-STUN-02
						if attribute == 0x0001 then
								att_str = "Mapped Address"
							elseif attribute == 0x0006 then
								att_str = "Username"
							elseif attribute == 0x0008 then
								att_str = "Message Integrity"
							elseif attribute == 0x0009 then
								att_str = "Error Code"
							elseif attribute == 0x000A then
								att_str = "Unknown Attributes"
							elseif attribute == 0x000D then
								att_str = "Lifetime"
							elseif attribute == 0x000E then
								att_str = "Alternate Server"
							elseif attribute == 0x000F then
								att_str = "Magic Cookie"
							elseif attribute == 0x0010 then
								att_str = "Bandwidth"
							elseif attribute == 0x0011 then
								att_str = "Destination Address"	
							elseif attribute == 0x0012 then
								att_str = "Remote Address"	
							elseif attribute == 0x0013 then
								att_str = "Data"	
							elseif attribute == 0x0014 then
								att_str = "Nonce"	
							elseif attribute == 0x0015 then
								att_str = "Realm"	
							elseif attribute == 0x0017 then
								att_str = "Requested Address Family"
							elseif attribute == 0x0020 then
								att_str = "XOR Mapped Address"
							elseif attribute == 0x0024 then
								att_str = "Priority (RFC5245)"
							elseif attribute == 0x0025 then
								att_str = "Use-Candidate (RFC5245)"						
						
						end
						
				
						attribute_val = tostring(bit.tohex(tvbuffer(absolutePosition,2):uint(),4)):upper()
						attributeTree = subtreeitem:add(F_attribute, tvbuffer(absolutePosition,lengthOfCommand+4), attribute_val)
						attributeTree:set_text("Attribute: 0x" .. attribute_val .. " (" .. att_str .. ")")
					
						attribute_length = string.format("%i", tvbuffer(absolutePosition+2,2):uint())
						attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+2,2), attribute_length)
								:set_text("Attribute Length: " .. attribute_length .. " Bytes")
						
						
						
						-- Defined in IETFDRAFT-STUN-02
						if attribute == 0x0001 then
							--att_str = "Mapped Address"
						
							attribute_bytes = tostring(bit.tohex(tvbuffer(absolutePosition+4,1):uint(),1)):upper()
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
									:set_text("Reserved " .. attribute_bytes) 
						
							fam_type = tvbuffer(absolutePosition+5,1):uint()
						
							if fam_type == 0x01 then
								att_str = "IPv4"
								att_bytes = "0x01"
							elseif fam_type == 0x02 then
								att_str = "IPv6"
								att_bytes = "0x02"
							end										
						
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+5,1), attribute_length)
									:set_text("Family: " .. att_str .. " (" .. att_bytes .. ")")
						
														
								port = tvbuffer(absolutePosition+6,2):uint()
								
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+6,2):uint())
								portstring = string.format("%i", port)
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+6,2), attribute_length)
										:set_text("Port: " ..  portstring .. " " .. attribute_bytes) 
								
								
								if fam_type == 0x01 then
								
								oct1 = tvbuffer(absolutePosition+8,1):uint()
								oct2 = tvbuffer(absolutePosition+9,1):uint()
								oct3 = tvbuffer(absolutePosition+10,1):uint()
								oct4 = tvbuffer(absolutePosition+11,1):uint()
								
								ip1string = string.format("%i", oct1)
								ip2string = string.format("%i", oct2)
								ip3string = string.format("%i", oct3)
								ip4string = string.format("%i", oct4)
													
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+8,4):uint())
								
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,4), attribute_length)
										:set_text("Address-IPv4: " .. ip1string .. "." .. ip2string .. "." .. ip3string .. "." .. ip4string .. " " .. attribute_bytes) 		
								
							elseif fam_type == 0x02 then
							-- Not decoding IPv6 fully yet. Need some capture data to test against.
							attribute_bytes = tostring(tvbuffer:range(absolutePosition+8,16))
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,16), attribute_length)
									:set_text("Address_IPv6: 0x" .. attribute_bytes)
							end
							
							
						elseif attribute == 0x0006 then
							--att_str = "Username"
							
							attribute_bytes = tostring(tvbuffer:range(absolutePosition+4,lengthOfCommand-4))
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,lengthOfCommand), attribute_length)
									:set_text("Username (<prefix,rounded-time,clientIP,hmac>): 0x" .. attribute_bytes)
							
						elseif attribute == 0x0008 then
							--att_str = "Message Integrity"
							
							attribute_bytes = tostring(tvbuffer:range(absolutePosition+4,lengthOfCommand-4))
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,lengthOfCommand), attribute_length)
									:set_text("HMAC HASH: 0x" .. attribute_bytes)
							
						elseif attribute == 0x0009 then
							--att_str = "Error Code"
							
							--	 0                   1                   2                   3
							--   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
							--   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
							--   |                   0                     |Class|     Number    |
							--   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
							--   |      Reason Phrase (variable)                                ..
							--   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
							
							
							local bits = tvbuffer(absolutePosition+4,3):uint()
							
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,3), attribute_length)
										:set_text("Reserved Bytes: 0x" .. tostring(bit.tohex((bit.band(bits,0xFFFFF0)),6)))
							
							local bits2 = tvbuffer(absolutePosition+6,1):uint()
							local bits3 = tvbuffer(absolutePosition+7,1):uint()
												
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+6,2), attribute_length)
										:set_text("Error Code: " .. string.format("%01d", (bit.band(bits2,0x0F))) ..  string.format("%02d", (bit.band(bits3,0xFF))))
							
												
							-- Convert to ASCII
							local asc = ""
							for i = absolutePosition+8, absolutePosition+8+lengthOfCommand-4 do
								local c = tvbuffer(i,1):uint()
								asc = string.format("%s%c", asc, c)
							end
				
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,lengthOfCommand-4), attribute_length)
									:set_text("Error: " .. asc)			
							
							
						
						elseif attribute == 0x000A then
							--att_str = "Unknown Attributes"
							
							attribute_bytes = tostring(bit.tohex(tvbuffer(absolutePosition+4,2):uint(),4))
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+2,2), attribute_length)
								:set_text("Attribute 1 Type: 0x" .. attribute_bytes)

							attribute_bytes = tostring(bit.tohex(tvbuffer(absolutePosition+6,2):uint(),4))
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+2,2), attribute_length)
								:set_text("Attribute 2 Type: 0x" .. attribute_bytes)
								
						elseif attribute == 0x000D then
							--att_str = "Lifetime"
							
							attribute_bytes = string.format("%i", tvbuffer(absolutePosition+4,4):uint())
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,4), attribute_length)
								:set_text("Lifetime: " .. attribute_bytes .. " Seconds")
						
						elseif attribute == 0x000E then
							--att_str = "Alternate Server"
							
							attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+4,1):uint())
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
									:set_text("Reserved " .. attribute_bytes) 
						
							fam_type = tvbuffer(absolutePosition+5,1):uint()
						
							if fam_type == 0x01 then
								att_str = "IPv4"
								att_bytes = "0x01"
							elseif fam_type == 0x02 then
								att_str = "IPv6"
								att_bytes = "0x02"
							end										
						
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+5,1), attribute_length)
									:set_text("Family: " .. att_str .. " (" .. att_bytes .. ")")
						
														
								port = tvbuffer(absolutePosition+6,2):uint()
								
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+6,2):uint())
								portstring = string.format("%i", port)
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+6,2), attribute_length)
										:set_text("Port: " ..  portstring .. " " .. attribute_bytes) 
							
							
								if fam_type == 0x01 then
								
								oct1 = tvbuffer(absolutePosition+8,1):uint()
								oct2 = tvbuffer(absolutePosition+9,1):uint()
								oct3 = tvbuffer(absolutePosition+10,1):uint()
								oct4 = tvbuffer(absolutePosition+11,1):uint()
								
								ip1string = string.format("%i", oct1)
								ip2string = string.format("%i", oct2)
								ip3string = string.format("%i", oct3)
								ip4string = string.format("%i", oct4)
													
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+8,4):uint())
								
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,4), attribute_length)
										:set_text("Address-IPv4: " .. ip1string .. "." .. ip2string .. "." .. ip3string .. "." .. ip4string .. " " .. attribute_bytes) 		
								
							elseif fam_type == 0x02 then
							-- Not decoding IPv6 fully yet.
							attribute_bytes = tostring(tvbuffer:range(absolutePosition+8,16))
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,16), attribute_length)
									:set_text("Address_IPv6: 0x" .. attribute_bytes)
							end
							
						elseif attribute == 0x000F then
							--att_str = "Magic Cookie"
							
							attribute_bytes = tostring(bit.tohex(tvbuffer(absolutePosition+4,4):uint(),8)):upper()
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,4), attribute_length)
								:set_text("Magic Cookie: 0x" .. attribute_bytes)
							
						elseif attribute == 0x0010 then
							--att_str = "Bandwidth"
							
							attribute_bytes = string.format("%i", tvbuffer(absolutePosition+4,4):uint())
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,4), attribute_length)
									:set_text("Bandwidth (peak): " .. attribute_bytes .. " kbps") 
								
							
						elseif attribute == 0x0011 then
							--att_str = "Desitination Address"

							attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+4,1):uint())
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
									:set_text("Reserved " .. attribute_bytes) 
						
							fam_type = tvbuffer(absolutePosition+5,1):uint()
						
							if fam_type == 0x01 then
								att_str = "IPv4"
								att_bytes = "0x01"
							elseif fam_type == 0x02 then
								att_str = "IPv6"
								att_bytes = "0x02"
							end										
						
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+5,1), attribute_length)
									:set_text("Family: " .. att_str .. " (" .. att_bytes .. ")")
						
														
								port = tvbuffer(absolutePosition+6,2):uint()
								
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+6,2):uint())
								portstring = string.format("%i", port)
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+6,2), attribute_length)
										:set_text("Port: " ..  portstring .. " " .. attribute_bytes) 
								
								
								-----------------------------------------------			
								-- Decode the 1024-65535 range ports from STUN
								-----------------------------------------------
								if prefs.port50000 then
									if port >= 1024 and port <= 65535 then
										myproto_udp_init(port) 
										myproto_tcp_init(port)
										--RTCP
										myproto_udp_init(port+1) --RTCP Port
										myproto_tcp_init(port+1) --RTCP Port								
										attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+6,2), attribute_length)
											:set_text("(INFO: Added " ..  portstring .. " to decode.)") 
									else
										attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+6,2), attribute_length)
											:set_text("(INFO: Not in 1024-65535 range. Not Added " ..  portstring .. " to decode.)")
									end
								else
									attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+6,2), attribute_length)
										:set_text("(INFO: Removed " ..  portstring .. " from decode.)")
									myproto_udp_remove_init(port)
									myproto_tcp_remove_init(port)
									myproto_udp_remove_init(port+1) -- RTCP Port
									myproto_tcp_remove_init(port+1) -- RTCP Port
								
								end
								
								
								if fam_type == 0x01 then
								
								oct1 = tvbuffer(absolutePosition+8,1):uint()
								oct2 = tvbuffer(absolutePosition+9,1):uint()
								oct3 = tvbuffer(absolutePosition+10,1):uint()
								oct4 = tvbuffer(absolutePosition+11,1):uint()
								
								ip1string = string.format("%i", oct1)
								ip2string = string.format("%i", oct2)
								ip3string = string.format("%i", oct3)
								ip4string = string.format("%i", oct4)
													
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+8,4):uint())
								
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,4), attribute_length)
										:set_text("Address-IPv4: " .. ip1string .. "." .. ip2string .. "." .. ip3string .. "." .. ip4string .. " " .. attribute_bytes) 		
								
							elseif fam_type == 0x02 then
							-- Not decoding IPv6 fully yet.
							attribute_bytes = tostring(tvbuffer:range(absolutePosition+8,16))
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,16), attribute_length)
									:set_text("Address_IPv6: 0x" .. attribute_bytes)
							end
							
						elseif attribute == 0x0012 then
							--att_str = "Remote Address"

							attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+4,1):uint())
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
									:set_text("Reserved " .. attribute_bytes) 
						
							fam_type = tvbuffer(absolutePosition+5,1):uint()
						
							if fam_type == 0x01 then
								att_str = "IPv4"
								att_bytes = "0x01"
							elseif fam_type == 0x02 then
								att_str = "IPv6"
								att_bytes = "0x02"
							end										
						
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+5,1), attribute_length)
									:set_text("Family: " .. att_str .. " (" .. att_bytes .. ")")
						
														
								port = tvbuffer(absolutePosition+6,2):uint()
								
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+6,2):uint())
								portstring = string.format("%i", port)
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+6,2), attribute_length)
										:set_text("Port: " ..  portstring .. " " .. attribute_bytes) 
								
								
								if fam_type == 0x01 then
								
								oct1 = tvbuffer(absolutePosition+8,1):uint()
								oct2 = tvbuffer(absolutePosition+9,1):uint()
								oct3 = tvbuffer(absolutePosition+10,1):uint()
								oct4 = tvbuffer(absolutePosition+11,1):uint()
								
								ip1string = string.format("%i", oct1)
								ip2string = string.format("%i", oct2)
								ip3string = string.format("%i", oct3)
								ip4string = string.format("%i", oct4)
													
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+8,4):uint())
								
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,4), attribute_length)
										:set_text("Address-IPv4: " .. ip1string .. "." .. ip2string .. "." .. ip3string .. "." .. ip4string .. " " .. attribute_bytes) 		
								
							elseif fam_type == 0x02 then
							-- Not decoding IPv6 fully yet.
							attribute_bytes = tostring(tvbuffer:range(absolutePosition+8,16))
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,16), attribute_length)
									:set_text("Address_IPv6: 0x" .. attribute_bytes) 
							end
							
						elseif attribute == 0x0013 then
							--att_str = "Data"

							attribute_bytes = tostring(tvbuffer:range(absolutePosition+4,lengthOfCommand))
							dataTree = attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,lengthOfCommand), attribute_length)
									dataTree:set_text("Data: " .. attribute_bytes)
								
								rtpTcpOffset = 0
								-- If it's TCP then apply 2 bytes of framing
								if f_tcp_srcport() ~= nil and f_tcp_dstport() ~= nil then
									if f_tcp_srcport().value or f_tcp_dstport().value then
										rtpTcpOffset = 2
										dataTree:add(F_stunname, tvbuffer(absolutePosition+4,2), cmd_str)
										:set_text("TCP Framing Bytes (2 Byte)")
									end
								end

								
								local datatype = tvbuffer(absolutePosition+4+rtpTcpOffset,1):uint()
								
														
								-- STUN CHECK
								stuncmdbyte = tvbuffer(absolutePosition+4+rtpTcpOffset,1):uint()
								stuncmd = tvbuffer(absolutePosition+4+rtpTcpOffset,2):uint()
								
								-- Check if encapsulated data is a STUN message
								if stuncmdbyte == 0x00 or stuncmdbyte == 0x01 then
									
									stuncmd_str = "unknown (Possible incorrect packet classification)"
									
									if stuncmd == 0x0001 then
											stuncmd_str = "STUN BINDING REQUEST"
										elseif stuncmd == 0x0101 then
											stuncmd_str = "STUN BINDING RESPONSE"
										elseif stuncmd == 0x0111 then
											stuncmd_str = "STUN BINDING ERROR RESPONSE"
										elseif stuncmd == 0x0011 then
											stuncmd_str = "STUN BINDING INDICATION"
										elseif stuncmd == 0x0002 then
											stuncmd_str = "STUN SHARED SECRET REQUEST - NOT SUPPORTED"
										elseif stuncmd == 0x0102 then
											stuncmd_str = "STUN SHARED SECRET RESPONSE - NOT SUPPORTED"
										elseif stuncmd == 0x0112 then
											stuncmd_str = "STUN SHARED SECRET ERROR RESPONSE - NOT SUPPORTED"
										elseif stuncmd == 0x0003 then
											stuncmd_str = "STUN ALLOCATE REQUEST"
										elseif stuncmd == 0x0103 then
											stuncmd_str = "STUN ALLOCATE RESPONSE"
										elseif stuncmd == 0x0113 then
											stuncmd_str = "STUN ALLOCATE ERROR RESPONSE"
										elseif stuncmd == 0x0004 then
											stuncmd_str = "STUN SEND REQUEST"
										elseif stuncmd == 0x0104 then
											stuncmd_str = "STUN REFRESH RESPONSE - NOT SUPPORTED"
										elseif stuncmd == 0x0114 then
											stuncmd_str = "STUN REFRESH ERROR RESPONSE - NOT SUPPORTED"
										elseif stuncmd == 0x0115 then
											stuncmd_str = "STUN DATA INDICATION"	
										elseif stuncmd == 0x0006 then
											stuncmd_str = "STUN SET ACTIVE DESTINATION REQUEST"
										elseif stuncmd == 0x0016 then
											stuncmd_str = "STUN SEND INDICATION"
										elseif stuncmd == 0x0106 then
											stuncmd_str = "STUN SET ACTIVE DESTINATION RESPONSE"
										elseif stuncmd == 0x0116 then
											stuncmd_str = "STUN SET ACTIVE DESTINATION ERROR RESPONSE"	
										elseif stuncmd == 0x0017 then
											stuncmd_str = "STUN DATA INDICATION"
										elseif stuncmd == 0x0008 then
											stuncmd_str = "STUN CREATE PERM REQUEST"
										elseif stuncmd == 0x0108 then
											stuncmd_str = "STUN CREATE PERM RESPONSE"
										elseif stuncmd == 0x0118 then
											stuncmd_str = "STUN CREATE_PERM ERROR RESPONSE"
										elseif stuncmd == 0x0009 then
											stuncmd_str = "STUN CHANNEL BIND REQUEST"
										elseif stuncmd == 0x0109 then
											stuncmd_str = "STUN CHANNEL BIND RESPONSE"
										elseif stuncmd == 0x0119 then
											stuncmd_str = "STUN CHANNEL BIND ERROR RESPONSE"
									end
									
									attribute_bytes = tostring(tvbuffer:range(absolutePosition+4+rtpTcpOffset,2)):upper()
									dataTree:add(F_stunname, tvbuffer(absolutePosition+4+rtpTcpOffset,2), attribute_bytes)
										   :set_text("STUN Message: " .. "Command String: " .. stuncmd_str .. " (0x" .. attribute_bytes .. ")")
									
									attribute_length_int = tvbuffer(absolutePosition+6+rtpTcpOffset,2):uint()
									attribute_length = string.format("%i", tvbuffer(absolutePosition+6+rtpTcpOffset,2):uint())
									dataTree:add(F_stunname, tvbuffer(absolutePosition+6+rtpTcpOffset,2), attribute_length)
												:set_text("Attribute Length: " .. attribute_length .. " Bytes")
									
									field1_val = tostring(tvbuffer:range(absolutePosition+8+rtpTcpOffset,4)):upper()
									dataTree:add(F_stunname, tvbuffer(absolutePosition+8+rtpTcpOffset,4), cmd_str)
											   :set_text("Magic Cookie: " .. "0x" .. field1_val)
									
									field1_val = tostring(tvbuffer:range(absolutePosition+12+rtpTcpOffset,12)):upper()
									dataTree:add(F_stunname, tvbuffer(absolutePosition+12+rtpTcpOffset,12), cmd_str)
											   :set_text("Transaction ID: 0x" .. field1_val)

									
									--Set the Protcol and Info Columns
									pinfo.cols.info = cmd_str .. " : Encapsulated Data = " .. stuncmd_str		
											
									
									--Limited decoding of the rest of the encapsulated STUN request...
									offset2 = absolutePosition + 24 + rtpTcpOffset
									relativePosition2 = 0
									-- Start reading Attributes - look for microsoft extensions
									
									
									-- Attribute Loop
									while true do
										
										-- position in packet
										local absolutePosition2 = offset2 + relativePosition2
										
										-- Get the attribute
										local attribute2 = tvbuffer(absolutePosition2,2):uint()
										
										-- Check if it's a microsoft attribute
										local ms_attribute2 = tvbuffer(absolutePosition2,1):uint()

										-- Get the Length of the attribute
										local lengthOfCommand2 = tvbuffer(absolutePosition2+2,2):uint()
										
										-- Calculate the final position
										local finalPosition2 = absolutePosition2 + lengthOfCommand2 + 4
									
										
										
											--Non Microsoft Specific Attributes
											-- Defined in IETFDRAFT-STUN-02
											if attribute2 == 0x0001 then
													att_str2 = "Mapped Address"
												elseif attribute2 == 0x0006 then
													att_str2 = "Username"
												elseif attribute2 == 0x0008 then
													att_str2 = "Message Integrity"
												elseif attribute2 == 0x0009 then
													att_str2 = "Error Code"
												elseif attribute2 == 0x000A then
													att_str2 = "Unknown Attributes"
												elseif attribute2 == 0x000D then
													att_str2 = "Lifetime"
												elseif attribute2 == 0x000E then
													att_str2 = "Alternate Server"
												elseif attribute2 == 0x000F then
													att_str2 = "Magic Cookie"
												elseif attribute2 == 0x0010 then
													att_str2 = "Bandwidth"
												elseif attribute2 == 0x0011 then
													att_str2 = "Destination Address"	
												elseif attribute2 == 0x0012 then
													att_str2 = "Remote Address"	
												elseif attribute2 == 0x0013 then
													att_str2 = "Data"	
												elseif attribute2 == 0x0014 then
													att_str2 = "Nonce"	
												elseif attribute2 == 0x0015 then
													att_str2 = "Realm"	
												elseif attribute2 == 0x0017 then
													att_str2 = "Requested Address Family"
												elseif attribute2 == 0x0020 then
													att_str2 = "XOR Mapped Address"
												elseif attribute2 == 0x0024 then
													att_str2 = "Priority (RFC5245)"
												elseif attribute2 == 0x0025 then
													att_str2 = "Use-Candidate (RFC5245)"						
												-- Microsoft Specific Attributes for STUN
												elseif attribute2 == 0x8008 then
													att_str2 = "MS-Version"
												elseif attribute2 == 0x8006 then
													att_str2 = "MS-Attribute"
												elseif attribute2 == 0x8020 then
													att_str2 = "XOR Mapped Address"
												elseif attribute2 == 0x8022 then
													att_str2 = "Software (RFC5389)"
												elseif attribute2 == 0x8023 then
													att_str2 = "Alternate-Server (RFC5389)"
												elseif attribute2 == 0x8028 then
													att_str2 = "Fingerprint (RFC5389)"
												elseif attribute2 == 0x8029 then
													att_str2 = "Ice Controlled (ICE-19)"
												elseif attribute2 == 0x802A then
													att_str2 = "Ice Controlling (ICE-19)"	
												elseif attribute2 == 0x8050 then
													att_str2 = "MS-Sequence Number"
												elseif attribute2 == 0x8054 then
													att_str2 = "Candidate Identifier"
												elseif attribute2 == 0x8055 then
													att_str2 = "MS-Service Quality"
												elseif attribute2 == 0x8056 then
													att_str2 = "Bandwidth Admission Control Message"
												elseif attribute2 == 0x8057 then
													att_str2 = "Bandwidth Reservation Identifier"
												elseif attribute2 == 0x8058 then
													att_str2 = "Bandwidth Reservation Amount"
												elseif attribute2 == 0x8059 then
													att_str = "Remote Site Address"	
												elseif attribute2 == 0x805A then
													att_str2 = "Remote Relay Site Address"	
												elseif attribute2 == 0x805B then
													att_str2 = "Local Site Address"	
												elseif attribute2 == 0x805C then
													att_str2 = "Local Relay Site Address"	
												elseif attribute2 == 0x805D then
													att_str2 = "Remote Site Address Response"	
												elseif attribute2 == 0x805E then
													att_str2 = "Remote Relay Site Address Response"	
												elseif attribute2 == 0x805F then
													att_str2 = "Local Site Address Response"	
												elseif attribute2 == 0x8060 then
													att_str2 = "Local Relay Site Address Response"	
												elseif attribute2 == 0x8061 then
													att_str2 = "SIP Dialog Identifier"	
												elseif attribute2 == 0x8062 then
													att_str2 = "SIP Call Identifier"	
												elseif attribute2 == 0x8068 then
													att_str2 = "Location Profile"
												elseif attribute2 == 0x8070 then
													att_str2 = "Implementation Version"									
												elseif attribute2 == 0x8090 then
													att_str2 = "MS-Alternate Mapped Address"
												else
													att_str2 = "Error: No Match (Possible incorrect packet classification)"
											
											end
											
										attribute_val2 = tostring(bit.tohex(tvbuffer(absolutePosition2,2):uint(),4)):upper()
										attributeTree2 = dataTree:add(F_attribute, tvbuffer(absolutePosition2,lengthOfCommand2+4), attribute_val2)
										attributeTree2:set_text("Data Attribute: 0x" .. attribute_val2 .. " (" .. att_str2 .. ")")
									
										attribute_length2Int = tvbuffer(absolutePosition2+2,2):uint()
										attribute_length2 = string.format("%i", tvbuffer(absolutePosition2+2,2):uint())
										attributeTree2:add(F_attribute_sub, tvbuffer(absolutePosition2+2,2), attribute_length2)
												:set_text("Data Attribute Length: " .. attribute_length2 .. " Bytes")
												
										attributeTree2:add(F_attribute_sub, tvbuffer(absolutePosition2+4, attribute_length2Int) , cmd_str)
												:set_text("Data: 0x" .. tostring( tvbuffer(absolutePosition2+4,attribute_length2Int)))
								
									-- If the length of the attribute is 00 then assume there is an error and break loop
									if lengthOfCommand2 == 0x0000 then
										attributeTree2:add(F_attribute_sub, tvbuffer(absolutePosition2+2,2), attribute_length2)
													:set_text("Error with data length value")
										break
									end
									
									-- If the length of the attribute is longer than the packet length then assume there is an error and break loop
									if lengthOfCommand2 > attribute_length2Int then
										attributeTree2:add(F_attribute_sub, tvbuffer(absolutePosition2+2,2), attribute_length2)
													:set_text("Error with data length value")
										break
									end
									
									--  attribute_length_int
									if finalPosition2 >= (attribute_length_int + absolutePosition + 24 + rtpTcpOffset) then
										break
									end
									relativePosition2 = finalPosition2 - offset2
								end
							end
							
							
							
							-- RTP CHECK
							-- Check Data payload starts with 80 or 81 or 82 and assume RTP. This method whilst not ideal works in majority of cases with Lync.
								if datatype == 128 or datatype == 129  or datatype == 130 then
														
								attribute_bytes = tostring(tvbuffer:range(absolutePosition+5+rtpTcpOffset,1)):upper()
								dataTree:add(F_stunname, tvbuffer(absolutePosition+5+rtpTcpOffset,1), attribute_bytes)
									   :set_text("RTP Message: " .. "(0x" .. attribute_bytes .. ")")
								
								
								local bits = tvbuffer(absolutePosition+4+rtpTcpOffset,1):uint()
								
								payload = bit.rshift(bit.band(bits,0xC0),6)
								
								att_str = "RTP PAYLOAD TYPE"
								if payload == 1 then
										att_str = "Version 1"
									elseif payload == 2 then
										att_str = "Version 2"
								end
								dataTree:add(F_attribute_sub, tvbuffer(absolutePosition+4+rtpTcpOffset,1), cmd_str)
										:set_text("RTP Version: " .. att_str .. " (" .. tostring(payload) .. ")")
										
								dataTree:add(F_attribute_sub, tvbuffer(absolutePosition+4+rtpTcpOffset,1), cmd_str)
										:set_text("padding: 0x" .. tostring(bit.tohex((bit.band(bits,0x20)),2)))
								
								dataTree:add(F_attribute_sub, tvbuffer(absolutePosition+4+rtpTcpOffset,1), cmd_str)
										:set_text("Extension: 0x" .. tostring(bit.tohex((bit.band(bits,0x10)),2)))
								
								local byte = tvbuffer(absolutePosition+4+rtpTcpOffset,1):uint()
								
								dataTree:add(F_attribute_sub, tvbuffer(absolutePosition+5+rtpTcpOffset,1), cmd_str)
										:set_text("CSRC count: 0x" .. tostring(bit.tohex((bit.band(bits,0x0F)),2)))
										
								local byte = tvbuffer(absolutePosition+5+rtpTcpOffset,1):uint()
								
								dataTree:add(F_attribute_sub, tvbuffer(absolutePosition+5+rtpTcpOffset,1), cmd_str)
										:set_text("Marker: 0x" .. tostring(bit.tohex((bit.band(byte,0x80)),2)))
								
								-- RTP Check
								payload = bit.band(byte,0x7F)
								
								-- RTCP Check
								rtcppayload = bit.band(byte,0xFF)
								
								att_str = "RTP PAYLOAD TYPE"
								if payload == 0 then
										att_str = "G.711 u-Law"
									elseif payload == 3 then
										att_str = "GSM 6.10"
									elseif payload == 4 then
										att_str = "G.723.1 "
									elseif payload == 8 then
										att_str = "G.711 A-Law"
									elseif payload == 9 or payload == 117 then
										att_str = "G.722"
									elseif payload == 13 then
										att_str = "Comfort Noise"
									elseif payload == 97 then
										att_str = "Redundant Audio Data Payload (FEC)"
									elseif payload == 101 then
										att_str = "DTMF"
									elseif payload == 103 then
										att_str = "SILK Narrowband"
									elseif payload == 104 then
										att_str = "SILK Wideband"
									elseif payload == 111 then
										att_str = "Siren"
									elseif payload == 112 then
										att_str = "G.722.1"
									elseif payload == 114 then
										att_str = "RT Audio Wideband"
									elseif payload == 115 then
										att_str = "RT Audio Narrowband"
									elseif payload == 116 then
										att_str = "G.726"
									elseif payload == 118 then
										att_str = "Comfort Noise Wideband"
									elseif payload == 34 then
										att_str = "H.263 [MS-H26XPF]"
									elseif payload == 121 then
										att_str = "RT Video"
									elseif payload == 122 then
										att_str = "H.264 [MS-H264PF]"
									elseif payload == 123 then
										att_str = "H.264 FEC [MS-H264PF]"
									elseif payload == 127 then
										att_str = "x-data (Content Sharing)"
									elseif payload == 200 then
										att_str = "RTCP PACKET SENDER"
									elseif payload == 201 then
										att_str = "RTCP PACKET RECEIVER"
									elseif payload == 202 then
										att_str = "RTCP Source Description"
									elseif payload == 203 then
										att_str = "RTCP Bye"
									elseif rtcppayload == 0xC8 then
										att_str = "RTCP PACKET SENDER" -- The RTP frame header is slightly different than RTCP. So the decoding is not perfect here.
									elseif rtcppayload == 0xC9 then
										att_str = "RTCP PACKET RECEIVER" -- The RTP frame header is slightly different than RTCP. So the decoding is not perfect here.
									else
										att_str = "Unknown Codec (Possible incorrect packet classification)"
										
										--IF IT'S ON PORT 443 THEN ASSUME THEN TRY THE TLS DECODER
										if f_tcp_srcport() ~= nil and f_tcp_dstport() ~= nil then
											if f_tcp_srcport().value == 443 or f_tcp_dstport().value == 443 then
											original_ssl_dissector:call(tvbuffer, pinfo, treeitem)   --DECODE AS TLS
											end
										end
								end
								

								dataTree:add(F_attribute_sub, tvbuffer(absolutePosition+5+rtpTcpOffset,1), cmd_str)
										:set_text("Payload Type: " .. att_str .. " (" .. tostring(payload) .. ")")
								
								--Set the Protcol and Info Columns
								pinfo.cols.info = cmd_str .. " : Encapsulated Data = Payload Type " .. att_str			
										
								dataTree:add(F_attribute_sub, tvbuffer(absolutePosition+6+rtpTcpOffset,lengthOfCommand-(6+rtpTcpOffset)), cmd_str)
										:set_text("Encapsulated Payload Data: " .. tostring(tvbuffer(absolutePosition+6+rtpTcpOffset,lengthOfCommand-(6+rtpTcpOffset))))
							end
								
						elseif attribute == 0x0014 then
							--att_str = "Nonce"	
							
							attribute_bytes = tostring(tvbuffer:range(absolutePosition+4,lengthOfCommand))
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,lengthOfCommand), attribute_length)
									:set_text("Nonce: 0x" .. attribute_bytes)
							
						elseif attribute == 0x0015 then
							--att_str = "Realm"	
							
							-- Convert to ASCII
							local asc = ""
							for i = absolutePosition+4, absolutePosition+4+lengthOfCommand-1 do
								local c = tvbuffer(i,1):uint()
								asc = string.format("%s%c", asc, c)
							end
							
							attribute_bytes = tostring(tvbuffer:range(absolutePosition+4,lengthOfCommand))
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,lengthOfCommand), attribute_length)
									:set_text("Realm: " .. asc .. " (0x" .. attribute_bytes .. ")")
							
						elseif attribute == 0x0017 then
							--att_str = "Requested Address Family"

							fam_type = tvbuffer(absolutePosition+4,1):uint()
						
							if fam_type == 0x01 then
								att_str = "IPv4"
								att_bytes = "0x01"
							elseif fam_type == 0x02 then
								att_str = "IPv6"
								att_bytes = "0x02"
							end										
						
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
									:set_text("Family: " .. att_str .. " (" .. att_bytes .. ")")
						
							attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+5,3):uint())
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+5,3), attribute_length)
									:set_text("Reserved " .. attribute_bytes) 
						
						elseif attribute == 0x0020 then
								--att_str = "XOR Mapped Address" from rfc5389
							
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+4,1):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
										:set_text("Reserved " .. attribute_bytes) 
							
								fam_type = tvbuffer(absolutePosition+5,1):uint()
							
								if fam_type == 0x01 then
									att_str = "IPv4"
									att_bytes = "0x01"
								elseif fam_type == 0x02 then
									att_str = "IPv6"
									att_bytes = "0x02"
								end										
							
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+5,1), attribute_length)
										:set_text("Family: " .. att_str .. " (" .. att_bytes .. ")")
							
							
								transaction_id_port = tvbuffer(4+tcpOffset,2):uint()
								xport = tvbuffer(absolutePosition+6,2):uint()
								port = bit.bxor(transaction_id_port, xport)
							
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+6,2):uint())
								portstring = string.format("%i", port)
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+6,2), attribute_length)
										:set_text("X-Port: " ..  portstring .. " " .. attribute_bytes) 
							
						
								if fam_type == 0x01 then
								
								oct1 = tvbuffer(4+tcpOffset,1):uint()
								xip1 = tvbuffer(absolutePosition+8,1):uint()
								ip1 = bin_xor(oct1,xip1)
								
								oct2 = tvbuffer(5+tcpOffset,1):uint()
								xip2 = tvbuffer(absolutePosition+9,1):uint()
								ip2 = bin_xor(oct2, xip2)
								
								oct3 = tvbuffer(6+tcpOffset,1):uint()
								xip3 = tvbuffer(absolutePosition+10,1):uint()
								ip3 = bin_xor(oct3, xip3)
								
								oct4 = tvbuffer(7+tcpOffset,1):uint()
								xip4 = tvbuffer(absolutePosition+11,1):uint()
								ip4 = bin_xor(oct4, xip4)
								
								ip1string = string.format("%i", ip1)
								ip2string = string.format("%i", ip2)
								ip3string = string.format("%i", ip3)
								ip4string = string.format("%i", ip4)
								
								
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+8,4):uint())
								
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,4), attribute_length)
										:set_text("X-Address-IPv4: " .. ip1string .. "." .. ip2string .. "." .. ip3string .. "." .. ip4string .. " " .. attribute_bytes) 		
								
								elseif fam_type == 0x02 then
								-- Not decoding IPv6 fully yet.
								attribute_bytes = tostring(tvbuffer:range(absolutePosition+8,16))
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,16), attribute_length)
									:set_text("X-Address_IPv6: 0x" .. attribute_bytes) 
								end
							
						elseif attribute == 0x0024 then
							--att_str = "Priority"	
							attribute_bytes = tostring(tvbuffer:range(absolutePosition+4,lengthOfCommand))
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,lengthOfCommand), attribute_length)
									:set_text("Priority: 0x" .. attribute_bytes)
							
									
						elseif attribute == 0x0025 then
							--att_str = "Use Candidate"	
							attribute_bytes = tostring(tvbuffer:range(absolutePosition+4,lengthOfCommand))
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,lengthOfCommand), attribute_length)
									:set_text("Use Candidate: 0x" .. attribute_bytes)
							
					end
										
				end
					if ms_attribute == 0x80 then
					-- Microsoft Specific Attributes for STUN
						att_str = "unknown 0x80XX (Possible incorrect packet classification)"
						if attribute == 0x8008 then
								att_str = "MS-Version"
							elseif attribute == 0x8006 then
								att_str = "MS-Attribute"
							elseif attribute == 0x8020 then
								att_str = "XOR Mapped Address"
							elseif attribute == 0x8022 then
								att_str = "Software (RFC5389)"
							elseif attribute == 0x8023 then
								att_str = "Alternate-Server (RFC5389)"
							elseif attribute == 0x8028 then
								att_str = "Fingerprint (RFC5389)"
							elseif attribute == 0x8029 then
								att_str = "Ice Controlled (ICE-19)"
							elseif attribute == 0x802A then
								att_str = "Ice Controlling (ICE-19)"	
							elseif attribute == 0x8050 then
								att_str = "MS-Sequence Number"
							elseif attribute == 0x8054 then
								att_str = "Candidate Identifier"
							elseif attribute == 0x8055 then
								att_str = "MS-Service Quality"
							elseif attribute == 0x8056 then
								att_str = "Bandwidth Admission Control Message"
							elseif attribute == 0x8057 then
								att_str = "Bandwidth Reservation Identifier"
							elseif attribute == 0x8058 then
								att_str = "Bandwidth Reservation Amount"
							elseif attribute == 0x8059 then
								att_str = "Remote Site Address"	
							elseif attribute == 0x805A then
								att_str = "Remote Relay Site Address"	
							elseif attribute == 0x805B then
								att_str = "Local Site Address"	
							elseif attribute == 0x805C then
								att_str = "Local Relay Site Address"	
							elseif attribute == 0x805D then
								att_str = "Remote Site Address Response"	
							elseif attribute == 0x805E then
								att_str = "Remote Relay Site Address Response"	
							elseif attribute == 0x805F then
								att_str = "Local Site Address Response"	
							elseif attribute == 0x8060 then
								att_str = "Local Relay Site Address Response"	
							elseif attribute == 0x8061 then
								att_str = "SIP Dialog Identifier"	
							elseif attribute == 0x8062 then
								att_str = "SIP Call Identifier"	
							elseif attribute == 0x8068 then
								att_str = "Location Profile"
							elseif attribute == 0x8070 then
								att_str = "Implementation Version"									
							elseif attribute == 0x8090 then
								att_str = "MS-Alternate Mapped Address"
						end
									
													
						attribute_val = string.format("0x%X", tvbuffer(absolutePosition,2):uint())
						attributeTree = subtreeitem:add(F_attribute, tvbuffer(absolutePosition,lengthOfCommand+4), attribute_val)
						attributeTree:set_text("Attribute: " .. attribute_val .. " (" .. att_str .. ")")
								
								
						attribute_length = string.format("%i", tvbuffer(absolutePosition+2,2):uint())
						attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+2,2), attribute_length)
								:set_text("Attribute Length: " .. attribute_length .. " Bytes")
						   
					
						if attribute == 0x8008 then
							--att_str = "MS-Version"
							msg_type = tvbuffer(absolutePosition+4,4):uint()
						
							if msg_type == 0x00000001 then
									att_str = "[MS-ICE]"
									att_bytes = "0x00000001"
								elseif msg_type == 0x00000002 then
									att_str = "[MS-ICE2]"
									att_bytes = "0x00000002"
								elseif msg_type == 0x00000003 then
									att_str = "[MS-ICE2] with support for HMACSHA-256"
									att_bytes = "0x00000003"
								elseif msg_type == 0x00000004 then
									att_str = "[MS-ICE2] with support for HMACSHA-256 and IPv6"
									att_bytes = "0x00000004"
							end
							
							attribute_bytes = tostring(bit.tohex(tvbuffer(absolutePosition+4,4):uint(),4))
							attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,4), attribute_length)
									:set_text("Version: " .. att_str .. " (" .. att_bytes .. ")")
							
							elseif attribute == 0x8006 then
								--att_str = "MS-Attribute"

								attribute_bytes = tostring(bit.tohex(tvbuffer(absolutePosition+4,4):uint(),8))
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,4), attribute_length)
										:set_text("Bytes: 0x" .. attribute_bytes)
															
							elseif attribute == 0x8020 then
								--att_str = "XOR Mapped Address" http://msdn.microsoft.com/en-us/library/dd909268(v=office.12).aspx
							
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+4,1):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
										:set_text("Reserved " .. attribute_bytes) 
							
								fam_type = tvbuffer(absolutePosition+5,1):uint()
							
								if fam_type == 0x01 then
									att_str = "IPv4"
									att_bytes = "0x01"
								elseif fam_type == 0x02 then
									att_str = "IPv6"
									att_bytes = "0x02"
								end										
							
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+5,1), attribute_length)
										:set_text("Family: " .. att_str .. " (" .. att_bytes .. ")")
							
							
								transaction_id_port = tvbuffer(4+tcpOffset,2):uint()
								xport = tvbuffer(absolutePosition+6,2):uint()
								port = bit.bxor(transaction_id_port, xport)
							
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+6,2):uint())
								portstring = string.format("%i", port)
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+6,2), attribute_length)
										:set_text("X-Port: " ..  portstring .. " " .. attribute_bytes) 
							
						
								if fam_type == 0x01 then
								
								oct1 = tvbuffer(4+tcpOffset,1):uint()
								xip1 = tvbuffer(absolutePosition+8,1):uint()
								ip1 = bin_xor(oct1,xip1)
								
								oct2 = tvbuffer(5+tcpOffset,1):uint()
								xip2 = tvbuffer(absolutePosition+9,1):uint()
								ip2 = bin_xor(oct2, xip2)
								
								oct3 = tvbuffer(6+tcpOffset,1):uint()
								xip3 = tvbuffer(absolutePosition+10,1):uint()
								ip3 = bin_xor(oct3, xip3)
								
								oct4 = tvbuffer(7+tcpOffset,1):uint()
								xip4 = tvbuffer(absolutePosition+11,1):uint()
								ip4 = bin_xor(oct4, xip4)
								
								ip1string = string.format("%i", ip1)
								ip2string = string.format("%i", ip2)
								ip3string = string.format("%i", ip3)
								ip4string = string.format("%i", ip4)
								
								
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+8,4):uint())
								
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,4), attribute_length)
										:set_text("X-Address-IPv4: " .. ip1string .. "." .. ip2string .. "." .. ip3string .. "." .. ip4string .. " " .. attribute_bytes) 		
								
								elseif fam_type == 0x02 then
								-- Not decoding IPv6 fully yet.
								attribute_bytes = tostring(tvbuffer:range(absolutePosition+8,16))
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,16), attribute_length)
									:set_text("X-Address_IPv6: 0x" .. attribute_bytes) 
								end
							
							elseif attribute == 0x8028 then
								--att_str = "Fingerprint"	
								attribute_bytes = tostring(tvbuffer:range(absolutePosition+4,lengthOfCommand))
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,lengthOfCommand), attribute_length)
									:set_text("Fingerprint: 0x" .. attribute_bytes)
							
							
							elseif attribute == 0x8029 then
								--att_str = "ICE Controlled"	
								attribute_bytes = tostring(tvbuffer:range(absolutePosition+4,lengthOfCommand))
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,lengthOfCommand), attribute_length)
									:set_text("ICE Controlled: 0x" .. attribute_bytes)
							
							
							elseif attribute == 0x802A then
								--att_str = "ICE Controlling"	
								attribute_bytes = tostring(tvbuffer:range(absolutePosition+4,lengthOfCommand))
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,lengthOfCommand), attribute_length)
									:set_text("ICE Controlling: 0x" .. attribute_bytes)
							
							elseif attribute == 0x8054 then
								--att_str = "Candidate Identifier"
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+4,4):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,4), attribute_length)
										:set_text("Foundation: " .. attribute_bytes)
							
						
							
							elseif attribute == 0x8050 then
								--att_str = "MS-Sequence Number" http://msdn.microsoft.com/en-us/library/dd925584(v=office.12).aspx
															
								attribute_bytes = tostring(tvbuffer:range(absolutePosition+4,20))
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,20), attribute_length)
									:set_text("Conenction ID: 0x" .. attribute_bytes)
									
									
								attribute_reserved = string.format("(0x%X)", tvbuffer(absolutePosition+24,4):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+24,4), attribute_length)
										:set_text("Sequence Number: " .. attribute_reserved)								
								
							elseif attribute == 0x8055 then
								--att_str = "MS-Service Quality" http://msdn.microsoft.com/en-us/library/dd949836(v=office.12).aspx
							
								msg_type = tvbuffer(absolutePosition+4,2):uint()
								
								if msg_type == 0x0001 then
									att_str = "Audio"
									att_bytes = "(0x0001)"
								elseif msg_type == 0x0002 then
									att_str = "Video"
									att_bytes = "(0x0002)"
								elseif msg_type == 0x0003 then
									att_str = "Supplemental Video"
									att_bytes = "(0x0003)"
								elseif msg_type == 0x0004 then
									att_str = "Data"
									att_bytes = "(0x0004)"
								else
									att_str = "Unknown (Possible incorrect packet classification)"
									att_bytes = ""
								end
								
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+4,2):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,2), attribute_length)
										:set_text("Stream Type: " .. att_str .. " " .. att_bytes)
							
								msg_type = tvbuffer(absolutePosition+6,2):uint()
								
								if msg_type == 0x0000 then
									att_str = "Best Effort"
									att_bytes = "(0x0000)"
								elseif msg_type == 0x0001 then
									att_str = "Reliable Delivery"
									att_bytes = "(0x0001)"
								else
									att_str = "Unknown (Possible incorrect packet classification)"
									att_bytes = ""
								end
								
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+6,2):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+6,2), attribute_length)
										:set_text("Quality Level: " .. att_str .. " " .. att_bytes)
							
							
							elseif attribute == 0x8056 then
							-- att_str = Bandwidth Admission Control Message
							
								attribute_reserved = string.format("(0x%X)", tvbuffer(absolutePosition+4,2):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,2), attribute_length)
										:set_text("Reserved: " .. attribute_reserved)
								
								msg_type = tvbuffer(absolutePosition+6,2):uint()
								if msg_type == 0x0000 then
									att_str = "Reservation Check"
									att_bytes = "0x0000"
								elseif msg_type == 0x0001 then
									att_str = "Reservation Commit"
									att_bytes = "0x0001"
								elseif msg_type == 0x0002 then
									att_str = "Reservation Update"
									att_bytes = "0x0002"
								else
									att_str = "Unknown (Possible incorrect packet classification)"
									att_bytes = ""
								end
								
								attribute_type = string.format("(0x%X)", tvbuffer(absolutePosition+6,2):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+6,2), att_str)
										:set_text("Message Type: " .. att_str .. " (" .. att_bytes .. ")")
							
							elseif attribute == 0x8057 then
							-- att_str = Bandwidth Reservation Identifier
							
								attribute_bytes = tostring(tvbuffer:range(absolutePosition+4,16))
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,16), attribute_length)
										:set_text("Reservation Id: 0x" .. attribute_bytes)
								
							elseif attribute == 0x8058 then
							-- att_str = Bandwidth Reservation Amount
							
								attribute_bytes = string.format("%i", tvbuffer(absolutePosition+4,4):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,4), attribute_length)
										:set_text("Minimum Send Bandwidth: " .. attribute_bytes .. "kbps") 
																
								attribute_bytes = string.format("%i", tvbuffer(absolutePosition+8,4):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,4), attribute_length)
										:set_text("Maximum Send Bandwidth: " .. attribute_bytes .. "kbps")
										
								attribute_bytes = string.format("%i", tvbuffer(absolutePosition+12,4):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+12,4), attribute_length)
										:set_text("Minimum Receive Bandwidth: " .. attribute_bytes .. "kbps")

								attribute_bytes = string.format("%i", tvbuffer(absolutePosition+16,4):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+16,4), attribute_length)
										:set_text("Maximum Receive Bandwidth: " .. attribute_bytes .. "kbps")
							
							elseif attribute == 0x8059 then
							-- att_str = Remote Site Address
							
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+4,1):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
										:set_text("Reserved " .. attribute_bytes) 
							
								fam_type = tvbuffer(absolutePosition+5,1):uint()
							
								if fam_type == 0x01 then
									att_str = "IPv4"
									att_bytes = "0x01"
								elseif fam_type == 0x02 then
									att_str = "IPv6"
									att_bytes = "0x02"
								end										
							
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+5,1), attribute_length)
										:set_text("Family: " .. att_str .. " (" .. att_bytes .. ")")
							
							
								transaction_id_port = tvbuffer(4+tcpOffset,2):uint()
								xport = tvbuffer(absolutePosition+6,2):uint()
								port = bit.bxor(transaction_id_port, xport)
							
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+6,2):uint())
								portstring = string.format("%i", port)
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+6,2), attribute_length)
										:set_text("X-Port: " ..  portstring .. " " .. attribute_bytes) 
							
							
								if fam_type == 0x01 then
								
								oct1 = tvbuffer(4+tcpOffset,1):uint()
								xip1 = tvbuffer(absolutePosition+8,1):uint()
								ip1 = bin_xor(oct1,xip1)
								
								oct2 = tvbuffer(5+tcpOffset,1):uint()
								xip2 = tvbuffer(absolutePosition+9,1):uint()
								ip2 = bin_xor(oct2, xip2)
								
								oct3 = tvbuffer(6+tcpOffset,1):uint()
								xip3 = tvbuffer(absolutePosition+10,1):uint()
								ip3 = bin_xor(oct3, xip3)
								
								oct4 = tvbuffer(7+tcpOffset,1):uint()
								xip4 = tvbuffer(absolutePosition+11,1):uint()
								ip4 = bin_xor(oct4, xip4)
								
								ip1string = string.format("%i", ip1)
								ip2string = string.format("%i", ip2)
								ip3string = string.format("%i", ip3)
								ip4string = string.format("%i", ip4)
								
								
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+8,4):uint())
								
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,4), attribute_length)
										:set_text("X-Address-IPv4: " .. ip1string .. "." .. ip2string .. "." .. ip3string .. "." .. ip4string .. " " .. attribute_bytes) 		
								
								elseif fam_type == 0x02 then
								-- Not decoding IPv6 fully yet.
								attribute_bytes = tostring(tvbuffer:range(absolutePosition+8,16))
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,16), attribute_length)
									:set_text("X-Address_IPv6: 0x" .. attribute_bytes)
								end
							
															
							elseif attribute == 0x805A then
							-- att_str = Remote Relay Site Address
							
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+4,1):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
										:set_text("Reserved " .. attribute_bytes) 
							
								fam_type = tvbuffer(absolutePosition+5,1):uint()
							
								if fam_type == 0x01 then
									att_str = "IPv4"
									att_bytes = "0x01"
								elseif fam_type == 0x02 then
									att_str = "IPv6"
									att_bytes = "0x02"
								end										
							
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+5,1), attribute_length)
										:set_text("Family: " .. att_str .. " (" .. att_bytes .. ")")
							
								--transaction_id = tvbuffer(51,63)
							
								transaction_id_port = tvbuffer(4+tcpOffset,2):uint()
								xport = tvbuffer(absolutePosition+6,2):uint()
								port = bit.bxor(transaction_id_port, xport)
							
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+6,2):uint())
								portstring = string.format("%i", port)
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+6,2), attribute_length)
										:set_text("X-Port: " ..  portstring .. " " .. attribute_bytes) 
							
							
								if fam_type == 0x01 then
								
								oct1 = tvbuffer(4+tcpOffset,1):uint()
								xip1 = tvbuffer(absolutePosition+8,1):uint()
								ip1 = bin_xor(oct1,xip1)
								
								oct2 = tvbuffer(5+tcpOffset,1):uint()
								xip2 = tvbuffer(absolutePosition+9,1):uint()
								ip2 = bin_xor(oct2, xip2)
								
								oct3 = tvbuffer(6+tcpOffset,1):uint()
								xip3 = tvbuffer(absolutePosition+10,1):uint()
								ip3 = bin_xor(oct3, xip3)
								
								oct4 = tvbuffer(7+tcpOffset,1):uint()
								xip4 = tvbuffer(absolutePosition+11,1):uint()
								ip4 = bin_xor(oct4, xip4)
								
								ip1string = string.format("%i", ip1)
								ip2string = string.format("%i", ip2)
								ip3string = string.format("%i", ip3)
								ip4string = string.format("%i", ip4)
								
								
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+8,4):uint())
								
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,4), attribute_length)
										:set_text("X-Address-IPv4: " .. ip1string .. "." .. ip2string .. "." .. ip3string .. "." .. ip4string .. " " .. attribute_bytes) 		
								
								elseif fam_type == 0x02 then
								-- Not decoding IPv6 fully yet.
								attribute_bytes = tostring(tvbuffer:range(absolutePosition+8,16))
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,16), attribute_length)
									:set_text("X-Address_IPv6: 0x" .. attribute_bytes) 
								end
							
							elseif attribute == 0x805B then
							-- att_str = Local Site Address
							
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+4,1):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
										:set_text("Reserved " .. attribute_bytes) 
							
								fam_type = tvbuffer(absolutePosition+5,1):uint()
							
								if fam_type == 0x01 then
									att_str = "IPv4"
									att_bytes = "0x01"
								elseif fam_type == 0x02 then
									att_str = "IPv6"
									att_bytes = "0x02"
								end										
							
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+5,1), attribute_length)
										:set_text("Family: " .. att_str .. " (" .. att_bytes .. ")")
							
							
								transaction_id_port = tvbuffer(4+tcpOffset,2):uint()
								xport = tvbuffer(absolutePosition+6,2):uint()
								port = bit.bxor(transaction_id_port, xport)
							
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+6,2):uint())
								portstring = string.format("%i", port)
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+6,2), attribute_length)
										:set_text("X-Port: " ..  portstring .. " " .. attribute_bytes) 
							
							
							
								if fam_type == 0x01 then
								
								oct1 = tvbuffer(4+tcpOffset,1):uint()
								xip1 = tvbuffer(absolutePosition+8,1):uint()
								ip1 = bin_xor(oct1,xip1)
								
								oct2 = tvbuffer(5+tcpOffset,1):uint()
								xip2 = tvbuffer(absolutePosition+9,1):uint()
								ip2 = bin_xor(oct2, xip2)
								
								oct3 = tvbuffer(6+tcpOffset,1):uint()
								xip3 = tvbuffer(absolutePosition+10,1):uint()
								ip3 = bin_xor(oct3, xip3)
								
								oct4 = tvbuffer(7+tcpOffset,1):uint()
								xip4 = tvbuffer(absolutePosition+11,1):uint()
								ip4 = bin_xor(oct4, xip4)
								
								ip1string = string.format("%i", ip1)
								ip2string = string.format("%i", ip2)
								ip3string = string.format("%i", ip3)
								ip4string = string.format("%i", ip4)
								
								
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+8,4):uint())
								
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,4), attribute_length)
										:set_text("X-Address-IPv4: " .. ip1string .. "." .. ip2string .. "." .. ip3string .. "." .. ip4string .. " " .. attribute_bytes) 		
								
								elseif fam_type == 0x02 then
								-- Not decoding IPv6 fully yet.
								attribute_bytes = tostring(tvbuffer:range(absolutePosition+8,16))
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,16), attribute_length)
									:set_text("X-Address_IPv6: 0x" .. attribute_bytes) 
								end
								
							elseif attribute == 0x805C then
							-- att_str = Local Relay Site Address
							
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+4,1):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
										:set_text("Reserved " .. attribute_bytes) 
							
								fam_type = tvbuffer(absolutePosition+5,1):uint()
							
								if fam_type == 0x01 then
									att_str = "IPv4"
									att_bytes = "0x01"
								elseif fam_type == 0x02 then
									att_str = "IPv6"
									att_bytes = "0x02"
								end										
							
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+5,1), attribute_length)
										:set_text("Family: " .. att_str .. " (" .. att_bytes .. ")")
							
							
								transaction_id_port = tvbuffer(4+tcpOffset,2):uint()
								xport = tvbuffer(absolutePosition+6,2):uint()
								port = bit.bxor(transaction_id_port, xport)
							
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+6,2):uint())
								portstring = string.format("%i", port)
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+6,2), attribute_length)
										:set_text("X-Port: " ..  portstring .. " " .. attribute_bytes) 
							
							
								if fam_type == 0x01 then
								
								oct1 = tvbuffer(4+tcpOffset,1):uint()
								xip1 = tvbuffer(absolutePosition+8,1):uint()
								ip1 = bin_xor(oct1,xip1)
								
								oct2 = tvbuffer(5+tcpOffset,1):uint()
								xip2 = tvbuffer(absolutePosition+9,1):uint()
								ip2 = bin_xor(oct2, xip2)
								
								oct3 = tvbuffer(6+tcpOffset,1):uint()
								xip3 = tvbuffer(absolutePosition+10,1):uint()
								ip3 = bin_xor(oct3, xip3)
								
								oct4 = tvbuffer(7+tcpOffset,1):uint()
								xip4 = tvbuffer(absolutePosition+11,1):uint()
								ip4 = bin_xor(oct4, xip4)
								
								ip1string = string.format("%i", ip1)
								ip2string = string.format("%i", ip2)
								ip3string = string.format("%i", ip3)
								ip4string = string.format("%i", ip4)
								
								
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+8,4):uint())
								
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,4), attribute_length)
										:set_text("X-Address-IPv4: " .. ip1string .. "." .. ip2string .. "." .. ip3string .. "." .. ip4string .. " " .. attribute_bytes) 		
								
								elseif fam_type == 0x02 then
								-- Not decoding IPv6 fully yet.
								attribute_bytes = tostring(tvbuffer:range(absolutePosition+8,16))
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,16), attribute_length)
									:set_text("X-Address_IPv6: 0x" .. attribute_bytes)
								end
								
							elseif attribute == 0x805D then
							--att_str = "Remote Site Address Response"
							
								local c = tvbuffer(absolutePosition+4,1):uint()

								local BitTable = to_bits(c)     
								  
								if BitTable[8] == 0 then 
									attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
											:set_text("A Valid Flag: Failed Bandwidth Policy Check")
								elseif BitTable[8] == 1 then
									attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
											:set_text("A Valid Flag: Passed Bandwidth Policy Check")
								end
								  
								if BitTable[7] == 0 then 
									attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
											:set_text("B PSTN Failover Flag: Failed Bandwidth Policy Check")
								elseif BitTable[7] == 1 then
									attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
											:set_text("B PSTN Failover Flag: Passed Bandwidth Policy Check")
								end			
							
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,4), attribute_length)
										:set_text("Reserved: MUST be zero")	
							
								attribute_bytes = string.format("%i", tvbuffer(absolutePosition+8,4):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,4), attribute_length)
										:set_text("Maximum Send Bandwidth: " .. attribute_bytes .. "kbs")
							
								attribute_bytes = string.format("%i", tvbuffer(absolutePosition+12,4):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+12,4), attribute_length)
										:set_text("Maximum Receive Bandwidth: " .. attribute_bytes .. "kbs")
															
							elseif attribute == 0x805E then
							--att_str = "Remote Relay Site Address Response"	
							
								local c = tvbuffer(absolutePosition+4,1):uint()

								local BitTable = to_bits(c)     
								  
								if BitTable[8] == 0 then 
									attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
											:set_text("A Valid Flag: Failed Bandwidth Policy Check")
								elseif BitTable[8] == 1 then
									attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
											:set_text("A Valid Flag: Passed Bandwidth Policy Check")
								end
								  
							
							
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,4), attribute_length)
										:set_text("Reserved: MUST be zero")	
							
								attribute_bytes = string.format("%i", tvbuffer(absolutePosition+8,4):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,4), attribute_length)
										:set_text("Maximum Send Bandwidth: " .. attribute_bytes .. "kbs")
							
								attribute_bytes = string.format("%i", tvbuffer(absolutePosition+12,4):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+12,4), attribute_length)
										:set_text("Maximum Receive Bandwidth: " .. attribute_bytes .. "kbs")
							
							elseif attribute == 0x805F then
							--att_str = "Local Site Address Response"	
							
								local c = tvbuffer(absolutePosition+4,1):uint()

								local BitTable = to_bits(c)     
								  
								if BitTable[8] == 0 then 
									attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
											:set_text("A Valid Flag: Failed Bandwidth Policy Check")
								elseif BitTable[8] == 1 then
									attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
											:set_text("A Valid Flag: Passed Bandwidth Policy Check")
								end
								 
								 if BitTable[7] == 0 then 
									attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
											:set_text("B PSTN Failover Flag: Failed Bandwidth Policy Check")
								elseif BitTable[7] == 1 then
									attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
											:set_text("B PSTN Failover Flag: Passed Bandwidth Policy Check")
								end	
								
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,4), attribute_length)
										:set_text("Reserved: MUST be zero")	
							
								attribute_bytes = string.format("%i", tvbuffer(absolutePosition+8,4):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,4), attribute_length)
										:set_text("Maximum Send Bandwidth: " .. attribute_bytes .. "kbs")
							
								attribute_bytes = string.format("%i", tvbuffer(absolutePosition+12,4):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+12,4), attribute_length)
										:set_text("Maximum Receive Bandwidth: " .. attribute_bytes .. "kbs")
							
							elseif attribute == 0x8060 then
							--att_str = "Local Relay Site Address Response"	
							
								local c = tvbuffer(absolutePosition+4,1):uint()

								local BitTable = to_bits(c)     
								  
								if BitTable[8] == 0 then 
									attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
											:set_text("A Valid Flag: Failed Bandwidth Policy Check")
								elseif BitTable[8] == 1 then
									attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
											:set_text("A Valid Flag: Passed Bandwidth Policy Check")
								end
																	
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,4), attribute_length)
										:set_text("Reserved: MUST be zero")	
							
								attribute_bytes = string.format("%i", tvbuffer(absolutePosition+8,4):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+8,4), attribute_length)
										:set_text("Maximum Send Bandwidth: " .. attribute_bytes .. "kbs")
							
								attribute_bytes = string.format("%i", tvbuffer(absolutePosition+12,4):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+12,4), attribute_length)
										:set_text("Maximum Receive Bandwidth: " .. attribute_bytes .. "kbs")
							
							elseif attribute == 0x8061 then
										
							--att_str = "SIP Dialog Identifier"
                            
							-- CHANGED FOR 2.0
                                --attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+4,lengthOfCommand):uint())
                                attribute_bytes = tvbuffer(absolutePosition+4,lengthOfCommand):string()
                                attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,lengthOfCommand), attribute_length)
                                        :set_text("SIP Dialog Identifier: " .. attribute_bytes)		
							
							
							elseif attribute == 0x8062 then
							--att_str = "SIP Call Identifier"

								-- CHANGED FOR 2.0
                                --attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+4,lengthOfCommand):uint())
                                attribute_bytes = tvbuffer(absolutePosition+4,lengthOfCommand):string()
                                attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,lengthOfCommand), attribute_length)
                                        :set_text("SIP Call Identifier: " .. attribute_bytes)	
									
							
							elseif attribute == 0x8068 then
							--att_str = "Location Profile"
							
								peer_type = tvbuffer(absolutePosition+4,1):uint()
							
								if peer_type == 0x00 then
									att_loc = "Unknown"
									att_bytes = "0x00"
								elseif peer_type == 0x01 then
									att_loc = "Internet"
									att_bytes = "0x01"
								elseif peer_type == 0x02 then
									att_loc = "Intranet"
									att_bytes = "0x02"
								end										
							
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,1), attribute_length)
										:set_text("Peer Location: " .. att_loc .. " (" .. att_bytes .. ")")
							
								peer_type = tvbuffer(absolutePosition+5,1):uint()
							
								if peer_type == 0x00 then
									att_loc = "Unknown"
									att_bytes = "0x00"
								elseif peer_type == 0x01 then
									att_loc = "Internet"
									att_bytes = "0x01"
								elseif peer_type == 0x02 then
									att_loc = "Intranet"
									att_bytes = "0x02"
								end										
							
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+5,1), attribute_length)
										:set_text("Self Location: " .. att_loc .. " (" .. att_bytes .. ")")
							
							
								peer_type = tvbuffer(absolutePosition+6,1):uint()
							
								if peer_type == 0x00 then
									att_loc = "Unknown"
									att_bytes = "0x00"
								elseif peer_type == 0x01 then
									att_loc = "Internet"
									att_bytes = "0x01"
								elseif peer_type == 0x02 then
									att_loc = "Intranet"
									att_bytes = "0x02"
								end										
							
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+6,1), attribute_length)
										:set_text("Federation Location: " .. att_loc .. " (" .. att_bytes .. ")")
								
								attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+7,1):uint())
								attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+7,1), attribute_length)
										:set_text("Reserved: " .. attribute_bytes)
							
							elseif attribute == 0x8070 then
							--att_str = Version Number
							
								-- CHANGED FOR 2.0
								--attribute_bytes = string.format("(0x%X)", tvbuffer(absolutePosition+4,lengthOfCommand):uint())
                                attribute_bytes = tvbuffer(absolutePosition+4,lengthOfCommand):string()
                                attributeTree:add(F_attribute_sub, tvbuffer(absolutePosition+4,lengthOfCommand), attribute_length)
                                        :set_text("Version Number: " .. attribute_bytes)
							
							
							elseif attribute == 0x8090 then
							--att_str = "MS-Alternate Mapped Address"
										
						end
					end
					
					if finalPosition >= tvbuffer:len() then
						return
					end
				
					relativePosition = finalPosition - offset
				
					end
				end
			end
		
		----- CHECK IF PACKETS ARE RTP OR RTCP!
		cmd = tvbuffer(1+tcpOffset,1):uint()
							   
		cmd_str = "unknown (Possible incorrect packet classification)"
		
			
		--	        0                   1                   2                   3
		--        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		--       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		--header |V=2|P|    RC   |   PT=SR=200   |             length            |
		--       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		--       |                         SSRC of sender                        |
		--       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
		--sender |              NTP timestamp, most significant word             |
		--info   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		--       |             NTP timestamp, least significant word             |
		--       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		--       |                         RTP timestamp                         |
		--       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		--       |                     sender's packet count                     |
		--       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		--       |                      sender's octet count                     |
				
		--SRTCP
		--  0                   1                   2                   3
		--      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		--     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
		--     |V=2|P|    RC   |   PT=SR or RR   |             length          | |
		--     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
		--     |                         SSRC of sender                        | |
		--   +>+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
		--   | ~                          sender info                          ~ |
		--   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
		--   | ~                         report block 1                        ~ |
		--   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
		--   | ~                         report block 2                        ~ |
		--   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
		--   | ~                              ...                              ~ |
		--   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
		--   | |V=2|P|    SC   |  PT=SDES=202  |             length            | |
		--   | +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
		--   | |                          SSRC/CSRC_1                          | |
		--   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
		--   | ~                           SDES items                          ~ |
		--   | +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
		--   | ~                              ...                              ~ |
		--   +>+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
		--   | |E|                         SRTCP index                         | |
		--   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
		--   | ~                     SRTCP MKI (OPTIONAL)                      ~ |
		--   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
		--   | :                     authentication tag                        : |
		--   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
		--   |                                                                   |
		--   +-- Encrypted Portion                    Authenticated Portion -----+	


		if cmd == 0xC8 then
			
			if f_tcp_srcport() ~= nil and f_tcp_dstport() ~= nil and tcpOffset == 0 then	
				
					-- Framing check failed so assume this isn't a TCP based RTP packet. Use SSL decoder if required.
					if f_tcp_srcport().value == 443 or f_tcp_dstport().value == 443 then
					
					original_ssl_dissector:call(tvbuffer, pinfo, treeitem)   --DECODE AS TLS
					
					else
					
					attributeTree = subtreeitem:add(F_stunname, tvbuffer(0+tcpOffset,1), attribute_bytes)
						   attributeTree:set_text("UNABLE TO DECODE THIS PACKET :(")
					
					end
					
			else
				
			local bytes = tvbuffer(1+tcpOffset,1):uint()
				
			-- IS AN RTCP PACKET
			cmd_str = "RTCP PACKET"
					
			--Set the Protcol and Info Columns
			pinfo.cols.protocol = "MSRTCP"
		
			packetlength = tvbuffer:len()
			length = tvbuffer(2+tcpOffset,2):uint()
			-- If the length of the attribute is longer than the packet length then assume there is an error and break loop
			
			if length > packetlength then
							
				pinfo.cols.info = "RTCP PACKET SENDER (Incorrect Length)"
				
				attribute_bytes = tostring(tvbuffer:range(1+tcpOffset,1)):upper()
				attributeTree = subtreeitem:add(F_stunname, tvbuffer(1+tcpOffset,1), attribute_bytes)
					   attributeTree:set_text("RTCP Sender Message: " .. "Payload Type: " .. tostring(bytes))
				
				--IF IT'S ON PORT 443 THEN ASSUME THEN TRY THE TLS DECODER
				if f_tcp_srcport() ~= nil and f_tcp_dstport() ~= nil then
					if f_tcp_srcport().value == 443 or f_tcp_dstport().value == 443 then
					original_ssl_dissector:call(tvbuffer, pinfo, treeitem)   --DECODE AS TLS
					end
				end
			
			
			else
		
			pinfo.cols.info = "RTCP PACKET SENDER"
			
			attribute_bytes = tostring(tvbuffer:range(1+tcpOffset,1)):upper()
			attributeTree = subtreeitem:add(F_stunname, tvbuffer(1+tcpOffset,1), attribute_bytes)
				   attributeTree:set_text("RTCP Sender Message: " .. "Payload Type: " .. tostring(bytes))
			   
			end
			
			local bits = tvbuffer(0+tcpOffset,1):uint()
							
			attributeTree:add(F_attribute_sub, tvbuffer(0+tcpOffset,1), cmd_str)
					:set_text("RTP Version: (2 bits) 0x" .. tostring(bit.tohex((bit.band(bits,0xC0)),2)))
					
			attributeTree:add(F_attribute_sub, tvbuffer(0+tcpOffset,1), cmd_str)
					:set_text("padding: (1 bit) 0x" .. tostring(bit.tohex((bit.band(bits,0x20)),2)))
			
			attributeTree:add(F_attribute_sub, tvbuffer(0+tcpOffset,1), cmd_str)
					:set_text("RC: (5 bits) 0x" .. tostring(bit.tohex((bit.band(bits,0x1F)),2)))
			
			local byte = tvbuffer(1+tcpOffset,1):uint()
			
			attributeTree:add(F_attribute_sub, tvbuffer(1+tcpOffset,1), cmd_str)
					:set_text("Payload Type: (8 bits) " .. tostring(byte))
			
			
			length = tvbuffer(2+tcpOffset,2):uint()
			
			--length x 32 / 8 + 4
			attributeTree:add(F_attribute_sub, tvbuffer(2+tcpOffset,2), cmd_str)
					:set_text("Length: " .. tostring(length) .. " (" .. tostring(((length * 32) / 8)+4) .. " Bytes)")
			
			packetlength = tvbuffer:len()
			length = tvbuffer(2+tcpOffset,2):uint()
			-- If the length of the attribute is longer than the packet length then assume there is an error and break loop
			if length > packetlength then
				attributeTree:add(F_attribute_sub, tvbuffer(2+tcpOffset,2), cmd_str)
							:set_text("(Error with data length value. Probably not an actual RTCP packet.)")
			end
			
			local bytes = tvbuffer(4+tcpOffset,4):uint()
			attributeTree:add(F_attribute_sub, tvbuffer(4+tcpOffset,4), cmd_str)
					:set_text("SSRC of sender: 0x" .. tostring(bit.tohex((bytes),8)):upper())		
					
			attributeTree:add(F_attribute_sub, tvbuffer(8+tcpOffset, tvbuffer:len()-tcpOffset-8) , cmd_str)
					:set_text("Payload: " .. tostring( tvbuffer(8+tcpOffset,tvbuffer:len()-tcpOffset-8)) )
			
			-- Assumed Payload is encrypted, so not attempting any break down further of data.
			
			end
			
		elseif cmd == 0xC9 then
		
			if f_tcp_srcport() ~= nil and f_tcp_dstport() ~= nil and tcpOffset == 0 then	
				
					-- Framing check failed so assume this isn't a TCP based RTP packet. Use SSL decoder if required.
					if f_tcp_srcport().value == 443 or f_tcp_dstport().value == 443 then
					
					original_ssl_dissector:call(tvbuffer, pinfo, treeitem)   --DECODE AS TLS
					
					else
					
					attributeTree = subtreeitem:add(F_stunname, tvbuffer(0+tcpOffset,1), attribute_bytes)
						   attributeTree:set_text("UNABLE TO DECODE THIS PACKET :(")
					
					end
					
			else
			
			local bytes = tvbuffer(1+tcpOffset,1):uint()
				
			-- IS AN RTCP PACKET
			cmd_str = "RTCP PACKET"
					
			--Set the Protcol and Info Columns
			pinfo.cols.protocol = "MSRTCP"
			
			packetlength = tvbuffer:len()
			length = tvbuffer(2+tcpOffset,2):uint()
			-- If the length of the attribute is longer than the packet length then assume there is an error and break loop
			if length > packetlength then
			
				pinfo.cols.info = "RTCP PACKET RECEIVER (Incorrect Length)"
				
				attribute_bytes = tostring(tvbuffer:range(1+tcpOffset,1)):upper()
				attributeTree = subtreeitem:add(F_stunname, tvbuffer(1+tcpOffset,1), attribute_bytes)
					   attributeTree:set_text("RTCP Receiver Message: " .. "Payload Type: " .. tostring(bytes))
				
				--IF IT'S ON PORT 443 THEN ASSUME THEN TRY THE TLS DECODER
				if f_tcp_srcport() ~= nil and f_tcp_dstport() ~= nil then
					if f_tcp_srcport().value == 443 or f_tcp_dstport().value == 443 then
					original_ssl_dissector:call(tvbuffer, pinfo, treeitem)   --DECODE AS TLS
					end
				end
			
			
			else
				pinfo.cols.info = "RTCP PACKET RECEIVER"
				
				attribute_bytes = tostring(tvbuffer:range(1+tcpOffset,1)):upper()
				attributeTree = subtreeitem:add(F_stunname, tvbuffer(1+tcpOffset,1), attribute_bytes)
					   attributeTree:set_text("RTCP Receiver Message: " .. "Payload Type: " .. tostring(bytes))
		
			end
			
			local bits = tvbuffer(0+tcpOffset,1):uint()
						
			attributeTree:add(F_attribute_sub, tvbuffer(0+tcpOffset,1), cmd_str)
					:set_text("RTP Version: (2 bits) 0x" .. tostring(bit.tohex((bit.band(bits,0xC0)),2)))
					
			attributeTree:add(F_attribute_sub, tvbuffer(0+tcpOffset,1), cmd_str)
					:set_text("padding: (1 bit) 0x" .. tostring(bit.tohex((bit.band(bits,0x20)),2)))
			
			attributeTree:add(F_attribute_sub, tvbuffer(0+tcpOffset,1), cmd_str)
					:set_text("RC: (5 bits) 0x" .. tostring(bit.tohex((bit.band(bits,0x1F)),2)))
			
			local byte = tvbuffer(1+tcpOffset,1):uint()
			
			attributeTree:add(F_attribute_sub, tvbuffer(1+tcpOffset,1), cmd_str)
					:set_text("Payload Type: (8 bits) " .. tostring(byte))
			
			
			length = tvbuffer(2+tcpOffset,2):uint()
			
			--length x 32 / 8 + 4
			attributeTree:add(F_attribute_sub, tvbuffer(2+tcpOffset,2), cmd_str)
					:set_text("Length: " .. tostring(length) .. " (" .. tostring(((length * 32) / 8)+4) .. " Bytes)")
			
			packetlength = tvbuffer:len()
			length = tvbuffer(2+tcpOffset,2):uint()
			-- If the length of the attribute is longer than the packet length then assume there is an error and break loop
			if length > packetlength then
				attributeTree:add(F_attribute_sub, tvbuffer(2+tcpOffset,2), cmd_str)
							:set_text("(Error with data length value. Probably not an actual RTCP packet.)")
			end
			
			local bytes = tvbuffer(4+tcpOffset,4):uint()
			attributeTree:add(F_attribute_sub, tvbuffer(4+tcpOffset,4), cmd_str)
					:set_text("SSRC of sender: 0x" .. tostring(bit.tohex((bytes),8)):upper())		
					
			attributeTree:add(F_attribute_sub, tvbuffer(8+tcpOffset, tvbuffer:len()-tcpOffset-8) , cmd_str)
					:set_text("Payload: " .. tostring( tvbuffer(8+tcpOffset,tvbuffer:len()-tcpOffset-8)) )
			
			-- Assumed Payload is encrypted, so not attempting any break down further of data.
			
			end
			
		elseif cmd == 0xCA then
		
			if f_tcp_srcport() ~= nil and f_tcp_dstport() ~= nil and tcpOffset == 0 then	
				
					-- Framing check failed so assume this isn't a TCP based RTP packet. Use SSL decoder if required.
					if f_tcp_srcport().value == 443 or f_tcp_dstport().value == 443 then
					
					original_ssl_dissector:call(tvbuffer, pinfo, treeitem)   --DECODE AS TLS
					
					else
					
					attributeTree = subtreeitem:add(F_stunname, tvbuffer(0+tcpOffset,1), attribute_bytes)
						   attributeTree:set_text("UNABLE TO DECODE THIS PACKET :(")
					
					end
					
			else
		--        0                   1                   2                   3
		--        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		--       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		--header |V=2|P|    SC   |  PT=SDES=202  |             length            |
		--       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
		--chunk  |                          SSRC/CSRC_1                          |
		--  1    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		--       |                           SDES items                          |
		--       |                              ...                              |
		--       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
		--chunk  |                          SSRC/CSRC_2                          |
		--  2    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		--       |                           SDES items                          |
		--       |                              ...                              |
		--       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

			cmd_str = "RTCP PACKET"
						
			--Set the Protcol and Info Columns
			pinfo.cols.protocol = "MSRTCP"
			
			local bytes = tvbuffer(1+tcpOffset,1):uint()

			packetlength = tvbuffer:len()
			length = tvbuffer(2+tcpOffset,2):uint()
			-- If the length of the attribute is longer than the packet length then assume there is an error and break loop
			if length > packetlength then
			
				pinfo.cols.info = "RTCP PACKET SENDER (Incorrect Length)"
					
				attribute_bytes = tostring(tvbuffer:range(1+tcpOffset,1)):upper()
				attributeTree = subtreeitem:add(F_stunname, tvbuffer(1+tcpOffset,1), attribute_bytes)
					   attributeTree:set_text("Source Description RTCP Packet: " .. "(0x" .. attribute_bytes .. ")")
			   
			   --IF IT'S ON PORT 443 THEN ASSUME THEN TRY THE TLS DECODER
				if f_tcp_srcport() ~= nil and f_tcp_dstport() ~= nil then
					if f_tcp_srcport().value == 443 or f_tcp_dstport().value == 443 then
					original_ssl_dissector:call(tvbuffer, pinfo, treeitem)   --DECODE AS TLS
					end
				end
			   
		   else
				pinfo.cols.info = "RTCP PACKET SENDER"
				
				attribute_bytes = tostring(tvbuffer:range(1+tcpOffset,1)):upper()
				attributeTree = subtreeitem:add(F_stunname, tvbuffer(1+tcpOffset,1), attribute_bytes)
					   attributeTree:set_text("Source Description RTCP Packet: " .. "(0x" .. attribute_bytes .. ")")   
		   
		   end
			
			local bits = tvbuffer(0+tcpOffset,1):uint()
							
			attributeTree:add(F_attribute_sub, tvbuffer(0+tcpOffset,1), cmd_str)
					:set_text("RTP Version: (2 bits) 0x" .. tostring(bit.tohex((bit.band(bits,0xC0)),2)))
					
			attributeTree:add(F_attribute_sub, tvbuffer(0+tcpOffset,1), cmd_str)
					:set_text("padding: (1 bit) 0x" .. tostring(bit.tohex((bit.band(bits,0x20)),2)))
			
			attributeTree:add(F_attribute_sub, tvbuffer(0+tcpOffset,1), cmd_str)
					:set_text("SC Type: (5 bits) 0x" .. tostring(bit.tohex((bit.band(bits,0x1F)),2)))
			
			local byte = tvbuffer(1+tcpOffset,1):uint()
			
			attributeTree:add(F_attribute_sub, tvbuffer(1+tcpOffset,1), cmd_str)
					:set_text("Payload Type: (8 bits) " .. tostring(byte))
			
			length = tvbuffer(2+tcpOffset,2):uint()
			
			attributeTree:add(F_attribute_sub, tvbuffer(2+tcpOffset,2), cmd_str)
					:set_text("Length: " .. tostring(length) .. " (" .. tostring(((length * 32) / 8)+4) .. " Bytes)")
			
			packetlength = tvbuffer:len()
			-- If the length of the attribute is longer than the packet length then assume there is an error and break loop
			if length > packetlength then
				attributeTree:add(F_attribute_sub, tvbuffer(2+tcpOffset,2), cmd_str)
							:set_text("(Error with data length value. Probably not an actual RTCP packet.)")
			end

			attributeTree:add(F_attribute_sub, tvbuffer(4+tcpOffset, tvbuffer:len()-tcpOffset-4) , cmd_str)
					:set_text("Payload: " .. tostring( tvbuffer(4+tcpOffset,tvbuffer:len()-tcpOffset-4)))
			
			
			-- Assumed Payload is encrypted, so not attempting any further decoding of data.
			
			end
			
		elseif cmd == 0xCB then
		
			if f_tcp_srcport() ~= nil and f_tcp_dstport() ~= nil and tcpOffset == 0 then	
				
					-- Framing check failed so assume this isn't a TCP based RTP packet. Use SSL decoder if required.
					if f_tcp_srcport().value == 443 or f_tcp_dstport().value == 443 then
					
					original_ssl_dissector:call(tvbuffer, pinfo, treeitem)   --DECODE AS TLS
					
					else
					
					attributeTree = subtreeitem:add(F_stunname, tvbuffer(0+tcpOffset,1), attribute_bytes)
						   attributeTree:set_text("UNABLE TO DECODE THIS PACKET :(")
					
					end
					
			else
			
			-- 0                   1                   2                   3
			--       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			--      |V=2|P|    SC   |   PT=BYE=203  |             length            |
			--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			--      |                           SSRC/CSRC                           |
			--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			--      :                              ...                              :
			--      +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
			--(opt) |     length    |               reason for leaving            ...
			--     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		
			cmd_str = "RTCP PACKET"
						
			--Set the Protcol and Info Columns
			pinfo.cols.protocol = "MSRTCP"
			
			local bytes = tvbuffer(1+tcpOffset,1):uint()
			
			packetlength = tvbuffer:len()
			length = tvbuffer(2+tcpOffset,2):uint()
			-- If the length of the attribute is longer than the packet length then assume there is an error and break loop
			if length > packetlength then
			
				pinfo.cols.info = "RTCP PACKET SENDER (Incorrect Length)"
					
				attribute_bytes = tostring(tvbuffer:range(1+tcpOffset,1)):upper()
				attributeTree = subtreeitem:add(F_stunname, tvbuffer(1+tcpOffset,1), attribute_bytes)
					   attributeTree:set_text("Source Description RTCP Packet: " .. "(0x" .. attribute_bytes .. ")")
					   
				--IF IT'S ON PORT 443 THEN ASSUME THEN TRY THE TLS DECODER
				if f_tcp_srcport() ~= nil and f_tcp_dstport() ~= nil then
					if f_tcp_srcport().value == 443 or f_tcp_dstport().value == 443 then
					original_ssl_dissector:call(tvbuffer, pinfo, treeitem)   --DECODE AS TLS
				end
				end
				
			else
				pinfo.cols.info = "RTCP PACKET SENDER"
					
				attribute_bytes = tostring(tvbuffer:range(1+tcpOffset,1)):upper()
				attributeTree = subtreeitem:add(F_stunname, tvbuffer(1+tcpOffset,1), attribute_bytes)
					   attributeTree:set_text("Source Description RTCP Packet: " .. "(0x" .. attribute_bytes .. ")")
			
			end
			
			local bits = tvbuffer(0+tcpOffset,1):uint()
							
			attributeTree:add(F_attribute_sub, tvbuffer(0+tcpOffset,1), cmd_str)
					:set_text("RTP Version: (2 bits) 0x" .. tostring(bit.tohex((bit.band(bits,0xC0)),2)))
					
			attributeTree:add(F_attribute_sub, tvbuffer(0+tcpOffset,1), cmd_str)
					:set_text("padding: (1 bit) 0x" .. tostring(bit.tohex((bit.band(bits,0x20)),2)))
			
			attributeTree:add(F_attribute_sub, tvbuffer(0+tcpOffset,1), cmd_str)
					:set_text("SC Type: (5 bits) 0x" .. tostring(bit.tohex((bit.band(bits,0x1F)),2)))
			
			local byte = tvbuffer(1+tcpOffset,1):uint()
			
			attributeTree:add(F_attribute_sub, tvbuffer(1+tcpOffset,1), cmd_str)
					:set_text("Payload Type: (8 bits) " .. tostring(byte))
			
			
			length = tvbuffer(2+tcpOffset,2):uint()
			
			attributeTree:add(F_attribute_sub, tvbuffer(2+tcpOffset,2), cmd_str)
					:set_text("Length: " .. tostring(length) .. " (" .. tostring(((length * 32) / 8)+4) .. " Bytes)")
			
			packetlength = tvbuffer:len()
			-- If the length of the attribute is longer than the packet length then assume there is an error and break loop
			if length > packetlength then
				attributeTree:add(F_attribute_sub, tvbuffer(2+tcpOffset,2), cmd_str)
							:set_text("(Error with data length value. Probably not an actual RTCP packet.)")
			end
			
			attributeTree:add(F_attribute_sub, tvbuffer(4+tcpOffset,4), cmd_str)
					:set_text("SSRC of Sender: " .. tostring(tvbuffer(4+tcpOffset,4)))
			
			attributeTree:add(F_attribute_sub, tvbuffer(8+tcpOffset, tvbuffer:len()-tcpOffset-8) , cmd_str)
					:set_text("Payload: " .. tostring( tvbuffer(8+tcpOffset,tvbuffer:len()-tcpOffset-8)))
			
			-- Assumed Payload is encrypted, so not attempting any break down further of data.	
			
			end
			
		elseif cmd == 0xCE then
		
			if f_tcp_srcport() ~= nil and f_tcp_dstport() ~= nil and tcpOffset == 0 then	
				
					-- Framing check failed so assume this isn't a TCP based RTP packet. Use SSL decoder if required.
					if f_tcp_srcport().value == 443 or f_tcp_dstport().value == 443 then
					
					original_ssl_dissector:call(tvbuffer, pinfo, treeitem)   --DECODE AS TLS
					
					else
					
					attributeTree = subtreeitem:add(F_stunname, tvbuffer(0+tcpOffset,1), attribute_bytes)
						   attributeTree:set_text("UNABLE TO DECODE THIS PACKET :(")
					
					end
					
			else		
			
			cmd_str = "RTCP PACKET"
					
			--			0                   1                   2                   3
			--    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			--   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			--   |V=2|P|   FMT   |       PT      |          length               |
			--   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			--   |                  SSRC of packet sender                        |
			--   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			--   |                  SSRC of media source                         |
			--   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			--   :            Feedback Control Information (FCI)                 :
			--   :                                                               :
					
			--Set the Protcol and Info Columns
			pinfo.cols.protocol = "MSRTCP"
			
			local bytes = tvbuffer(1+tcpOffset,1):uint()
			
			
			packetlength = tvbuffer:len()
			length = tvbuffer(2+tcpOffset,2):uint()
			-- If the length of the attribute is longer than the packet length then assume there is an error and break loop
			if length > packetlength then
				
				pinfo.cols.info = "RTCP PAYLOAD-SPECIFIC FEEDBACK (Incorrect Length)"
					
				attribute_bytes = tostring(tvbuffer:range(1+tcpOffset,1)):upper()
				attributeTree = subtreeitem:add(F_stunname, tvbuffer(1+tcpOffset,1), attribute_bytes)
					   attributeTree:set_text("Source Description RTCP Packet: " .. "(0x" .. attribute_bytes .. ")")
					   
				--IF IT'S ON PORT 443 THEN ASSUME THEN TRY THE TLS DECODER
				if f_tcp_srcport() ~= nil and f_tcp_dstport() ~= nil then
					if f_tcp_srcport().value == 443 or f_tcp_dstport().value == 443 then
					original_ssl_dissector:call(tvbuffer, pinfo, treeitem)   --DECODE AS TLS
					end
				end
			
			else
				pinfo.cols.info = "RTCP PAYLOAD-SPECIFIC FEEDBACK"
					
				attribute_bytes = tostring(tvbuffer:range(1+tcpOffset,1)):upper()
				attributeTree = subtreeitem:add(F_stunname, tvbuffer(1+tcpOffset,1), attribute_bytes)
					   attributeTree:set_text("Source Description RTCP Packet: " .. "(0x" .. attribute_bytes .. ")")
			
			end
			
			local bits = tvbuffer(0+tcpOffset,1):uint()
							
			attributeTree:add(F_attribute_sub, tvbuffer(0+tcpOffset,1), cmd_str)
					:set_text("RTP Version: (2 bits) 0x" .. tostring(bit.tohex((bit.band(bits,0xC0)),2)))
					
			attributeTree:add(F_attribute_sub, tvbuffer(0+tcpOffset,1), cmd_str)
					:set_text("padding: (1 bit) 0x" .. tostring(bit.tohex((bit.band(bits,0x20)),2)))
			
			attributeTree:add(F_attribute_sub, tvbuffer(0+tcpOffset,1), cmd_str)
					:set_text("FMT: (5 bits) 0x" .. tostring(bit.tohex((bit.band(bits,0x1F)),2)))
			
			local byte = tvbuffer(1+tcpOffset,1):uint()
			
			attributeTree:add(F_attribute_sub, tvbuffer(1+tcpOffset,1), cmd_str)
					:set_text("Payload Type: (8 bits) " .. tostring(byte))
			
			
			length = tvbuffer(2+tcpOffset,2):uint()
			
			attributeTree:add(F_attribute_sub, tvbuffer(2+tcpOffset,2), cmd_str)
					:set_text("Length: " .. tostring(length) .. " (" .. tostring(((length * 32) / 8)+4) .. " Bytes)")
			
			packetlength = tvbuffer:len()			
			-- If the length of the attribute is longer than the packet length then assume there is an error and break loop
			if length > packetlength then
				attributeTree:add(F_attribute_sub, tvbuffer(2+tcpOffset,2), cmd_str)
							:set_text("(Error with data length value. Probably not an actual RTCP packet.)")
			end
			
			attributeTree:add(F_attribute_sub, tvbuffer(4+tcpOffset, tvbuffer:len()-tcpOffset-4) , cmd_str)
					:set_text("Payload: " .. tostring( tvbuffer(4+tcpOffset,tvbuffer:len()-tcpOffset-4)))
			
			-- Assumed Payload is encrypted, so not attempting any break down further of data.	
			
			end
		
		else	-- ALL THE REST :)
		
			--	    0                   1                   2                   3
			--    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			--   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			--   |V=2|P|X|  CC   |M|     PT      |       sequence number         |
			--   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			--   |                           timestamp                           |
			--   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			--   |           synchronization source (SSRC) identifier            |
			--   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
			--   |            contributing source (CSRC) identifiers             |
			--   |                             ....                              |
			--   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

			--OTHER PACKET TYPE CHECKS
			
			-- PsudeoTLS Hello Check
			frameCheck = tvbuffer(0,2):uint()
			frameCheckOffset = tvbuffer(tcpOffset,2):uint()
			
			if frameCheck == 0x1603 then
			
			-- FALL BACK TO THE WIRESHARK STANDARD SSL/TLS DISSECTOR. DOES A LOT BETTER JOB THAN I DO OF DECODING TLS...
			
			original_ssl_dissector:call(tvbuffer, pinfo, treeitem)
			
			--[[
			--Set the Protcol and Info Columns
			pinfo.cols.protocol = "MSTLS"
			pinfo.cols.info = "TLS Negotiation (Possible Psuedo TLS setup)"	
			
			subtreeitem:add(F_stunname, tvbuffer(0,2), cmd_str)
						:set_text("TLS Negotiation")
						
			attribute_bytes = tostring(tvbuffer:range(0,1)):upper()
			attributeTree = subtreeitem:add(F_stunname, tvbuffer(0,1), attribute_bytes)
			   attributeTree:set_text("Record Layer: " .. "(0x" .. attribute_bytes .. ")")
					
			tlsversion = tvbuffer(1,2):uint()
			
			if tlsversion == 0x0003 then
				versionstring = "SSL v3"
			elseif tlsversion == 0x0301 then
				versionstring = "TLS v1.0"
			elseif tlsversion == 0x0302 then
				versionstring = "TLS v1.1"
			elseif tlsversion == 0x0303 then
				versionstring = "TLS v1.2"
			end
			
			attribute_bytes = tostring(tvbuffer:range(1,2)):upper()
			attributeTree = subtreeitem:add(F_stunname, tvbuffer(1,2), attribute_bytes)
			   attributeTree:set_text("Record Version: " .. versionstring .. " (0x" .. attribute_bytes .. ")")
			
			attribute_bytes = tostring(tvbuffer:range(3,2)):upper()
			attributeTree = subtreeitem:add(F_stunname, tvbuffer(3,2), attribute_bytes)
			   attributeTree:set_text("Record Length: " .. "(0x" .. attribute_bytes .. ")")
			
			local handshaketype = tvbuffer(5,1):uint()
			
			if handshaketype == 0x01 then
				handshaketypestring = "Client Hello"
			elseif handshaketype == 0x02 then
				handshaketypestring = "Server Hello"
			elseif handshaketype == 0x0B then
				handshaketypestring = "Certificate"
			elseif handshaketype == 0x0C then
				handshaketypestring = "Server Key Exchange"
			elseif handshaketype == 0x0E then
				handshaketypestring = "Server Hello Done"
			elseif handshaketype == 0x10 then
				handshaketypestring = "Client Key Exchange"
			elseif handshaketype == 0x14 then
				handshaketypestring = "Finished"
			end
			
			attribute_bytes = tostring(tvbuffer:range(5,1)):upper()
			attributeTree = subtreeitem:add(F_stunname, tvbuffer(5,1), attribute_bytes)
			   attributeTree:set_text("Handshake Type: " .. handshaketypestring .. " (0x" .. attribute_bytes .. ")")
			
			attribute_bytes = tostring(tvbuffer:range(6,3)):upper()
			attributeTree = subtreeitem:add(F_stunname, tvbuffer(6,3), attribute_bytes)
			   attributeTree:set_text("Handshake Length: " .. "(0x" .. attribute_bytes .. ")")
			
			attribute_bytes = tostring(tvbuffer:range(9,1)):upper()
			attributeTree = subtreeitem:add(F_stunname, tvbuffer(9,1), attribute_bytes)
			   attributeTree:set_text("Handshake Version Major: " .. "(0x" .. attribute_bytes .. ")")
			
			attribute_bytes = tostring(tvbuffer:range(10,1)):upper()
			attributeTree = subtreeitem:add(F_stunname, tvbuffer(10,1), attribute_bytes)
			   attributeTree:set_text("Handshake Version Minor: " .. "(0x" .. attribute_bytes .. ")")
			   
			attribute_bytes = tostring(tvbuffer:range(11,4)):upper()
			attributeTree = subtreeitem:add(F_stunname, tvbuffer(11,4), attribute_bytes)
			   attributeTree:set_text("Timestamp: " .. "(0x" .. attribute_bytes .. ")")
			   
			attribute_bytes = tostring(tvbuffer:range(15,28)):upper()
			attributeTree = subtreeitem:add(F_stunname, tvbuffer(15,28), attribute_bytes)
			   attributeTree:set_text("Random Value: " .. "(0x" .. attribute_bytes .. ")")

			sessionIdLength = tvbuffer(43,1):uint()
			
			attribute_bytes = tostring(tvbuffer:range(43,1)):upper()
			attributeTree = subtreeitem:add(F_stunname, tvbuffer(43,1), attribute_bytes)
			   attributeTree:set_text("Session ID Length: " .. "(0x" .. attribute_bytes .. ")")
			
			cipherSuiteLength = 0
			
			if sessionIdLength ~= 0 then
				attribute_bytes = tostring(tvbuffer:range(44,sessionIdLength)):upper()
				attributeTree = subtreeitem:add(F_stunname, tvbuffer(44,sessionIdLength), attribute_bytes)
				   attributeTree:set_text("Session ID: " .. "(0x" .. attribute_bytes .. ")")
				
			else
				cipherSuiteLength = tvbuffer(44+sessionIdLength,2):uint()
				
				attribute_bytes = tostring(tvbuffer:range(44+sessionIdLength,2)):upper()
				attributeTree = subtreeitem:add(F_stunname, tvbuffer(44+sessionIdLength,2), attribute_bytes)
				   attributeTree:set_text("Cipher Suite Length: " .. "(0x" .. attribute_bytes .. ")")
			end
						
			
			attribute_bytes = tostring(tvbuffer:range(44+sessionIdLength+cipherSuiteLength,2)):upper()
			attributeTree = subtreeitem:add(F_stunname, tvbuffer(44+sessionIdLength+cipherSuiteLength,2), attribute_bytes)
			   attributeTree:set_text("Cipher Suite: " .. "(0x" .. attribute_bytes .. ")")
			
			
			attribute_bytes = tostring(tvbuffer:range(46+sessionIdLength+cipherSuiteLength,1)):upper()
			attributeTree = subtreeitem:add(F_stunname, tvbuffer(46+sessionIdLength+cipherSuiteLength,1), attribute_bytes)
			   attributeTree:set_text("Compression Method: " .. "(0x" .. attribute_bytes .. ")")
			
			attribute_bytes = tostring(tvbuffer:range(47+sessionIdLength+cipherSuiteLength,1)):upper()
			attributeTree = subtreeitem:add(F_stunname, tvbuffer(47+sessionIdLength+cipherSuiteLength,1), attribute_bytes)
			   attributeTree:set_text("Handshake Type: " .. "(0x" .. attribute_bytes .. ")")
			
			--]]
			
			elseif frameCheck == 0x1703 then
			
			-- FALL BACK TO THE WIRESHARK STANDARD SSL/TLS DISSECTOR. DOES A LOT BETTER JOB THAN I DO OF DECODING TLS...

			original_ssl_dissector:call(tvbuffer, pinfo, treeitem)
			
			--[[
			--Set the Protcol and Info Columns
			pinfo.cols.protocol = "MSTLS"
			pinfo.cols.info = "TLS Traffic (Application Data)"	
			
			subtreeitem:add(F_stunname, tvbuffer(0,2), cmd_str)
						:set_text("TLS Application Data")
						
			attribute_bytes = tostring(tvbuffer:range(0,1)):upper()
			attributeTree = subtreeitem:add(F_stunname, tvbuffer(0,1), attribute_bytes)
			   attributeTree:set_text("Record Layer: " .. "(0x" .. attribute_bytes .. ")")
			
			local tlsversion = tvbuffer(1,2):uint()
			
			if tlsversion == 0x0003 then
				versionstring = "SSL v3"
			elseif tlsversion == 0x0301 then
				versionstring = "TLS v1.0"
			elseif tlsversion == 0x0302 then
				versionstring = "TLS v1.1"
			elseif tlsversion == 0x0303 then
				versionstring = "TLS v1.2"
			end
			
			attribute_bytes = tostring(tvbuffer:range(1,2)):upper()
			attributeTree = subtreeitem:add(F_stunname, tvbuffer(1,2), attribute_bytes)
			   attributeTree:set_text("Record Version: " .. versionstring .. " (0x" .. attribute_bytes .. ")")
			
			attribute_bytes = tostring(tvbuffer:range(3,2)):upper()
			attributeTree = subtreeitem:add(F_stunname, tvbuffer(3,2), attribute_bytes)
			   attributeTree:set_text("Record Length: " .. tvbuffer(3,2):uint() .. " Bytes " .. "(0x" .. attribute_bytes .. ")")
			   
			attributeTree = subtreeitem:add(F_attribute_sub, tvbuffer(5,tvbuffer:len()-5), cmd_str)
						attributeTree:set_text("Data: " .. tostring(tvbuffer(5,tvbuffer:len()-5)))
			
			--]]	

			elseif frameCheck == 0x1403 then
			--Assume TLS
			original_ssl_dissector:call(tvbuffer, pinfo, treeitem)
			
			elseif frameCheck == 0x1503 then
			--Assume TLS
			original_ssl_dissector:call(tvbuffer, pinfo, treeitem)
			
			elseif frameCheck == 0xFF80 then
			
			--Set the Protcol and Info Columns
			pinfo.cols.protocol = "MSREP"
			pinfo.cols.info = "LYNC EDGE INTERNAL REPLICATION DATA"	
			
			subtreeitem:add(F_stunname, tvbuffer(0,4), cmd_str)
						:set_text("Lync Replication Traffic - Proprietary Format")
			
			-- 0x4000 – 0xFFFF
			elseif frameCheckOffset  >= 0xFF00 and frameCheckOffset <= 0xFFFF then
			
			packetlength = tvbuffer:len()
			-- Channel Data messages should be less than 22 bytes in size.
			if(packetlength <= 22) then
			
				--Set the Protcol and Info Columns
				pinfo.cols.protocol = "STUN"
				pinfo.cols.info = "STUN ChannelData Message"	
				
				attribute_bytes = tostring(tvbuffer:range(0+tcpOffset,4)):upper()
				attributeTree = subtreeitem:add(F_stunname, tvbuffer(0+tcpOffset,4), attribute_bytes)
						   attributeTree:set_text("Channel Data Message")
							
				attribute_bytes = string.format("(0x%X)", tvbuffer(0+tcpOffset,2):uint())
							attributeTree:add(F_attribute_sub, tvbuffer(0+tcpOffset,2), attribute_bytes)
									:set_text("Channel Number: " .. attribute_bytes)
				
				attribute_bytes = string.format("(0x%X)", tvbuffer(2+tcpOffset,2):uint())
							attributeTree:add(F_attribute_sub, tvbuffer(2+tcpOffset,2), attribute_bytes)
									:set_text("Length: " .. attribute_bytes)
				
												
				port = tvbuffer(4+tcpOffset,2):uint()
					attribute_bytes = string.format("(0x%X)", tvbuffer(4+tcpOffset,2):uint())
					portstring = string.format("%i", port)
					attributeTree:add(F_attribute_sub, tvbuffer(4+tcpOffset,2), attribute_bytes)
						:set_text("STUN Port: " ..  portstring .. " " .. attribute_bytes) 
			
			
				-----------------------------------------------			
				-- Decode the 1024-65535 range ports from STUN
				-----------------------------------------------
				if prefs.port50000 then
					if port >= 1024 and port <= 65535 then
						attribute_bytes = string.format("(0x%X)", tvbuffer(4+tcpOffset,2):uint())
						attributeTree:add(F_attribute_sub, tvbuffer(4+tcpOffset,2), attribute_bytes)
							:set_text("(INFO: Added " ..  portstring .. " to decode.)")
						myproto_udp_init(port)
						myproto_tcp_init(port)
						--RTCP
						myproto_udp_init(port+1)
						myproto_tcp_init(port+1)					
					else
						attribute_bytes = string.format("(0x%X)", tvbuffer(4+tcpOffset,2):uint())
						attributeTree:add(F_attribute_sub, tvbuffer(4+tcpOffset,2), attribute_bytes)
							:set_text("(INFO: Not in 1024-65535 range. Have not added " ..  portstring .. " to decode.)")
					end
				else
					myproto_udp_remove_init(port)
					myproto_tcp_remove_init(port)
					myproto_udp_remove_init(port+1)
					myproto_tcp_remove_init(port+1)
				end
							
				port = tvbuffer(6+tcpOffset,2):uint()
					attribute_bytes = string.format("(0x%X)", tvbuffer(6+tcpOffset,2):uint())
					portstring = string.format("%i", port)
					attributeTree:add(F_attribute_sub, tvbuffer(6+tcpOffset,2), attribute_bytes)
						:set_text("STUN Port: " ..  portstring .. " " .. attribute_bytes) 
				
				-----------------------------------------------			
				-- Decode the 1024-65535 range ports from STUN
				-----------------------------------------------
				if prefs.port50000 then
					if port >= 1024 and port <= 65535 then
						attribute_bytes = string.format("(0x%X)", tvbuffer(4+tcpOffset,2):uint())
						attributeTree:add(F_attribute_sub, tvbuffer(4+tcpOffset,2), attribute_bytes)
							:set_text("(INFO: Added " ..  portstring .. " to decode.)")
						
						myproto_udp_init(port)
						myproto_tcp_init(port)
						--RTCP
						myproto_udp_init(port+1)
						myproto_tcp_init(port+1)					
					else
						attribute_bytes = string.format("(0x%X)", tvbuffer(4+tcpOffset,2):uint())
						attributeTree:add(F_attribute_sub, tvbuffer(4+tcpOffset,2), attribute_bytes)
							:set_text("(INFO: Not in 50000-65535 range. Have not added " ..  portstring .. " to decode.)")
					end
				else
					myproto_udp_remove_init(port)
					myproto_tcp_remove_init(port)
					myproto_udp_remove_init(port+1) -- RTCP Port
					myproto_tcp_remove_init(port+1) -- RTCP Port
				end
			end
			
			else  -- RTP Decode
			
				local datatype = tvbuffer(0+tcpOffset,1):uint()
			
				-- Check Data payload starts with 80 or 81 or 82 and assume RTP. This method whilst not ideal works in majority of cases with Lync / Skype for Business.
				if datatype == 128 or datatype == 129 or datatype == 130 then
					-- TCP FRAMING CHECK
					if f_tcp_srcport() ~= nil and f_tcp_dstport() ~= nil and tcpOffset == 0 then	
						
						-- Framing check failed so assume this isn't a TCP based RTP packet. Use SSL decoder if required.
						if f_tcp_srcport().value == 443 or f_tcp_dstport().value == 443 then
						
						original_ssl_dissector:call(tvbuffer, pinfo, treeitem)   --DECODE AS TLS
						
						else
						
						attributeTree = subtreeitem:add(F_stunname, tvbuffer(0+tcpOffset,1), attribute_bytes)
							   attributeTree:set_text("UNABLE TO DECODE THIS PACKET :(")
						
						end
					else					
						cmd_str = "RTP PACKET"
									
						local bytes = tvbuffer(1+tcpOffset,1):uint()
										
						attribute_bytes = tostring(tvbuffer:range(1+tcpOffset,1)):upper()
						attributeTree = subtreeitem:add(F_stunname, tvbuffer(1+tcpOffset,1), attribute_bytes)
							   attributeTree:set_text("RTP Message: " .. "Payload Type: " .. tostring((bit.band(bytes,0x7F)),2))
						
						
						local bits = tvbuffer(0+tcpOffset,1):uint()
						
						payload = bit.rshift(bit.band(bits,0xC0),6)
						
						att_str = "RTP PAYLOAD TYPE"
						if payload == 1 then
								att_str = "Version 1"
							elseif payload == 2 then
								att_str = "Version 2"
						end
						attributeTree:add(F_attribute_sub, tvbuffer(0+tcpOffset,1), cmd_str)
								:set_text("RTP Version (2 bits): " .. att_str .. " (" .. tostring(payload) .. ")")
								
						attributeTree:add(F_attribute_sub, tvbuffer(0+tcpOffset,1), cmd_str)
								:set_text("padding (1 bit): 0x" .. tostring(bit.tohex((bit.band(bits,0x20)),2)))
						
						attributeTree:add(F_attribute_sub, tvbuffer(0+tcpOffset,1), cmd_str)
								:set_text("Extension (1 bit): 0x" .. tostring(bit.tohex((bit.band(bits,0x10)),2)))
						
						
						attributeTree:add(F_attribute_sub, tvbuffer(0+tcpOffset,1), cmd_str)
								:set_text("CSRC count (4 bits): 0x" .. tostring(bit.tohex((bit.band(bits,0x0F)),2)))
						
						local byte = tvbuffer(1+tcpOffset,1):uint()
						
						attributeTree:add(F_attribute_sub, tvbuffer(1+tcpOffset,1), cmd_str)
								:set_text("Marker (1 bit): 0x" .. tostring(bit.tohex((bit.band(byte,0x80)),2)))
										
						
							-- Can't decode payloads because of encryption :(	
							--0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
							--+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
							--|V=2|P|X| CC |M| PT | sequence number |
							--| | | | |0| 101 | |
							--+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
							--| timestamp |
							--| |
							--+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
							--| synchronization source (SSRC) identifier |
							--| |
							--+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
							--| event |E R| volume | duration |
							--| 1 |1 0| 20 | 1760 |
							--+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+					
						
						payload = bit.band(byte,0x7F)
						
						att_str = "RTP PAYLOAD TYPE"
						if payload == 0 then
								att_str = "G.711 u-Law"
							elseif payload == 3 then
								att_str = "GSM 6.10"
							elseif payload == 4 then
								att_str = "G.723.1 "
							elseif payload == 8 then
								att_str = "G.711 A-Law"
							elseif payload == 9 or payload == 117 then
								att_str = "G.722"
							elseif payload == 13 then
								att_str = "Comfort Noise"
							elseif payload == 97 then
								att_str = "Redundant Audio Data Payload (FEC)"
							elseif payload == 101 then
								att_str = "DTMF"
							elseif payload == 103 then
									att_str = "SILK Narrow"
							elseif payload == 104 then
									att_str = "SILK Wideband"
							elseif payload == 111 then
								att_str = "Siren"
							elseif payload == 112 then
								att_str = "G.722.1"
							elseif payload == 114 then
								att_str = "RT Audio Wideband"
							elseif payload == 115 then
								att_str = "RT Audio Narrowband"
							elseif payload == 116 then
								att_str = "G.726"
							elseif payload == 118 then
								att_str = "Comfort Noise Wideband"
							elseif payload == 34 then
								att_str = "H.263 [MS-H26XPF]"
							elseif payload == 121 then
								att_str = "RT Video"
							elseif payload == 122 then
								att_str = "H.264 [MS-H264PF]"
							elseif payload == 123 then
								att_str = "H.264 FEC [MS-H264PF]"
							elseif payload == 127 then
								att_str = "x-data"
							else
								att_str = "Unknown Codec"
								
								--IF IT'S ON PORT 443 THEN ASSUME THEN TRY THE TLS DECODER
								if f_tcp_srcport() ~= nil and f_tcp_dstport() ~= nil then
									if f_tcp_srcport().value == 443 or f_tcp_dstport().value == 443 then
									original_ssl_dissector:call(tvbuffer, pinfo, treeitem)   --DECODE AS TLS
									end
								end
						end

						attributeTree:add(F_attribute_sub, tvbuffer(1+tcpOffset,1), cmd_str)
								:set_text("Payload Type (7 bits): " .. att_str .. " (" .. tostring(payload) .. ")")
						
						--Set the Protcol and Info Columns
						if(att_str ~= "Unknown Codec") then
							pinfo.cols.protocol = "MSRTP"
							pinfo.cols.info = "RTP PACKET : Payload Type = " .. att_str			
						end
						
						local bytes = tvbuffer(2+tcpOffset,2):uint()
										
						attributeTree:add(F_stunname, tvbuffer(2+tcpOffset,2), bytes)
							   :set_text("Sequence Number: " .. bytes)
						
						local bytes = tvbuffer(4+tcpOffset,4):uint()
												
						attributeTree:add(F_stunname, tvbuffer(4+tcpOffset,4), bytes)
							   :set_text("Timestamp: " .. tostring(bytes))
							   
						attributeTree:add(F_attribute_sub, tvbuffer(8+tcpOffset,tvbuffer:len()-8-tcpOffset), cmd_str)
								:set_text("Payload: " .. tostring(tvbuffer(8+tcpOffset,tvbuffer:len()-8-tcpOffset)))
					end
				else
					--IF WE HAVE MADE IT ALL THE WAY THOUGH AND PORT 443 IS BEING USED THEN ASSUME IT'S TLS
					if f_tcp_srcport() ~= nil and f_tcp_dstport() ~= nil then
						if f_tcp_srcport().value == 443 or f_tcp_dstport().value == 443 then
						
						original_ssl_dissector:call(tvbuffer, pinfo, treeitem)   --DECODE AS TLS
						
						else
						
						attributeTree = subtreeitem:add(F_stunname, tvbuffer(0+tcpOffset,1), attribute_bytes)
							   attributeTree:set_text("UNABLE TO DECODE THIS PACKET :(")
						
						end
					end
				end
			end
		end	
	end -- 2.0 Buffer size check
	end	
		
	
	-- Fast XOR Arno Wagner <arno@wagner.name>
	function bin_xor(x, y)
	   local z = 0
	   for i = 0, 31 do
		  if (x % 2 == 0) then                      -- x had a '0' in bit i
			 if ( y % 2 == 1) then                  -- y had a '1' in bit i
				y = y - 1 
				z = z + 2 ^ i                       -- set bit i of z to '1' 
			 end
		  else                                      -- x had a '1' in bit i
			 x = x - 1
			 if (y % 2 == 0) then                  -- y had a '0' in bit i
				z = z + 2 ^ i                       -- set bit i of z to '1' 
			 else
				y = y - 1 
			 end
		  end
		  y = y / 2
		  x = x / 2
	   end
	   return z
	end
	
	-- Convert Byte to BitArray ####################################################
	function to_bits(n)
	 --check_int(n)
	 --if(n < 0) then
	  -- negative
	  --return to_bits(bit.bnot(math.abs(n)) + 1)
	 --end

	 -- to bits table
	 local tbl = {}
	 local cnt = 1
	 while (n > 0) do
	 --CHANGED FOR 2.0 - mod not supported anymore
	  --local last = math.mod(n,2)
	  local last = math.fmod(n,2)
	  if(last == 1) then
	   tbl[cnt] = 1
	  else
		tbl[cnt] = 0
	  end
	  n = (n-last)/2
	  cnt = cnt + 1
	 end
	 return tbl
	end
	
	original_udp_port = prefs.udpprotocolport
	original_tcp_port = prefs.tcpprotocolport
	
    local udp_dissector_table = DissectorTable.get("udp.port")
    original_stun_dissector = udp_dissector_table:get_dissector(original_udp_port) -- save the original dissector so we can still get to it
    
	local tcp_dissector_table = DissectorTable.get("tcp.port")
	original_tcp_stun_dissector = tcp_dissector_table:get_dissector(original_tcp_port) -- save the original dissector so we can still get to it
		
		
	function lync_wrapper_proto.init() --Preference Update
		if original_udp_port ~= prefs.udpprotocolport then
			udp_dissector_table:add(original_udp_port, original_stun_dissector)
			udp_dissector_table:add(prefs.udpprotocolport, lync_wrapper_proto)
		end
		
		if original_tcp_port ~= prefs.tcpprotocolport then
			tcp_dissector_table:add(original_tcp_port, original_tcp_stun_dissector)
			tcp_dissector_table:add(prefs.tcpprotocolport, lync_wrapper_proto)
		end
		
		if prefs.port50000 and prefs.port3478 then
			
			--Add dissector for 3478
			udp_dissector_table:add(prefs.udpprotocolport, lync_wrapper_proto)
		
		elseif not prefs.port50000 and prefs.port3478 then
			
			--Add dissector for 3478
			udp_dissector_table:add(prefs.udpprotocolport, lync_wrapper_proto)
			
		elseif prefs.port50000 and not prefs.port3478 then
			
			--Remove dissector for 3478
			udp_dissector_table:remove(prefs.udpprotocolport, lync_wrapper_proto)
					
		else
			--Reset to initial dissector
			udp_dissector_table:add(original_udp_port, original_stun_dissector)	
		end
		
		--Setup TCP Dissector
		if prefs.port443 then
			tcp_dissector_table:add(prefs.tcpprotocolport, lync_wrapper_proto)
		else
			tcp_dissector_table:add(original_tcp_port, original_tcp_stun_dissector)
		end
		
		if prefs.portexternal443 then
			tcp_dissector_table:add(prefs.tcpexternalprotocolport, lync_wrapper_proto)
		else
			tcp_dissector_table:add(original_tcp_port, original_tcp_stun_dissector)
		end
		
		
	end
	
	function myproto_udp_init(port)
		-- load the udp.port table
		udp_table = DissectorTable.get("udp.port")
		-- register the protocol to handle rtp port dynamically
		udp_table:add(port,lync_wrapper_proto)
	end
	
	function myproto_udp_remove_init(port)
		-- load the udp.port table
		udp_table = DissectorTable.get("udp.port")
		-- register the protocol to handle rtp port dynamically
		udp_table:remove(port,lync_wrapper_proto)
	end
	
	function myproto_tcp_init(port)
		-- load the udp.port table
		tcp_table = DissectorTable.get("tcp.port")
		-- register the protocol to handle rtp port dynamically
		tcp_table:add(port,lync_wrapper_proto)
	end
	
	function myproto_tcp_remove_init(port)
		-- load the tcp.port table
		tcp_table = DissectorTable.get("tcp.port")
		-- register the protocol to handle rtp port dynamically
		tcp_table:remove(port,lync_wrapper_proto)
	end
end
