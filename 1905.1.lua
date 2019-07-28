-- This is an IEEE 1905.1 protocol dissector for Wireshark written in the Lua
-- scripting language.
-- 
-- Installation
-- *************
-- Shutdown wireshark. Copy this file into the installation directory given
-- below.
--
-- Windows
-- -------
-- The installation directory can be selected among the following:
-- C:\Program Files\Wireshark\plugins\1.12.0\ 
--     Copying files there, needs Administrator privileges.
-- C:\Users\[username]\AppData\Roaming\Wireshark\plugins
--     No Admin privileges needed.
--
-- Linux
-- -----
-- The installation directory is: /usr/lib/wireshark/plugins/
--
-- Test
-- ****
-- Launch wireshark. If the dissector loaded correctly, the IEEE 1905.1
-- protocol appears in the supported protocols list. This list can be shown by
-- selecting "Internals | Supported protocols" menu item in the wireshark
-- application.
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.
--
-- Author: Oliver Maye
--         IHP GmbH, Frankfurt (Oder), Germany
-- Date  : 28. October 2014
--


-- declare protocol + version
local version_string = "1.7.20150108"
local cdhnp_proto = Proto("ieee_1905.1","IEEE 1905.1 Standard for a Convergent Digital Home Network (" .. version_string .. ")")

-- translation tables used for some of the fields
local tab_msg_type = {
                [0] = "Topology discovery",
                [1] = "Topology notification",
                [2] = "Topology query",
                [3] = "Topology response",
                [4] = "Vendor specific",
                [5] = "Link metric query",
                [6] = "Link metric response",
                [7] = "AP-autoconfiguration search",
                [8] = "AP-autoconfiguration response",
                [9] = "AP-autoconfiguration WiFi simple configuration (WSC)",
                [10] = "AP-autoconfiguration renew",
                [11] = "1905.1 push button event notification",
                [12] = "1905.1 push button join notification",
        }

local tab_tlv_type = {
                [0] = "End of message",
                [1] = "1905.1 abstraction layer MAC address",
                [2] = "Interface MAC address",
                [3] = "Device information",
                [4] = "Device bridging capability",
                [6] = "Non-1905 neighbor device list",
                [7] = "Neighbor device",
                [8] = "Link metric query",
                [9] = "Transmitter link metric",
                [10] = "Receiver link metric",
                [11] = "Vendor specific",
                [12] = "Link metric result",
                [13] = "Autoconfig role",
                [14] = "Autoconfig frequency band",
                [15] = "Supported role",
                [16] = "Supported frequency band",
                [17] = "WiFi simple configuration (WSC)",
                [18] = "Push button event notification",
                [19] = "Push button join notification"
        }

local tab_media_type = {
                [0x0000] = "IEEE 802.3u Fast Ethernet",
                [0x0001] = "IEEE 802.3ab Gigabit Ethernet",
                [0x0100] = "IEEE 802.11b (2.4 GHz)",
                [0x0101] = "IEEE 802.11g (2.4 GHz)",
                [0x0102] = "IEEE 802.11a (5 GHz)",
                [0x0103] = "IEEE 802.11n (2.4 GHz)",
                [0x0104] = "IEEE 802.11n (5 GHz)",
                [0x0105] = "IEEE 802.11ac (5 GHz)",
                [0x0106] = "IEEE 802.11ad (60 GHz)",
                [0x0107] = "IEEE 802.11af (Whitespace)",
                [0x0200] = "IEEE 1901 Wavelet",
                [0x0201] = "IEEE 1901 FFT",
                [0x0300] = "MoCA v1.1",
                [0xFFFF] = "Unknown media",
        }

local tab_mi_ieee_role = {
                [0] = "Access point",
                [1] = "Reserved value",
                [2] = "Reserved value",
                [3] = "Reserved value",
                [4] = "non-AP / non-PCP STA",
                [8] = "WiFi P2P Client",
                [9] = "WiFi P2P Group owner",
                [10] = "802.11ad PCP",
                [11] = "Reserved value",
                [0xFF] = "Reserved value"
        }

local tab_lm_nbor = {
                [0] = "All neighbors",
                [1] = "Specific neighbor",
                [2] = "Reserved value",
                [0xFF] = "Reserved value"
        }

local tab_lm_req = {
                [0] = "Tx link metrics only",
                [1] = "Rx link metrics only",
                [2] = "Both, Tx and Rx link metrics",
                [0xFF] = "Reserved value"
        }

local tab_lm_result = {
                [0] = "Invalid neighbor",
                [1] = "Reserved value",
                [0xFF] = "Reserved value"
        }

local tab_role = {
                [0] = "Registrar",
                [1] = "Reserved value",
                [0xFF] = "Reserved value"
        }

local tab_freq_band = {
                [0] = "802.11 2.4 GHz",
                [1] = "802.11 5 GHz",
                [2] = "802.11 60 GHz",
                [3] = "Reserved value",
                [0xFF] = "Reserved value"
        }


--declare fields
local pf_message_version = ProtoField.uint8( "cdhnp.msg_ver", "Message Version", base.HEX )
local pf_reserved = ProtoField.uint8( "cdhnp.reserved", "Reserved", base.HEX )
local pf_message_type = ProtoField.uint16( "cdhnp.msg_type", "Message Type", base.DEC, tab_msg_type )
local pf_message_id = ProtoField.uint16( "cdhnp.msg_id", "Message ID", base.HEX )
local pf_fragment_id = ProtoField.uint8( "cdhnp.frag_id", "Fragment ID", base.HEX )
local pf_indicators = ProtoField.uint8( "cdhnp.indicators", "Indicators", base.HEX )
local fl_ind_lastFragment = ProtoField.bool( "cdhnp.indicators.lastFragment", "Last Fragment", 2, nil, 0x80)
local fl_ind_relay = ProtoField.bool( "cdhnp.indicators.relay", "Relay", 2, nil, 0x40 )
local pf_tlv = ProtoField.bytes( "cdhnp.tlv", "TLV" )
local pf_excess_data = ProtoField.bytes( "cdhnp.excess.data", "Excess data" )
local pf_padding = ProtoField.bytes( "cdhnp.padding", "Padding" )
local pf_generic_num8 = ProtoField.uint8( "cdhnp.generic.num8", "Number", base.DEC )

local pf_tlv_type = ProtoField.uint8( "cdhnp.tlv.type", "TLV type", base.HEX, tab_tlv_type )
local pf_tlv_len  = ProtoField.uint16( "cdhnp.tlv.length", "TLV length", base.DEC )
local pf_tlv_value= ProtoField.bytes( "cdhnp.tlv.value", "TLV value" )

local pf_tlv_vs_oui  = ProtoField.uint32( "cdhnp.tlv.vs.oui", "Vendor specific OUI", base.HEX )
local pf_tlv_vs_info = ProtoField.bytes( "cdhnp.tlv.vs.info", "Vendor specific information" )
local pf_tlv_mac = ProtoField.ether( "cdhnp.tlv.mac", "EUI-48" )
local pf_tlv_mac_tx = ProtoField.ether( "cdhnp.tlv.mac.tx", "MAC address of transmitter" )
local pf_tlv_mac_rx = ProtoField.ether( "cdhnp.tlv.mac.rx", "MAC address of receiver" )
local pf_tlv_mac_nbor = ProtoField.ether( "cdhnp.tlv.mac.nbor", "MAC address of neighbor" )
local pf_tlv_num_if = ProtoField.uint8( "cdhnp.tlv.num.if", "Number of interfaces", base.DEC )
local pf_tlv_if_info = ProtoField.bytes( "cdhnp.tlv.if.info", "Interface info" )
local pf_tlv_media_type = ProtoField.uint16( "cdhnp.tlv.media.type", "Media type", base.HEX, tab_media_type )
local pf_tlv_media_info_len = ProtoField.bytes( "cdhnp.tlv.media.info.len", "Length of media specific information" )
local pf_tlv_media_info = ProtoField.bytes( "cdhnp.tlv.media.info", "Media specific information" )
local pf_tlv_mi_ieee_role = ProtoField.uint8( "cdhnp.tlv.mi.ieee.role", "Role", base.HEX, tab_mi_ieee_role, 0xF0 )
local pf_tlv_mi_ieee_bw = ProtoField.uint8( "cdhnp.tlv.mi.ieee.bw", "Channel bandwidth", base.HEX )
local pf_tlv_mi_ieee_idx1 = ProtoField.uint8( "cdhnp.tlv.mi.ieee.idx1", "Center frequency index 1", base.HEX )
local pf_tlv_mi_ieee_idx2 = ProtoField.uint8( "cdhnp.tlv.mi.ieee.idx2", "Center frequency index 2", base.HEX )
local pf_tlv_bridge_tuple = ProtoField.bytes( "cdhnp.tlv.bridging.tuple", "Bridging tuple" )
local pf_tlv_bridge_exist = ProtoField.bool( "cdhnp.tlv.bridging.exist", "Bridge exists", 1, nil, 0x80)
local pf_tlv_nbor_info = ProtoField.bytes( "cdhnp.tlv.nbor.info", "Neighbor info" )
local pf_tlv_lm_nbor = ProtoField.uint8( "cdhnp.tlv.lm.nbor", "Neighbor", base.HEX, tab_lm_nbor )
local pf_tlv_lm_req = ProtoField.uint8( "cdhnp.tlv.lm.req", "Link metrics requested", base.HEX, tab_lm_req )
local pf_tlv_lm_brex = ProtoField.bool( "cdhnp.tlv.bridging.exist", "IEEE 802.1 bridge", 8, nil, 0xFF)
local pf_tlv_lm_pkt_err = ProtoField.uint32( "cdhnp.tlv.lm.pkt.err", "Packet errors", base.DEC )
local pf_tlv_lm_pkt_tx = ProtoField.uint32( "cdhnp.tlv.lm.pkt.tx", "Packets transmitted", base.DEC )
local pf_tlv_lm_mac_cap = ProtoField.uint16( "cdhnp.tlv.lm.mac.cap", "MAC throughput capacity (Mb/s)", base.DEC )
local pf_tlv_lm_avail = ProtoField.uint16( "cdhnp.tlv.lm.avail", "Link availability (%)", base.DEC )
local pf_tlv_lm_phy_rate = ProtoField.uint16( "cdhnp.tlv.lm.phy.rate", "PHY rate (Mb/s)", base.DEC )
local pf_tlv_lm_pkt_rx = ProtoField.uint32( "cdhnp.tlv.lm.pkt.rx", "Packets received", base.DEC )
local pf_tlv_lm_rssi = ProtoField.uint8( "cdhnp.tlv.lm.rssi", "RSSI (dB)", base.DEC )
local pf_tlv_lm_result = ProtoField.uint8( "cdhnp.tlv.lm.result", "Link metric result code", base.HEX, tab_lm_result )
local pf_tlv_role = ProtoField.uint8( "cdhnp.tlv.role", "Role", base.HEX, tab_role )
local pf_tlv_freq_band = ProtoField.uint8( "cdhnp.tlv.freq.band", "Frequency band", base.HEX, tab_freq_band)
local pf_tlv_wsc= ProtoField.bytes( "cdhnp.tlv.wsc", "WSC frame" )

cdhnp_proto.fields = { pf_message_version, pf_reserved, pf_message_type, pf_message_id,
                       pf_fragment_id, pf_indicators,
                            fl_ind_lastFragment, fl_ind_relay,
                       pf_tlv, pf_excess_data, pf_padding, pf_generic_num8, 
                            pf_tlv_type, pf_tlv_len, pf_tlv_value,
                            pf_tlv_vs_oui, pf_tlv_vs_info, pf_tlv_mac, pf_tlv_num_if,
                            pf_tlv_if_info, pf_tlv_media_type, pf_tlv_media_info_len, pf_tlv_media_info,
                            pf_tlv_mi_ieee_role, pf_tlv_mi_ieee_bw,
                            pf_tlv_mi_ieee_idx1, pf_tlv_mi_ieee_idx2, pf_tlv_bridge_tuple,
                            pf_tlv_bridge_exist, pf_tlv_nbor_info, pf_tlv_lm_nbor, pf_tlv_lm_req, pf_tlv_mac_tx,
                            pf_tlv_mac_rx, pf_tlv_mac_nbor, pf_tlv_lm_brex, pf_tlv_lm_pkt_err, 
                            pf_tlv_lm_pkt_tx, pf_tlv_lm_mac_cap, pf_tlv_lm_avail,
                            pf_tlv_lm_phy_rate, pf_tlv_lm_pkt_rx, pf_tlv_lm_rssi,
                            pf_tlv_lm_result, pf_tlv_role, pf_tlv_freq_band, pf_tlv_wsc }

-- Constants
local CDHNP_MIN_LEN = 50

-- create a function to dissect it
function cdhnp_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "IEEE 1905.1"
    local subtree = tree:add(cdhnp_proto, buffer(), "IEEE 1905.1 Protocol Data")
    local has_eof_tlv = false
    
    if buffer:len() >= 1 then
    	subtree:add( pf_message_version, buffer:range(0,1) )
    end
    if buffer:len() >= 2 then
	    subtree:add( pf_reserved, buffer(1,1) )
    end
    if buffer:len() >= 4 then
	    subtree:add( pf_message_type, buffer:range(2,2) )
	    pinfo.cols.info:set(tab_msg_type[buffer:range(2,2):uint()])
	else
    	pinfo.cols.info:set("--Erroneous--")
    end
    if buffer:len() >= 6 then
    	subtree:add( pf_message_id, buffer:range(4,2) )
    end
    if buffer:len() >= 7 then
	    subtree:add( pf_fragment_id, buffer:range(6,1) )
    end
    if buffer:len() >= 8 then
	    local ind_tree = subtree:add( pf_indicators, buffer:range(7,1) )
	    ind_tree:add(fl_ind_lastFragment, buffer:range(7,1) )
	    ind_tree:add(fl_ind_relay, buffer:range(7,1) )
	else
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "CMDU header too short")
        return
    end
    
    local offset = 8
    while offset < buffer:len() do
      if (offset+3) > buffer:len() then
        local tlv_tree = subtree:add(pf_tlv, buffer:range(offset, buffer:len()-offset) )
        tlv_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "TLV too short.")
        break
      end
      local tlv_type = buffer:range(offset, 1):uint()
      local tlv_len = buffer:range(offset+1,2):uint()
      if offset+3+tlv_len > buffer:len() then
        local tlv_tree = subtree:add(pf_tlv, buffer:range(offset, buffer:len()-offset) )
        tlv_tree:add( pf_tlv_type, buffer:range(offset,1) )
        tlv_tree:add( pf_tlv_len, buffer:range(offset+1,2) )
        tlv_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "TLV length exceeds packet size.")
        break
      end
      local tlv_tree = subtree:add(pf_tlv, buffer:range(offset, 3+tlv_len) )
      local tlv_num_if=0
      if tab_tlv_type[tlv_type]~=nil then
        tlv_tree:set_text( "TLV: "..tab_tlv_type[tlv_type] )
      end
      tlv_tree:add( pf_tlv_type, buffer:range(offset, 1) )
      tlv_tree:add( pf_tlv_len, buffer:range(offset+1,2) )
      
      if tlv_type==0 then
        has_eof_tlv = true
        if tlv_len~=0 then
          tlv_tree:add_expert_info(PI_PROTOCOL, PI_WARN, "Length is not zero!")
        end
        offset = offset + 3
        if offset < buffer:len() then
        	if buffer:len() <= CDHNP_MIN_LEN then
	        	subtree:add_expert_info(PI_UNDECODED, PI_CHAT, "Ethernet padding follows.")
	        	subtree:add( pf_padding, buffer:range(offset, buffer:len()-offset) )
	        elseif offset < CDHNP_MIN_LEN then
	        	subtree:add_expert_info(PI_UNDECODED, PI_CHAT, "Ethernet padding follows.")
	        	subtree:add( pf_padding, buffer:range(offset, CDHNP_MIN_LEN-offset) )
        		subtree:add_expert_info(PI_SECURITY, PI_WARN, "Padding followed by further packet data.")
	        	subtree:add( pf_excess_data, buffer:range(CDHNP_MIN_LEN, buffer:len()-CDHNP_MIN_LEN) )
			else
        		subtree:add_expert_info(PI_SECURITY, PI_WARN, "End of message TLV followed by further packet data.")
	        	subtree:add( pf_excess_data, buffer:range(offset, buffer:len()-offset) )
	        end
        end
        break
      elseif tlv_type==1 then
        tlv_tree:add( pf_tlv_mac, buffer:range(offset+3,6) )
      elseif tlv_type==2 then
        tlv_tree:add( pf_tlv_mac, buffer:range(offset+3,6) )
      elseif tlv_type==3 then
        tlv_tree:add( pf_tlv_mac, buffer:range(offset+3,6) )
        tlv_tree:add( pf_tlv_num_if, buffer:range(offset+9,1) )
        tlv_num_if=buffer:range(offset+9,1):uint()
        local local_offset=offset+10
        local media_type=0
        for k=1, tlv_num_if do
          local local_n = buffer:range(local_offset+6+2,1):uint()
          local if_tree = tlv_tree:add( pf_tlv_if_info, buffer:range(local_offset,6+2+1+local_n) )
          if_tree:set_text("Interface #" .. k)
          if_tree:add( pf_tlv_mac, buffer:range(local_offset,6) )
          if_tree:add( pf_tlv_media_type, buffer:range(local_offset+6,2) )
          media_type = buffer:range(local_offset+6,2):uint()
          if_tree:add( pf_tlv_media_info_len, buffer:range(local_offset+6+2,1) )
          local mi_tree = if_tree:add( pf_tlv_media_info, buffer:range(local_offset+9,local_n) )
          if media_type>=0x0100 and media_type<=0x0107 and local_n>=10 then
            local bssid_mac = buffer:range(local_offset+9, 6):ether()
            mi_tree:add( pf_tlv_mac, buffer:range(local_offset+9, 6) ):set_text("BSSID: " .. tostring(bssid_mac) )
            mi_tree:add( pf_tlv_mi_ieee_role, buffer:range(local_offset+15, 1) )
            mi_tree:add( pf_tlv_mi_ieee_bw, buffer:range(local_offset+16, 1) )
            mi_tree:add( pf_tlv_mi_ieee_idx1, buffer:range(local_offset+17, 1) )
            mi_tree:add( pf_tlv_mi_ieee_idx2, buffer:range(local_offset+18, 1) )
          end
          local_offset = local_offset+6+2+1+local_n
        end
      elseif tlv_type==4 then
        local local_m = buffer:range( offset+3, 1):uint()
        tlv_tree:add( pf_generic_num8, buffer:range( offset+3, 1) ):set_text("Number of bridging tuples: " .. local_m)
        local local_offset=offset+3+1
        for m=1, local_m do
          local local_k = buffer:range( local_offset, 1):uint()
          local tuple_tree = tlv_tree:add( pf_tlv_bridge_tuple, buffer:range(local_offset,1+6*local_k) )
          tuple_tree:set_text("Bridging tuple #" .. m)
          tuple_tree:add( pf_generic_num8, buffer:range( local_offset, 1) ):set_text("Number of MAC addresses in this bridging tuple: " .. local_k)
          local_offset = local_offset+1
          for k=1, local_k do
            tuple_tree:add( pf_tlv_mac, buffer:range(local_offset,6) )
            local_offset = local_offset+6
          end
        end
      elseif tlv_type==6 then
		if tlv_len<6 then
			tlv_tree:add_expert_info(PI_PROTOCOL, PI_ERROR, "MAC address of the local interface missing/malformed.")
		else
			tlv_tree:add( pf_tlv_mac, buffer:range(offset+3,6) )
            local local_offset=offset+3+6
            while local_offset+6 <= offset+3+tlv_len do
              tlv_tree:add( pf_tlv_mac_nbor, buffer:range(local_offset,6) )
              local_offset = local_offset+6
            end
            if local_offset < offset + 3 + tlv_len then
              local xtra_tree
              xtra_tree = tlv_tree:add( pf_excess_data, buffer:range(local_offset, offset+3+tlv_len-local_offset) )
              xtra_tree:add_expert_info(PI_SECURITY, PI_WARN, "TLV has extra data that cannot be interpreted!")
            end
		end
      elseif tlv_type==7 then
          if tlv_len<6 then
            tlv_tree:add_expert_info(PI_PROTOCOL, PI_ERROR, "MAC address of the local interface missing/malformed.")
          else
            tlv_tree:add( pf_tlv_mac, buffer:range(offset+3,6) )
            local local_offset=offset+3+6
            local nbor_num=0
            local nbor_tree
            while local_offset+7 <= offset+3+tlv_len do
              nbor_tree = tlv_tree:add( pf_tlv_nbor_info, buffer:range( local_offset, 7 ))
              nbor_num = nbor_num+1
              nbor_tree:set_text("Neighbor #" .. nbor_num)
              nbor_tree:add( pf_tlv_mac_nbor, buffer:range(local_offset,6) )
              nbor_tree:add( pf_tlv_bridge_exist, buffer:range(local_offset+6,1)  )
              local_offset = local_offset+7
            end
            if local_offset < offset + 3 + tlv_len then
              nbor_tree = tlv_tree:add( pf_excess_data, buffer:range(local_offset, offset+3+tlv_len-local_offset) )
              nbor_tree:add_expert_info(PI_SECURITY, PI_WARN, "TLV has extra data that cannot be interpreted!")
            end
          end
      elseif tlv_type==8 then
          local nbor=buffer:range( offset+3, 1):uint()
          tlv_tree:add( pf_tlv_lm_nbor, buffer:range(offset+3,1) )
          if nbor==1 then
            tlv_tree:add( pf_tlv_mac, buffer:range(offset+3+1,6) )
          elseif tlv_len>2 then
              local xtra_tree = tlv_tree:add( pf_excess_data, buffer:range(offset+3+1, tlv_len-2) )
              xtra_tree:add_expert_info(PI_SECURITY, PI_WARN, "TLV has extra data - superfluous AL neighbor mac address .... ?")
          end
          tlv_tree:add( pf_tlv_lm_req, buffer:range(offset+3+tlv_len-1,1) )
      elseif tlv_type==9 then
          tlv_tree:add( pf_tlv_mac_tx, buffer:range(offset+3,6) )
          tlv_tree:add( pf_tlv_mac_nbor, buffer:range(offset+3+6,6) )
          for local_offset=offset+15, offset+tlv_len+2, 29 do
          	if local_offset+29 > offset+3+tlv_len then
              local xtra_tree = tlv_tree:add( pf_excess_data, buffer:range(local_offset, offset+3+tlv_len-local_offset) )
              xtra_tree:add_expert_info(PI_SECURITY, PI_WARN, "TLV has extra data or malformed interface pair.")
          	else
	            local ifpair_tree = tlv_tree:add( pf_tlv_value, buffer:range(local_offset,29) )
	            ifpair_tree:set_text("Interface pair")
	            ifpair_tree:add( pf_tlv_mac_rx, buffer:range(local_offset,6) )
	            ifpair_tree:add( pf_tlv_mac_nbor, buffer:range(local_offset+6,6) )
	            ifpair_tree:add( pf_tlv_media_type, buffer:range(local_offset+12,2) )
	            ifpair_tree:add( pf_tlv_lm_brex, buffer:range(local_offset+14,1) )
	            ifpair_tree:add( pf_tlv_lm_pkt_err, buffer:range(local_offset+15,4) )
	            ifpair_tree:add( pf_tlv_lm_pkt_tx, buffer:range(local_offset+19,4) )
	            ifpair_tree:add( pf_tlv_lm_mac_cap, buffer:range(local_offset+23,2) )
	            ifpair_tree:add( pf_tlv_lm_avail, buffer:range(local_offset+25,2) )
	            ifpair_tree:add( pf_tlv_lm_phy_rate, buffer:range(local_offset+27,2) )
	        end
          end
      elseif tlv_type==10 then
          tlv_tree:add( pf_tlv_mac_tx, buffer:range(offset+3,6) )
          tlv_tree:add( pf_tlv_mac_nbor, buffer:range(offset+3+6,6) )
          for local_offset=offset+15, offset+tlv_len+2, 23 do
          	if local_offset+23 > offset+3+tlv_len then
              local xtra_tree = tlv_tree:add( pf_excess_data, buffer:range(local_offset, offset+3+tlv_len-local_offset) )
              xtra_tree:add_expert_info(PI_SECURITY, PI_WARN, "TLV has extra data or malformed interface pair.")
          	else
	            local ifpair_tree = tlv_tree:add( pf_tlv_value, buffer:range(local_offset,23) )
	            ifpair_tree:set_text("Interface pair")
	            ifpair_tree:add( pf_tlv_mac_rx, buffer:range(local_offset,6) )
	            ifpair_tree:add( pf_tlv_mac_nbor, buffer:range(local_offset+6,6) )
	            ifpair_tree:add( pf_tlv_media_type, buffer:range(local_offset+12,2) )
	            ifpair_tree:add( pf_tlv_lm_pkt_err, buffer:range(local_offset+14,4) )
	            ifpair_tree:add( pf_tlv_lm_pkt_rx, buffer:range(local_offset+18,4) )
	            ifpair_tree:add( pf_tlv_lm_rssi, buffer:range(local_offset+22,1) )
            end
          end
      elseif tlv_type==11 then
        tlv_tree:add( pf_tlv_vs_oui, buffer:range(offset+3,3) )
        tlv_tree:add( pf_tlv_vs_info, buffer:range(offset+3+3, tlv_len-3) )
      elseif tlv_type==12 then
        tlv_tree:add( pf_tlv_lm_result, buffer:range(offset+3, 1) )
      elseif tlv_type==13 or tlv_type==15 then
        tlv_tree:add( pf_tlv_role, buffer:range(offset+3, 1) )
      elseif tlv_type==14 or tlv_type==16 then
        tlv_tree:add( pf_tlv_freq_band, buffer:range(offset+3, 1) )
      elseif tlv_type==17 then
        tlv_tree:add( pf_tlv_wsc, buffer:range(offset+3, tlv_len) )
      elseif tlv_type==18 then
        local local_m = buffer:range( offset+3, 1):uint()
        local local_offset=offset+3+1
        local media_type=0
        for m=1, local_m do
          tlv_tree:add( pf_tlv_media_type, buffer:range(local_offset, 2) )
          media_type = buffer:range(local_offset, 2):uint()
          local local_k = buffer:range( local_offset+2, 1):uint()
          if local_k > 0 then
            local mi_tree = tlv_tree:add( pf_tlv_media_info, buffer:range(local_offset+3, local_k) )
            if media_type>=0x0100 and media_type<=0x0107 and local_k>=10 then
              mi_tree:add( pf_tlv_mac, buffer:range(local_offset+3, 6) )
              mi_tree:add( pf_tlv_mi_ieee_role, buffer:range(local_offset+9, 1) )
              mi_tree:add( pf_tlv_mi_ieee_bw, buffer:range(local_offset+10, 1) )
              mi_tree:add( pf_tlv_mi_ieee_idx1, buffer:range(local_offset+11, 1) )
              mi_tree:add( pf_tlv_mi_ieee_idx2, buffer:range(local_offset+12, 1) )
            end
          end
          local_offset = local_offset + 3 + local_k
        end
      elseif tlv_type==19 then
        local mac_addr = buffer:range(offset+3, 6):ether()
        tlv_tree:add( pf_tlv_mac, buffer:range(offset+3, 6) ):set_text("Abstraction layer ID of the notification message sender: " .. tostring(mac_addr) )
        tlv_tree:add( pf_message_id, buffer:range(offset+9, 2) )
        mac_addr = buffer:range(offset+11, 6):ether()
        tlv_tree:add( pf_tlv_mac, buffer:range(offset+11, 6) ):set_text("Transmitting device in the medium on which a new device joined: " .. tostring(mac_addr) )
        mac_addr = buffer:range(offset+17, 6):ether()
        tlv_tree:add( pf_tlv_mac, buffer:range(offset+17, 6) ):set_text("New device joined: " .. tostring(mac_addr) )
      else
        tlv_tree:add( pf_tlv_type, buffer:range(offset,1) )
        tlv_tree:add( pf_tlv_len, buffer:range(offset+1,2) )
        if tlv_len>0 then
          tlv_tree:add( pf_tlv_value, buffer:range(offset+3,tlv_len) )
        end
      end
      offset = offset + 3 + tlv_len
    end
    
    if not has_eof_tlv then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Missing end-of-message TLV.")
    end
    if buffer:len() < CDHNP_MIN_LEN then
    	subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short, needs more padding to suffice minimal ethernet packet size")
    end
    
end

-- load the ethernet table
ether_table = DissectorTable.get("ethertype")

-- register our protocol to handle ethernet packets of type 0x893A
if ether_table~=nil then
  ether_table:add(0x893A,cdhnp_proto)
end
