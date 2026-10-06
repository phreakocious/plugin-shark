-- Vendored from https://github.com/gr8drag1/gd_tcflag (9d7abb6). Modified 2026-10-05: loadstring shim for Lua 5.4+.
local loadstring = loadstring or load
-------------------------------------------------------------------------------
-- gd_tcflag : TCP conversation state tracking postdissector                 --
-------------------------------------------------------------------------------

-------------------------------------------------------------------------------
-- Copyright - Vadim Zakharine, 2019
-- License GPLv2+: GNU GPL version 2 or later
-- <http://www.gnu.org/licenses/old-licenses/gpl-2.0.html>
-- This is free software; There are no restrictions on its use. There are
-- restrictions on its distribution. There is NO warranty; not even for
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
-------------------------------------------------------------------------------

-------------------------------------------------------------------------------
-- Acknowledgements
--
-- G. Dragon for his original idea
-- Tsapsleoni and Matthew Winnett's dog for their inspiration
-- Betty DuBois for Bettyland
-- Laura Chappell for her "Golden Graph" idea
-- Jasper Bongertz for his byte ratio idea
-------------------------------------------------------------------------------

-----------------------------------History-------------------------------------
-- r4 : The single flag End de-aggregated into Fin and Rst
-- r5 : Individual flag names added to the filter syntax
-- r6 : Counter for tracking for "tcp.analysis.flags" added
-- r7 : Check for not tcp_keep_alive added to payload (Data) tracking
-- r8 : Tracking for jumbo IP MTU and for IP fragments added
-- r9 : Changed IP fragments check from "ip.fragment" to "ip.flags.mf"
-- r10 : Detalisation for r6 added
-- r11 : Combinations like Rst+Ack no longer count as an Ack
--       Duplicate Ack added to TCP analysis counters
-- r12 : Simplified filter syntax for flags set on either A or B (or both)
-- r13 : Keep counters separate for fast, spurious and plain retransmissions
-- r14 : Handle multiple passes in TCP analysis tracking
-- r15 : TCP analysis differentiation between peers added
-- r16 : Statistics section added
-- r17 : Sections activation made configurable
-- r18 : TCP window size field tracking added to the statistics
-- r19 : TCP bytes in flight tracking added to the statistics
-- r20 : Clear the global logical structures before processing a new capture
-- r21 : Maximum tcp.analysis.duplicate_ack_num added under duplicate Ack
-- r22 : Unused fields of TCP bitmap ("[TCBM]") no longer displayed
-- r23 : Displaying TCBM unused fields made configurable
--       RTT/IRTT ratio added to stream flow control tracking
-- r24 : Aggregate status flags
--        gd_tcflag.tcbm.Syn, gd_tcflag.tcbm.SnA, gd_tcflag.tcbm.Ack,
--        gd_tcflag.tcbm.Dat, gd_tcflag.tcbm.fragment, gd_tcflag.tcbm.End,
--        gd_tcflag.tcbm.Fin, gd_tcflag.tcbm.Rst
--       no longer set by the unused fields display option enabled
-- r25 : Code added for handling encapsulated TCP streams
--       Counters for ICMP added to TCP analysis section
-- r26 : Maximum RTT changed to per direction
--       Corrections to maximum bytes in flight tracking
--
--        If ICMP truncates the TCP header, then the TCP dissector may not
--        associated the header with the TCP stream
--        https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=16396
--
--       Code rewritten to stay below Lua limitation:
--
--   tshark: Lua: syntax error: .... gd_tcflag.lua: too many local variables (limit is 200) in main function
-- r27 : Cosmetic improvements preventing the plugin from reporting errors when
--        tshark is run without "-2"
--
-------------------------------------------------------------------------------


local gd_tcflag_pt = Proto("gd_tcflag", "TCP stream tracking")

local gd_tcflag_bm = ProtoField.new("TCBM", "gd_tcflag.tcbm", ftypes.UINT16, nil, base.HEX)
local gd_tcflag_Syn = {}
gd_tcflag_Syn[0] = ProtoField.new("Syn", "gd_tcflag.tcbm.Syn", ftypes.BOOLEAN)
gd_tcflag_Syn[1] = ProtoField.new("Syn A [0x00'01]", "gd_tcflag.tcbm.SynA", ftypes.BOOLEAN)
gd_tcflag_Syn[2] = ProtoField.new("Syn B [0x00'02]", "gd_tcflag.tcbm.SynB", ftypes.BOOLEAN)
local gd_tcflag_SnA = {}
gd_tcflag_SnA[0] = ProtoField.new("Syn+Ack", "gd_tcflag.tcbm.SnA", ftypes.BOOLEAN)
gd_tcflag_SnA[1] = ProtoField.new("Syn+Ack A [0x00'04]", "gd_tcflag.tcbm.SnAA", ftypes.BOOLEAN)
gd_tcflag_SnA[2] = ProtoField.new("Syn+Ack B [0x00'08]", "gd_tcflag.tcbm.SnAB", ftypes.BOOLEAN)
local gd_tcflag_Ack = {}
gd_tcflag_Ack[0] = ProtoField.new("Ack", "gd_tcflag.tcbm.Ack", ftypes.BOOLEAN)
gd_tcflag_Ack[1] = ProtoField.new("Ack A [0x00'10]", "gd_tcflag.tcbm.AckA", ftypes.BOOLEAN)
gd_tcflag_Ack[2] = ProtoField.new("Ack B [0x00'20]", "gd_tcflag.tcbm.AckB", ftypes.BOOLEAN)
local gd_tcflag_Dat = {}
gd_tcflag_Dat[0] = ProtoField.new("Data", "gd_tcflag.tcbm.Dat", ftypes.BOOLEAN)
gd_tcflag_Dat[1] = ProtoField.new("Data A [0x00'40]", "gd_tcflag.tcbm.DatA", ftypes.BOOLEAN)
gd_tcflag_Dat[2] = ProtoField.new("Data B [0x00'80]", "gd_tcflag.tcbm.DatB", ftypes.BOOLEAN)
local gd_tcflag_MTUgt1500 = {}
gd_tcflag_MTUgt1500[0] = ProtoField.new("MTU > 1500 B", "gd_tcflag.tcbm.MTUgt1500", ftypes.BOOLEAN)
gd_tcflag_MTUgt1500[1] = ProtoField.new("MTU A > 1500 B [0x01'00]", "gd_tcflag.tcbm.MTUgt1500A", ftypes.BOOLEAN)
gd_tcflag_MTUgt1500[2] = ProtoField.new("MTU B > 1500 B [0x02'00]", "gd_tcflag.tcbm.MTUgt1500B", ftypes.BOOLEAN)
gd_tcflag_fragment = {}
gd_tcflag_fragment[0] = ProtoField.new("fragmented", "gd_tcflag.tcbm.fragment", ftypes.BOOLEAN)
gd_tcflag_fragment[1] = ProtoField.new("fragmented A [0x04'00]", "gd_tcflag.tcbm.fragmentA", ftypes.BOOLEAN)
gd_tcflag_fragment[2] = ProtoField.new("fragmented B [0x08'00]", "gd_tcflag.tcbm.fragmentB", ftypes.BOOLEAN)
local gd_tcflag_Fin = {}
gd_tcflag_Fin[0] = ProtoField.new("Fin", "gd_tcflag.tcbm.Fin", ftypes.BOOLEAN)
gd_tcflag_Fin[1] = ProtoField.new("Fin A [0x10'00]", "gd_tcflag.tcbm.FinA", ftypes.BOOLEAN)
gd_tcflag_Fin[2] = ProtoField.new("Fin B [0x20'00]", "gd_tcflag.tcbm.FinB", ftypes.BOOLEAN)
local gd_tcflag_Rst = {}
gd_tcflag_Rst[0] = ProtoField.new("Rst", "gd_tcflag.tcbm.Rst", ftypes.BOOLEAN)
gd_tcflag_Rst[1] = ProtoField.new("Rst A [0x40'00]", "gd_tcflag.tcbm.RstA", ftypes.BOOLEAN)
gd_tcflag_Rst[2] = ProtoField.new("Rst B [0x80'00]", "gd_tcflag.tcbm.RstB", ftypes.BOOLEAN)
local gd_tcflag_End = ProtoField.new("End", "gd_tcflag.tcbm.End", ftypes.BOOLEAN)

local gd_tcanfl_cn = ProtoField.new("TCP analysis flagged", "gd_tcflag.tcanflcn", ftypes.UINT32)
local gd_tcanfl_cn_A = ProtoField.new("Analysis flagged A", "gd_tcflag.tcanflcn_A", ftypes.UINT32)
local gd_tcanfl_cn_B = ProtoField.new("Analysis flagged B", "gd_tcflag.tcanflcn_B", ftypes.UINT32)
local gd_tcanfl_cn_frtr = ProtoField.new("Analysis fast retransmission", "gd_tcflag.tcanflcn.fast_retransmission", ftypes.UINT32)
local gd_tcanfl_cn_frtr_A = ProtoField.new("Analysis fast retransmission A", "gd_tcflag.tcanflcn.fast_retransmission_A", ftypes.UINT32)
local gd_tcanfl_cn_frtr_B = ProtoField.new("Analysis fast retransmission B", "gd_tcflag.tcanflcn.fast_retransmission_B", ftypes.UINT32)
local gd_tcanfl_cn_ka = ProtoField.new("Analysis keep-alive", "gd_tcflag.tcanflcn.keep_alive", ftypes.UINT32)
local gd_tcanfl_cn_ka_A = ProtoField.new("Analysis keep-alive A", "gd_tcflag.tcanflcn.keep_alive_A", ftypes.UINT32)
local gd_tcanfl_cn_ka_B = ProtoField.new("Analysis keep-alive B", "gd_tcflag.tcanflcn.keep_alive_B", ftypes.UINT32)
local gd_tcanfl_cn_kaa = ProtoField.new("Analysis keep-alive Ack", "gd_tcflag.tcanflcn.keep_alive_ack", ftypes.UINT32)
local gd_tcanfl_cn_kaa_A = ProtoField.new("Analysis keep-alive Ack A", "gd_tcflag.tcanflcn.keep_alive_ack_A", ftypes.UINT32)
local gd_tcanfl_cn_kaa_B = ProtoField.new("Analysis keep-alive Ack B", "gd_tcflag.tcanflcn.keep_alive_ack_B", ftypes.UINT32)
local gd_tcanfl_cn_losg = ProtoField.new("Analysis lost segment", "gd_tcflag.tcanflcn.lost_segment", ftypes.UINT32)
local gd_tcanfl_cn_losg_A = ProtoField.new("Analysis lost segment A", "gd_tcflag.tcanflcn.lost_segment_A", ftypes.UINT32)
local gd_tcanfl_cn_losg_B = ProtoField.new("Analysis lost segment B", "gd_tcflag.tcanflcn.lost_segment_B", ftypes.UINT32)
local gd_tcanfl_cn_ooo = ProtoField.new("Analysis out of order", "gd_tcflag.tcanflcn.out_of_order", ftypes.UINT32)
local gd_tcanfl_cn_ooo_A = ProtoField.new("Analysis out of order A", "gd_tcflag.tcanflcn.out_of_order_A", ftypes.UINT32)
local gd_tcanfl_cn_ooo_B = ProtoField.new("Analysis out of order B", "gd_tcflag.tcanflcn.out_of_order_B", ftypes.UINT32)
local gd_tcanfl_cn_rtr = ProtoField.new("Analysis retransmission", "gd_tcflag.tcanflcn.retransmission", ftypes.UINT32)
local gd_tcanfl_cn_rtr_A = ProtoField.new("Analysis retransmission A", "gd_tcflag.tcanflcn.retransmission_A", ftypes.UINT32)
local gd_tcanfl_cn_rtr_B = ProtoField.new("Analysis retransmission B", "gd_tcflag.tcanflcn.retransmission_B", ftypes.UINT32)
local gd_tcanfl_cn_rusp = ProtoField.new("Analysis reused ports", "gd_tcflag.tcanflcn.reused_ports", ftypes.UINT32)
local gd_tcanfl_cn_rusp_A = ProtoField.new("Analysis reused ports A", "gd_tcflag.tcanflcn.reused_ports_A", ftypes.UINT32)
local gd_tcanfl_cn_rusp_B = ProtoField.new("Analysis reused ports B", "gd_tcflag.tcanflcn.reused_ports_B", ftypes.UINT32)
local gd_tcanfl_cn_srtr = ProtoField.new("Analysis spurious retransmission", "gd_tcflag.tcanflcn.tcp.analysis.spurious_retransmission", ftypes.UINT32)
local gd_tcanfl_cn_srtr_A = ProtoField.new("Analysis spurious retransmission A", "gd_tcflag.tcanflcn.tcp.analysis.spurious_retransmission_A", ftypes.UINT32)
local gd_tcanfl_cn_srtr_B = ProtoField.new("Analysis spurious retransmission B", "gd_tcflag.tcanflcn.tcp.analysis.spurious_retransmission_B", ftypes.UINT32)
local gd_tcanfl_cn_wful = ProtoField.new("Analysis window full", "gd_tcflag.tcanflcn.window_full", ftypes.UINT32)
local gd_tcanfl_cn_wful_A = ProtoField.new("Analysis window full A", "gd_tcflag.tcanflcn.window_full_A", ftypes.UINT32)
local gd_tcanfl_cn_wful_B = ProtoField.new("Analysis window full B", "gd_tcflag.tcanflcn.window_full_B", ftypes.UINT32)
local gd_tcanfl_cn_wupd = ProtoField.new("Analysis window update", "gd_tcflag.tcanflcn.window_update", ftypes.UINT32)
local gd_tcanfl_cn_wupd_A = ProtoField.new("Analysis window update A", "gd_tcflag.tcanflcn.window_update_A", ftypes.UINT32)
local gd_tcanfl_cn_wupd_B = ProtoField.new("Analysis window update B", "gd_tcflag.tcanflcn.window_update_B", ftypes.UINT32)
local gd_tcanfl_cn_dack = ProtoField.new("Analysis duplicate Ack", "gd_tcflag.tcanflcn.duplicate_ack", ftypes.UINT32)
local gd_tcanfl_cn_dack_A = ProtoField.new("Analysis duplicate Ack A", "gd_tcflag.tcanflcn.duplicate_ack_A", ftypes.UINT32)
local gd_tcanfl_cn_dack_A_mx = ProtoField.new("Duplicate Ack A max", "gd_tcflag.tcanflcn.duplicate_ack_A_max", ftypes.UINT16)
local gd_tcanfl_cn_dack_B = ProtoField.new("Analysis duplicate Ack B", "gd_tcflag.tcanflcn.duplicate_ack_B", ftypes.UINT32)
local gd_tcanfl_cn_dack_B_mx = ProtoField.new("Duplicate Ack B max", "gd_tcflag.tcanflcn.duplicate_ack_B_max", ftypes.UINT16)
local gd_tcanfl_cn_zwin = ProtoField.new("Analysis zero window", "gd_tcflag.tcanflcn.zero_window", ftypes.UINT32)
local gd_tcanfl_cn_zwin_A = ProtoField.new("Analysis zero window A", "gd_tcflag.tcanflcn.zero_window_A", ftypes.UINT32)
local gd_tcanfl_cn_zwin_B = ProtoField.new("Analysis zero window B", "gd_tcflag.tcanflcn.zero_window_B", ftypes.UINT32)
local gd_tcanfl_cn_zwp = ProtoField.new("Analysis zero window probe", "gd_tcflag.tcanflcn.zero_window_probe", ftypes.UINT32)
local gd_tcanfl_cn_zwp_A = ProtoField.new("Analysis zero window probe A", "gd_tcflag.tcanflcn.zero_window_probe_A", ftypes.UINT32)
local gd_tcanfl_cn_zwp_B = ProtoField.new("Analysis zero window probe B", "gd_tcflag.tcanflcn.zero_window_probe_B", ftypes.UINT32)
local gd_tcanfl_cn_zwpa = ProtoField.new("Analysis zero window probe Ack", "gd_tcflag.tcanflcn.zero_window_probe_ack", ftypes.UINT32)
local gd_tcanfl_cn_zwpa_A = ProtoField.new("Analysis zero window probe Ack A", "gd_tcflag.tcanflcn.zero_window_probe_ack_A", ftypes.UINT32)
local gd_tcanfl_cn_zwpa_B = ProtoField.new("Analysis zero window probe Ack B", "gd_tcflag.tcanflcn.zero_window_probe_ack_B", ftypes.UINT32)
local gd_tcanfl_cn_akls = ProtoField.new("Analysis lost segment Ack", "gd_tcflag.tcanflcn.ack_lost_segment", ftypes.UINT32)
local gd_tcanfl_cn_akls_A = ProtoField.new("Analysis lost segment Ack A", "gd_tcflag.tcanflcn.ack_lost_segment_A", ftypes.UINT32)
local gd_tcanfl_cn_akls_B = ProtoField.new("Analysis lost segment Ack B", "gd_tcflag.tcanflcn.ack_lost_segment_B", ftypes.UINT32)

local gd_tcicfl_cn = {}
gd_tcicfl_cn[0] = ProtoField.new("ICMP total", "gd_tcflag.tcicflcn", ftypes.UINT32)
gd_tcicfl_cn[3] = ProtoField.new("Type 3, Destination unreachable", "gd_tcflag.tcicflcn.type3", ftypes.UINT32)
gd_tcicfl_cn[11] = ProtoField.new("Type 11, Time exceeded", "gd_tcflag.tcicflcn.type11", ftypes.UINT32)

local gd_tcstatfl_root = ProtoField.new("Stream stats", "gd_tcflag.tcstatfl", ftypes.PROTOCOL)
local gd_tcstatfl_durt = ProtoField.new("Duration", "gd_tcflag.tcstatfl.duration", ftypes.FLOAT)
local gd_tcstatfl_bgnf = ProtoField.new("Earliest frame", "gd_tcflag.tcstatfl.begin", ftypes.FRAMENUM)
local gd_tcstatfl_endf = ProtoField.new("Latest frame", "gd_tcflag.tcstatfl.end", ftypes.FRAMENUM)
local gd_tcstatfl_fcnt = ProtoField.new("Total frames", "gd_tcflag.tcstatfl.framcount", ftypes.UINT32)
local gd_tcstatfl_fcnt_A = ProtoField.new("Frames from A", "gd_tcflag.tcstatfl.framcount_A", ftypes.UINT32)
local gd_tcstatfl_fcnt_B = ProtoField.new("Frames from B", "gd_tcflag.tcstatfl.framcount_B", ftypes.UINT32)
local gd_tcstatfl_bcnt = ProtoField.new("Total payload bytes", "gd_tcflag.tcstatfl.bytecount", ftypes.UINT32)
local gd_tcstatfl_bcnt_A = ProtoField.new("Bytes from A", "gd_tcflag.tcstatfl.bytecount_A", ftypes.UINT32)
local gd_tcstatfl_bcnt_B = ProtoField.new("Bytes from B", "gd_tcflag.tcstatfl.bytecount_B", ftypes.UINT32)
local gd_tcstatfl_bcnt_r = ProtoField.new("Payload ratio, 0..100 dB", "gd_tcflag.tcstatfl.byteratio", ftypes.FLOAT)
local gd_tcstatfl_sub_fc = ProtoField.new("Stream flow control", "gd_tcflag.tcstatfl.fc", ftypes.PROTOCOL)
local gd_tcstatfl_wmnsz_A = ProtoField.new("Minumum win from A", "gd_tcflag.tcstatfl.fc.winsizmin_A", ftypes.UINT32)
local gd_tcstatfl_wmnsz_B = ProtoField.new("Minumum win from B", "gd_tcflag.tcstatfl.fc.winsizmin_B", ftypes.UINT32)
local gd_tcstatfl_wmxsz_A = ProtoField.new("Maximum win from A", "gd_tcflag.tcstatfl.fc.winsizmax_A", ftypes.UINT32)
local gd_tcstatfl_wmxsz_B = ProtoField.new("Maximum win from B", "gd_tcflag.tcstatfl.fc.winsizmax_B", ftypes.UINT32)
local gd_tcstatfl_wmxrat = ProtoField.new("Highest win max/min, 0..100 dB", "gd_tcflag.tcstatfl.fc.winsizratio", ftypes.FLOAT)
local gd_tcstatfl_binfx_A = ProtoField.new("Maximum bytes in flight from A", "gd_tcflag.tcstatfl.fc.byteinflmax_A", ftypes.UINT32)
local gd_tcstatfl_binfx_B = ProtoField.new("Maximum bytes in flight from B", "gd_tcflag.tcstatfl.fc.byteinflmax_B", ftypes.UINT32)
local gd_tcstatfl_rttmx_A = ProtoField.new("Highest RTT from A", "gd_tcflag.tcstatfl.fc.rttmax_A", ftypes.FLOAT)
local gd_tcstatfl_rttmx_B = ProtoField.new("Highest RTT from B", "gd_tcflag.tcstatfl.fc.rttmax_B", ftypes.FLOAT)
local gd_tcstatfl_rttrat = ProtoField.new("Highest RTT/IRTT, 0..100 dB", "gd_tcflag.tcstatfl.fc.rttratio", ftypes.FLOAT)

gd_tcflag_pt.fields = {
 gd_tcflag_bm,
 gd_tcflag_Syn[0],
 gd_tcflag_Syn[1],
 gd_tcflag_Syn[2],
 gd_tcflag_SnA[0],
 gd_tcflag_SnA[1],
 gd_tcflag_SnA[2],
 gd_tcflag_Ack[0],
 gd_tcflag_Ack[1],
 gd_tcflag_Ack[2],
 gd_tcflag_Dat[0],
 gd_tcflag_Dat[1],
 gd_tcflag_Dat[2],
 gd_tcflag_MTUgt1500[0],
 gd_tcflag_MTUgt1500[1],
 gd_tcflag_MTUgt1500[2],
 gd_tcflag_fragment[0],
 gd_tcflag_fragment[1],
 gd_tcflag_fragment[2],
 gd_tcflag_Fin[0],
 gd_tcflag_Fin[1],
 gd_tcflag_Fin[2],
 gd_tcflag_Rst[0],
 gd_tcflag_Rst[1],
 gd_tcflag_Rst[2],
 gd_tcflag_End,
 gd_tcanfl_cn,
 gd_tcanfl_cn_A,
 gd_tcanfl_cn_B,
 gd_tcanfl_cn_frtr,
 gd_tcanfl_cn_frtr_A,
 gd_tcanfl_cn_frtr_B,
 gd_tcanfl_cn_ka,
 gd_tcanfl_cn_ka_A,
 gd_tcanfl_cn_ka_B,
 gd_tcanfl_cn_kaa,
 gd_tcanfl_cn_kaa_A,
 gd_tcanfl_cn_kaa_B,
 gd_tcanfl_cn_losg,
 gd_tcanfl_cn_losg_A,
 gd_tcanfl_cn_losg_B,
 gd_tcanfl_cn_ooo,
 gd_tcanfl_cn_ooo_A,
 gd_tcanfl_cn_ooo_B,
 gd_tcanfl_cn_rtr,
 gd_tcanfl_cn_rtr_A,
 gd_tcanfl_cn_rtr_B,
 gd_tcanfl_cn_rusp,
 gd_tcanfl_cn_rusp_A,
 gd_tcanfl_cn_rusp_B,
 gd_tcanfl_cn_srtr,
 gd_tcanfl_cn_srtr_A,
 gd_tcanfl_cn_srtr_B,
 gd_tcanfl_cn_wful,
 gd_tcanfl_cn_wful_A,
 gd_tcanfl_cn_wful_B,
 gd_tcanfl_cn_wupd,
 gd_tcanfl_cn_wupd_A,
 gd_tcanfl_cn_wupd_B,
 gd_tcanfl_cn_dack,
 gd_tcanfl_cn_dack_A,
 gd_tcanfl_cn_dack_A_mx,
 gd_tcanfl_cn_dack_B,
 gd_tcanfl_cn_dack_B_mx,
 gd_tcanfl_cn_zwin,
 gd_tcanfl_cn_zwin_A,
 gd_tcanfl_cn_zwin_B,
 gd_tcanfl_cn_zwp,
 gd_tcanfl_cn_zwp_A,
 gd_tcanfl_cn_zwp_B,
 gd_tcanfl_cn_zwpa,
 gd_tcanfl_cn_zwpa_A,
 gd_tcanfl_cn_zwpa_B,
 gd_tcanfl_cn_akls,
 gd_tcanfl_cn_akls_A,
 gd_tcanfl_cn_akls_B,
 gd_tcicfl_cn[0],
 gd_tcicfl_cn[3],
 gd_tcicfl_cn[11],
 gd_tcstatfl_root,
 gd_tcstatfl_durt,
 gd_tcstatfl_bgnf,
 gd_tcstatfl_endf,
 gd_tcstatfl_fcnt,
 gd_tcstatfl_fcnt_A,
 gd_tcstatfl_fcnt_B,
 gd_tcstatfl_bcnt,
 gd_tcstatfl_bcnt_A,
 gd_tcstatfl_bcnt_B,
 gd_tcstatfl_bcnt_r,
 gd_tcstatfl_sub_fc,
 gd_tcstatfl_wmxrat,
 gd_tcstatfl_wmnsz_A,
 gd_tcstatfl_wmnsz_B,
 gd_tcstatfl_wmxsz_A,
 gd_tcstatfl_wmxsz_B,
 gd_tcstatfl_binfx_A,
 gd_tcstatfl_binfx_B,
 gd_tcstatfl_rttmx_A,
 gd_tcstatfl_rttmx_B,
 gd_tcstatfl_rttrat
}

local x_ip = Field.new("ip")
local x_iplngt = Field.new("ip.len")
local x_ipfrag = Field.new("ip.flags.mf")
local x_tcflag = Field.new("tcp.flags")
local x_tcstrm = Field.new("tcp.stream")
local x_tcwsiz = Field.new("tcp.window_size")
local x_tclngt = Field.new("tcp.len")
local x_tccrtt = Field.new("tcp.analysis.ack_rtt")
local x_tcirtt = Field.new("tcp.analysis.initial_rtt")
local x_tcanfl = Field.new("tcp.analysis.flags")
local x_tcanfrtr = Field.new("tcp.analysis.fast_retransmission")
local x_tcanka = Field.new("tcp.analysis.keep_alive")
local x_tcankaa = Field.new("tcp.analysis.keep_alive_ack")
local x_tcanlosg = Field.new("tcp.analysis.lost_segment")
local x_tcanooo = Field.new("tcp.analysis.out_of_order")
local x_tcanrtr = Field.new("tcp.analysis.retransmission")
local x_tcanrusp = Field.new("tcp.analysis.reused_ports")
local x_tcansrtr = Field.new("tcp.analysis.spurious_retransmission")
local x_tcanwful = Field.new("tcp.analysis.window_full")
local x_tcanwupd = Field.new("tcp.analysis.window_update")
local x_tcandack = Field.new("tcp.analysis.duplicate_ack_num")
local x_tcanzwin = Field.new("tcp.analysis.zero_window")
local x_tcanzwp = Field.new("tcp.analysis.zero_window_probe")
local x_tcanzwpa = Field.new("tcp.analysis.zero_window_probe_ack")
local x_tcanakls = Field.new("tcp.analysis.ack_lost_segment")
local x_tcanbinf = Field.new("tcp.analysis.bytes_in_flight")
local x_icmptype = Field.new("icmp.type")

local tcbm = {}
local tcanflcn = {}
local tcanflcn_A = {}
local tcanflcn_B = {}
local tcanfl_frtr = {}
local tcanfl_frtr_A = {}
local tcanfl_frtr_B = {}
local tcanfl_ka = {}
local tcanfl_ka_A = {}
local tcanfl_ka_B = {}
local tcanfl_kaa = {}
local tcanfl_kaa_A = {}
local tcanfl_kaa_B = {}
local tcanfl_losg = {}
local tcanfl_losg_A = {}
local tcanfl_losg_B = {}
local tcanfl_ooo = {}
local tcanfl_ooo_A = {}
local tcanfl_ooo_B = {}
local tcanfl_rtr = {}
local tcanfl_rtr_A = {}
local tcanfl_rtr_B = {}
local tcanfl_rusp = {}
local tcanfl_rusp_A = {}
local tcanfl_rusp_B = {}
local tcanfl_srtr = {}
local tcanfl_srtr_A = {}
local tcanfl_srtr_B = {}
local tcanfl_wful = {}
local tcanfl_wful_A = {}
local tcanfl_wful_B = {}
local tcanfl_wupd = {}
local tcanfl_wupd_A = {}
local tcanfl_wupd_B = {}
local tcanfl_dack = {}
local tcanfl_dack_A = {}
local tcanfl_dack_A_mx = {}
local tcanfl_dack_B = {}
local tcanfl_dack_B_mx = {}
local tcanfl_zwin = {}
local tcanfl_zwin_A = {}
local tcanfl_zwin_B = {}
local tcanfl_zwp = {}
local tcanfl_zwp_A = {}
local tcanfl_zwp_B = {}
local tcanfl_zwpa = {}
local tcanfl_zwpa_A = {}
local tcanfl_zwpa_B = {}
local tcanfl_akls = {}
local tcanfl_akls_A = {}
local tcanfl_akls_B = {}
local tcicfl_totl = {}
local tcicfl_cn = {}
tcicfl_cn[3] = {}
tcicfl_cn[11] = {}
local tcstatfl_fc = {}
local tcstatfl_bc = {}
local tcstatfl_gnf = {}
local tcstatfl_gnt = {}
local tcstatfl_ndf = {}
local tcstatfl_ndt = {}
local tcstatfl_fcA = {}
local tcstatfl_bcA = {}
local tcstatfl_fcB = {}
local tcstatfl_bcB = {}
local tcstatfl_wiA = {}
local tcstatfl_wxA = {}
local tcstatfl_wiB = {}
local tcstatfl_wxB = {}
local tcstatfl_bfxA = {}
local tcstatfl_bfxB = {}
local tcstatfl_rtxA = {}
local tcstatfl_rtxB = {}

local gd_tcanflmap_ol = {}
local gd_icmptype_ol = {}
local gd_tc_lastframnr = 0

function gd_tcflag_pt.dissector(tvb, pinfo, root)


 local gd_tcflag = 0
 local gd_tcanflmap_nu = 0

 if not pinfo.visited then
  if pinfo.number <= gd_tc_lastframnr then
   gd_tc_lastframnr = pinfo.number
   tcbm = {}
   tcanflcn = {}
   tcanflcn_A = {}
   tcanflcn_B = {}
   tcanfl_frtr = {}
   tcanfl_frtr_A = {}
   tcanfl_frtr_B = {}
   tcanfl_ka = {}
   tcanfl_ka_A = {}
   tcanfl_ka_B = {}
   tcanfl_kaa = {}
   tcanfl_kaa_A = {}
   tcanfl_kaa_B = {}
   tcanfl_losg = {}
   tcanfl_losg_A = {}
   tcanfl_losg_B = {}
   tcanfl_ooo = {}
   tcanfl_ooo_A = {}
   tcanfl_ooo_B = {}
   tcanfl_rtr = {}
   tcanfl_rtr_A = {}
   tcanfl_rtr_B = {}
   tcanfl_rusp = {}
   tcanfl_rusp_A = {}
   tcanfl_rusp_B = {}
   tcanfl_srtr = {}
   tcanfl_srtr_A = {}
   tcanfl_srtr_B = {}
   tcanfl_wful = {}
   tcanfl_wful_A = {}
   tcanfl_wful_B = {}
   tcanfl_wupd = {}
   tcanfl_wupd_A = {}
   tcanfl_wupd_B = {}
   tcanfl_dack = {}
   tcanfl_dack_A = {}
   tcanfl_dack_A_mx = {}
   tcanfl_dack_B = {}
   tcanfl_dack_B_mx = {}
   tcanfl_zwin = {}
   tcanfl_zwin_A = {}
   tcanfl_zwin_B = {}
   tcanfl_zwp = {}
   tcanfl_zwp_A = {}
   tcanfl_zwp_B = {}
   tcanfl_zwpa = {}
   tcanfl_zwpa_A = {}
   tcanfl_zwpa_B = {}
   tcanfl_akls = {}
   tcanfl_akls_A = {}
   tcanfl_akls_B = {}
   tcicfl_totl = {}
   tcicfl_cn = {}
   tcicfl_cn[3] = {}
   tcicfl_cn[11] = {}
   tcstatfl_fc = {}
   tcstatfl_bc = {}
   tcstatfl_gnf = {}
   tcstatfl_gnt = {}
   tcstatfl_ndf = {}
   tcstatfl_ndt = {}
   tcstatfl_fcA = {}
   tcstatfl_bcA = {}
   tcstatfl_fcB = {}
   tcstatfl_bcB = {}
   tcstatfl_wiA = {}
   tcstatfl_wxA = {}
   tcstatfl_wiB = {}
   tcstatfl_wxB = {}
   tcstatfl_bfxA = {}
   tcstatfl_bfxB = {}
   tcstatfl_rtxA = {}
   tcstatfl_rtxB = {}
   gd_tcanflmap_ol = {}
   gd_icmptype_ol = {}
  else
   gd_tc_lastframnr = pinfo.number
  end
 end

 if x_tcstrm() then

  local gd_tcflag_tr = {}

  if gd_tcflag_pt.prefs.tcbm and x_tcflag() then
   if tcbm[x_tcstrm().value] then
    gd_tcflag = tcbm[x_tcstrm().value]
   end
   if x_ip() and x_iplngt().value > 1500 then
    if pinfo.src_port < pinfo.dst_port then
     gd_tcflag = bit.bor(gd_tcflag, 256)
    elseif pinfo.src_port > pinfo.dst_port then
     gd_tcflag = bit.bor(gd_tcflag, 512)
    elseif pinfo.net_src < pinfo.net_dst then
     gd_tcflag = bit.bor(gd_tcflag, 256)
    elseif pinfo.net_src > pinfo.net_dst then
     gd_tcflag = bit.bor(gd_tcflag, 512)
    else
     gd_tcflag = bit.bor(gd_tcflag, 768)
    end
   end
   if x_ip() and x_ipfrag().value then
    if pinfo.src_port < pinfo.dst_port then
     gd_tcflag = bit.bor(gd_tcflag, 1024)
    elseif pinfo.src_port > pinfo.dst_port then
     gd_tcflag = bit.bor(gd_tcflag, 2048)
    elseif pinfo.net_src < pinfo.net_dst then
     gd_tcflag = bit.bor(gd_tcflag, 1024)
    elseif pinfo.net_src > pinfo.net_dst then
     gd_tcflag = bit.bor(gd_tcflag, 2048)
    else
     gd_tcflag = bit.bor(gd_tcflag, 3072)
    end
   end
   if x_tclngt() and x_tclngt().value > 0 and bit.band(x_tcflag().value, 4) == 0 and not x_tcanka() then
    if pinfo.src_port < pinfo.dst_port then
     gd_tcflag = bit.bor(gd_tcflag, 64)
    elseif pinfo.src_port > pinfo.dst_port then
     gd_tcflag = bit.bor(gd_tcflag, 128)
    elseif pinfo.net_src < pinfo.net_dst then
     gd_tcflag = bit.bor(gd_tcflag, 64)
    elseif pinfo.net_src > pinfo.net_dst then
     gd_tcflag = bit.bor(gd_tcflag, 128)
    else
     gd_tcflag = bit.bor(gd_tcflag, 192)
    end
   end
   if not x_tclngt() or x_tclngt().value == 0 then
    if bit.band(x_tcflag().value, 23) == 18 then
     if pinfo.src_port <  pinfo.dst_port then
      gd_tcflag = bit.bor(gd_tcflag, 4)
     elseif pinfo.src_port > pinfo.dst_port then
      gd_tcflag = bit.bor(gd_tcflag, 8)
     elseif pinfo.net_src < pinfo.net_dst then
      gd_tcflag = bit.bor(gd_tcflag, 4)
     elseif pinfo.net_src > pinfo.net_dst then
      gd_tcflag = bit.bor(gd_tcflag, 8)
     else
      gd_tcflag = bit.bor(gd_tcflag,12)
     end
    elseif bit.band(x_tcflag().value, 23) == 2 then
     if pinfo.src_port <  pinfo.dst_port then
      gd_tcflag = bit.bor(gd_tcflag, 1)
     elseif pinfo.src_port > pinfo.dst_port then
      gd_tcflag = bit.bor(gd_tcflag, 2)
     elseif pinfo.net_src < pinfo.net_dst then
      gd_tcflag = bit.bor(gd_tcflag, 1)
     elseif pinfo.net_src > pinfo.net_dst then
      gd_tcflag = bit.bor(gd_tcflag, 2)
     else
      gd_tcflag = bit.bor(gd_tcflag, 3)
     end
    elseif bit.band(x_tcflag().value, 23) == 16 then
     if pinfo.src_port <  pinfo.dst_port then
      gd_tcflag = bit.bor(gd_tcflag, 16)
     elseif pinfo.src_port > pinfo.dst_port then
      gd_tcflag = bit.bor(gd_tcflag, 32)
     elseif pinfo.net_src < pinfo.net_dst then
      gd_tcflag = bit.bor(gd_tcflag, 16)
     elseif pinfo.net_src > pinfo.net_dst then
      gd_tcflag = bit.bor(gd_tcflag, 32)
     else
      gd_tcflag = bit.bor(gd_tcflag().value, 48)
     end
    end
   end
   if bit.band(x_tcflag().value, 1) == 1 then
    if pinfo.src_port <  pinfo.dst_port then
     gd_tcflag = bit.bor(gd_tcflag, 4096)
    elseif pinfo.src_port >  pinfo.dst_port then
     gd_tcflag = bit.bor(gd_tcflag, 8192)
    elseif pinfo.net_src < pinfo.net_dst then
     gd_tcflag = bit.bor(gd_tcflag, 4096)
    elseif pinfo.net_src > pinfo.net_dst then
     gd_tcflag = bit.bor(gd_tcflag, 8192)
    else
     gd_tcflag = bit.bor(gd_tcflag, 12288)
    end
   elseif bit.band(x_tcflag().value, 4) == 4 then
    if pinfo.src_port <  pinfo.dst_port then
     gd_tcflag = bit.bor(gd_tcflag, 16384)
    elseif pinfo.src_port >  pinfo.dst_port then
     gd_tcflag = bit.bor(gd_tcflag, 32768)
    elseif pinfo.net_src < pinfo.net_dst then
     gd_tcflag = bit.bor(gd_tcflag, 16384)
    elseif pinfo.net_src > pinfo.net_dst then
     gd_tcflag = bit.bor(gd_tcflag, 32768)
    else
     gd_tcflag = bit.bor(gd_tcflag, 49152)
    end
   end
   tcbm[x_tcstrm().value] = gd_tcflag
  end

  if not pinfo.visited then
   if gd_tcflag_pt.prefs.tcanfl then
    tcanflcn[x_tcstrm().value] = 0
    tcanflcn_A[x_tcstrm().value] = 0
    tcanflcn_B[x_tcstrm().value] = 0
    gd_tcanflmap_ol[pinfo.number] = 0
    if not tcanfl_frtr[x_tcstrm().value] then
     tcanfl_frtr[x_tcstrm().value] = 0
     tcanfl_frtr_A[x_tcstrm().value] = 0
     tcanfl_frtr_B[x_tcstrm().value] = 0
    end
    if not tcanfl_ka[x_tcstrm().value] then
     tcanfl_ka[x_tcstrm().value] = 0
     tcanfl_ka_A[x_tcstrm().value] = 0
     tcanfl_ka_B[x_tcstrm().value] = 0
    end
    if not tcanfl_kaa[x_tcstrm().value] then
     tcanfl_kaa[x_tcstrm().value] = 0
     tcanfl_kaa_A[x_tcstrm().value] = 0
     tcanfl_kaa_B[x_tcstrm().value] = 0
    end
    if not tcanfl_losg[x_tcstrm().value] then
     tcanfl_losg[x_tcstrm().value] = 0
     tcanfl_losg_A[x_tcstrm().value] = 0
     tcanfl_losg_B[x_tcstrm().value] = 0
    end
    if not tcanfl_ooo[x_tcstrm().value] then
     tcanfl_ooo[x_tcstrm().value] = 0
     tcanfl_ooo_A[x_tcstrm().value] = 0
     tcanfl_ooo_B[x_tcstrm().value] = 0
    end
    if not tcanfl_rtr[x_tcstrm().value] then
     tcanfl_rtr[x_tcstrm().value] = 0
     tcanfl_rtr_A[x_tcstrm().value] = 0
     tcanfl_rtr_B[x_tcstrm().value] = 0
    end
    if not tcanfl_rusp[x_tcstrm().value] then
     tcanfl_rusp[x_tcstrm().value] = 0
     tcanfl_rusp_A[x_tcstrm().value] = 0
     tcanfl_rusp_B[x_tcstrm().value] = 0
    end
    if not tcanfl_srtr[x_tcstrm().value] then
     tcanfl_srtr[x_tcstrm().value] = 0
     tcanfl_srtr_A[x_tcstrm().value] = 0
     tcanfl_srtr_B[x_tcstrm().value] = 0
    end
    if not tcanfl_wful[x_tcstrm().value] then
     tcanfl_wful[x_tcstrm().value] = 0
     tcanfl_wful_A[x_tcstrm().value] = 0
     tcanfl_wful_B[x_tcstrm().value] = 0
    end
    if not tcanfl_wupd[x_tcstrm().value] then
     tcanfl_wupd[x_tcstrm().value] = 0
     tcanfl_wupd_A[x_tcstrm().value] = 0
     tcanfl_wupd_B[x_tcstrm().value] = 0
    end
    if not tcanfl_dack[x_tcstrm().value] then
     tcanfl_dack[x_tcstrm().value] = 0
     tcanfl_dack_A[x_tcstrm().value] = 0
     tcanfl_dack_A_mx[x_tcstrm().value] = 0
     tcanfl_dack_B[x_tcstrm().value] = 0
     tcanfl_dack_B_mx[x_tcstrm().value] = 0
    end
    if not tcanfl_zwin[x_tcstrm().value] then
     tcanfl_zwin[x_tcstrm().value] = 0
     tcanfl_zwin_A[x_tcstrm().value] = 0
     tcanfl_zwin_B[x_tcstrm().value] = 0
    end
    if not tcanfl_zwp[x_tcstrm().value] then
     tcanfl_zwp[x_tcstrm().value] = 0
     tcanfl_zwp_A[x_tcstrm().value] = 0
     tcanfl_zwp_B[x_tcstrm().value] = 0
    end
    if not tcanfl_zwpa[x_tcstrm().value] then
     tcanfl_zwpa[x_tcstrm().value] = 0
     tcanfl_zwpa_A[x_tcstrm().value] = 0
     tcanfl_zwpa_B[x_tcstrm().value] = 0
    end
    if not tcanfl_akls[x_tcstrm().value] then
     tcanfl_akls[x_tcstrm().value] = 0
     tcanfl_akls_A[x_tcstrm().value] = 0
     tcanfl_akls_B[x_tcstrm().value] = 0
    end
   end
   if gd_tcflag_pt.prefs.tcstatfl then
    if not tcstatfl_gnt[x_tcstrm().value] then
     tcstatfl_fc[x_tcstrm().value] = 1
     if x_tclngt() then
      tcstatfl_bc[x_tcstrm().value] = x_tclngt().value
     else
      tcstatfl_bc[x_tcstrm().value] = 0
     end
     tcstatfl_gnt[x_tcstrm().value] = pinfo.abs_ts
     tcstatfl_ndt[x_tcstrm().value] = pinfo.abs_ts
     tcstatfl_gnf[x_tcstrm().value] = pinfo.number
     tcstatfl_ndf[x_tcstrm().value] = pinfo.number
     if pinfo.src_port < pinfo.dst_port then
      tcstatfl_fcA[x_tcstrm().value] = 1
      if x_tclngt() then
       tcstatfl_bcA[x_tcstrm().value] = x_tclngt().value
      else
       tcstatfl_bcA[x_tcstrm().value] = 0
      end
      tcstatfl_fcB[x_tcstrm().value] = 0
      tcstatfl_bcB[x_tcstrm().value] = 0
      tcstatfl_wiA[x_tcstrm().value] = x_tcwsiz().value
      tcstatfl_wxA[x_tcstrm().value] = x_tcwsiz().value
      if x_tcanbinf() then
       tcstatfl_bfxA[x_tcstrm().value] = x_tcanbinf().value
      else
       tcstatfl_bfxA[x_tcstrm().value] = 0
      end
      tcstatfl_bfxB[x_tcstrm().value] = 0
      if x_tccrtt() and x_tccrtt().value then
       if tcstatfl_rtxA[x_tcstrm().value] then
        if tcstatfl_rtxA[x_tcstrm().value] < loadstring("return " .. tostring(x_tccrtt().value))() then
         tcstatfl_rtxA[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
        end
       else
        tcstatfl_rtxA[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
       end
      end
     elseif pinfo.src_port > pinfo.dst_port then
      tcstatfl_fcA[x_tcstrm().value] = 0
      tcstatfl_bcA[x_tcstrm().value] = 0
      tcstatfl_fcB[x_tcstrm().value] = 1
      if x_tclngt() then
       tcstatfl_bcB[x_tcstrm().value] = x_tclngt().value
      else
       tcstatfl_bcB[x_tcstrm().value] = 0
      end
      tcstatfl_wiB[x_tcstrm().value] = x_tcwsiz().value
      tcstatfl_wxB[x_tcstrm().value] = x_tcwsiz().value
      tcstatfl_bfxA[x_tcstrm().value] = 0
      if x_tcanbinf() then
       tcstatfl_bfxB[x_tcstrm().value] = x_tcanbinf().value
      else
       tcstatfl_bfxB[x_tcstrm().value] = 0
      end
      if x_tccrtt() and x_tccrtt().value then
       if tcstatfl_rtxB[x_tcstrm().value] then
        if tcstatfl_rtxB[x_tcstrm().value] < loadstring("return " .. tostring(x_tccrtt().value))() then
         tcstatfl_rtxB[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
        end
       else
        tcstatfl_rtxB[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
       end
      end
     elseif pinfo.net_src < pinfo.net_dst then
      tcstatfl_fcA[x_tcstrm().value] = 1
      if x_tclngt() then
       tcstatfl_bcA[x_tcstrm().value] = x_tclngt().value
      else
       tcstatfl_bcA[x_tcstrm().value] = 0
      end
      tcstatfl_fcB[x_tcstrm().value] = 0
      tcstatfl_bcB[x_tcstrm().value] = 0
      tcstatfl_wiA[x_tcstrm().value] = x_tcwsiz().value
      tcstatfl_wxA[x_tcstrm().value] = x_tcwsiz().value
      if x_tcanbinf() then
       tcstatfl_bfxA[x_tcstrm().value] = x_tcanbinf().value
      else
       tcstatfl_bfxA[x_tcstrm().value] = 0
      end
      tcstatfl_bfxB[x_tcstrm().value] = 0
      if x_tccrtt() and x_tccrtt().value then
       if tcstatfl_rtxA[x_tcstrm().value] then
        if tcstatfl_rtxA[x_tcstrm().value] < loadstring("return " .. tostring(x_tccrtt().value))() then
         tcstatfl_rtxA[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
        end
       else
        tcstatfl_rtxA[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
       end
      end
     elseif pinfo.net_src > pinfo.net_dst then
      tcstatfl_fcA[x_tcstrm().value] = 0
      tcstatfl_bcA[x_tcstrm().value] = 0
      tcstatfl_fcB[x_tcstrm().value] = 1
      if x_tclngt() then
       tcstatfl_bcB[x_tcstrm().value] = x_tclngt().value
      else
       tcstatfl_bcB[x_tcstrm().value] = 0
      end
      tcstatfl_wiB[x_tcstrm().value] = x_tcwsiz().value
      tcstatfl_wxB[x_tcstrm().value] = x_tcwsiz().value
      tcstatfl_bfxA[x_tcstrm().value] = 0
      if x_tcanbinf() then
       tcstatfl_bfxB[x_tcstrm().value] = x_tcanbinf().value
      else
       tcstatfl_bfxB[x_tcstrm().value] = 0
      end
      if x_tccrtt() and x_tccrtt().value then
       if tcstatfl_rtxB[x_tcstrm().value] then
        if tcstatfl_rtxB[x_tcstrm().value] < loadstring("return " .. tostring(x_tccrtt().value))() then
         tcstatfl_rtxB[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
        end
       else
        tcstatfl_rtxB[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
       end
      end
     end
    else
     tcstatfl_fc[x_tcstrm().value] = tcstatfl_fc[x_tcstrm().value] + 1
     tcstatfl_bc[x_tcstrm().value] = tcstatfl_bc[x_tcstrm().value] + x_tclngt().value
     if tcstatfl_gnt[x_tcstrm().value] > pinfo.abs_ts then
      tcstatfl_gnt[x_tcstrm().value] = pinfo.abs_ts
      tcstatfl_gnf[x_tcstrm().value] = pinfo.number
     elseif tcstatfl_ndt[x_tcstrm().value] < pinfo.abs_ts then
      tcstatfl_ndt[x_tcstrm().value] = pinfo.abs_ts
      tcstatfl_ndf[x_tcstrm().value] = pinfo.number
     elseif tcstatfl_ndt[x_tcstrm().value] == pinfo.abs_ts and tcstatfl_ndf[x_tcstrm().value] < pinfo.number then
      tcstatfl_ndf[x_tcstrm().value] = pinfo.number
     end
     if pinfo.src_port < pinfo.dst_port then
      tcstatfl_fcA[x_tcstrm().value] = tcstatfl_fcA[x_tcstrm().value] + 1
      tcstatfl_bcA[x_tcstrm().value] = tcstatfl_bcA[x_tcstrm().value] + x_tclngt().value
      if x_tcanbinf() and tcstatfl_bfxA[x_tcstrm().value] < x_tcanbinf().value then
       tcstatfl_bfxA[x_tcstrm().value] = x_tcanbinf().value
      end
      if bit.band(x_tcflag().value, 4) == 0 then
       if tcstatfl_wiA[x_tcstrm().value] then
        if tcstatfl_wiA[x_tcstrm().value] > x_tcwsiz().value then
         tcstatfl_wiA[x_tcstrm().value] = x_tcwsiz().value
        elseif tcstatfl_wxA[x_tcstrm().value] < x_tcwsiz().value then
         tcstatfl_wxA[x_tcstrm().value] = x_tcwsiz().value
        end
       else
        tcstatfl_wiA[x_tcstrm().value] = x_tcwsiz().value
        tcstatfl_wxA[x_tcstrm().value] = x_tcwsiz().value
       end
      end
      if x_tccrtt() and x_tccrtt().value then
       if tcstatfl_rtxA[x_tcstrm().value] then
        if tcstatfl_rtxA[x_tcstrm().value] < loadstring("return " .. tostring(x_tccrtt().value))() then
         tcstatfl_rtxA[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
        end
       else
        tcstatfl_rtxA[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
       end
      end
     elseif pinfo.src_port > pinfo.dst_port then
      tcstatfl_fcB[x_tcstrm().value] = tcstatfl_fcB[x_tcstrm().value] + 1
      tcstatfl_bcB[x_tcstrm().value] = tcstatfl_bcB[x_tcstrm().value] + x_tclngt().value
      if x_tcanbinf() and tcstatfl_bfxB[x_tcstrm().value] < x_tcanbinf().value then
       tcstatfl_bfxB[x_tcstrm().value] = x_tcanbinf().value
      end
      if bit.band(x_tcflag().value, 4) == 0 then
       if tcstatfl_wiB[x_tcstrm().value] then
        if tcstatfl_wiB[x_tcstrm().value] > x_tcwsiz().value then
         tcstatfl_wiB[x_tcstrm().value] = x_tcwsiz().value
        elseif tcstatfl_wxB[x_tcstrm().value] < x_tcwsiz().value then
         tcstatfl_wxB[x_tcstrm().value] = x_tcwsiz().value
        end
       else
        tcstatfl_wiB[x_tcstrm().value] = x_tcwsiz().value
        tcstatfl_wxB[x_tcstrm().value] = x_tcwsiz().value
       end
      end
      if x_tccrtt() and x_tccrtt().value then
       if tcstatfl_rtxB[x_tcstrm().value] then
        if tcstatfl_rtxB[x_tcstrm().value] < loadstring("return " .. tostring(x_tccrtt().value))() then
         tcstatfl_rtxB[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
        end
       else
        tcstatfl_rtxB[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
       end
      end
     elseif pinfo.net_src < pinfo.net_dst then
      tcstatfl_fcA[x_tcstrm().value] = tcstatfl_fcA[x_tcstrm().value] + 1
      tcstatfl_bcA[x_tcstrm().value] = tcstatfl_bcA[x_tcstrm().value] + x_tclngt().value
      if x_tcanbinf() and tcstatfl_bfxA[x_tcstrm().value] < x_tcanbinf().value then
       tcstatfl_bfxA[x_tcstrm().value] = x_tcanbinf().value
      end
      if bit.band(x_tcflag().value, 4) == 0 then
       if tcstatfl_wiA[x_tcstrm().value] then
        if tcstatfl_wiA[x_tcstrm().value] > x_tcwsiz().value then
         tcstatfl_wiA[x_tcstrm().value] = x_tcwsiz().value
        elseif tcstatfl_wxA[x_tcstrm().value] < x_tcwsiz().value then
         tcstatfl_wxA[x_tcstrm().value] = x_tcwsiz().value
        end
       else
        tcstatfl_wiA[x_tcstrm().value] = x_tcwsiz().value
        tcstatfl_wxA[x_tcstrm().value] = x_tcwsiz().value
       end
      end
      if x_tccrtt() and x_tccrtt().value then
       if tcstatfl_rtxA[x_tcstrm().value] then
        if tcstatfl_rtxA[x_tcstrm().value] < loadstring("return " .. tostring(x_tccrtt().value))() then
         tcstatfl_rtxA[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
        end
       else
        tcstatfl_rtxA[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
       end
      end
     elseif pinfo.net_src > pinfo.net_dst then
      tcstatfl_fcB[x_tcstrm().value] = tcstatfl_fcB[x_tcstrm().value] + 1
      tcstatfl_bcB[x_tcstrm().value] = tcstatfl_bcB[x_tcstrm().value] + x_tclngt().value
      if x_tcanbinf() and tcstatfl_bfxB[x_tcstrm().value] < x_tcanbinf().value then
       tcstatfl_bfxB[x_tcstrm().value] = x_tcanbinf().value
      end
      if bit.band(x_tcflag().value, 4) == 0 then
       if tcstatfl_wiB[x_tcstrm().value] then
        if tcstatfl_wiB[x_tcstrm().value] > x_tcwsiz().value then
         tcstatfl_wiB[x_tcstrm().value] = x_tcwsiz().value
        elseif tcstatfl_wxB[x_tcstrm().value] < x_tcwsiz().value then
         tcstatfl_wxB[x_tcstrm().value] = x_tcwsiz().value
        end
       else
        tcstatfl_wiB[x_tcstrm().value] = x_tcwsiz().value
        tcstatfl_wxB[x_tcstrm().value] = x_tcwsiz().value
       end
      end
      if x_tccrtt() and x_tccrtt().value then
       if tcstatfl_rtxB[x_tcstrm().value] then
        if tcstatfl_rtxB[x_tcstrm().value] < loadstring("return " .. tostring(x_tccrtt().value))() then
         tcstatfl_rtxB[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
        end
       else
        tcstatfl_rtxB[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
       end
      end
     end
    end
   end
  else
   if gd_tcflag_pt.prefs.tcanfl then
    if x_tcanfrtr() then
     gd_tcanflmap_nu = bit.bor(gd_tcanflmap_nu, 1)
    end
    if x_tcanka() then
     gd_tcanflmap_nu = bit.bor(gd_tcanflmap_nu, 2)
    end
    if x_tcankaa() then
     gd_tcanflmap_nu = bit.bor(gd_tcanflmap_nu, 4)
    end
    if x_tcanlosg() then
     gd_tcanflmap_nu = bit.bor(gd_tcanflmap_nu, 8)
    end
    if x_tcanooo() then
     gd_tcanflmap_nu = bit.bor(gd_tcanflmap_nu, 16)
    end
    if x_tcanrtr() and not x_tcanfrtr() and not x_tcansrtr() then
     gd_tcanflmap_nu = bit.bor(gd_tcanflmap_nu, 32)
    end
    if x_tcanrusp() then
     gd_tcanflmap_nu = bit.bor(gd_tcanflmap_nu, 64)
    end
    if x_tcansrtr() then
     gd_tcanflmap_nu = bit.bor(gd_tcanflmap_nu, 128)
    end
    if x_tcanwful() then
     gd_tcanflmap_nu = bit.bor(gd_tcanflmap_nu, 256)
    end
    if x_tcanwupd() then
     gd_tcanflmap_nu = bit.bor(gd_tcanflmap_nu, 512)
    end
    if x_tcandack() then
     gd_tcanflmap_nu = bit.bor(gd_tcanflmap_nu, 1024)
    end
    if x_tcanzwin() then
     gd_tcanflmap_nu = bit.bor(gd_tcanflmap_nu, 2048)
    end
    if x_tcanzwp() then
     gd_tcanflmap_nu = bit.bor(gd_tcanflmap_nu, 4096)
    end
    if x_tcanzwpa() then
     gd_tcanflmap_nu = bit.bor(gd_tcanflmap_nu, 8192)
    end
    if x_tcanakls() then
     gd_tcanflmap_nu = bit.bor(gd_tcanflmap_nu, 16384)
    end

    if not gd_tcanflmap_ol[pinfo.number] then
     gd_tcanflmap_ol[pinfo.number] = 0
    elseif gd_tcanflmap_ol[pinfo.number] > 0 then
     if gd_tcanflmap_nu == 0 and tcanflcn[x_tcstrm().value] > 0 then
      tcanflcn[x_tcstrm().value] = tcanflcn[x_tcstrm().value] - 1
      if pinfo.src_port <  pinfo.dst_port then
       tcanflcn_A[x_tcstrm().value] = tcanflcn_A[x_tcstrm().value] - 1
      elseif pinfo.src_port > pinfo.dst_port then
       tcanflcn_B[x_tcstrm().value] = tcanflcn_B[x_tcstrm().value] - 1
      elseif pinfo.net_src < pinfo.net_dst then
       tcanflcn_A[x_tcstrm().value] = tcanflcn_A[x_tcstrm().value] - 1
      elseif pinfo.net_src > pinfo.net_dst then
       tcanflcn_B[x_tcstrm().value] = tcanflcn_B[x_tcstrm().value] - 1
      end
     end
    else
     if gd_tcanflmap_nu > 0 then
      tcanflcn[x_tcstrm().value] = tcanflcn[x_tcstrm().value] + 1
      if pinfo.src_port <  pinfo.dst_port then
       tcanflcn_A[x_tcstrm().value] = tcanflcn_A[x_tcstrm().value] + 1
      elseif pinfo.src_port > pinfo.dst_port then
       tcanflcn_B[x_tcstrm().value] = tcanflcn_B[x_tcstrm().value] + 1
      elseif pinfo.net_src < pinfo.net_dst then
       tcanflcn_A[x_tcstrm().value] = tcanflcn_A[x_tcstrm().value] + 1
      elseif pinfo.net_src > pinfo.net_dst then
       tcanflcn_B[x_tcstrm().value] = tcanflcn_B[x_tcstrm().value] + 1
      end
     end
    end
    gd_tcanflmap_nu = bit.bxor(gd_tcanflmap_ol[pinfo.number], gd_tcanflmap_nu)
    if gd_tcanflmap_nu > 0 then
     if bit.band(gd_tcanflmap_nu, 1) == 1 then
      if bit.band(gd_tcanflmap_ol[pinfo.number], 1) == 0 then
       tcanfl_frtr[x_tcstrm().value] = tcanfl_frtr[x_tcstrm().value] + 1
       if pinfo.src_port <  pinfo.dst_port then
        tcanfl_frtr_A[x_tcstrm().value] = tcanfl_frtr_A[x_tcstrm().value] + 1
       elseif pinfo.src_port > pinfo.dst_port then
        tcanfl_frtr_B[x_tcstrm().value] = tcanfl_frtr_B[x_tcstrm().value] + 1
       elseif pinfo.net_src < pinfo.net_dst then
        tcanfl_frtr_A[x_tcstrm().value] = tcanfl_frtr_A[x_tcstrm().value] + 1
       elseif pinfo.net_src > pinfo.net_dst then
        tcanfl_frtr_B[x_tcstrm().value] = tcanfl_frtr_B[x_tcstrm().value] + 1
       end
      else
       if tcanfl_frtr[x_tcstrm().value] > 0 then
        tcanfl_frtr[x_tcstrm().value] = tcanfl_frtr[x_tcstrm().value] - 1
        if pinfo.src_port <  pinfo.dst_port then
         tcanfl_frtr_A[x_tcstrm().value] = tcanfl_frtr_A[x_tcstrm().value] - 1
        elseif pinfo.src_port > pinfo.dst_port then
         tcanfl_frtr_B[x_tcstrm().value] = tcanfl_frtr_B[x_tcstrm().value] - 1
        elseif pinfo.net_src < pinfo.net_dst then
         tcanfl_frtr_A[x_tcstrm().value] = tcanfl_frtr_A[x_tcstrm().value] - 1
        elseif pinfo.net_src > pinfo.net_dst then
         tcanfl_frtr_B[x_tcstrm().value] = tcanfl_frtr_B[x_tcstrm().value] - 1
        end
       end
      end
     end
     if bit.band(gd_tcanflmap_nu, 2) == 2 then
      if bit.band(gd_tcanflmap_ol[pinfo.number], 2) == 0 then
       tcanfl_ka[x_tcstrm().value] = tcanfl_ka[x_tcstrm().value] + 1
       if pinfo.src_port <  pinfo.dst_port then
        tcanfl_ka_A[x_tcstrm().value] = tcanfl_ka_A[x_tcstrm().value] + 1
       elseif pinfo.src_port > pinfo.dst_port then
        tcanfl_ka_B[x_tcstrm().value] = tcanfl_ka_B[x_tcstrm().value] + 1
       elseif pinfo.net_src < pinfo.net_dst then
        tcanfl_ka_A[x_tcstrm().value] = tcanfl_ka_A[x_tcstrm().value] + 1
       elseif pinfo.net_src > pinfo.net_dst then
        tcanfl_ka_B[x_tcstrm().value] = tcanfl_ka_B[x_tcstrm().value] + 1
       end
      else
       if tcanfl_ka[x_tcstrm().value] > 0 then
        tcanfl_ka[x_tcstrm().value] = tcanfl_ka[x_tcstrm().value] - 1
        if pinfo.src_port <  pinfo.dst_port then
         tcanfl_ka_A[x_tcstrm().value] = tcanfl_ka_A[x_tcstrm().value] - 1
        elseif pinfo.src_port > pinfo.dst_port then
         tcanfl_ka_B[x_tcstrm().value] = tcanfl_ka_B[x_tcstrm().value] - 1
        elseif pinfo.net_src < pinfo.net_dst then
         tcanfl_ka_A[x_tcstrm().value] = tcanfl_ka_A[x_tcstrm().value] - 1
        elseif pinfo.net_src > pinfo.net_dst then
         tcanfl_ka_B[x_tcstrm().value] = tcanfl_ka_B[x_tcstrm().value] - 1
        end
       end
      end
     end
     if bit.band(gd_tcanflmap_nu, 4) == 4 then
      if bit.band(gd_tcanflmap_ol[pinfo.number], 4) == 0 then
       tcanfl_kaa[x_tcstrm().value] = tcanfl_kaa[x_tcstrm().value] + 1
       if pinfo.src_port <  pinfo.dst_port then
        tcanfl_kaa_A[x_tcstrm().value] = tcanfl_kaa_A[x_tcstrm().value] + 1
       elseif pinfo.src_port > pinfo.dst_port then
        tcanfl_kaa_B[x_tcstrm().value] = tcanfl_kaa_B[x_tcstrm().value] + 1
       elseif pinfo.net_src < pinfo.net_dst then
        tcanfl_kaa_A[x_tcstrm().value] = tcanfl_kaa_A[x_tcstrm().value] + 1
       elseif pinfo.net_src > pinfo.net_dst then
        tcanfl_kaa_B[x_tcstrm().value] = tcanfl_kaa_B[x_tcstrm().value] + 1
       end
      else
       if tcanfl_kaa[x_tcstrm().value] > 0 then
        tcanfl_kaa[x_tcstrm().value] = tcanfl_kaa[x_tcstrm().value] - 1
        if pinfo.src_port <  pinfo.dst_port then
         tcanfl_kaa_A[x_tcstrm().value] = tcanfl_kaa_A[x_tcstrm().value] - 1
        elseif pinfo.src_port > pinfo.dst_port then
         tcanfl_kaa_B[x_tcstrm().value] = tcanfl_kaa_B[x_tcstrm().value] - 1
        elseif pinfo.net_src < pinfo.net_dst then
         tcanfl_kaa_A[x_tcstrm().value] = tcanfl_kaa_A[x_tcstrm().value] - 1
        elseif pinfo.net_src > pinfo.net_dst then
         tcanfl_kaa_B[x_tcstrm().value] = tcanfl_kaa_B[x_tcstrm().value] - 1
        end
       end
      end
     end
     if bit.band(gd_tcanflmap_nu, 8) == 8 then
      if bit.band(gd_tcanflmap_ol[pinfo.number], 8) == 0 then
       tcanfl_losg[x_tcstrm().value] = tcanfl_losg[x_tcstrm().value] + 1
       if pinfo.src_port <  pinfo.dst_port then
        tcanfl_losg_A[x_tcstrm().value] = tcanfl_losg_A[x_tcstrm().value] + 1
       elseif pinfo.src_port > pinfo.dst_port then
        tcanfl_losg_B[x_tcstrm().value] = tcanfl_losg_B[x_tcstrm().value] + 1
       elseif pinfo.net_src < pinfo.net_dst then
        tcanfl_losg_A[x_tcstrm().value] = tcanfl_losg_A[x_tcstrm().value] + 1
       elseif pinfo.net_src > pinfo.net_dst then
        tcanfl_losg_B[x_tcstrm().value] = tcanfl_losg_B[x_tcstrm().value] + 1
       end
      else
       if tcanfl_losg[x_tcstrm().value] > 0 then
        tcanfl_losg[x_tcstrm().value] = tcanfl_losg[x_tcstrm().value] - 1
        if pinfo.src_port <  pinfo.dst_port then
         tcanfl_losg_A[x_tcstrm().value] = tcanfl_losg_A[x_tcstrm().value] - 1
        elseif pinfo.src_port > pinfo.dst_port then
         tcanfl_losg_B[x_tcstrm().value] = tcanfl_losg_B[x_tcstrm().value] - 1
        elseif pinfo.net_src < pinfo.net_dst then
         tcanfl_losg_A[x_tcstrm().value] = tcanfl_losg_A[x_tcstrm().value] - 1
        elseif pinfo.net_src > pinfo.net_dst then
         tcanfl_losg_B[x_tcstrm().value] = tcanfl_losg_B[x_tcstrm().value] - 1
        end
       end
      end
     end
     if bit.band(gd_tcanflmap_nu, 16) == 16 then
      if bit.band(gd_tcanflmap_ol[pinfo.number], 16) == 0 then
       tcanfl_ooo[x_tcstrm().value] = tcanfl_ooo[x_tcstrm().value] + 1
       if pinfo.src_port <  pinfo.dst_port then
        tcanfl_ooo_A[x_tcstrm().value] = tcanfl_ooo_A[x_tcstrm().value] + 1
       elseif pinfo.src_port > pinfo.dst_port then
        tcanfl_ooo_B[x_tcstrm().value] = tcanfl_ooo_B[x_tcstrm().value] + 1
       elseif pinfo.net_src < pinfo.net_dst then
        tcanfl_ooo_A[x_tcstrm().value] = tcanfl_ooo_A[x_tcstrm().value] + 1
       elseif pinfo.net_src > pinfo.net_dst then
        tcanfl_ooo_B[x_tcstrm().value] = tcanfl_ooo_B[x_tcstrm().value] + 1
       end
      else
       if tcanfl_ooo[x_tcstrm().value] > 0 then
        tcanfl_ooo[x_tcstrm().value] = tcanfl_ooo[x_tcstrm().value] - 1
        if pinfo.src_port <  pinfo.dst_port then
         tcanfl_ooo_A[x_tcstrm().value] = tcanfl_ooo_A[x_tcstrm().value] - 1
        elseif pinfo.src_port > pinfo.dst_port then
         tcanfl_ooo_B[x_tcstrm().value] = tcanfl_ooo_B[x_tcstrm().value] - 1
        elseif pinfo.net_src < pinfo.net_dst then
         tcanfl_ooo_A[x_tcstrm().value] = tcanfl_ooo_A[x_tcstrm().value] - 1
        elseif pinfo.net_src > pinfo.net_dst then
         tcanfl_ooo_B[x_tcstrm().value] = tcanfl_ooo_B[x_tcstrm().value] - 1
        end
       end
      end
     end
     if bit.band(gd_tcanflmap_nu, 32) == 32 then
      if bit.band(gd_tcanflmap_ol[pinfo.number], 32) == 0 then
       tcanfl_rtr[x_tcstrm().value] = tcanfl_rtr[x_tcstrm().value] + 1
       if pinfo.src_port <  pinfo.dst_port then
        tcanfl_rtr_A[x_tcstrm().value] = tcanfl_rtr_A[x_tcstrm().value] + 1
       elseif pinfo.src_port > pinfo.dst_port then
        tcanfl_rtr_B[x_tcstrm().value] = tcanfl_rtr_B[x_tcstrm().value] + 1
       elseif pinfo.net_src < pinfo.net_dst then
        tcanfl_rtr_A[x_tcstrm().value] = tcanfl_rtr_A[x_tcstrm().value] + 1
       elseif pinfo.net_src > pinfo.net_dst then
        tcanfl_rtr_B[x_tcstrm().value] = tcanfl_rtr_B[x_tcstrm().value] + 1
       end
      else
       if tcanfl_rtr[x_tcstrm().value] > 0 then
        tcanfl_rtr[x_tcstrm().value] = tcanfl_rtr[x_tcstrm().value] - 1
        if pinfo.src_port <  pinfo.dst_port then
         tcanfl_rtr_A[x_tcstrm().value] = tcanfl_rtr_A[x_tcstrm().value] - 1
        elseif pinfo.src_port > pinfo.dst_port then
         tcanfl_rtr_B[x_tcstrm().value] = tcanfl_rtr_B[x_tcstrm().value] - 1
        elseif pinfo.net_src < pinfo.net_dst then
         tcanfl_rtr_A[x_tcstrm().value] = tcanfl_rtr_A[x_tcstrm().value] - 1
        elseif pinfo.net_src > pinfo.net_dst then
         tcanfl_rtr_B[x_tcstrm().value] = tcanfl_rtr_B[x_tcstrm().value] - 1
        end
       end
      end
     end
     if bit.band(gd_tcanflmap_nu, 64) == 64 then
      if bit.band(gd_tcanflmap_ol[pinfo.number], 64) == 0 then
       tcanfl_rusp[x_tcstrm().value] = tcanfl_rusp[x_tcstrm().value] + 1
       if pinfo.src_port <  pinfo.dst_port then
        tcanfl_rusp_A[x_tcstrm().value] = tcanfl_rusp_A[x_tcstrm().value] + 1
       elseif pinfo.src_port > pinfo.dst_port then
        tcanfl_rusp_B[x_tcstrm().value] = tcanfl_rusp_B[x_tcstrm().value] + 1
       elseif pinfo.net_src < pinfo.net_dst then
        tcanfl_rusp_A[x_tcstrm().value] = tcanfl_rusp_A[x_tcstrm().value] + 1
       elseif pinfo.net_src > pinfo.net_dst then
        tcanfl_rusp_B[x_tcstrm().value] = tcanfl_rusp_B[x_tcstrm().value] + 1
       end
      else
       if tcanfl_rusp[x_tcstrm().value] > 0 then
        tcanfl_rusp[x_tcstrm().value] = tcanfl_rusp[x_tcstrm().value] - 1
        if pinfo.src_port <  pinfo.dst_port then
         tcanfl_rusp_A[x_tcstrm().value] = tcanfl_rusp_A[x_tcstrm().value] - 1
        elseif pinfo.src_port > pinfo.dst_port then
         tcanfl_rusp_B[x_tcstrm().value] = tcanfl_rusp_B[x_tcstrm().value] - 1
        elseif pinfo.net_src < pinfo.net_dst then
         tcanfl_rusp_A[x_tcstrm().value] = tcanfl_rusp_A[x_tcstrm().value] - 1
        elseif pinfo.net_src > pinfo.net_dst then
         tcanfl_rusp_B[x_tcstrm().value] = tcanfl_rusp_B[x_tcstrm().value] - 1
        end
       end
      end
     end
     if bit.band(gd_tcanflmap_nu, 128) == 128 then
      if bit.band(gd_tcanflmap_ol[pinfo.number], 128) == 0 then
       tcanfl_srtr[x_tcstrm().value] = tcanfl_srtr[x_tcstrm().value] + 1
       if pinfo.src_port <  pinfo.dst_port then
        tcanfl_srtr_A[x_tcstrm().value] = tcanfl_srtr_A[x_tcstrm().value] + 1
       elseif pinfo.src_port > pinfo.dst_port then
        tcanfl_srtr_B[x_tcstrm().value] = tcanfl_srtr_B[x_tcstrm().value] + 1
       elseif pinfo.net_src < pinfo.net_dst then
        tcanfl_srtr_A[x_tcstrm().value] = tcanfl_srtr_A[x_tcstrm().value] + 1
       elseif pinfo.net_src > pinfo.net_dst then
        tcanfl_srtr_B[x_tcstrm().value] = tcanfl_srtr_B[x_tcstrm().value] + 1
       end
      else
       if tcanfl_srtr[x_tcstrm().value] > 0 then
        tcanfl_srtr[x_tcstrm().value] = tcanfl_srtr[x_tcstrm().value] - 1
        if pinfo.src_port <  pinfo.dst_port then
         tcanfl_srtr_A[x_tcstrm().value] = tcanfl_srtr_A[x_tcstrm().value] - 1
        elseif pinfo.src_port > pinfo.dst_port then
         tcanfl_srtr_B[x_tcstrm().value] = tcanfl_srtr_B[x_tcstrm().value] - 1
        elseif pinfo.net_src < pinfo.net_dst then
         tcanfl_srtr_A[x_tcstrm().value] = tcanfl_srtr_A[x_tcstrm().value] - 1
        elseif pinfo.net_src > pinfo.net_dst then
         tcanfl_srtr_B[x_tcstrm().value] = tcanfl_srtr_B[x_tcstrm().value] - 1
        end
       end
      end
     end
     if bit.band(gd_tcanflmap_nu, 256) == 256 then
      if bit.band(gd_tcanflmap_ol[pinfo.number], 256) == 0 then
       tcanfl_wful[x_tcstrm().value] = tcanfl_wful[x_tcstrm().value] + 1
       if pinfo.src_port <  pinfo.dst_port then
        tcanfl_wful_A[x_tcstrm().value] = tcanfl_wful_A[x_tcstrm().value] + 1
       elseif pinfo.src_port > pinfo.dst_port then
        tcanfl_wful_B[x_tcstrm().value] = tcanfl_wful_B[x_tcstrm().value] + 1
       elseif pinfo.net_src < pinfo.net_dst then
        tcanfl_wful_A[x_tcstrm().value] = tcanfl_wful_A[x_tcstrm().value] + 1
       elseif pinfo.net_src > pinfo.net_dst then
        tcanfl_wful_B[x_tcstrm().value] = tcanfl_wful_B[x_tcstrm().value] + 1
       end
      else
       if tcanfl_wful[x_tcstrm().value] > 0 then
        tcanfl_wful[x_tcstrm().value] = tcanfl_wful[x_tcstrm().value] - 1
        if pinfo.src_port <  pinfo.dst_port then
         tcanfl_wful_A[x_tcstrm().value] = tcanfl_wful_A[x_tcstrm().value] - 1
        elseif pinfo.src_port > pinfo.dst_port then
         tcanfl_wful_B[x_tcstrm().value] = tcanfl_wful_B[x_tcstrm().value] - 1
       elseif pinfo.net_src < pinfo.net_dst then
        tcanfl_wful_A[x_tcstrm().value] = tcanfl_wful_A[x_tcstrm().value] - 1
       elseif pinfo.net_src > pinfo.net_dst then
        tcanfl_wful_A[x_tcstrm().value] = tcanfl_wful_B[x_tcstrm().value] - 1
        end
       end
      end
     end
     if bit.band(gd_tcanflmap_nu, 512) == 512 then
      if bit.band(gd_tcanflmap_ol[pinfo.number], 512) == 0 then
       tcanfl_wupd[x_tcstrm().value] = tcanfl_wupd[x_tcstrm().value] + 1
       if pinfo.src_port <  pinfo.dst_port then
        tcanfl_wupd_A[x_tcstrm().value] = tcanfl_wupd_A[x_tcstrm().value] + 1
       elseif pinfo.src_port > pinfo.dst_port then
        tcanfl_wupd_B[x_tcstrm().value] = tcanfl_wupd_B[x_tcstrm().value] + 1
       elseif pinfo.net_src < pinfo.net_dst then
        tcanfl_wupd_A[x_tcstrm().value] = tcanfl_wupd_A[x_tcstrm().value] + 1
       elseif pinfo.net_src > pinfo.net_dst then
        tcanfl_wupd_B[x_tcstrm().value] = tcanfl_wupd_B[x_tcstrm().value] + 1
       end
      else
       if tcanfl_wupd[x_tcstrm().value] > 0 then
        tcanfl_wupd[x_tcstrm().value] = tcanfl_wupd[x_tcstrm().value] - 1
        if pinfo.src_port <  pinfo.dst_port then
         tcanfl_wupd_A[x_tcstrm().value] = tcanfl_wupd_A[x_tcstrm().value] - 1
        elseif pinfo.src_port > pinfo.dst_port then
         tcanfl_wupd_B[x_tcstrm().value] = tcanfl_wupd_B[x_tcstrm().value] - 1
        elseif pinfo.net_src < pinfo.net_dst then
         tcanfl_wupd_A[x_tcstrm().value] = tcanfl_wupd_A[x_tcstrm().value] - 1
        elseif pinfo.net_src > pinfo.net_dst then
         tcanfl_wupd_B[x_tcstrm().value] = tcanfl_wupd_B[x_tcstrm().value] - 1
        end
       end
      end
     end
     if bit.band(gd_tcanflmap_nu, 1024) == 1024 then
      if bit.band(gd_tcanflmap_ol[pinfo.number], 1024) == 0 then
       tcanfl_dack[x_tcstrm().value] = tcanfl_dack[x_tcstrm().value] + 1
       if pinfo.src_port <  pinfo.dst_port then
        tcanfl_dack_A[x_tcstrm().value] = tcanfl_dack_A[x_tcstrm().value] + 1
        if x_tcandack().value > tcanfl_dack_A_mx[x_tcstrm().value] then
         tcanfl_dack_A_mx[x_tcstrm().value] = x_tcandack().value
        end
       elseif pinfo.src_port > pinfo.dst_port then
        tcanfl_dack_B[x_tcstrm().value] = tcanfl_dack_B[x_tcstrm().value] + 1
        if x_tcandack().value > tcanfl_dack_B_mx[x_tcstrm().value] then
         tcanfl_dack_B_mx[x_tcstrm().value] = x_tcandack().value
        end
       elseif pinfo.net_src < pinfo.net_dst then
        tcanfl_dack_A[x_tcstrm().value] = tcanfl_dack_A[x_tcstrm().value] + 1
        if x_tcandack().value > tcanfl_dack_A_mx[x_tcstrm().value] then
         tcanfl_dack_A_mx[x_tcstrm().value] = x_tcandack().value
        end
       elseif pinfo.net_src > pinfo.net_dst then
        tcanfl_dack_B[x_tcstrm().value] = tcanfl_dack_B[x_tcstrm().value] + 1
        if x_tcandack().value > tcanfl_dack_B_mx[x_tcstrm().value] then
         tcanfl_dack_B_mx[x_tcstrm().value] = x_tcandack().value
        end
       end
      else
       if tcanfl_dack[x_tcstrm().value] > 0 then
        tcanfl_dack[x_tcstrm().value] = tcanfl_dack[x_tcstrm().value] - 1
        if pinfo.src_port <  pinfo.dst_port then
         tcanfl_dack_A[x_tcstrm().value] = tcanfl_dack_A[x_tcstrm().value] - 1
        elseif pinfo.src_port > pinfo.dst_port then
         tcanfl_dack_B[x_tcstrm().value] = tcanfl_dack_B[x_tcstrm().value] - 1
        elseif pinfo.net_src < pinfo.net_dst then
         tcanfl_dack_A[x_tcstrm().value] = tcanfl_dack_A[x_tcstrm().value] - 1
        elseif pinfo.net_src > pinfo.net_dst then
         tcanfl_dack_B[x_tcstrm().value] = tcanfl_dack_B[x_tcstrm().value] - 1
        end
       end
      end
     end
     if bit.band(gd_tcanflmap_nu, 2048) == 2048 then
      if bit.band(gd_tcanflmap_ol[pinfo.number], 2048) == 0 then
       tcanfl_zwin[x_tcstrm().value] = tcanfl_zwin[x_tcstrm().value] + 1
       if pinfo.src_port <  pinfo.dst_port then
        tcanfl_zwin_A[x_tcstrm().value] = tcanfl_zwin_A[x_tcstrm().value] + 1
       elseif pinfo.src_port > pinfo.dst_port then
        tcanfl_zwin_B[x_tcstrm().value] = tcanfl_zwin_B[x_tcstrm().value] + 1
       elseif pinfo.net_src < pinfo.net_dst then
        tcanfl_zwin_A[x_tcstrm().value] = tcanfl_zwin_A[x_tcstrm().value] + 1
       elseif pinfo.net_src > pinfo.net_dst then
        tcanfl_zwin_B[x_tcstrm().value] = tcanfl_zwin_B[x_tcstrm().value] + 1
       end
      else
       if tcanfl_zwin[x_tcstrm().value] > 0 then
        tcanfl_zwin[x_tcstrm().value] = tcanfl_zwin[x_tcstrm().value] - 1
        if pinfo.src_port <  pinfo.dst_port then
         tcanfl_zwin_A[x_tcstrm().value] = tcanfl_zwin_A[x_tcstrm().value] - 1
        elseif pinfo.src_port > pinfo.dst_port then
         tcanfl_zwin_B[x_tcstrm().value] = tcanfl_zwin_B[x_tcstrm().value] - 1
        elseif pinfo.net_src < pinfo.net_dst then
         tcanfl_zwin_A[x_tcstrm().value] = tcanfl_zwin_A[x_tcstrm().value] - 1
        elseif pinfo.net_src > pinfo.net_dst then
         tcanfl_zwin_B[x_tcstrm().value] = tcanfl_zwin_B[x_tcstrm().value] - 1
        end
       end
      end
     end
     if bit.band(gd_tcanflmap_nu, 4096) == 4096 then
      if bit.band(gd_tcanflmap_ol[pinfo.number], 4096) == 0 then
       tcanfl_zwp[x_tcstrm().value] = tcanfl_zwp[x_tcstrm().value] + 1
       if pinfo.src_port <  pinfo.dst_port then
        tcanfl_zwp_A[x_tcstrm().value] = tcanfl_zwp_A[x_tcstrm().value] + 1
       elseif pinfo.src_port > pinfo.dst_port then
        tcanfl_zwp_B[x_tcstrm().value] = tcanfl_zwp_B[x_tcstrm().value] + 1
       elseif pinfo.net_src < pinfo.net_dst then
        tcanfl_zwp_A[x_tcstrm().value] = tcanfl_zwp_A[x_tcstrm().value] + 1
       elseif pinfo.net_src > pinfo.net_dst then
        tcanfl_zwp_B[x_tcstrm().value] = tcanfl_zwp_B[x_tcstrm().value] + 1
       end
      else
       if tcanfl_zwp[x_tcstrm().value] > 0 then
        tcanfl_zwp[x_tcstrm().value] = tcanfl_zwp[x_tcstrm().value] - 1
        if pinfo.src_port <  pinfo.dst_port then
         tcanfl_zwp_A[x_tcstrm().value] = tcanfl_zwp_A[x_tcstrm().value] - 1
        elseif pinfo.src_port > pinfo.dst_port then
         tcanfl_zwp_B[x_tcstrm().value] = tcanfl_zwp_B[x_tcstrm().value] - 1
        elseif pinfo.net_src < pinfo.net_dst then
         tcanfl_zwp_A[x_tcstrm().value] = tcanfl_zwp_A[x_tcstrm().value] - 1
        elseif pinfo.net_src > pinfo.net_dst then
         tcanfl_zwp_B[x_tcstrm().value] = tcanfl_zwp_B[x_tcstrm().value] - 1
        end
       end
      end
     end
     if bit.band(gd_tcanflmap_nu, 8192) == 8192 then
      if bit.band(gd_tcanflmap_ol[pinfo.number], 8182) == 0 then
       tcanfl_zwpa[x_tcstrm().value] = tcanfl_zwpa[x_tcstrm().value] + 1
       if pinfo.src_port <  pinfo.dst_port then
        tcanfl_zwpa_A[x_tcstrm().value] = tcanfl_zwpa_A[x_tcstrm().value] + 1
       elseif pinfo.src_port > pinfo.dst_port then
        tcanfl_zwpa_B[x_tcstrm().value] = tcanfl_zwpa_B[x_tcstrm().value] + 1
       elseif pinfo.net_src < pinfo.net_dst then
        tcanfl_zwpa_A[x_tcstrm().value] = tcanfl_zwpa_A[x_tcstrm().value] + 1
       elseif pinfo.net_src > pinfo.net_dst then
        tcanfl_zwpa_B[x_tcstrm().value] = tcanfl_zwpa_B[x_tcstrm().value] + 1
       end
      else
       if tcanfl_zwpa[x_tcstrm().value] > 0 then
        tcanfl_zwpa[x_tcstrm().value] = tcanfl_zwpa[x_tcstrm().value] - 1
        if pinfo.src_port <  pinfo.dst_port then
         tcanfl_zwpa_A[x_tcstrm().value] = tcanfl_zwpa_A[x_tcstrm().value] - 1
        elseif pinfo.src_port > pinfo.dst_port then
         tcanfl_zwpa_B[x_tcstrm().value] = tcanfl_zwpa_B[x_tcstrm().value] - 1
        elseif pinfo.net_src < pinfo.net_dst then
         tcanfl_zwpa_A[x_tcstrm().value] = tcanfl_zwpa_A[x_tcstrm().value] - 1
        elseif pinfo.net_src > pinfo.net_dst then
         tcanfl_zwpa_B[x_tcstrm().value] = tcanfl_zwpa_B[x_tcstrm().value] - 1
        end
       end
      end
     end
     if bit.band(gd_tcanflmap_nu, 16384) == 16384 then
      if bit.band(gd_tcanflmap_ol[pinfo.number], 16384) == 0 then
       tcanfl_akls[x_tcstrm().value] = tcanfl_akls[x_tcstrm().value] + 1
       if pinfo.src_port <  pinfo.dst_port then
        tcanfl_akls_A[x_tcstrm().value] = tcanfl_akls_A[x_tcstrm().value] + 1
       elseif pinfo.src_port > pinfo.dst_port then
        tcanfl_akls_B[x_tcstrm().value] = tcanfl_akls_B[x_tcstrm().value] + 1
       elseif pinfo.net_src < pinfo.net_dst then
        tcanfl_akls_A[x_tcstrm().value] = tcanfl_akls_A[x_tcstrm().value] + 1
       elseif pinfo.net_src > pinfo.net_dst then
        tcanfl_akls_B[x_tcstrm().value] = tcanfl_akls_B[x_tcstrm().value] + 1
       end
      else
       if tcanfl_akls[x_tcstrm().value] > 0 then
        tcanfl_akls[x_tcstrm().value] = tcanfl_akls[x_tcstrm().value] - 1
        if pinfo.src_port <  pinfo.dst_port then
         tcanfl_akls_A[x_tcstrm().value] = tcanfl_akls_A[x_tcstrm().value] - 1
        elseif pinfo.src_port > pinfo.dst_port then
         tcanfl_akls_B[x_tcstrm().value] = tcanfl_akls_B[x_tcstrm().value] - 1
        elseif pinfo.net_src < pinfo.net_dst then
         tcanfl_akls_A[x_tcstrm().value] = tcanfl_akls_A[x_tcstrm().value] - 1
        elseif pinfo.net_src > pinfo.net_dst then
         tcanfl_akls_B[x_tcstrm().value] = tcanfl_akls_B[x_tcstrm().value] - 1
        end
       end
      end
     end
     gd_tcanflmap_ol[pinfo.number] = bit.bxor(gd_tcanflmap_ol[pinfo.number], gd_tcanflmap_nu)
    end
    if x_icmptype() then
     if not gd_icmptype_ol[pinfo.number] then
      gd_icmptype_ol[pinfo.number] = x_icmptype().value
      if not tcicfl_totl[x_tcstrm().value] then
       tcicfl_totl[x_tcstrm().value] = 1
       if gd_icmptype_ol[pinfo.number] == 3 then
        tcicfl_cn[3][x_tcstrm().value] = 1
       elseif gd_icmptype_ol[pinfo.number] == 11 then
        tcicfl_cn[11][x_tcstrm().value] = 1
       end
      else
       tcicfl_totl[x_tcstrm().value] = tcicfl_totl[x_tcstrm().value] + 1
       if gd_icmptype_ol[pinfo.number] == 3 then
        if not tcicfl_cn[3][x_tcstrm().value] then
         tcicfl_cn[3][x_tcstrm().value] = 1
        else
         tcicfl_cn[3][x_tcstrm().value] = tcicfl_cn[3][x_tcstrm().value] + 1
        end
       elseif gd_icmptype_ol[pinfo.number] == 11 then
        if not fl_typ[Bx_tcstrm().value] then
         tcicfl_cn[11][x_tcstrm().value] = 1
        else
         tcicfl_cn[11][x_tcstrm().value] = tcicfl_cn[11][x_tcstrm().value] + 1
        end
       end
      end
     else
      if gd_icmptype_ol[pinfo.number] ~= x_icmptype().value then
       if gd_icmptype_ol[pinfo.number] == 3 then
        if tcicfl_cn[3][x_tcstrm().value] then
         if tcicfl_cn[3][x_tcstrm().value] > 0 then
          tcicfl_cn[3][x_tcstrm().value] = tcicfl_cn[3][x_tcstrm().value] - 1
         else
          tcicfl_cn[3][x_tcstrm().value] = 0
         end
        end
       elseif gd_icmptype_ol[pinfo.number] == 11 then
        if tcicfl_cn[11][x_tcstrm().value] then
         if tcicfl_cn[11][x_tcstrm().value] > 0 then
          tcicfl_cn[11][x_tcstrm().value] = tcicfl_cn[11][x_tcstrm().value] - 1
         else
          tcicfl_cn[11][x_tcstrm().value] = 0
         end
        end
       end
       gd_icmptype_ol[pinfo.number] = x_icmptype().value
       if gd_icmptype_ol[pinfo.number] == 3 then
        if not tcicfl_cn[3][x_tcstrm().value] then
         tcicfl_cn[3][x_tcstrm().value] = 1
        else
         tcicfl_cn[3][x_tcstrm().value] = tcicfl_cn[3][x_tcstrm().value] + 1
        end
       elseif gd_icmptype_ol[pinfo.number] == 11 then
        if not fl_typ[Bx_tcstrm().value] then
         tcicfl_cn[11][x_tcstrm().value] = 1
        else
         tcicfl_cn[11][x_tcstrm().value] = tcicfl_cn[11][x_tcstrm().value] + 1
        end
       end
      end
     end
    end
   end
   if gd_tcflag_pt.prefs.tcstatfl then
    if not tcstatfl_gnt[x_tcstrm().value] then
     tcstatfl_fc[x_tcstrm().value] = 1
     tcstatfl_gnt[x_tcstrm().value] = pinfo.abs_ts
     tcstatfl_ndt[x_tcstrm().value] = pinfo.abs_ts
     tcstatfl_gnf[x_tcstrm().value] = pinfo.number
     tcstatfl_ndf[x_tcstrm().value] = pinfo.number
     if x_tclngt() then
      tcstatfl_bc[x_tcstrm().value] = x_tclngt().value
      if pinfo.src_port < pinfo.dst_port then
       tcstatfl_fcA[x_tcstrm().value] = 1
       tcstatfl_bcA[x_tcstrm().value] = x_tclngt().value
       tcstatfl_fcB[x_tcstrm().value] = 0
       tcstatfl_bcB[x_tcstrm().value] = 0
       tcstatfl_wiA[x_tcstrm().value] = x_tcwsiz().value
       tcstatfl_wxA[x_tcstrm().value] = x_tcwsiz().value
       if x_tcanbinf() then
        tcstatfl_bfxA[x_tcstrm().value] = x_tcanbinf().value
       else
        tcstatfl_bfxA[x_tcstrm().value] = 0
       end
       tcstatfl_bfxB[x_tcstrm().value] = 0
       if x_tccrtt() and x_tccrtt().value then
        if tcstatfl_rtxA[x_tcstrm().value] then
         if tcstatfl_rtxA[x_tcstrm().value] < loadstring("return " .. tostring(x_tccrtt().value))() then
          tcstatfl_rtxA[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
         end
        else
         tcstatfl_rtxA[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
        end
       end
      elseif pinfo.src_port > pinfo.dst_port then
       tcstatfl_fcA[x_tcstrm().value] = 0
       tcstatfl_bcA[x_tcstrm().value] = 0
       tcstatfl_fcB[x_tcstrm().value] = 1
       tcstatfl_bcB[x_tcstrm().value] = x_tclngt().value
       tcstatfl_wiB[x_tcstrm().value] = x_tcwsiz().value
       tcstatfl_wxB[x_tcstrm().value] = x_tcwsiz().value
       tcstatfl_bfxA[x_tcstrm().value] = 0
       if x_tcanbinf() then
        tcstatfl_bfxB[x_tcstrm().value] = x_tcanbinf().value
       else
        tcstatfl_bfxB[x_tcstrm().value] = 0
       end
       if x_tccrtt() and x_tccrtt().value then
        if tcstatfl_rtxB[x_tcstrm().value] then
         if tcstatfl_rtxB[x_tcstrm().value] < loadstring("return " .. tostring(x_tccrtt().value))() then
          tcstatfl_rtxB[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
         end
        else
         tcstatfl_rtxB[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
        end
       end
      elseif pinfo.net_src < pinfo.net_dst then
       tcstatfl_fcA[x_tcstrm().value] = 1
       tcstatfl_bcA[x_tcstrm().value] = x_tclngt().value
       tcstatfl_fcB[x_tcstrm().value] = 0
       tcstatfl_bcB[x_tcstrm().value] = 0
       tcstatfl_wiA[x_tcstrm().value] = x_tcwsiz().value
       tcstatfl_wxA[x_tcstrm().value] = x_tcwsiz().value
       if x_tcanbinf() then
        tcstatfl_bfxA[x_tcstrm().value] = x_tcanbinf().value
       else
        tcstatfl_bfxA[x_tcstrm().value] = 0
       end
       tcstatfl_bfxB[x_tcstrm().value] = 0
       if x_tccrtt() and x_tccrtt().value then
        if tcstatfl_rtxA[x_tcstrm().value] then
         if tcstatfl_rtxA[x_tcstrm().value] < loadstring("return " .. tostring(x_tccrtt().value))() then
          tcstatfl_rtxA[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
         end
        else
         tcstatfl_rtxA[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
        end
       end
      elseif pinfo.net_src > pinfo.net_dst then
       tcstatfl_fcA[x_tcstrm().value] = 0
       tcstatfl_bcA[x_tcstrm().value] = 0
       tcstatfl_fcB[x_tcstrm().value] = 1
       tcstatfl_bcB[x_tcstrm().value] = x_tclngt().value
       tcstatfl_wiB[x_tcstrm().value] = x_tcwsiz().value
       tcstatfl_wxB[x_tcstrm().value] = x_tcwsiz().value
       tcstatfl_bfxA[x_tcstrm().value] = 0
       if x_tcanbinf() then
        tcstatfl_bfxB[x_tcstrm().value] = x_tcanbinf().value
       else
        tcstatfl_bfxB[x_tcstrm().value] = 0
       end
       if x_tccrtt() and x_tccrtt().value then
        if tcstatfl_rtxB[x_tcstrm().value] then
         if tcstatfl_rtxB[x_tcstrm().value] < loadstring("return " .. tostring(x_tccrtt().value))() then
          tcstatfl_rtxB[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
         end
        else
         tcstatfl_rtxB[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
        end
       end
      end
     else
      tcstatfl_bc[x_tcstrm().value] = 0
      tcstatfl_bcA[x_tcstrm().value] = 0
      tcstatfl_bcB[x_tcstrm().value] = 0
      if pinfo.src_port < pinfo.dst_port then
       tcstatfl_fcA[x_tcstrm().value] = 1
       tcstatfl_fcB[x_tcstrm().value] = 0
       if x_tcwsiz() then
        tcstatfl_wiA[x_tcstrm().value] = x_tcwsiz().value
        tcstatfl_wxA[x_tcstrm().value] = x_tcwsiz().value
       end
       if x_tcanbinf() then
        tcstatfl_bfxA[x_tcstrm().value] = x_tcanbinf().value
       else
        tcstatfl_bfxA[x_tcstrm().value] = 0
       end
       tcstatfl_bfxB[x_tcstrm().value] = 0
       if x_tccrtt() and x_tccrtt().value then
        if tcstatfl_rtxA[x_tcstrm().value] then
         if tcstatfl_rtxA[x_tcstrm().value] < loadstring("return " .. tostring(x_tccrtt().value))() then
          tcstatfl_rtxA[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
         end
        else
         tcstatfl_rtxA[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
        end
       end
      elseif pinfo.src_port > pinfo.dst_port then
       tcstatfl_fcA[x_tcstrm().value] = 0
       tcstatfl_fcB[x_tcstrm().value] = 1
       if x_tcwsiz() then
        tcstatfl_wiB[x_tcstrm().value] = x_tcwsiz().value
        tcstatfl_wxB[x_tcstrm().value] = x_tcwsiz().value
       end
       tcstatfl_bfxA[x_tcstrm().value] = 0
       if x_tcanbinf() then
        tcstatfl_bfxB[x_tcstrm().value] = x_tcanbinf().value
       else
        tcstatfl_bfxB[x_tcstrm().value] = 0
       end
       if x_tccrtt() and x_tccrtt().value then
        if tcstatfl_rtxB[x_tcstrm().value] then
         if tcstatfl_rtxB[x_tcstrm().value] < loadstring("return " .. tostring(x_tccrtt().value))() then
          tcstatfl_rtxB[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
         end
        else
         tcstatfl_rtxB[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
        end
       end
      elseif pinfo.net_src < pinfo.net_dst then
       tcstatfl_fcA[x_tcstrm().value] = 1
       tcstatfl_fcB[x_tcstrm().value] = 0
       if x_tcwsiz() then
        tcstatfl_wiA[x_tcstrm().value] = x_tcwsiz().value
        tcstatfl_wxA[x_tcstrm().value] = x_tcwsiz().value
       end
       if x_tcanbinf() then
        tcstatfl_bfxA[x_tcstrm().value] = x_tcanbinf().value
       else
        tcstatfl_bfxA[x_tcstrm().value] = 0
       end
       tcstatfl_bfxB[x_tcstrm().value] = 0
       if x_tccrtt() and x_tccrtt().value then
        if tcstatfl_rtxA[x_tcstrm().value] then
         if tcstatfl_rtxA[x_tcstrm().value] < loadstring("return " .. tostring(x_tccrtt().value))() then
          tcstatfl_rtxA[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
         end
        else
         tcstatfl_rtxA[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
        end
       end
      elseif pinfo.net_src > pinfo.net_dst then
       tcstatfl_fcA[x_tcstrm().value] = 0
       tcstatfl_fcB[x_tcstrm().value] = 1
       if x_tcwsiz() then
        tcstatfl_wiB[x_tcstrm().value] = x_tcwsiz().value
        tcstatfl_wxB[x_tcstrm().value] = x_tcwsiz().value
       end
       tcstatfl_bfxA[x_tcstrm().value] = 0
       if x_tcanbinf() then
        tcstatfl_bfxB[x_tcstrm().value] = x_tcanbinf().value
       else
        tcstatfl_bfxB[x_tcstrm().value] = 0
       end
       if x_tccrtt() and x_tccrtt().value then
        if tcstatfl_rtxB[x_tcstrm().value] then
         if tcstatfl_rtxB[x_tcstrm().value] < loadstring("return " .. tostring(x_tccrtt().value))() then
          tcstatfl_rtxB[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
         end
        else
         tcstatfl_rtxB[x_tcstrm().value] = loadstring("return " .. tostring(x_tccrtt().value))()
        end
       end
      end
     end
    end
   end
  end

  if gd_tcflag_pt.prefs.tcbm or gd_tcflag_pt.prefs.tcanfl or gd_tcflag_pt.prefs.tcstatfl then
   gd_tcflag_tr[0] = root:add(gd_tcflag_pt):set_generated()
   if gd_tcflag_pt.prefs.tcbm then
    gd_tcflag_tr[1] = gd_tcflag_tr[0]:add(gd_tcflag_bm, gd_tcflag):set_generated()
    if bit.band(gd_tcflag, 3) > 0 then
     gd_tcflag_tr[1]:add(gd_tcflag_Syn[0], true):set_hidden()
     if bit.band(gd_tcflag, 1) == 1 then
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Syn[1], true):set_generated()
      gd_tcflag_tr[2]:set_text("SynA : True = peer A initiated Syn")
     else
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Syn[1], false):set_generated()
      gd_tcflag_tr[2]:set_text("SynA : False")
     end
     if bit.band(gd_tcflag, 2) == 2 then
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Syn[2], true):set_generated()
      gd_tcflag_tr[2]:set_text("SynB : True = peer B initiated Syn")
     else
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Syn[2], false):set_generated()
      gd_tcflag_tr[2]:set_text("SynB : False")
     end
    elseif gd_tcflag_pt.prefs.tcbm_keep0s then
     gd_tcflag_tr[1]:add(gd_tcflag_Syn[0], false):set_hidden()
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Syn[1], false):set_generated()
     gd_tcflag_tr[2]:set_text("SynA : False")
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Syn[2], false):set_generated()
     gd_tcflag_tr[2]:set_text("SynB : False")
    end
    if bit.band(gd_tcflag, 12) > 0 then
     gd_tcflag_tr[1]:add(gd_tcflag_SnA[0], true):set_hidden()
     if bit.band(gd_tcflag, 4) == 4 then
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_SnA[1], true):set_generated()
      gd_tcflag_tr[2]:set_text("SnAA : True = peer A replied with Syn+Ack")
     else
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_SnA[1], false):set_generated()
      gd_tcflag_tr[2]:set_text("SnAA : False")
     end
     if bit.band(gd_tcflag, 8) == 8 then
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_SnA[2], true):set_generated()
      gd_tcflag_tr[2]:set_text("SnAB : True = peer B replied with Syn+Ack")
     else
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_SnA[2], false):set_generated()
      gd_tcflag_tr[2]:set_text("SnAB : False")
     end
    elseif gd_tcflag_pt.prefs.tcbm_keep0s then
     gd_tcflag_tr[1]:add(gd_tcflag_SnA[0], false):set_hidden()
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_SnA[1], false):set_generated()
     gd_tcflag_tr[2]:set_text("SnAA : False")
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_SnA[2], false):set_generated()
     gd_tcflag_tr[2]:set_text("SnAB : False")
    end
    if bit.band(gd_tcflag, 48) > 0 then
     gd_tcflag_tr[1]:add(gd_tcflag_Ack[0], true):set_hidden()
     if bit.band(gd_tcflag, 16) == 16 then
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Ack[1], true):set_generated()
      gd_tcflag_tr[2]:set_text("AckA : True = peer A sent empty Ack")
     else
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Ack[1], false):set_generated()
      gd_tcflag_tr[2]:set_text("AckA : False")
     end
     if bit.band(gd_tcflag, 32) == 32 then
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Ack[2], true):set_generated()
      gd_tcflag_tr[2]:set_text("AckB : True = Peer B sent empty Ack")
     else
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Ack[2], false):set_generated()
      gd_tcflag_tr[2]:set_text("AckB : False")
     end
    elseif gd_tcflag_pt.prefs.tcbm_keep0s then
     gd_tcflag_tr[1]:add(gd_tcflag_Ack[0], false):set_hidden()
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Ack[1], false):set_generated()
     gd_tcflag_tr[2]:set_text("AckA : False")
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Ack[2], false):set_generated()
     gd_tcflag_tr[2]:set_text("AckB : False")
    end
    if bit.band(gd_tcflag, 192) > 0 then
     gd_tcflag_tr[1]:add(gd_tcflag_Dat[0], true):set_hidden()
     if bit.band(gd_tcflag, 64) == 64 then
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Dat[1], true):set_generated()
      gd_tcflag_tr[2]:set_text("DatA : True = peer A sent payload")
     else
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Dat[1], false):set_generated()
      gd_tcflag_tr[2]:set_text("DatA : False")
     end
     if bit.band(gd_tcflag, 128) == 128 then
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Dat[2], true):set_generated()
      gd_tcflag_tr[2]:set_text("DatB : True = peer B sent payload")
     else
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Dat[2], false):set_generated()
      gd_tcflag_tr[2]:set_text("DatB : False")
     end
    elseif gd_tcflag_pt.prefs.tcbm_keep0s then
     gd_tcflag_tr[1]:add(gd_tcflag_Dat[0], false):set_hidden()
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Dat[1], false):set_generated()
     gd_tcflag_tr[2]:set_text("DatA : False")
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Dat[2], false):set_generated()
     gd_tcflag_tr[2]:set_text("DatB : False")
    end
    if bit.band(gd_tcflag, 768) > 0 then
     gd_tcflag_tr[1]:add(gd_tcflag_MTUgt1500[0], true):set_hidden()
     if bit.band(gd_tcflag, 256) == 256 then
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_MTUgt1500[1], true):set_generated()
      gd_tcflag_tr[2]:set_text("MTUAgt1500 : True = peer A sent IP length > 1500 B")
     else
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_MTUgt1500[1], false):set_generated()
      gd_tcflag_tr[2]:set_text("MTUAgt1500 : False")
     end
     if bit.band(gd_tcflag, 512) == 512 then
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_MTUgt1500[2], true):set_generated()
      gd_tcflag_tr[2]:set_text("MTUBgt1500 : True = peer B sent IP length > 1500 B")
     else
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_MTUgt1500[2], false):set_generated()
      gd_tcflag_tr[2]:set_text("MTUBgt1500 : False")
     end
    elseif gd_tcflag_pt.prefs.tcbm_keep0s then
     gd_tcflag_tr[1]:add(gd_tcflag_MTUgt1500[0], false):set_hidden()
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_MTUgt1500[1], false):set_generated()
     gd_tcflag_tr[2]:set_text("MTUAgt1500 : False")
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_MTUgt1500[2], false):set_generated()
     gd_tcflag_tr[2]:set_text("MTUBgt1500 : False")
    end
    if bit.band(gd_tcflag, 3072) > 0 then
     gd_tcflag_tr[1]:add(gd_tcflag_fragment[0], true):set_hidden()
     if bit.band(gd_tcflag, 1024) == 1024 then
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_fragment[1], true):set_generated()
      gd_tcflag_tr[2]:set_text("fragmentA : True = peer A sent IP fragmented")
     else
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_fragment[1], false):set_generated()
      gd_tcflag_tr[2]:set_text("fragmentA : False")
     end
     if bit.band(gd_tcflag, 2048) == 2048 then
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_fragment[2], true):set_generated()
      gd_tcflag_tr[2]:set_text("fragmentB : True = peer B sent IP fragmented")
     else
      gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_fragment[2], false):set_generated()
      gd_tcflag_tr[2]:set_text("fragmentB : False")
     end
    elseif gd_tcflag_pt.prefs.tcbm_keep0s then
     gd_tcflag_tr[1]:add(gd_tcflag_fragment[0], false):set_hidden()
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_fragment[1], false):set_generated()
     gd_tcflag_tr[2]:set_text("fragmentA : False")
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_fragment[2], false):set_generated()
     gd_tcflag_tr[2]:set_text("fragmentB : False")
    end
    if bit.band(gd_tcflag, 61440) > 0 then
     gd_tcflag_tr[1]:add(gd_tcflag_End, true):set_hidden()
     if bit.band(gd_tcflag, 12288) > 0 then
      gd_tcflag_tr[1]:add(gd_tcflag_Fin[0], true):set_hidden()
      if bit.band(gd_tcflag, 4096) == 4096 then
       gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Fin[1], true):set_generated()
       gd_tcflag_tr[2]:set_text("FinA : True = peer A sent Fin")
      else
       gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Fin[1], false):set_generated()
       gd_tcflag_tr[2]:set_text("FinA : False")
      end
      if bit.band(gd_tcflag, 8192) == 8192 then
       gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Fin[2], true):set_generated()
       gd_tcflag_tr[2]:set_text("FinB : True = peer B sent Fin")
      else
       gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Fin[2], false):set_generated()
       gd_tcflag_tr[2]:set_text("FinB : False")
      end
     end
     if bit.band(gd_tcflag, 49152) > 0 then
      gd_tcflag_tr[1]:add(gd_tcflag_Rst[0], true):set_hidden()
      if bit.band(gd_tcflag, 16384) == 16384 then
       gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Rst[1], true):set_generated()
       gd_tcflag_tr[2]:set_text("RstA : True = peer A originated Rst")
      else
       gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Rst[1], false):set_generated()
       gd_tcflag_tr[2]:set_text("RstA : False")
      end
      if bit.band(gd_tcflag, 32768) == 32768 then
       gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Rst[2], true):set_generated()
       gd_tcflag_tr[2]:set_text("RstB : True = peer B originated Rst")
      else
       gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Rst[2], false):set_generated()
       gd_tcflag_tr[2]:set_text("RstB : False")
      end
     end
    elseif gd_tcflag_pt.prefs.tcbm_keep0s then
     gd_tcflag_tr[1]:add(gd_tcflag_End, false):set_hidden()
     gd_tcflag_tr[1]:add(gd_tcflag_Fin[0], false):set_hidden()
     gd_tcflag_tr[1]:add(gd_tcflag_Rst[0], false):set_hidden()
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Fin[1], false):set_generated()
     gd_tcflag_tr[2]:set_text("FinA : False")
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Fin[2], false):set_generated()
     gd_tcflag_tr[2]:set_text("FinB : False")
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Rst[1], false):set_generated()
     gd_tcflag_tr[2]:set_text("RstA : False")
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcflag_Rst[2], false):set_generated()
     gd_tcflag_tr[2]:set_text("RstB : False")
    end
   end

   if gd_tcflag_pt.prefs.tcanfl then
    gd_tcflag_tr[1] = gd_tcflag_tr[0]:add(gd_tcanfl_cn, tcanflcn[x_tcstrm().value]):set_generated()
    gd_tcflag_tr[1]:add(gd_tcanfl_cn_A, tcanflcn_A[x_tcstrm().value]):set_generated()
    gd_tcflag_tr[1]:add(gd_tcanfl_cn_B, tcanflcn_B[x_tcstrm().value]):set_generated()
    if tcanfl_dack[x_tcstrm().value] > 0 then
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcanfl_cn_dack, tcanfl_dack[x_tcstrm().value]):set_generated()
     if tcanfl_dack_A[x_tcstrm().value] then
      gd_tcflag_tr[3] = gd_tcflag_tr[2]:add(gd_tcanfl_cn_dack_A, tcanfl_dack_A[x_tcstrm().value]):set_generated()
      if tcanfl_dack_A[x_tcstrm().value] > 0 then
       gd_tcflag_tr[3]:add(gd_tcanfl_cn_dack_A_mx, tcanfl_dack_A_mx[x_tcstrm().value]):set_generated()
      end
      gd_tcflag_tr[3] = gd_tcflag_tr[2]:add(gd_tcanfl_cn_dack_B, tcanfl_dack_B[x_tcstrm().value]):set_generated()
      if tcanfl_dack_B[x_tcstrm().value] > 0 then
       gd_tcflag_tr[3]:add(gd_tcanfl_cn_dack_B_mx, tcanfl_dack_B_mx[x_tcstrm().value]):set_generated()
      end
     end
    end
    if tcanfl_frtr[x_tcstrm().value] > 0 then
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcanfl_cn_frtr, tcanfl_frtr[x_tcstrm().value]):set_generated()
     if tcanfl_frtr_A[x_tcstrm().value] then
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_frtr_A, tcanfl_frtr_A[x_tcstrm().value]):set_generated()
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_frtr_B, tcanfl_frtr_B[x_tcstrm().value]):set_generated()
     end
    end
    if tcanfl_ka[x_tcstrm().value] > 0 then
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcanfl_cn_ka, tcanfl_ka[x_tcstrm().value]):set_generated()
     if tcanfl_ka_A[x_tcstrm().value] then
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_ka_A, tcanfl_ka_A[x_tcstrm().value]):set_generated()
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_ka_B, tcanfl_ka_B[x_tcstrm().value]):set_generated()
     end
    end
    if tcanfl_kaa[x_tcstrm().value] > 0 then
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcanfl_cn_kaa, tcanfl_kaa[x_tcstrm().value]):set_generated()
     if tcanfl_kaa_A[x_tcstrm().value] then
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_kaa_A, tcanfl_kaa_A[x_tcstrm().value]):set_generated()
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_kaa_B, tcanfl_kaa_B[x_tcstrm().value]):set_generated()
     end
    end
    if tcanfl_losg[x_tcstrm().value] > 0 then
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcanfl_cn_losg, tcanfl_losg[x_tcstrm().value]):set_generated()
     if tcanfl_losg_A[x_tcstrm().value] then
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_losg_A, tcanfl_losg_A[x_tcstrm().value]):set_generated()
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_losg_B, tcanfl_losg_B[x_tcstrm().value]):set_generated()
     end
    end
    if tcanfl_akls[x_tcstrm().value] > 0 then
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcanfl_cn_akls, tcanfl_akls[x_tcstrm().value]):set_generated()
     if tcanfl_akls_A[x_tcstrm().value] then
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_akls_A, tcanfl_akls_A[x_tcstrm().value]):set_generated()
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_akls_B, tcanfl_akls_B[x_tcstrm().value]):set_generated()
     end
    end
    if tcanfl_ooo[x_tcstrm().value] > 0 then
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcanfl_cn_ooo, tcanfl_ooo[x_tcstrm().value]):set_generated()
     if tcanfl_ooo_A[x_tcstrm().value] then
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_ooo_A, tcanfl_ooo_A[x_tcstrm().value]):set_generated()
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_ooo_B, tcanfl_ooo_B[x_tcstrm().value]):set_generated()
     end
    end
    if tcanfl_rtr[x_tcstrm().value] > 0 then
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcanfl_cn_rtr, tcanfl_rtr[x_tcstrm().value]):set_generated()
     if tcanfl_rtr_A[x_tcstrm().value] then
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_rtr_A, tcanfl_rtr_A[x_tcstrm().value]):set_generated()
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_rtr_B, tcanfl_rtr_B[x_tcstrm().value]):set_generated()
     end
    end
    if tcanfl_rusp[x_tcstrm().value] > 0 then
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcanfl_cn_rusp, tcanfl_rusp[x_tcstrm().value]):set_generated()
     if tcanfl_rusp_A[x_tcstrm().value] then
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_rusp_A, tcanfl_rusp_A[x_tcstrm().value]):set_generated()
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_rusp_B, tcanfl_rusp_B[x_tcstrm().value]):set_generated()
     end
    end
    if tcanfl_srtr[x_tcstrm().value] > 0 then
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcanfl_cn_srtr, tcanfl_srtr[x_tcstrm().value]):set_generated()
     if tcanfl_srtr_A[x_tcstrm().value] then
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_srtr_A, tcanfl_srtr_A[x_tcstrm().value]):set_generated()
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_srtr_B, tcanfl_srtr_B[x_tcstrm().value]):set_generated()
     end
    end
    if tcanfl_wful[x_tcstrm().value] > 0 then
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcanfl_cn_wful, tcanfl_wful[x_tcstrm().value]):set_generated()
     if tcanfl_wful_A[x_tcstrm().value] then
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_wful_A, tcanfl_wful_A[x_tcstrm().value]):set_generated()
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_wful_B, tcanfl_wful_B[x_tcstrm().value]):set_generated()
     end
    end
    if tcanfl_wupd[x_tcstrm().value] > 0 then
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcanfl_cn_wupd, tcanfl_wupd[x_tcstrm().value]):set_generated()
     if tcanfl_wupd_A[x_tcstrm().value] then
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_wupd_A, tcanfl_wupd_A[x_tcstrm().value]):set_generated()
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_wupd_B, tcanfl_wupd_B[x_tcstrm().value]):set_generated()
     end
    end
    if tcanfl_zwin[x_tcstrm().value] > 0 then
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcanfl_cn_zwin, tcanfl_zwin[x_tcstrm().value]):set_generated()
     if tcanfl_zwin_A[x_tcstrm().value] then
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_zwin_A, tcanfl_zwin_A[x_tcstrm().value]):set_generated()
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_zwin_B, tcanfl_zwin_B[x_tcstrm().value]):set_generated()
     end
    end
    if tcanfl_zwp[x_tcstrm().value] > 0 then
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcanfl_cn_zwp, tcanfl_zwp[x_tcstrm().value]):set_generated()
     if tcanfl_zwp_A[x_tcstrm().value] then
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_zwp_A, tcanfl_zwp_A[x_tcstrm().value]):set_generated()
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_zwp_B, tcanfl_zwp_B[x_tcstrm().value]):set_generated()
     end
    end
    if tcanfl_zwpa[x_tcstrm().value] > 0 then
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcanfl_cn_zwpa, tcanfl_zwpa[x_tcstrm().value]):set_generated()
     if tcanfl_zwpa_A[x_tcstrm().value] then
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_zwpa_A, tcanfl_zwpa_A[x_tcstrm().value]):set_generated()
      gd_tcflag_tr[2]:add(gd_tcanfl_cn_zwpa_B, tcanfl_zwpa_B[x_tcstrm().value]):set_generated()
     end
    end
    if tcicfl_totl[x_tcstrm().value] then
     gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcicfl_cn[0], tcicfl_totl[x_tcstrm().value]):set_generated()
     if tcicfl_totl[x_tcstrm().value] > 0 then
      if tcicfl_cn[3][x_tcstrm().value] then
       gd_tcflag_tr[2]:add(gd_tcicfl_cn[3], tcicfl_cn[3][x_tcstrm().value]):set_generated()
      end
      if tcicfl_cn[11][x_tcstrm().value] then
       gd_tcflag_tr[2]:add(gd_tcicfl_cn[11], tcicfl_cn[11][x_tcstrm().value]):set_generated()
      end
     end
    end
   end
   if gd_tcflag_pt.prefs.tcstatfl then
    gd_tcflag_tr[1] = gd_tcflag_tr[0]:add(gd_tcstatfl_root):set_generated()
    gd_tcflag_tr[1]:add(gd_tcstatfl_durt, tcstatfl_ndt[x_tcstrm().value] - tcstatfl_gnt[x_tcstrm().value]):set_generated()
    gd_tcflag_tr[1]:add(gd_tcstatfl_bgnf, tcstatfl_gnf[x_tcstrm().value]):set_generated()
    gd_tcflag_tr[1]:add(gd_tcstatfl_endf, tcstatfl_ndf[x_tcstrm().value]):set_generated()
    gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcstatfl_fcnt, tcstatfl_fc[x_tcstrm().value]):set_generated()
    gd_tcflag_tr[2]:add(gd_tcstatfl_fcnt_A, tcstatfl_fcA[x_tcstrm().value]):set_generated()
    gd_tcflag_tr[2]:add(gd_tcstatfl_fcnt_B, tcstatfl_fcB[x_tcstrm().value]):set_generated()
    gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcstatfl_bcnt, tcstatfl_bc[x_tcstrm().value]):set_generated()
    gd_tcflag_tr[2]:add(gd_tcstatfl_bcnt_A, tcstatfl_bcA[x_tcstrm().value]):set_generated()
    gd_tcflag_tr[2]:add(gd_tcstatfl_bcnt_B, tcstatfl_bcB[x_tcstrm().value]):set_generated()
    if tcstatfl_bcA[x_tcstrm().value] == tcstatfl_bcB[x_tcstrm().value] then
     gd_tcflag_tr[2]:add(gd_tcstatfl_bcnt_r, 0.0):set_generated()
    elseif tcstatfl_bcA[x_tcstrm().value] == 0 or tcstatfl_bcB[x_tcstrm().value] == 0 then
     gd_tcflag_tr[2]:add(gd_tcstatfl_bcnt_r, 100.0):set_generated()
    else
     if tcstatfl_bcA[x_tcstrm().value] > tcstatfl_bcB[x_tcstrm().value] then
      gd_tcanflmap_nu = math.log(tcstatfl_bcA[x_tcstrm().value] / tcstatfl_bcB[x_tcstrm().value]) / math.log(10.0)
     else
      gd_tcanflmap_nu = math.log(tcstatfl_bcB[x_tcstrm().value] / tcstatfl_bcA[x_tcstrm().value]) / math.log(10.0)
     end
     if gd_tcanflmap_nu < 10 then
      gd_tcanflmap_nu = gd_tcanflmap_nu * 10.0
     else
      gd_tcanflmap_nu = 100.0
     end
     gd_tcflag_tr[2]:add(gd_tcstatfl_bcnt_r, gd_tcanflmap_nu):set_generated()
    end
    gd_tcflag_tr[2] = gd_tcflag_tr[1]:add(gd_tcstatfl_sub_fc):set_generated()
    if tcstatfl_wiA[x_tcstrm().value] then
     gd_tcflag_tr[2]:add(gd_tcstatfl_wmnsz_A, tcstatfl_wiA[x_tcstrm().value]):set_generated()
     gd_tcflag_tr[2]:add(gd_tcstatfl_wmxsz_A, tcstatfl_wxA[x_tcstrm().value]):set_generated()
    end
    if tcstatfl_wiB[x_tcstrm().value] then
     gd_tcflag_tr[2]:add(gd_tcstatfl_wmnsz_B, tcstatfl_wiB[x_tcstrm().value]):set_generated()
     gd_tcflag_tr[2]:add(gd_tcstatfl_wmxsz_B, tcstatfl_wxB[x_tcstrm().value]):set_generated()
    end
    if tcstatfl_wiA[x_tcstrm().value] and tcstatfl_wiB[x_tcstrm().value] then
     if tcstatfl_wiA[x_tcstrm().value] == 0 or tcstatfl_wiB[x_tcstrm().value] == 0 then
      gd_tcanflmap_nu = 100.0
     else
      if (tcstatfl_wxA[x_tcstrm().value] / tcstatfl_wiA[x_tcstrm().value]) > (tcstatfl_wxB[x_tcstrm().value] / tcstatfl_wiB[x_tcstrm().value]) then
       gd_tcanflmap_nu = math.log(tcstatfl_wxA[x_tcstrm().value] / tcstatfl_wiA[x_tcstrm().value])
      else
       gd_tcanflmap_nu = math.log(tcstatfl_wxB[x_tcstrm().value] / tcstatfl_wiB[x_tcstrm().value])
      end
      if gd_tcanflmap_nu < 10 then
       gd_tcanflmap_nu = gd_tcanflmap_nu * 10.0
      else
       gd_tcanflmap_nu = 100.0
      end
     end
     gd_tcflag_tr[2]:add(gd_tcstatfl_wmxrat, gd_tcanflmap_nu):set_generated()
    end
    if tcstatfl_bfxA[x_tcstrm().value] then
     gd_tcflag_tr[2]:add(gd_tcstatfl_binfx_A, tcstatfl_bfxA[x_tcstrm().value]):set_generated()
    end
    if tcstatfl_bfxB[x_tcstrm().value] then
     gd_tcflag_tr[2]:add(gd_tcstatfl_binfx_B, tcstatfl_bfxB[x_tcstrm().value]):set_generated()
    end
    if tcstatfl_rtxA[x_tcstrm().value] then
     gd_tcflag_tr[2]:add(gd_tcstatfl_rttmx_A, tcstatfl_rtxA[x_tcstrm().value]):set_generated()
    end
    if tcstatfl_rtxB[x_tcstrm().value] then
     gd_tcflag_tr[2]:add(gd_tcstatfl_rttmx_B, tcstatfl_rtxB[x_tcstrm().value]):set_generated()
    end
    if (x_tcirtt() and x_tcirtt().value and loadstring("return " .. tostring(x_tcirtt().value))() > 0) and (tcstatfl_rtxA[x_tcstrm().value] or tcstatfl_rtxB[x_tcstrm().value]) then
     if (not tcstatfl_rtxA[x_tcstrm().value]) or (tcstatfl_rtxB[x_tcstrm().value] and (tcstatfl_rtxA[x_tcstrm().value] < tcstatfl_rtxB[x_tcstrm().value])) then
      tcstatfl_rtxA[x_tcstrm().value] = tcstatfl_rtxB[x_tcstrm().value]
     end
     if tcstatfl_rtxA[x_tcstrm().value] >= loadstring("return " .. tostring(x_tcirtt().value))() then
      tcstatfl_rtxA[x_tcstrm().value] = tcstatfl_rtxA[x_tcstrm().value] /loadstring("return " .. tostring(x_tcirtt().value))()
      tcstatfl_rtxA[x_tcstrm().value] = math.log(tcstatfl_rtxA[x_tcstrm().value]) / math.log(10.0)
      if tcstatfl_rtxA[x_tcstrm().value] < 10 then
       tcstatfl_rtxA[x_tcstrm().value] = tcstatfl_rtxA[x_tcstrm().value] * 10.0
      else
       tcstatfl_rtxA[x_tcstrm().value] = 100.0
      end
      gd_tcflag_tr[2]:add(gd_tcstatfl_rttrat, tcstatfl_rtxA[x_tcstrm().value]):set_generated()
     end
    end
   end
  end

 end

end

register_postdissector(gd_tcflag_pt)

gd_tcflag_pt.prefs.header = Pref.statictext("<br><b>gd_tcflag</b> preference settings<br>", "")

gd_tcflag_pt.prefs.tcbm = Pref.bool( "Enable TCP flags tracking", true, "Uncheck to disable the subsection")
gd_tcflag_pt.prefs.tcbm_keep0s = Pref.bool( " » In TCP flags tracking keep unused flags", true, "Uncheck to save screen space")

gd_tcflag_pt.prefs.tcanfl = Pref.bool( "Enable tcp.analysis tracking", true, "Uncheck to disable the subsection")
gd_tcflag_pt.prefs.tcstatfl = Pref.bool( "Enable TCP statistics tracking", true, "Uncheck to disable the subsection")

gd_tcflag_pt.prefs.footer = Pref.statictext("<br>Developed by Vadim Zakharine - see <a href=\"https://github.com/gr8drag1/gd_tcflag\">github.com/gr8drag1/gd_tcflag</a>", "")
