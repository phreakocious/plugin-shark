<h1>gd_tcflag release history</h1>
<table>
<body>
<tr>
<th>r4</th><td>The single flag End de-aggregated into Fin and Rst.
  <br><b>gd_tcflag.tcbm.End</b> remains for filtering TCP streams containing either Fin or Rst</td></tr>
<th>r5</th><td>Individual flag names added to the filter syntax</td></tr>
  <th>r6</th><td>Counter for tracking "tcp.analysis.flags" added <b>gd_tcflag.tcanfl</b>
  <br><i>Thanks to Laura Chappel</i></td></tr>
<th>r7</th><td>Check for not tcp_keep_alive when tracking the payload (Data)</td></tr>
<th>r8</th><td>Tracking for jumbo IP MTU and for IP fragments added</td></tr>
<th>r9</th><td>Changed IP fragments check from "ip.fragment" to "ip.flags.mf"</td></tr>
<th>r10</th><td>Branches detalisation added for section <b>gd_tcflag.tcanfl</b></td></tr>
<th>r11</th><td>Duplicate Ack added to tracking "tcp.analysis.flags"</td></tr>
<th>r12</th><td>Simplified filter syntax for flags set on either <b>A</b> or <b>B</b> (or both)</td></tr>
<th>r13</th><td>Keep counters separate for fast, spurious and plain retransmissions</td></tr>
<th>r14</th><td>Support for multiple passes in TCP analysis tracking</td></tr>
<th>r15</th><td>TCP analysis differentiation between peers <b>A</b> and <b>B</b> added</td></tr>
<th>r16</th><td>Statistics section <b>gd_tcflag.tcstatfl</b> added</td></tr>
<tr><th>r17</th><td>Sections activation made configurable</td></tr>
<tr><th>r18</th><td>TCP window size field tracking added to the statistics</td></tr>
<tr><th>r19</th><td>TCP bytes in flight tracking added to the statistics
  <br>TCP flow control stats grouped under <b>gd_tcflag.tcstatfl.fc</b></td></tr>
<tr><th>r20</th><td>Clear the global logical structures before processing a new capture</td></tr>
<tr><th>r21</th><td>Maximum tcp.analysis.duplicate_ack_num added under duplicate Ack</td></tr>
<tr><th>r22</th><td>Unused fields of TCP bitmap ("[TCBM]") no longer displayed</td></tr>
<tr><th>r23</th><td>Displaying TCBM unused fields made configurable
  <br><img src="whatsnew-r23.png">
  <br>RTT/IRTT ratio added to stream flow control tracking</td></tr>
 <tr><th>r24</th><td>Aggregate status flags:
  <blockquote>gd_tcflag.tcbm.Syn, gd_tcflag.tcbm.SnA, gd_tcflag.tcbm.Ack, gd_tcflag.tcbm.Dat, gd_tcflag.tcbm.fragment, gd_tcflag.tcbm.End, gd_tcflag.tcbm.Fin, gd_tcflag.tcbm.Rst</blockquote>
  no longer set by enabling the unused fields display option. E. g. a display filter syntax for TCP conversations containing Syn and no data
  <ul>
   <li>With <b>keep unused flags</b> set (the default behaviour):
     <blockquote><i>gd_tcflag.tcbm.Syn == 1 && gd_tcflag.tcbm.Dat == 0</i></blockquote>
   </li>
   <li>With <b>keep unused flags</b> unset:
     <blockquote><i>gd_tcflag.tcbm.Syn && ! gd_tcflag.tcbm.Dat</i></blockquote>
   </li>
  </ul>
  </td></tr>
<tr><th>r25</th><td>
  <ul>
  <li>Code added for handling encapsulated TCP streams</li>
  <li>Counters for ICMP added to TCP analysis section<br>It's worth mentioning that if ICMP truncates the TCP header, then the TCP dissector may not associated the header with the TCP stream <a href="https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=16396">Bug 16396</a>. As long as no TCP stream number is available, this plug-in will not be able to count the ICMP message against the TCP stream</li>
  <li>Code rewritten to stay below Lua limitation:</li>
  <blockquote>tshark: Lua: syntax error: .... gd_tcflag.lua: too many local variables (limit is 200) in main function</blockquote></td></td></tr>
<tr><th>r26</th>
<td><ul>
  <li>Maximum RTT changed to per direction</li>
  <li>Corrections to maximum bytes in flight tracking</li>
  <li>If ICMP truncates the TCP header, then the TCP dissector may not associated the header with the TCP stream https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=16396</li>
  <li>Code rewritten to stay below Lua limitation:<br>
 tshark: Lua: syntax error: .... gd_tcflag.lua: too many local variables (limit is 200) in main function</li></ul></td><tr>
<tr><th>r27</th>
<td>Cosmetic improvements preventing the plugin from reporting errors when tshark is run without "-2"</td></tr>
</tbody>
</table>
