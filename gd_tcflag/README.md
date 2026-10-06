<h1><b>gd_tcflag</b> Wireshark Lua (wslua) post-dissector plug-in</h1>

<table border="0">
<thead>
<tr>
 <th>A Wireshark Lua post-dissector for express analysis of TCP conversations performance</th>
 <td align="center" valign="center"><img src="Wireshark.png"></td></tr>
 </tr>
 <tr>
  <td colspan="2">
   Allows display filters to include complete TCP streams which contained at some point Syn, Syn+Ack, Fin, Rst, payload, retransmissions, zero window and etc., as well as total duration, number of frames and payload bytes<br>
   The reverse also holds true: by examining any frame it is possible to see if the corresponding TCP stream had Syn, Syn+Ack, Fin, Rst, payload, retransmissions, zero window and etc., for how long the conversation lasted and how many frames and payload bytes from each endpoint were seen
</thead>
<tbody>
<tr>
 <td colspan="2">
Each conversation endpoint, A and B, is tracked individually. The decision which side is A or B is performed as follows:
<ul>
 <li>If one TCP port is numerically less than the other, then the lesser port is A and the greater port is B</li>
 <li>If the port values are identical, then A is the numerically lesser IP address</li>
</ul>
 </tr>
</tbody>
</table>

The post-dissector creates its own section with three subsections.

<h2>Protocol flags subsection, <i>gd_tcflag.tcbm</i></h2>
    
<p>
Composed of the following boolean flags:
<ul>
 <li><b>gd_tcflag.tcbm.Syn</b> : either gd_tcflag.tcbm.SynA or gd_tcflag.tcbm.SynB
  <blockquote>
  <sup>[1]</sup> gd_tcflag.tcbm.SynA : peer A sent flag Syn<br>
  <sup>[2]</sup> gd_tcflag.tcbm.SynB : peer B sent flag Syn
  </blockquote>
 </li>
 <li><b>gd_tcflag.tcbm.SnA</b> : either gd_tcflag.tcbm.SnAA or gd_tcflag.tcbm.SnAB
  <blockquote>
  <sup>[4]</sup> gd_tcflag.tcbm.SnAA : peer A sent flags Syn+Ack<br>
  <sup>[8]</sup> gd_tcflag.tcbm.SnAB : peer B sent flags Syn+Ack
  </blockquote>
 </li>
 <li><b>gd_tcflag.tcbm.Ack</b> : either gd_tcflag.tcbm.AckA or gd_tcflag.tcbm.AckB
  <blockquote>
  <sup>[16]</sup> gd_tcflag.tcbm.AckA : peer A sent flag Ack (with no data payload)<br>
  <sup>[32]</sup> gd_tcflag.tcbm.AckB : peer B sent flag Ack (with no data payload)
  </blockquote>
</li>
 <li><b>gd_tcflag.tcbm.Dat</b> : either gd_tcflag.tcbm.DatA or gd_tcflag.tcbm.DatB
  <blockquote>
  <sup>[64]</sup> gd_tcflag.tcbm.DatA : peer A sent a TCP segment containing data payload<br>
  <sup>[128]</sup> gd_tcflag.tcbm.DatB : peer B sent a TCP segment containing data payload
  </blockquote>
 </li>
 <li><b>gd_tcflag.tcbm.MTUgt1500</b> : either gd_tcflag.tcbm.MTUgt1500A or gd_tcflag.tcbm.MTUgt1500B
  <blockquote>
   <sup>[256]</sup> gd_tcflag.tcbm.MTUgt1500A : peer A sent an IP packet longer than 1500 B<br>
   <sup>[512]</sup> gd_tcflag.tcbm.MTUgt1500B : peer B sent an IP packet longer than 1500 B
  </blockquote>
 </li>
 <li><b>gd_tcflag.tcbm.fragment</b> : either gd_tcflag.tcbm.fragmentA or gd_tcflag.tcbm.fragmentB
  <blockquote>
    <sup>[1024]</sup> gd_tcflag.tcbm.fragmentA : peer A sent a IP packet with MF (more fragments) flag set<br>
    <sup>[2048]</sup> gd_tcflag.tcbm.fragmentB : peer B sent a IP packet with MF (more fragments) flag set
  </blockquote>
 </li>
 <li><b>gd_tcflag.tcbm.Fin</b> : either gd_tcflag.tcbm.FinA or gd_tcflag.tcbm.FinB
  <blockquote>
   <sup>[4096]</sup> gd_tcflag.tcbm.FinA : peer A sent flag Fin<br>
   <sup>[8192]</sup> gd_tcflag.tcbm.FinB : peer B sent flag Fin
  </blockquote>
 </li>
 <li><b>gd_tcflag.tcbm.Rst</b> : either gd_tcflag.tcbm.RstA or gd_tcflag.tcbm.RstB
  <blockquote>
   <sup>[16384]</sup> gd_tcflag.tcbm.RstA : peer A sent flag Rst<br>
   <sup>[32768]</sup> gd_tcflag.tcbm.RstB : peer B sent flag Rst
  </blockquote>
 </li>
</ul>
</p>

<h2>Protocol analysis counters subsection, <i>gd_tcflag.tcanflcn</i></h2>

<p>
TCP payload gone missing
 <ul>
  <li><i>gd_tcflag.tcanflcn.ooo</i> : Number of frames flagged with <b>tcp.analysis.out_of_order</b></li>
  <li><i>gd_tcflag.tcanflcn.rtr</i> : Number of frames flagged with <b>tcp.analysis.retransmission</b></li>
  <li><i>gd_tcflag.tcanflcn.frtr</i> : Number of frames flagged with <b>tcp.analysis.fast_retransmission</b></li>
  <li><i>gd_tcflag.tcanflcn.srtr</i> : Number of frames flagged with <b>tcp.analysis.spurious_retransmission</b></li>
  <li><i>gd_tcflag.tcanflcn.dack</i> : Number of frames flagged with <b>tcp.analysis.duplicate_ack_num</b></li>
  <li><i>gd_tcflag.tcanflcn.losg</i> : Number of frames flagged with <b>tcp.analysis.lost_segment</b></li>
 </ul>
</p>

<p>
TCP window flow control
<ul>
 <li><i>gd_tcflag.tcanflcn.wful</i> : Number of frames flagged with <b>tcp.analysis.window_full</b></li>
 <li><i>gd_tcflag.tcanflcn.wupd</i> : Number of frames flagged with <b>tcp.analysis.window_update</b></li>
 <li><i>gd_tcflag.tcanflcn.zwin</i> : Number of frames flagged with <b>tcp.analysis.zero_window</b></li>
 <li><i>gd_tcflag.tcanflcn.zwp</i> : Number of frames flagged with <b>tcp.analysis.zero_window_probe</b></li>
 <li><i>gd_tcflag.tcanflcn.zwpa</i> : Number of frames flagged with <b>tcp.analysis.zero_window_probe_ack</b></li>
</ul>
</p>

<p>
TCP keep-alive
<ul>
 <li><i>gd_tcflag.tcanflcn.ka</i> : Number of frames flagged with <b>tcp.analysis.keep_alive</b></li>
 <li><i>gd_tcflag.tcanflcn.kaa</i> : Number of frames flagged with <b>tcp.analysis.keep_alive_ack</b></li>
</ul>
</p>

<p>
Miscellaneous
<ul><li><i>gd_tcflag.tcanflcn.rusp</i> : Number of frames flagged with <b>tcp.analysis.reused_ports</b></li></ul>
</p>

<h2>Protocol statistics counters subsection, <i>gd_tcflag.tcstatfl</i></h2>

<p>
 <ul>
  <li><b>gd_tcflag.tcstatfl.duration</b> : TCP stream duration</li>
  <li><b>gd_tcflag.tcstatfl.begin</b> : First frame of the TCP stream</li>
  <li><b>gd_tcflag.tcstatfl.end</b> : Last frame of the TCP stream</li>
 </ul>
</p>

<p>
 <ul>
  <li><b>gd_tcflag.tcstatfl.framcount</b> : Total number of frames
   <ul>
    <li><i>gd_tcflag.tcstatfl.framcount_A</i> : Number of frames received from A</li>
    <li><i>gd_tcflag.tcstatfl.framcount_B</i> : Number of frames received from B</li>
   </ul>
  </li> 
 </ul>
</p>

<p>
<ul>
 <li><b>gd_tcflag.tcstatfl.bytecount</b> : Total number of payload bytes
  <ul>
   <li><i>gd_tcflag.tcstatfl.bytecount_A</i> : Number of payload bytes received from A</li>
   <li><i>gd_tcflag.tcstatfl.bytecount_B</i> : Number of payload bytes received from B</li>
   <li><b>gd_tcflag.tcstatfl.byteratio</b> : Ratio of payload bytes, dB (logarithmic, between 0 and 100)
    <ul>
     <li>If the actual ratio value is higher, it it capped at 100 dB still</li>
     <li>Values close to 0 dB mean that each endpoint sent an approximately equal number of payload bytes</li>
     <li>By the nature of the scale, each 3 dB approximately equals to two times the difference. Each 10 dB represents an order of magnitude difference</li>
    </ul>
   </li>
  </ul>
 </li>
</ul>
</p>

<p>
<ul>
 <li><b>gd_tcflag.tcstatfl.fc</b> : TCP flow control
  <ul>
   <li><i>gd_tcflag.tcstatfl.fc.winsizmin_A</i> : Lowest receive window size received from A</li>
   <li><i>gd_tcflag.tcstatfl.fc.winsizmax_A</i> : Highest receive window size received from A</li>
   <li><i>gd_tcflag.tcstatfl.fc.winsizmin_B</i> : Lowest receive window size received from B</li>
   <li><i>gd_tcflag.tcstatfl.fc.winsizmax_B</i> : Highest receive window size received from B</li>
   <li><b>gd_tcflag.tcstatfl.fc.winsizratio</b> : Window sizes ratio, dB (logarithmic, between 0 and 100)
    <ul>
     <li>If the actual ratio value is higher, it it capped at 100 dB still</li>
     <li>Values close to 0 dB mean that the lowest and the highest window sizes are approximately equal</li>
     <li>By the nature of the scale, each 3 dB approximately equals to two times the difference. Each 10 dB represents an order of magnitude difference</li>
    </ul>
   </li>
   <li><i>gd_tcflag.tcstatfl.fc.byteinflmax_A</i> : Highest value of bytes in flight seen from A</li>
   <li><i>gd_tcflag.tcstatfl.fc.byteinflmax_B</i> : Highest value of bytes in flight seen from B</li>
  </ul>
 </li>
</ul>
</p>

<h2>Known limitations</h2>

<p>
Believed fundamental to the architecture of the host code
</p>

<p>
<ul>
 <li>TCP stream numbering. The decision between whether a frame belongs to an existing TCP stream or to a new one belongs to the TCP protocol dissector</li>
  <li>Wireshark (GUI) parses the loaded packet trace digressing during the second pass [displaying the packets updated by these digressions], while tshark (CLI) performs the second pass [explicitly enforced with option <b>-2</b>] linearly. As a result:
<ul>
 <li>In the GUI gd_tcflag values always covers the complete TCP stream and it is immediately possible to see whether the respective TCP stream contained any Syn, data payload, Fin or Rst by looking at any arbitrary TCP segment of the stream</li>
 <li>In the CLI gd_tcflag values may be accumulating over the lifetime of the TCP stream registering new events with only the last TCP segment of the stream is guaranteed to contain the complete record</li>
  <li>In the CLI gd_tcflag values may be accumulating over the lifetime of the TCP stream registering new events with only the last TCP segment of the stream is guaranteed to contain the complete record</li>
 <li>If a packet capture is being open in an existing window of Wireshark with a non-empty display filter other than <b>tcp.analysis.flags</b>, then counters of section <b>[TCP analysis flagged]</b> may report incorrect values until the display filter is changed</li>
</ul>
 </li>
 </ul>
