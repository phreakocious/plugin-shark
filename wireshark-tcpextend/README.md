# wireshark-tcpextend
A Wireshark LUA script to display some additional TCP information.

This is a post-dissector script which adds a new tree to the Wireshark view, _TCP extended info_.

All statistics, except delta and ack_sz, are referenced to the sending node, and displayed on both sent and received packets.
* **bsp**: bytes sent since the last push flag. Same as the builtin (since v2.2) tcp.analysis.push_bytes_sent, except this displays for all packets in the flow.
* **bif**: bytes in flight. This will normally equal the built-in `tcp.analysis.bytes_in_flight`, however it is also displayed on the ACK packets.
* **max_tx**: maximum size packet the server can send, equal to the client's receive window minus the server's bytes in flight.
* **pba**: number of packets between this ACK and the packet it ACKs (equal to the builtin `frame.number` minus `tcp.analysis.acks_frame`). TODO: this should be count of how many data packets were received, it is currently everything, even non-TCP.
* **ack_frame**:	frame number which ACKs this packet. Basically the inverse of the builtin tcp.analysis.acks_frame
* **delta**: time since the previous packet was transmitted. Unlike the builtin time delta which is relative to the previous displayed packet, this is relative to the previous packet from the matching sender.
* **ack_sz**: size of the segment(s) this ACK is ACKing.
* **ip_inc**: incremental value of the IP ID field, ie how much bigger (or smaller) than the previous packet. Useful for spotting out of order packets in situations where the IP ID increments by 1 each packet. If Large Segment Offload is running on the server then expect to see frequent large negative values.

## Usage:
Copy to your Wireshark plugins folder:
* on Windows 8 and later: `C:\Users\<username>\AppData\Roaming\Wireshark\plugins`
* on Unix-like systems: `~/.local/lib/wireshark/plugins`

You may need to create the folder first. Read the [Wireshark Docs](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html) for more options, such as installing for all users.

Now when viewing a capture in Wireshark you'll see an extra line in the protocol list, _TCP extended info_. These can be filtered and displayed as columns, just like any native Wireshark protocol information.

**Additional protocol tree:**

![Screenshot of additional protocol tree](https://cloud.githubusercontent.com/assets/1311209/22630851/22ee5e00-ec66-11e6-8fb1-9f7110ca52f1.png)

**Additional columns (highlighted):**

![Screenshot of additional columns](https://cloud.githubusercontent.com/assets/1311209/22630850/22e8597e-ec66-11e6-9c81-93b7d6b75742.png)

## Compatibility
Tested on Wireshark 2.2.4 under Windows 10. It may work with other OS and versions, if it doesn't submit an issue or pull request.

## Known limitiations:
* PBA counts all packets, not just TCP packets
