# plugin-shark
**A collection of useful Wireshark/tshark plugins**

## Install

```sh
git clone --recursive https://github.com/phreakocious/plugin-shark ~/.local/lib/wireshark/plugins/plugin-shark
```

Wireshark loads every `.lua` file under its personal Lua plugin folder, subfolders included. *Help → About Wireshark → Folders* shows where that folder is on your system.

## Included plugins

`./check.sh` installs the repo into a throwaway plugin folder. It fails if a plugin does not load, or raises a Lua error while dissecting `test.pcap` (TCP, HTTP and TLS over loopback, starting mid-stream). Last passed on Wireshark 4.6.6 (Lua 5.5).

| PLUGIN | WHAT IT ADDS | SOURCE | CHECKED |
| ------ | ------------ | ------ | ------- |
| [gd_l4](gd_l4/gd_l4.lua) | L4 stream index and protocol name, for one column across all protocols | [gr8drag1/gd_l4](https://github.com/gr8drag1/gd_l4), vendored | dissects test.pcap |
| [gd_tcflag](gd_tcflag/gd_tcflag.lua) | Per-TCP-conversation flags and stats, so a display filter can select whole streams | [gr8drag1/gd_tcflag](https://github.com/gr8drag1/gd_tcflag) r27, vendored | dissects test.pcap |
| [TCPextend](wireshark-tcpextend/TCPextend-post_dissector.lua) | Bytes in flight, bytes since push and per-sender delta on every packet | [gaddman/wireshark-tcpextend](https://github.com/gaddman/wireshark-tcpextend), vendored | dissects test.pcap |
| [TLSextend](TLSextend/TLSextend.lua) | TLS handshake state per TCP stream: `TLSextend.state==1` finds a ClientHello that got no ServerHello | [syn-bit/TLSextend](https://github.com/syn-bit/TLSextend), vendored | dissects test.pcap |
| [http-extra](wireshark-http-extra/http_response_patcher.lua) | Request method, URI and host on each HTTP response; full URL on both | [shomeax/wireshark-http-extra](https://github.com/shomeax/wireshark-http-extra), vendored | dissects test.pcap |
| [Cap'n Proto RPC](wireshark-plugins/plugins) | Cap'n Proto RPC dissector | [kaos/wireshark-plugins](https://github.com/kaos/wireshark-plugins), submodule | loads |
| [Lync / Skype for Business](Lync-Skype4B-Plugin2_00.lua) | MS-TURN, ICE and RTP/RTCP for Lync and Skype for Business | James Cussen, v2.0.0 (original pages are gone) | loads |
| [MPEG2 TS dump](mpeg_packets_dump.lua) | *Tools → Dump MPEG TS Packets* writes MPEG TS packets to a file (GUI only) | [Cisco](https://www.cisco.com/c/en/us/support/docs/broadband-cable/cable-modem-termination-systems-cmts/214210-convert-a-sniffer-trace-to-mpeg-video.html) | loads |
| [TCP statistics](tcp_stats.lua.disabled) | Per-stream TCP report: MSS, window scaling, SACK, iRTT, worst delta and window | [Wireshark wiki](https://gitlab.com/wireshark/wireshark/-/wikis/Contrib) | runs on test.pcap |

*Vendored* means copied into this repo and patched where Wireshark 4.x needed it. The first line of each vendored file names its upstream commit; `git log` has the changes. Every third-party file keeps its author's license: GPL for the vendored plugins; the Lync plugin's header forbids commercial use without its author's consent; the MPEG dump and TCP statistics scripts state no license. The BSD-2-Clause [LICENSE](LICENSE) covers only what this repo adds: `check.sh`, `test.pcap`, this README and `preferences.plugin-shark`.

In tshark, TCPextend and TLSextend fill their fields on the second pass. Use `-2 -R frame`: without a read filter, tshark's first pass gives Lua plugins no field values.

TCP statistics prints a report, so it would print into every tshark run if Wireshark auto-loaded it. Its file name does not end in `.lua`, so run it on demand:

```sh
tshark -o tcp.calculate_timestamps:TRUE -q -n -X lua_script:tcp_stats.lua.disabled -r capture.pcapng
```

`preferences.plugin-shark` is a Wireshark preferences file. Its "host" column uses `http_resp.host` from http-extra.

### Dropped: Wireshark now dissects these natively

NMEA 0183, Redis (RESP), IEEE 1905.1a, MQTT, DoIP, DLMS, protobuf, and SAP's NI, Router, Diag, Message Server, Enqueue, IGS, SNC and HDB protocols. Pyreshark is gone too (archived in 2015).

### Untested plugins

**Disclaimer: plugins listed below have not been tested!**

| PLUGIN | DESCRIPTION |
| ------ | ------ |
| [Aerospike Plugin](https://github.com/aerospike-community/aerospike-wireshark-plugin) | Plugin to interpret Aerospike wire protocol
| [Apple Continuity](https://github.com/furiousMAC/continuity) | Apple Continuity protocol dissector (C)
| [Chromium IPC Sniffer](https://github.com/tomer8007/chromium-ipc-sniffer) | Capture and dissect messages between Chromium processes (Windows)
| [CITP-Dissector](https://github.com/hossimo/CITP-Dissector) | Wireshark CITP Lua Dissector
| [Cloudshark Plugin](https://github.com/cloudshark/) | Upload captures directly to CloudShark from Wireshark
| [Edgeshark](https://github.com/siemens/cshargextcap) | Extcap: live capture from containers and pods (Linux, Windows)
| [FoxIO JA4+](https://github.com/FoxIO-LLC/ja4/tree/main/wireshark) | JA4S, JA4H, JA4L, JA4X, JA4SSH, JA4T and JA4D fingerprints (Wireshark has JA3 and JA4 built in). Native: prebuilt for macOS arm64, Linux, Windows; FoxIO license
| [FRITZ!Box extcap](https://github.com/Rob--W/fritzbox-extcap-wireshark) | Extcap: capture from FRITZ!Box routers
| [h264extractor](https://github.com/volvet/h264extractor) | Extract H.264 or opus stream from rtp packets
| [HEP Wireshark](https://github.com/sipcapture/hep-wireshark) | Wireshark Dissector for the HEP Encapsulation Protocol
| [Inspektor Gadget extcap](https://github.com/inspektor-gadget/ig-extcap) | Extcap: capture from Kubernetes pods
| [KDNET Debugger](https://github.com/Lekensteyn/kdnet) | Windows Kernel Debugger over Network
| [KSNIFF](https://github.com/eldadru/ksniff) | Kubectl plugin to ease sniffing on Kubernetes pods using tcpdump and Wireshark
| [Open Drone ID](https://github.com/opendroneid/wireshark-dissector) | Drone Remote ID broadcast dissector
| [RFC8450 VC2 Dissector](https://github.com/bbc/rfc8450-vc2-dissector) | Wireshark plugin to parse RTP streams implementing the VC-2 HQ payload specification
| [RSocket](https://github.com/rsocket/rsocket-wireshark) | Wireshark/tshark Plugin in C for RSocket & supports all RSocket frames, except resumption
| [RTP Video and Audio Dissector Wireshark Plugin](https://github.com/hongch911/WiresharkPlugin) | Wireshark plugin for H.265, H.264, PS, PCM, AMR, and SILK Codecs by hongch911
| [STOMP Dissector](https://github.com/ficoos/wireshark-stomp-plugin) | STOMP dissector for Wireshark
| [suriwire](https://github.com/regit/suriwire) | Displays Suricata analysis info
| [Telegram MTProto](https://github.com/tomer8007/mtproto-dissector) | Telegram MTProto dissector
| [Wireshark Plugin AFDX](https://github.com/redlab-i/wireshark-plugin-afdx) | AFDX protocol dissector for Wireshark
| [WiresharkLIFXDissector](https://github.com/mab5vot9us9a/WiresharkLIFXDissector) | Dissects packets of the LIFX LAN Protocol
