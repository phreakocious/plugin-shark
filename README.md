# plugin-shark
**A collection of useful wireshark/tshark plugins**

\*Plugins directly included in this repo have been tested and verified as functioning.

If they are available on GitHub, they are included as submodules.  Others have been copied from the sources cited below.

| PLUGIN | SOURCE |
| ------ | ------ |
| [1905.1 Protocol Dissector](https://github.com/phreakocious/plugin-shark/blob/master/1905.1.lua) | [sourceforge.net](https://sourceforge.net/p/cdhn4ws) |
| [Microsoft Lync / Skype for Business Plugin](https://github.com/phreakocious/plugin-shark/blob/master/Lync-Skype4B-Plugin2.00.lua) | [Microsoft](https://gallery.technet.microsoft.com/office/Lync-Skype-for-Businesss-d422212f)
| [MPEG2 Transport Stream Packets Dump](https://github.com/phreakocious/plugin-shark/blob/master/mpeg_packets_dump.lua) |[Cisco](https://www.cisco.com/c/en/us/support/docs/broadband-cable/cable-modem-termination-systems-cmts/214210-convert-a-sniffer-trace-to-mpeg-video.html)
| [TCP Statistics](https://github.com/phreakocious/plugin-shark/blob/master/tcp_stats.lua) | [wiki.wireshark.org](https://wiki.wireshark.org/Contrib#Statistic_Taps_or_Post-Dissectors)


### Untested Plugins

**Disclaimer: plugins listed below have not been tested!**

\*\*Denotes that plugin was written in a language other than Lua.

| PLUGIN | DESCRIPTION |
| ------ | ------ |
|[Aerospike Plugin](https://github.com/aerospike/aerospike-wireshark-plugin) | Plugin to interpret Aerospike wire protocol
| [amos-ss16-proj3](https://github.com/AMOS-ss16-proj3/amos-ss16-proj3)  |Plugin for monitoring DoIP network traffic
| [Cap'n Proto RPC protocol dissector](https://github.com/kaos/wireshark-plugins) | Cap'n Proto RPC protocol dissector custom plugin by Kaos
| [CITP-Dissector](https://github.com/hossimo/CITP-Dissector) | Wireshark CITP Lua Dissector
| [Cloudshark Plugin](https://github.com/cloudshark/) | Upload captures directly to CloudShark from Wireshark
| [h264extractor](https://github.com/volvet/h264extractor) | Extract H.264 or opus stream from rtp packets
| [HEP Wireshark](https://github.com/sipcapture/hep-wireshark) | Wireshark Dissector for the HEP Encapsulation Protocol
| [KDNET Debugger](https://github.com/Lekensteyn/kdnet) | Windows Kernel Debugger over Network
|[KSNIFF](https://github.com/eldadru/ksniff)| Kubectl plugin to ease sniffing on Kubernetes pods using tcpdump and Wireshark
| [MQTT Dissector](https://github.com/Johann-Angeli/wireshark-plugin-mqtt) | Authorizes Wireshark to identify and display clearly MQTT messages decoding fixed and variable header
| [protobuf dissector](https://github.com/128technology/protobuf_dissector) | Lua plugin for decoding Google protobuf packets
| [Pyreshark\*\*](https://github.com/ashdnazg/pyreshark) | Provides a simple interface for writing dissectors in Python
| [RFC8450 VC2 Dissector](https://github.com/bbc/rfc8450-vc2-dissector) | Wireshark plugin to parse RTP streams implementing the VC-2 HQ payload specification
| [RSocket](https://github.com/rsocket/rsocket-wireshark) | Wireshark/tshark Plugin in C for RSocket & supports all RSocket frames, except resumption
| [RTP Video and Audio Dissector Wireshark Plugin](https://github.com/hongch911/WiresharkPlugin) | Wireshark plugin for H.265, H.264, PS, PCM, AMR, and SILK Codecs by hongch911
| [SAP Dissector Plugin for Wireshark](https://github.com/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark) | Provides dissection of SAP's NI, Message Server, Router, Diag, Enqueue, IGS, SNC and HDB protocols
| [STOMP Dissector](https://github.com/ficoos/wireshark-stomp-plugin) | STOMP dissector for Wireshark
| [suriwire](https://github.com/regit/suriwire) | Displays Suricata analysis info
| [Wireshark DLMS](https://github.com/bearxiong99/wireshark-dlms) | Dissects DLMS APDUs in HDLC frames, IEC 61334-4-32 frames, wrapper frames, or raw data
| [Wireshark Plugin AFDX](https://github.com/redlab-i/wireshark-plugin-afdx) | AFDX protocol dissector for Wireshark
| [WiresharkLIFXDissector](https://github.com/mab5vot9us9a/WiresharkLIFXDissector) | Dissects packets of the LIFX LAN Protocol