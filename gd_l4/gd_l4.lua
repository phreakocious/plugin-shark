-- Vendored from https://github.com/gr8drag1/gd_l4 (6e5e4d7). Modified 2019-07-28: F5 trailer fields removed.
-- Post-dissector creating subtree "gd_l4" with L4 stream id and IP protocol
-- name. If the IP protocol is not identified, but L4 stream id is present,
-- then the name is set to either "T+" or "U+". If IP protocol field is not
-- present, then the name is set to '-'
-- (C) G. Dragon


local gd_l4ip4lngt = Field.new("ip.len")
local gd_l4ip6lngt = Field.new("ipv6.plen")
local gd_l4ip4prot = Field.new("ip.proto")
local gd_l4ip4fof = Field.new("ip.frag_offset")
local gd_l4ip4fmo = Field.new("ip.flags.mf")
local gd_l4ip6prot = Field.new("ipv6.nxt")
local gd_l4ip6dst = Field.new("ipv6.dstopts.nxt")
local gd_l4ip6hop = Field.new("ipv6.hopopts.nxt")
local gd_l4ip6fpr = Field.new("ipv6.fraghdr.nxt")
local gd_l4ip6fof = Field.new("ipv6.fraghdr.offset")
local gd_l4ip6fmo = Field.new("ipv6.fraghdr.more")
local gd_l4ip6rtn = Field.new("ipv6.routing.nxt")
local gd_l4tcstrm = Field.new("tcp.stream")
local gd_l4udstrm = Field.new("udp.stream")
local gd_l4scstrm = Field.new("sctp.assoc_index")

local gd_l4proto = Proto("gd_l4", "Layer 4 id")
local l3ln = ProtoField.new("L3ln", "gd_l4.l3ln", ftypes.UINT32)
local l4ix = ProtoField.new("L4id", "gd_l4.l4ix", ftypes.UINT32)
local l4nm = ProtoField.new("L4nm", "gd_l4.l4nm", ftypes.STRING)

gd_l4proto.fields = {
 l3ln,
 l4ix,
 l4nm
}

function gd_l4proto.dissector(tvbuf, pktinfo, root)

 local gd_l4tree = root:add(gd_l4proto):set_generated()
 local lngt = nil
 local indx = nil
 local pnam = nil

 if gd_l4ip4lngt() then
  lngt = gd_l4ip4lngt().value
  if gd_l4ip4prot() then
   indx = gd_l4ip4prot().value
  end
 elseif gd_l4ip6lngt() then
  lngt = gd_l4ip6lngt().value
  if gd_l4ip6prot() then
--   local indxlist = {gd_l4ip6prot()}
--   for i in pairs(indxlist) do
--    if indx ~= 6 and indx ~= 17 and indx ~= 58 and indx ~= 132 then
--     indx = indxlist[i]
--    end
--   end
   if gd_l4ip6fpr() then
    indx = gd_l4ip6fpr().value
   elseif gd_l4ip6hop() then
    indx = gd_l4ip6hop().value
   elseif gd_l4ip6dst() then
    indx = gd_l4ip6dst().value
   elseif gd_l4ip6rtn() then
    indx = gd_l4ip6rtn().value
   else
    indx = gd_l4ip6prot().value
   end
  end
 end

 if lngt then
  gd_l4tree:add(l3ln, lngt):set_generated()
 end

 if indx == 1 or indx == 58 then
--  1 is ICMP
-- 58 is ICMPv6
  if gd_l4tcstrm() then
   gd_l4tree:add(l4ix, gd_l4tcstrm().value):set_generated()
   pnam = "T\\I"
  elseif gd_l4udstrm() then
   gd_l4tree:add(l4ix, gd_l4udstrm().value):set_generated()
   pnam = "U\\I"
  elseif gd_l4scstrm() then
   gd_l4tree:add(l4ix, gd_l4scstrm().value):set_generated()
   pnam = "s\\I"
  else
   pnam = "I"
  end
 elseif indx == 6 then
  if gd_l4tcstrm() then
--  indx = string.format("%sT", gd_l4tcstrm().value)
   gd_l4tree:add(l4ix, gd_l4tcstrm().value):set_generated()
   pnam = "T"
  elseif (gd_l4ip4fmo() and gd_l4ip4fmo().value == true) or
   (gd_l4ip6fmo() and gd_l4ip6fmo().value == true) then
   pnam = "T>"
  elseif (gd_l4ip4fof() and gd_l4ip4fof().value > 0) or
   (gd_l4ip6fof() and gd_l4ip6fof().value > 0) then
   pnam = "T<"
  else
   pnam = "T\\"
  end
 elseif indx == 17 then
  if gd_l4udstrm() then
--  indx = string.format("%sU", gd_l4udstrm().value)
   gd_l4tree:add(l4ix, gd_l4udstrm().value):set_generated()
   pnam = "U"
  elseif (gd_l4ip4fmo() and gd_l4ip4fmo().value == true) or
   (gd_l4ip6fmo() and gd_l4ip6fmo().value == true) then
   pnam = "U>"
  elseif (gd_l4ip4fof() and gd_l4ip4fof().value > 0) or
   (gd_l4ip6fof() and gd_l4ip6fof().value > 0) then
   pnam = "U<"
  else
   pnam = "U\\"
  end
 elseif indx == 47 then
  if gd_l4tcstrm() then
   gd_l4tree:add(l4ix, gd_l4tcstrm().value):set_generated()
   pnam = "T\\G"
  elseif gd_l4udstrm() then
   gd_l4tree:add(l4ix, gd_l4udstrm().value):set_generated()
   pnam = "U\\G"
  else
   pnam = "G"
  end
 elseif indx == 132 then
  if gd_l4scstrm() then
   gd_l4tree:add(l4ix, gd_l4scstrm().value):set_generated()
   pnam = "s"
  elseif (gd_l4ip4fmo() and gd_l4ip4fmo().value == true) or
   (gd_l4ip6fmo() and gd_l4ip6fmo().value == true) then
   pnam = "s>"
  elseif (gd_l4ip4fof() and gd_l4ip4fof().value > 0) or
   (gd_l4ip6fof() and gd_l4ip6fof().value > 0) then
   pnam = "s<"
  else
   pnam = "s\\"
  end
 elseif gd_l4tcstrm() then
--  indx = string.format("%sT+", gd_l4tcstrm().value)
  gd_l4tree:add(l4ix, gd_l4tcstrm().value):set_generated()
  pnam = "T\\-"
 elseif gd_l4udstrm() then
--  indx = string.format("%sU+", gd_l4udstrm().value)
  gd_l4tree:add(l4ix, gd_l4udstrm().value):set_generated()
  pnam = "U\\-"
 elseif gd_l4scstrm() then
  gd_l4tree:add(l4ix, gd_l4scstrm().value):set_generated()
  pnam = "s\\-"
 else
-- Unknown protocol carrying no L4 stream
  if indx == nil then
   pnam = "-"
  elseif indx == 50 then
   pnam = "E"
  else
   pnam = tostring(indx)
  end
 end
 if pnam then
  gd_l4tree:add(l4nm, pnam):set_generated()
 end
end

register_postdissector(gd_l4proto)
-- https://wiki.wireshark.org/Lua/Dissectors
