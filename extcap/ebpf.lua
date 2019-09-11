--
-- (C) 20198 - ntop.org
--
-- This plugin is part of libebpflow (https://github.com/ntop/libebpfflow)
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software Foundation,
-- Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
--

local ebpfflow_proto = Proto("ebpfflow", "ebpfflow Protocol Interpreter")

ebpfflow_proto.fields = {}

local ebpfflow_fds        = ebpfflow_proto.fields
ebpfflow_fds.ktime_sec    = ProtoField.new("Kernel time (sec)", "ebpfflow.ktime.sec", ftypes.UINT32)
ebpfflow_fds.ktime_usec   = ProtoField.new("Kernel time (usec)", "ebpfflow.ktime.sec", ftypes.UINT32)
ebpfflow_fds.ifname       = ProtoField.new("Interface name", "ebpfflow.ifname", ftypes.STRING)
ebpfflow_fds.evttime_sec  = ProtoField.uint64("ebpfflow.evttime.sec", "Event time (sec)")
ebpfflow_fds.evttime_usec = ProtoField.uint64("ebpfflow.evttime.sec", "Event time (usec)")
ebpfflow_fds.ip_version   = ProtoField.uint8("ebpfflow.ip_version",  "Event IP protocol version")
ebpfflow_fds.direction    = ProtoField.uint8("ebpfflow.direction", "Event direction")
ebpfflow_fds.etype        = ProtoField.uint16("ebpfflow.etype", "Event type")
ebpfflow_fds.sipaddr4     = ProtoField.new("IPv4 src address", "ebpfflow.srcipv4", ftypes.IPv4)
ebpfflow_fds.dipaddr4     = ProtoField.new("IPv4 dst address", "ebpfflow.dstipv4", ftypes.IPv4)
ebpfflow_fds.sipaddr6     = ProtoField.new("IPv6 src address", "ebpfflow.srcipv6", ftypes.IPv6)
ebpfflow_fds.dipaddr6     = ProtoField.new("IPv6 dst address", "ebpfflow.dstipv6", ftypes.IPv6)
ebpfflow_fds.proto        = ProtoField.uint8("ebpfflow.proto", "Event protocol")
ebpfflow_fds.sport        = ProtoField.uint16("ebpfflow.sport", "Event source port")
ebpfflow_fds.dport        = ProtoField.uint16("ebpfflow.dport", "Event destination port")
ebpfflow_fds.latency      = ProtoField.uint32("ebpfflow.latency", "Event latency (usec)")
ebpfflow_fds.retr         = ProtoField.uint16("ebpfflow.retr", "Event retransmissions")

ebpfflow_fds.proc_pid     = ProtoField.uint32("ebpfflow.proc_pid", "Event Process PID")
ebpfflow_fds.proc_tid     = ProtoField.uint32("ebpfflow.proc_tid", "Event Process TID")
ebpfflow_fds.proc_uid     = ProtoField.uint32("ebpfflow.proc_uid", "Event Process UID")
ebpfflow_fds.proc_gid     = ProtoField.uint32("ebpfflow.proc_gid", "Event Process GID")
ebpfflow_fds.proc_task    = ProtoField.new("Event Process Task", "ebpfflow.proc_task", ftypes.STRING)

ebpfflow_fds.father_pid     = ProtoField.uint32("ebpfflow.father_pid", "Event Father PID")
ebpfflow_fds.father_tid     = ProtoField.uint32("ebpfflow.father_tid", "Event Father TID")
ebpfflow_fds.father_uid     = ProtoField.uint32("ebpfflow.father_uid", "Event Father UID")
ebpfflow_fds.father_gid     = ProtoField.uint32("ebpfflow.father_gid", "Event Father GID")
ebpfflow_fds.father_task    = ProtoField.new("Event Father Task", "ebpfflow.father_task", ftypes.STRING)

ebpfflow_fds.container_id   = ProtoField.new("Event Container Id", "ebpfflow.container_id", ftypes.STRING)


-- ebpfflow_fds.application_protocol = ProtoField.new("ebpfflow Application Protocol", "ebpfflow.protocol.application", ftypes.UINT8, nil, base.DEC)
-- ebpfflow_fds.name                 = ProtoField.new("ebpfflow Protocol Name", "ebpfflow.protocol.name", ftypes.STRING)

-- ###############################################

local f_null_type        = Field.new("null.type")

local debug                  = false

-- ###############################################

function ebpfflow_proto.init()

end

-- ###############################################

-- Print contents of `tbl`, with indentation.
-- You can call it as tprint(mytable)
-- The other two parameters should not be set
function tprint(s, l, i)
   l = (l) or 1000; i = i or "";-- default item limit, indent string
   if (l<1) then io.write("ERROR: Item limit reached.\n"); return l-1 end;
   local ts = type(s);
   if (ts ~= "table") then io.write(i..' '..ts..' '..tostring(s)..'\n'); return l-1 end
   io.write(i..' '..ts..'\n');
   for k,v in pairs(s) do
      local indent = ""

      if(i ~= "") then
	 indent = i .. "."
      end
      indent = indent .. tostring(k)

      l = tprint(v, l, indent);
      if (l < 0) then break end
   end

   return l
end

-- ###############################################

local function getstring(finfo)
   local ok, val = pcall(tostring, finfo)
   if not ok then val = "(unknown)" end
   return val
end

local function getval(finfo)
   local ok, val = pcall(tostring, finfo)
   if not ok then val = nil end
   return val
end

function dump_pinfo(pinfo)
   local fields = { all_field_infos() }
   for ix, finfo in ipairs(fields) do
      --  output = output .. "\t[" .. ix .. "] " .. finfo.name .. " = " .. getstring(finfo) .. "\n"
      --print(finfo.name .. "\n")
      print("\t[" .. ix .. "] " .. finfo.name .. " = " .. getstring(finfo) .. "\n")
   end
end

-- ###############################################

-- the dissector function callback
function ebpfflow_proto.dissector(tvb, pinfo, tree)
   -- Wireshark dissects the packet twice. We ignore the first
   -- run as on that step the packet is still undecoded
   -- The trick below avoids to process the packet twice

   if(pinfo.visited == true) then
      local null_type = f_null_type()

      if(null_type ~= nil) then
	 local null_type = getval(null_type)

	 if(null_type == "0x000007e3") then
	    -- libebpf packet: TODO use file format to avoid dummy nullernet
	    local ebpf_subtree = tree:add(ebpfflow_proto, tvb(), "eBPFFlow Protocol")

	    offset = 4 -- DLT_NULL offset
	    ebpf_subtree:add_le(ebpfflow_fds.ktime_sec,  tvb:range(offset,4))
	    offset = offset + 4
	    
	    ebpf_subtree:add_le(ebpfflow_fds.ktime_usec, tvb:range(offset,4))
	    offset = offset + 4
	    
	    ebpf_subtree:add(ebpfflow_fds.ifname,     tvb:range(offset,16))
	    offset = offset + 16

	    ebpf_subtree:add_le(ebpfflow_fds.evttime_sec, tvb:range(offset,8))
	    offset = offset + 8

	    ebpf_subtree:add_le(ebpfflow_fds.evttime_usec, tvb:range(offset,8))
	    offset = offset + 8

	    r = tvb:range(offset,1)
	    ip_version = r:le_uint()
	    ebpf_subtree:add_le(ebpfflow_fds.ip_version, r, ip_version)

	    r = tvb:range(offset,1)
	    direction = r:le_uint()
	    ebpf_subtree:add_le(ebpfflow_fds.direction, r, direction)
	    offset = offset + 1
	    
	    etype_r = tvb:range(offset,2)
	    etype = etype_r:le_uint()
	    offset = offset + 2

	    if(ip_version == 4) then
	       offset = offset + 5
	       ebpf_subtree:add(ebpfflow_fds.sipaddr4, tvb:range(offset,4))
	       offset = offset + 8
	       ebpf_subtree:add(ebpfflow_fds.dipaddr4, tvb:range(offset,4))
	       offset = offset + 19
	    else
	       ebpf_subtree:add(ebpfflow_fds.sipaddr6, tvb:range(offset,16))
	       offset = offset + 16
	       --
	       ebpf_subtree:add(ebpfflow_fds.dipaddr6, tvb:range(offset,16))
	       offset = offset + 16
	    end

	    offset = offset + 5 -- padding

	    r = tvb:range(offset,1)
	    proto = r:le_uint()
	    ebpf_subtree:add(ebpfflow_fds.proto, r)
	    offset = offset + 1

	    offset = offset + 1 -- pad
	    
	    ebpf_subtree:add_le(ebpfflow_fds.sport, tvb:range(offset,2))
	    offset = offset + 2

	    ebpf_subtree:add_le(ebpfflow_fds.dport, tvb:range(offset,2))
	    offset = offset + 2

	    if(proto == 6) then
	       -- TCP
	       ebpf_subtree:add(ebpfflow_fds.etype, etype_r)
	       
	       ebpf_subtree:add(ebpfflow_fds.latency, tvb:range(offset,4))
	       offset = offset + 4
	       
	       ebpf_subtree:add(ebpfflow_fds.retr, tvb:range(offset,2))
	       offset = offset + 6
	    else
	       offset = offset + 10
	    end	   
	    
	    -- Tasks
	    ebpf_subtree:add_le(ebpfflow_fds.proc_pid, tvb:range(offset,4))
	    offset = offset + 4

	    ebpf_subtree:add_le(ebpfflow_fds.proc_tid, tvb:range(offset,4))
	    offset = offset + 4

	    ebpf_subtree:add_le(ebpfflow_fds.proc_uid, tvb:range(offset,4))
	    offset = offset + 4

	    ebpf_subtree:add_le(ebpfflow_fds.proc_gid, tvb:range(offset,4))
	    offset = offset + 4

	    ebpf_subtree:add(ebpfflow_fds.proc_task, tvb:range(offset,16))
	    offset = offset + 16

	    offset = offset + 8 -- ptr

	    -- Father Task
	    ebpf_subtree:add_le(ebpfflow_fds.father_pid, tvb:range(offset,4))
	    offset = offset + 4

	    ebpf_subtree:add_le(ebpfflow_fds.father_tid, tvb:range(offset,4))
	    offset = offset + 4

	    ebpf_subtree:add_le(ebpfflow_fds.father_uid, tvb:range(offset,4))
	    offset = offset + 4

	    ebpf_subtree:add_le(ebpfflow_fds.father_gid, tvb:range(offset,4))
	    offset = offset + 4

	    ebpf_subtree:add(ebpfflow_fds.father_task, tvb:range(offset,16))
	    offset = offset + 16

	    offset = offset + 8 -- ptr

	    -- Container
	    ebpf_subtree:add(ebpfflow_fds.container_id, tvb:range(offset,128))
	    offset = offset + 128
	 end
      end
   end
   
   -- ###########################################

   -- As we do not need to add fields to the dissection
   -- there is no need to process the packet multiple times
   if(pinfo.visited == true) then return end

   num_pkts = num_pkts + 1
   if((num_pkts > 1) and (pinfo.number == 1)) then return end

   ebpfflow_dissector(tvb, pinfo, tree)
end

register_postdissector(ebpfflow_proto)
