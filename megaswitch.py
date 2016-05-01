"""
The skeleton Megaswitch component

Megaswitch is a silly name, but basically, this component combines information
it's given about the topology of switches with information it's given about
where hosts are, and installs rules in switches so that the hosts can talk
to each other.  Or at least it's supposed to do that.  But making it actually
happen is your job.
"""

# Import the POX core object
from pox.core import core

# Classes used in POX to represent addresses
from pox.lib.addresses import EthAddr, IPAddr

# Utility functions for converting back and forth between numeric DPIDs and
# string representations thereof.
from pox.lib.util import str_to_dpid, dpid_to_str

# The POX packet parsing/construction library
import pox.lib.packet # Probably won't really need this
from pox.lib.packet.ethernet import ETHER_BROADCAST # FF:FF:FF:FF:FF:FF

# Stuff from the POX messenger component
from pox.messenger import ChannelBot

# The NetworkX graph library
import networkx as nx

# gutil -- a graph utility library
from gutil import gutil

# POX's OpenFlow 1.0 library
import pox.openflow.libopenflow_01 as of01

# Some useful constants and classes from basic OpenFlow 1.0.
from pox.openflow.libopenflow_01 import (
  OFPFC_DELETE,
  OFPPC_PORT_DOWN,
  OFPPR_ADD,
  OFPPR_DELETE,
  OFPPR_MODIFY,
  OFPP_MAX,
  ofp_action_output,
  ofp_action_set_vlan_vid,
  ofp_action_strip_vlan,
  )

# Nicira extensions to OpenFlow
import pox.openflow.nicira as nxt

# Useful stuff from the Nicira OpenFlow extensions.
from pox.openflow.nicira import (
  ofp_flow_mod_table_id, # Extended ofp_flow_mod with a table_id field
  nx_flow_mod_table_id,  # Enables the above extension
  )
# Wrappers to make some Nicira extensions look a bit more like plain old
# OpenFlow 1.0 -- just for simplicty's sake.
# These shouldn't really have the "ofp_" prefix, but we do it for regularity.
# Rather than classes, they're just functions which return objects.

def ofp_action_set_in_port (in_port = 0):
  """
  Creates an action that modifies a packet's in_port

  Use like: ofp_action_set_in_port(in_port = 42)
  If in_port is not given, defaults to 0 (a port never used by OpenFlow)
  """
  # Return action that loads the OF_IN_PORT register with the given value
  return nxt.nx_reg_load(dst=nxt.NXM_OF_IN_PORT, value=in_port)

def ofp_action_resubmit (table_id = None, in_port = of01.OFPP_IN_PORT):
  """
  Creates an action which processes a packet again or using a different table

  If table_id is not specified, the packet is processed again using the same
  table.  Otherwise, it's procssed using the specified table.
  If in_port is specified, the match done as part of the resubmit behaves as
  if the ingress port was in_port.  (Note that this only affects the match!)
  """
  if table_id is None:
    return nxt.nx_action_resubmit.resubmit(in_port=in_port)
  return nxt.nx_action_resubmit.resubmit_table(table=table_id, in_port=in_port)


class MegaswitchBot (ChannelBot):
  """
  This is a simple messenger "bot" for the megaswitch

  This bot hangs out on a Messenger channel and listens for information about
  hosts and their locations (e.g., from garnet's sync_hosts() command) and
  access control entries from the ACL utility.  We just forward these to the
  main Megaswitch class and let it process them, so you shouldn't really need
  to modify this.
  """
  def _init (self, extra):
    self.parent = extra['parent'] # The Megaswitch

  def _exec_hosts (self, event, value):
    """
    Receive list of hosts
    """
    self.parent.set_hosts(value)

  def _exec_acls (self, event, value):
    """
    Receive list of access control entries (an ACL)
    """
    self.parent.set_acl(value)


# Set up a logger, because logs are nicer than prints.
_log = core.getLogger()


class Megaswitch (object):
  """
  The main class implementing the component.
  """
  def __init__ (self, topo_graph):
    # Set up a logger...
    self.log = _log.getChild("main")

    # Save the graph as an instance attribute.
    self.graph = topo_graph
    self.down_switches = {}
    self.hosts = {}

    # Container for our ACL list, or None if we don't have any ACLs.
    # foreach ace in acl_list
    # mode = ace["mode"]
    # src = ace["ether_src"]
    # dst = ace["ether_dst"]
    self.acl_list = None
    # If we should even look at ACLs. Could make this a commandline switch, but nope.
    self.ACL_FEATURE_ENABLED = True
    # Cached host data so we can re-init when we receive ACLs
    self.last_host_data = None

    # This component relies on some other components.  This registers those
    # dependencies and automatically binds event listeners (such as the
    # _handle_openflow_PacketIn event listener below).
    core.listen_to_dependencies(self, components="MessengerNexus".split())

  def _all_dependencies_met (self):
    """
    Called when all the other components we're dependent on are available
    """
    # Now that the messenger component is available, let's set up a channel
    # called "megaswitch" and put a bot in it which actually listens for
    # host and ACL information and relays it to us by calling our set_hosts()
    # and set_acl() methods.
    channel = core.MessengerNexus.get_channel("megaswitch")
    MegaswitchBot(channel, extra=dict(parent=self))

    self.log.info("Ready.  Topology has %s node(s) and %s link(s).",
                  len(self.graph), self.graph.size())

  def set_hosts (self, host_data):
    """
    Receive list of hosts

    This gets called with a list of dictionaries that each contain information
    about a host.  Each time this is called, you get a complete list of all
    current hosts.  Each entry looks something like this:
      {"ether" : "01:02:03:04:05:06", "ip" : "1.2.3.4",
       "attached_switch" : dpid, "attached_port" : portno},
    In a datacenter, you might get this kind of information from a Cloud
    Management System.  In our case, garnet's sync_hosts() sends us the list
    of Host entities in the "emulated" network garnet is managing.  We
    receive it via the POX Messenger component and the messenger bot above.
    """
    self.last_host_data = host_data
    for host in host_data:
      self.log.info("Got host: %s", " ".join("%s=%s" % kv
                                             for kv in sorted(host.items())))
      
      host_e = str(host['ether'])
      switch_dpid = host['attached_switch']
      switch_port = host['attached_port']
      switch_name = self.graph.names[switch_dpid]

      self.hosts[host_e] = switch_dpid

      if host_e in self.graph:
        self.graph.remove_node(host_e)
        # alter table info on attached switch

      self.graph.add_node(host_e)
      attached_switch = self.graph.names[switch_dpid]
      self.graph.add_edge(host_e, attached_switch)
      self.graph.add_edge(attached_switch, host_e)
      port_dict = {'ports': {attached_switch: switch_port}}
      self.graph.edge[host_e][attached_switch] = port_dict   
      self.graph.edge[attached_switch][host_e] = port_dict
      
      data = []

      fm = ofp_flow_mod_table_id(
              table_id = 0,
              match = of01.ofp_match(dl_dst=host_e),
              actions = [ofp_action_strip_vlan(), ofp_action_output(port=switch_port)])
      data.append(fm.pack())

      for dst_host, dst_switch_dpid in self.hosts.items():
        if dst_host == host_e:
          continue
        if not self._connection_is_permitted(host_e, dst_host):
          # If we're not allowed to send to this host (or this host is not allowed to receive), tell our switch
          # to send all traffic going this way to port 0 (drop)
          self.log.info("MatchedDenyACE: src=%s dst=%s" % host_e, dst_host)
          fm = ofp_flow_mod_table_id(
                table_id = 0,
                match = of01.ofp_match(dl_src=host_e, dl_dst=dst_host),
                actions = [ofp_action_output(0)])
          data.append(fm.pack())
          continue

        #dst_switch_name = self.graph.names[dst_switch_dpid]
        #next_hop = nx.shortest_path(self.graph, source=switch_name, target=dst_switch_name)[1] 
        #shortest_path_port = self.graph[switch_name][next_hop]['ports'][switch_name]
        #self.log.info(str(host_e) + ' ' + str(dst_host))
        #self.log.info(str(dst_switch_dpid) + ' ' + str(shortest_path_port))
        
        fm = ofp_flow_mod_table_id(
                table_id = 0,
                match = of01.ofp_match(dl_src=host_e, dl_dst=dst_host),
                actions = [ofp_action_set_vlan_vid(vlan_vid=dst_switch_dpid)])
        data.append(fm.pack())
 
        fm = ofp_flow_mod_table_id(
               table_id = 0,
               match = of01.ofp_match(dl_src=dst_host, dl_dst=host_e),
               actions = [ofp_action_set_vlan_vid(vlan_vid=switch_dpid)])
        core.openflow.sendToDPID(dst_switch_dpid, fm.pack()) 
      
      core.openflow.sendToDPID(switch_dpid, b''.join(data))
   
      # handle host with different attached switch, !down host!, host with different attached port
      # tell attached_switch to add and remove VLAN tags
      
  def set_acl (self, acl_data):
    """
    Receive list of access control entries (an ACL)

    This gets called with a list of dictionaries that each contain an access
    control entry.  The order is significant.  For example, if you have an
    entry that permits all traffic as your first entry, then it doesn't matter
    what comes after it -- all traffic will be permitted!  At the end of the
    list, there's an implicit "deny everything" rule.  Each entry looks
    something like:
      {"ether_src" : "01:02:03:04:05:06", "ether_dst" : None, "mode" : "permit"}
    In this case, traffic from a specific MAC to *any* address (None means
    wildcard) should be permitted.
    The "sync" command in the ACL utility will send this data, and we receive
    it through the POX Messenger component and the messenger bot above.
    """
    for ace in acl_data:
      self.log.info("Got ACE: %s", " ".join("%s=%s" % kv
                                            for kv in sorted(ace.items())))
    self.acl_list = acl_data
    # Go through and reinstall rules on each host to drop traffic if we're already up.
    if self.last_host_data:
      self.set_hosts(self.last_host_data)

  def _handle_openflow_PacketIn (self, e):
    """
    Handles packets that switches send to the controller

    This is the key to writing a reactive controller.  But we're not writing a
    reactive controller.  So you should basically never get these!
    """
    self.log.warn("Switch [%s] sent packet %s", dpid_to_str(e.dpid), e.parsed)

  def shortest_paths_to_switches (self):
    all_paths = nx.shortest_path(self.graph)
    for src, paths in all_paths.items():
      src_dpid = self.graph.node[src]['dpid'] 
      if core.openflow.getConnection(src_dpid):
        data = []
     
        for dst, path in paths.items():
          if dst == src:
            continue
          dst_dpid = self.graph.node[dst]['dpid']
          next_hop = path[1]
          shortest_path_port = self.graph[src][next_hop]['ports'][src]
         
          fm = ofp_flow_mod_table_id(
                  table_id = 0,
                  match = of01.ofp_match(dl_vlan=dst_dpid),
                  actions = [ofp_action_output(port=shortest_path_port)])
          data.append(fm.pack())
      
        core.openflow.sendToDPID(src_dpid, b''.join(data))

  def _connection_is_permitted (self, src, dst):
      """
      Determine if the connection between our two hosts is allowed or not by our ACL list.
      :param src: The source ethernet address
      :param dst: The destination ethernet address.
      :return: True if the edge is permitted by our ACL list, or we have ACLs off. False if we block it.
      """
      # If we don't have an ACL list, or we disabled the feature in config, just return True.
      if (not self.ACL_FEATURE_ENABLED or not self.acl_list):
          return True

      elif (len(self.acl_list) == 0):
          # This means we have an empty rules file, so we implicitly drop all traffic.
          return False

      else:
          # mode = ace["mode"]
          # src = ace["ether_src"]
          # dst = ace["ether_dst"]

          # Grab our set of rules that match src destination, keeping them in order.
          src_matching_rules = []
          for ace in self.acl_list:
            if (not src or src == ace["ether_src"]):
                src_matching_rules.append(ace)

          # Append our implicit "deny it all" rule at the end.
          src_matching_rules.append({"ether_src" : None, "ether_dst" : None, "mode" : "deny"})

          # For each rule that we matched the src, check if we match the destination too
          for ace in src_matching_rules:
              # Try to match our ACE with either a wildcard dst or a specific dst.
              if (not dst or dst == ace["ether_dst"]):
                  # If we hit a match, check it's decision, if empty decision or deny, block it!
                  if (ace["mode"] or ace["mode"] == "deny"):
                      return False
                  # Otherwise allow this connection and break out of this code block.
                  else:
                      return True

          # We didn't find a match, so we allow this connection.
          return True

  def _handle_openflow_ConnectionUp (self, e):
    """
    Handle the case when your connection to a switch goes up

    You can now control this switch.
    """
    self.log.info("Switch [%s] has gone up", dpid_to_str(e.dpid))
    
    e.connection.send(nx_flow_mod_table_id())  # Enables multiple tables

    switch_name = self.graph.names[e.dpid]
   
    if switch_name not in self.graph:
      zombie = self.down_switches[switch_name]
      self.graph.add_node(switch_name)
      self.graph.node[switch_name] = zombie[0]
      for edge in zombie[1]:
        self.graph.add_edge(switch_name, edge)
        self.graph.add_edge(edge, switch_name)
        self.graph.edge[switch_name][edge] = zombie[1][edge]
        self.graph.edge[edge][switch_name] = zombie[1][edge]

    self.shortest_paths_to_switches()  

  def _handle_openflow_ConnectionDown (self, e):
    """
    Handle the case when your connection to a switch goes down

    Your assumption should be that if you've lost connectivity to a switch,
    the switch has failed.
    """
    self.log.warn("Switch [%s] has gone down", dpid_to_str(e.dpid))
   
    switch_name = self.graph.names[e.dpid]
 
    self.down_switches[switch_name] = [self.graph.node[switch_name], self.graph[switch_name]]
    self.graph.remove_node(switch_name)
    self.shortest_paths_to_switches()
 
  def _handle_openflow_PortStatus (self, e):
    """
    Handle ofp_port_status messages

    This gets called when ports go up or down or are added or removed.  This
    will also be called when we "fail" links by setting a port down in garnet.
    If a port corresponding to a link that you're using goes down, you should
    probably do something about it...
    """
    dpid = dpid_to_str(e.dpid) # the event object has the DPID of the switch
    port_no = e.ofp.desc.port_no # e.ofp is the ofp_port_status message
    if (e.ofp.desc.state & OFPPC_PORT_DOWN):
      state = "down"
    else:
      state = "up"
    if e.ofp.reason == OFPPR_DELETE:
      reason = "deleted"
      state = "down" # If it's gone, we can probably consider it down!
    elif e.ofp.reason == OFPPR_MODIFY:
      reason = "modified"
    elif e.ofp.reason == OFPPR_ADD:
      reason = "added"

    self.log.info("Switch [%s]'s port %s was %s (it's %s)",
                  dpid, port_no, reason, state)


def launch (topo):
  """
  Launch the Megaswitch component

  This is called to intialize this component.  Commandline arguments to this
  component show up as arguments to this function.  We take "topo", which
  should be the filename of a topology file.
  """
  # We're given a topology file.  Quite possibly the same exact one as used by
  # garnet.  Let's load it and then do a little processing of the graph here to
  # remove hosts and convert any string-format DPIDs to numeric DPIDs.
  g = gutil.get_graph(topo)

  bad_nodes = set() # Things that aren't usable switches
  g.names = {}

  for n,info in g.nodes(data=True):
    if info.get('entity_type','').lower() == 'host':
      # Skip hosts
      bad_nodes.add(n)
      continue
    if 'dpid' not in info:
      # Our switches need DPIDs!
      bad_nodes.add(n)
      continue

    # Fix string DPIDs
    dpid = info['dpid']
    if isinstance(dpid, str):
      info['dpid'] = str_to_dpid(dpid)
    g.names[info['dpid']] = n

  g.remove_nodes_from(bad_nodes)  

  # Create the component and "register" it on the POX core object
  core.registerNew(Megaswitch, topo_graph=g)
