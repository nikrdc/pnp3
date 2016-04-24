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
    for host in host_data:
      self.log.info("Got host: %s", " ".join("%s=%s" % kv
                                             for kv in sorted(host.items())))

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

  def _handle_openflow_PacketIn (self, e):
    """
    Handles packets that switches send to the controller

    This is the key to writing a reactive controller.  But we're not writing a
    reactive controller.  So you should basically never get these!
    """
    self.log.warn("Switch [%s] sent packet %s", dpid_to_str(e.dpid), e.parsed)

  def _handle_openflow_ConnectionUp (self, e):
    """
    Handle the case when your connection to a switch goes up

    You can now control this switch.
    """
    self.log.info("Switch [%s] has gone up", dpid_to_str(e.dpid))
    
    e.connection.send(nx_flow_mod_table_id())  # Enables multiple tables

    switch = self.graph.dpids[e.dpid]

    paths = nx.shortest_path(self.graph, source=switch)
    data = []
    for dst, path in paths.items():
      if dst == switch:
        continue
      
      dst_dpid = self.graph.node[dst]['dpid']
      next_hop = path[1]
      shortest_path_port = self.graph[switch][next_hop]['ports'][switch]
      #self.log.info(str(switch) + ' --> ' + str(dst) + ' : ' + str(shortest_path_port))
      
      fm = ofp_flow_mod_table_id(
              table_id = 0,
              match = of01.ofp_match(dl_vlan=dst_dpid),
              actions = ofp_action_output(port=shortest_path_port))
      data.append(fm.pack())
    
    core.openflow.sendToDPID(e.dpid, b''.join(data))

  def _handle_openflow_ConnectionDown (self, e):
    """
    Handle the case when your connection to a switch goes down

    Your assumption should be that if you've lost connectivity to a switch,
    the switch has failed.
    """
    self.log.warn("Switch [%s] has gone down", dpid_to_str(e.dpid))

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
  g.dpids = {}

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
    g.dpids[info['dpid']] = n

  g.remove_nodes_from(bad_nodes)  

  # Create the component and "register" it on the POX core object
  core.registerNew(Megaswitch, topo_graph=g)
