from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import inet, ether
from ryu.lib.packet import arp, packet, icmp

class Hub(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Hub, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match_icmp = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                     ip_proto=inet.IPPROTO_ICMP)

        match_other = parser.OFPMatch()

        actions_flood = [parser.OFPActionOutput(ofproto.OFPP_ALL)]

        actions_controller = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                     ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 10, match_icmp, actions_flood)
        self.add_flow(datapath, 0, match_other, actions_controller)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_icmp = pkt.get_protocol(icmp.icmp)

        if pkt_arp:

            self.logger.info("Packet-in message ARP packet from port %s", in_port)
            if pkt_arp.opcode == arp.ARP_REQUEST:
                self.logger.info("Who has xxx.xxx.xxx.xxx? Tell %s", pkt_arp.src_ip)

            else:
                self.logger.info("%s is at oo:xx:oo:xx:oo:xx", pkt_arp.src_ip)

        elif pkt_icmp:
            self.logger.info("Packet-in message ICMP packet from port %s", in_port)

        else:
            pass
            #self.logger.info("Not ARP and ICMP packet")

        actions = [parser.OFPActionOutput(ofproto.OFPP_ALL)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

