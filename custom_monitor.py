from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub
import time


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}

        self.statistics_interval = 10
        self.monitor_thread = hub.spawn(self._monitor)

    def _monitor(self):
        while True:
            # self.logger.info("Collecting statistics - interval: %d seconds", self.statistics_interval)
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.statistics_interval)

    def _request_stats(self, datapath):

        self.logger.debug('Sending stats request to datapath: %016x', datapath.id)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):

        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('Switch registered: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == CONFIG_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('Switch unregistered: %016x', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):

        body = ev.msg.body
        datapath = ev.msg.datapath
        dpid = datapath.id

        # Kiểm tra xem có flow stats nào không
        if not body:
            return

        border = "=" * 60
        separator = "-" * 60

        self.logger.info("\n%s\n Flow Statistics for Switch: %016x \n%s", border, dpid, separator)
        self.logger.info(" %-8s | %-18s | %-10s | %-10s | %-15s",
                         "In-Port", "Eth-Dst", "Packets", "Bytes")
        self.logger.info(separator)

        for stat in sorted([flow for flow in body if flow.priority > 0],
                           key=lambda flow: (flow.match.get('in_port', 0),
                                             flow.match.get('eth_dst', '00:00:00:00:00:00'))):
            if 'in_port' in stat.match and 'eth_dst' in stat.match:
                self.logger.info(" %-8d | %-18s | %-10d | %-10d | %-15.2f",
                                 stat.match['in_port'], stat.match['eth_dst'],
                                 stat.packet_count, stat.byte_count)
        self.logger.info(separator)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):

        body = ev.msg.body
        datapath = ev.msg.datapath
        dpid = datapath.id

        # Kiểm tra xem có port stats nào không
        if not body:
            return

        # Tạo đường viền
        border = "=" * 75
        separator = "-" * 75

        self.logger.info("\n%s\n Port Statistics for Switch: %016x \n%s", border, dpid, separator)
        self.logger.info(" %-5s | %-10s | %-12s | %-10s | %-12s | %-8s",
                         "Port", "Rx-Pkts", "Rx-Bytes", "Tx-Pkts", "Tx-Bytes", "Errors")
        self.logger.info(separator)

        for stat in sorted(body, key=lambda s: s.port_no):
            if stat.port_no < 4294967000:  # Bỏ qua các port ảo có số hiệu lớn
                self.logger.info(" %-5d | %-10d | %-12d | %-10d | %-12d | %-8d",
                                 stat.port_no, stat.rx_packets, stat.rx_bytes,
                                 stat.tx_packets, stat.tx_bytes,
                                 (stat.rx_errors + stat.tx_errors))
            else:
                # Hiển thị port số lớn (OFPP_LOCAL = 4294967294) một cách đẹp hơn
                port_name = "LOCAL" if stat.port_no == 4294967294 else str(stat.port_no)
                self.logger.info(" %-5s | %-10d | %-12d | %-10d | %-12d | %-8d",
                                 port_name, stat.rx_packets, stat.rx_bytes,
                                 stat.tx_packets, stat.tx_bytes,
                                 (stat.rx_errors + stat.tx_errors))
        self.logger.info(separator)
