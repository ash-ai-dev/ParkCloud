# vlan_l2_controller.py
# Passive VLAN-aware OpenFlow 1.3 logger
#
# - Does NOT modify dataplane (no flow installs, no PacketOuts)
# - Relies on OVS NORMAL switching and VLAN config
# - Logs PacketIn events, DoS symptoms, flow stats, and conflicts
# - Detects FLOW_TABLE_FULL errors from switch

import time
from collections import deque

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from ryu.lib import hub


class PassiveVlanLogger(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        self.packet_in_times = deque(maxlen=2000)
        self.DOS_THRESHOLD = 50  # PacketIns/sec
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("Passive VLAN Logger initialized (no flow installs).")

    # ---------------------------------------------------------
    # Switch connection: add table-miss rule to mirror traffic
    # ---------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # Table-miss: mirror to controller + let OVS handle switching (NORMAL)
        actions = [
            parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER),
            parser.OFPActionOutput(ofp.OFPP_NORMAL)
        ]
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst)
        dp.send_msg(mod)

        self.logger.info("Switch connected (dpid=%s): table-miss -> CONTROLLER + NORMAL", dp.id)

    # ---------------------------------------------------------
    # Flow monitoring + conflict reporting
    # ---------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                req = dp.ofproto_parser.OFPFlowStatsRequest(dp)
                dp.send_msg(req)
            hub.sleep(10)  # poll every 10s

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        flows = ev.msg.body
        self.logger.info("Flow stats from switch %016x (%d entries):", dpid, len(flows))

        seen = {}
        for stat in flows:
            match_str = str(stat.match)
            act_str = str(stat.instructions)
            self.logger.info("  prio=%s match=%s actions=%s pkts=%d bytes=%d",
                             stat.priority, match_str, act_str,
                             stat.packet_count, stat.byte_count)
            # Detect conflicting rules (same match, different actions)
            if match_str in seen and seen[match_str] != act_str:
                self.logger.warning("⚠️  Conflict: match=%s old=%s new=%s",
                                    match_str, seen[match_str], act_str)
            else:
                seen[match_str] = act_str

    # ---------------------------------------------------------
    # Error handling (flow table full, etc.)
    # ---------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def error_msg_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        if msg.type == dp.ofproto.OFPET_FLOW_MOD_FAILED and msg.code == dp.ofproto.OFPFMFC_TABLE_FULL:
            self.logger.error("🚨 Switch %016x: FLOW TABLE FULL (DoS symptom)", dp.id)
        else:
            self.logger.debug("OFP ERROR type=%s code=%s", msg.type, msg.code)

    # ---------------------------------------------------------
    # PacketIn: log events + detect DoS rate
    # ---------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        now = time.time()
        self.packet_in_times.append(now)
        rate = sum(1 for t in self.packet_in_times if now - t <= 1)
        if rate > self.DOS_THRESHOLD:
            self.logger.warning("⚠️  High PACKET_IN rate detected (%.1f pkt/s) — possible DoS", rate)

        msg = ev.msg
        in_port = msg.match.get("in_port", "unknown")
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth:
            self.logger.info("PacketIn: src=%s dst=%s in_port=%s len=%d",
                             eth.src, eth.dst, in_port, len(msg.data))
        else:
            self.logger.debug("PacketIn (non-ethernet) in_port=%s len=%d", in_port, len(msg.data))
