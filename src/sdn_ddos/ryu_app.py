from __future__ import annotations

from collections import Counter
import ipaddress
import time
from typing import Any

try:
    from os_ken.base import app_manager
    from os_ken.controller import ofp_event
    from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
    from os_ken.ofproto import ofproto_v1_3
    from os_ken.lib.packet import ether_types, packet, ethernet, ipv4, tcp, udp
    from os_ken.lib import hub
    ControllerApp = app_manager.OSKenApp
except ModuleNotFoundError:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
    from ryu.ofproto import ofproto_v1_3
    from ryu.lib.packet import ether_types, packet, ethernet, ipv4, tcp, udp
    from ryu.lib import hub
    ControllerApp = app_manager.RyuApp

from .config import load_config
from .detectors.entropy import EntropyDetector
from .detectors.threshold import ThresholdDetector
from .features import counter_rate, traffic_features
from .flow_stats import FlowRateTracker, FlowStatsAssembler, transport_protocol


class DDoSDetectorApp(ControllerApp):
    """Lightweight Ryu application that monitors switch flow stats and applies mitigation."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        self.flow_snapshot = {}
        self.alerts = []
        self.config = load_config()
        self._stats_interval = self.config.stats_interval_seconds
        self.mac_to_port = {}
        self._last_stats_at = {}
        self._port_counters = {}
        self._last_port_stats_at = {}
        self._source_totals = {}
        self._flow_packet_counts = {}
        self._flow_stats_assembler = FlowStatsAssembler()
        self._flow_rate_tracker = FlowRateTracker()
        self._pending_flow_stats = {}
        self._syn_events = Counter()
        self._detector_name = self.config.detection.get("selected", "threshold").lower()
        threshold_config = self.config.detection.get("threshold", {})
        self.threshold_detector = ThresholdDetector(thresholds={
            "packet_rate": float(threshold_config.get("packet_rate", 85.0)),
            "byte_rate": float(threshold_config.get("byte_rate", 70000.0)),
            "flow_rate": float(threshold_config.get("flow_rate", 30.0)),
            "syn_ratio": float(threshold_config.get("syn_ratio", 0.25)),
            "udp_ratio": float(threshold_config.get("udp_ratio", 0.18)),
        }, minimum_packet_rate_for_ratio=float(
            threshold_config.get("minimum_packet_rate_for_ratio", self.config.normal_rate_per_second)
        ))
        entropy_config = self.config.detection.get("entropy", {})
        self.entropy_detector = EntropyDetector(
            baseline_entropy=float(entropy_config.get("baseline_entropy", 3.0)),
            sensitivity=float(entropy_config.get("sensitivity", 0.75)),
        )
        self.random_forest_detector = None
        if self._detector_name == "random_forest":
            from .detectors.random_forest import RandomForestDetector
            from .traffic import build_synthetic_dataset

            rf_config = self.config.detection.get("random_forest", {})
            self.random_forest_detector = RandomForestDetector(
                n_estimators=int(rf_config.get("n_estimators", 200)),
                random_state=int(rf_config.get("random_state", 42)),
            )
            training_data = [
                {**traffic_features(record), "label": record["label"]}
                for record in build_synthetic_dataset()
            ]
            self.random_forest_detector.fit(training_data)
        self.monitor_thread = hub.spawn(self._monitor)

    def _monitor(self) -> None:
        while True:
            for datapath in list(self.datapaths.values()):
                self._request_stats(datapath)
            hub.sleep(self._stats_interval)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev: Any) -> None:
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        self.logger.info("Switch %s connected", datapath.id)
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        instruction = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=instruction,
        ))
        self._request_stats(datapath)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev: Any) -> None:
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        learned = self.mac_to_port.setdefault(datapath.id, {})
        learned[eth.src] = in_port
        out_port = learned.get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match_fields = {"in_port": in_port, "eth_dst": eth.dst}
            ip_header = pkt.get_protocol(ipv4.ipv4)
            if ip_header is not None:
                match_fields.update({
                    "eth_type": ether_types.ETH_TYPE_IP,
                    "ipv4_src": ip_header.src,
                    "ipv4_dst": ip_header.dst,
                })
                tcp_header = pkt.get_protocol(tcp.tcp)
                udp_header = pkt.get_protocol(udp.udp)
                if tcp_header is not None:
                    match_fields.update({
                        "ip_proto": 6,
                        "tcp_src": tcp_header.src_port,
                        "tcp_dst": tcp_header.dst_port,
                    })
                    if tcp_header.bits & 0x02 and not tcp_header.bits & 0x10:
                        self._syn_events[datapath.id] += 1
                elif udp_header is not None:
                    match_fields.update({
                        "ip_proto": 17,
                        "udp_src": udp_header.src_port,
                        "udp_dst": udp_header.dst_port,
                    })
            match = parser.OFPMatch(**match_fields)
            instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            datapath.send_msg(parser.OFPFlowMod(
                datapath=datapath,
                priority=1,
                match=match,
                instructions=instructions,
                idle_timeout=60,
            ))

        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        ))

    def _request_stats(self, datapath: Any) -> None:
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto_v1_3.OFPP_ANY)
        datapath.send_msg(req)
        pending = self._pending_flow_stats.get(datapath.id)
        now = time.monotonic()
        if pending is not None:
            pending_xid, requested_at = pending
            timeout = max(5.0, self._stats_interval * 5)
            if now - requested_at < timeout:
                return
            self.logger.warning(
                "Flow stats request %s timed out for switch %s; requesting a fresh snapshot",
                pending_xid,
                datapath.id,
            )
            self._flow_stats_assembler.discard(datapath.id, pending_xid)
            del self._pending_flow_stats[datapath.id]
        flow_req = parser.OFPFlowStatsRequest(datapath, 0, 0, ofproto_v1_3.OFPP_ANY, ofproto_v1_3.OFPG_ANY)
        datapath.send_msg(flow_req)
        if flow_req.xid is not None:
            self._pending_flow_stats[datapath.id] = (flow_req.xid, now)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev: Any) -> None:
        msg = ev.msg
        datapath = msg.datapath
        port_stats = []
        current_counters = {}
        packet_delta = 0
        byte_delta = 0
        now = time.monotonic()
        previous_counters = self._port_counters.get(datapath.id, {})
        previous_time = self._last_port_stats_at.get(datapath.id)
        elapsed = max(now - previous_time, 1e-6) if previous_time is not None else self._stats_interval
        for stat in msg.body:
            port_stats.append({
                "port_no": stat.port_no,
                "rx_packets": stat.rx_packets,
                "tx_packets": stat.tx_packets,
                "rx_bytes": stat.rx_bytes,
                "tx_bytes": stat.tx_bytes,
            })
            if stat.port_no == ofproto_v1_3.OFPP_LOCAL:
                continue
            current = (stat.rx_packets, stat.rx_bytes)
            current_counters[stat.port_no] = current
            previous = previous_counters.get(stat.port_no, current)
            packet_delta += max(0, current[0] - previous[0])
            byte_delta += max(0, current[1] - previous[1])

        self._port_counters[datapath.id] = current_counters
        self._last_port_stats_at[datapath.id] = now
        self.logger.info("Port stats for switch %s: %s", datapath.id, port_stats)
        sample = dict(self.flow_snapshot.get(datapath.id, {}))
        sample["packet_rate"] = counter_rate(packet_delta, 0, elapsed)
        sample["byte_rate"] = counter_rate(byte_delta, 0, elapsed)
        sample["syn_count"] = float(self._syn_events.pop(datapath.id, 0))
        sample["syn_ratio"] = min(sample["syn_count"] / packet_delta, 1.0) if packet_delta else 0.0
        protocol_counts = sample.get("protocol_distribution", {})
        protocol_total = sum(protocol_counts.values())
        sample["udp_ratio"] = protocol_counts.get("UDP", 0) / protocol_total if protocol_total else 0.0
        self.flow_snapshot[datapath.id] = sample
        self._analyze_sample(datapath, sample)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev: Any) -> None:
        datapath = ev.msg.datapath
        msg = ev.msg
        pending = self._pending_flow_stats.get(datapath.id)
        if pending is not None and msg.xid != pending[0]:
            return
        flow_entries = self._flow_stats_assembler.add_reply(
            datapath.id,
            msg.xid,
            msg.body,
            has_more=bool(msg.flags & datapath.ofproto.OFPMPF_REPLY_MORE),
        )
        if flow_entries is None:
            return
        if pending is not None:
            del self._pending_flow_stats[datapath.id]

        flow_stats = []
        source_ip_counts: Counter[str] = Counter()
        protocol_counts: Counter[str] = Counter()
        current_packet_counts = {}
        now = time.monotonic()
        current_keys = set()
        for stat in flow_entries:
            if stat.priority == 0:
                continue
            match = stat.match
            ip_src = match.get("ipv4_src") if match.get("eth_type") == ether_types.ETH_TYPE_IP else None
            flow_key = (datapath.id, stat.table_id, stat.priority, str(match))
            current_keys.add(flow_key)
            current_packet_counts[flow_key] = stat.packet_count
            previous_packet_count = self._flow_packet_counts.get(datapath.id, {}).get(flow_key)
            packet_delta = (
                stat.packet_count
                if previous_packet_count is None or stat.packet_count < previous_packet_count
                else stat.packet_count - previous_packet_count
            )
            proto = transport_protocol(match)
            if proto == "TCP":
                protocol_counts["TCP"] += packet_delta
            elif proto == "UDP":
                protocol_counts["UDP"] += packet_delta
            flow_stats.append({
                "priority": stat.priority,
                "packets": packet_delta,
                "bytes": stat.byte_count,
                "duration": stat.duration_sec,
                "src_ip": str(ip_src) if ip_src is not None else "unknown",
            })
            if ip_src is not None:
                source_ip_counts[str(ip_src)] += packet_delta
        self._flow_packet_counts[datapath.id] = current_packet_counts
        self._source_totals[datapath.id] = source_ip_counts
        flow_rate = self._flow_rate_tracker.update(datapath.id, current_keys, now)
        protocol_total = sum(protocol_counts.values())
        sample = {
            "packet_rate": self.flow_snapshot.get(datapath.id, {}).get("packet_rate", 0.0),
            "byte_rate": self.flow_snapshot.get(datapath.id, {}).get("byte_rate", 0.0),
            "flow_count": len(flow_stats),
            "flow_rate": flow_rate,
            "source_ip_distribution": dict(source_ip_counts),
            "protocol_distribution": dict(protocol_counts),
            "syn_count": 0.0,
            "syn_ratio": 0.0,
            "udp_ratio": protocol_counts["UDP"] / protocol_total if protocol_total else 0.0,
        }
        self.flow_snapshot[datapath.id] = sample
        self.logger.info("Flow stats for switch %s: %s", datapath.id, sample)

    def _analyze_sample(self, datapath: Any, sample: dict[str, Any]) -> None:
        features = traffic_features(sample)
        decision = self._detect(features, sample)
        self.logger.info("Detection result: %s", decision)
        if decision["decision"] == "suspicious":
            self.alerts.append(decision)
            suspicious_sources = [
                source for source, packets in sample.get("source_ip_distribution", {}).items()
                if packets > 0
                and source not in {self.config.client_ip, self.config.server_ip}
                and ipaddress.ip_address(source) in ipaddress.ip_network(self.config.lab_network)
            ]
            if suspicious_sources:
                self._apply_mitigation(datapath, suspicious_sources[:1])

    def _detect(self, features: dict[str, float], sample: dict[str, Any]) -> dict[str, Any]:
        if self._detector_name == "threshold":
            result = self.threshold_detector.detect(features)
        elif self._detector_name == "entropy":
            result = self.entropy_detector.detect({
                "source_ip_distribution": sample["source_ip_distribution"]
            })
        elif self._detector_name == "random_forest":
            if self.random_forest_detector is None:
                raise RuntimeError("Random Forest detector was selected but not initialized.")
            result = self.random_forest_detector.detect(features)
        else:
            raise ValueError(f"Unsupported detector configured: {self._detector_name}")
        result["measured_values"] = features
        result["proposed_action"] = "temporary_source_block" if result["decision"] == "suspicious" else "none"
        return result

    def _apply_mitigation(self, datapath: Any, suspicious_ips: list[str]) -> None:
        if not suspicious_ips:
            return
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        for ip in suspicious_ips:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip)
            actions = []
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                datapath=datapath,
                match=match,
                cookie=0,
                cookie_mask=0,
                table_id=0,
                command=ofproto.OFPFC_ADD,
                idle_timeout=30,
                hard_timeout=30,
                priority=100,
                instructions=inst,
            )
            datapath.send_msg(mod)
            self.alerts.append({"switch_id": datapath.id, "suspicious_ip": ip, "action": "temporary_drop", "timestamp": self._time_now()})
            self.logger.warning("Applied temporary source drop for %s on switch %s (30s timeout)", ip, datapath.id)

    def _time_now(self) -> str:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()
