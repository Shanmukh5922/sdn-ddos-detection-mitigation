from __future__ import annotations

from sdn_ddos.config import load_config
from sdn_ddos.controller import ControllerMonitor
from sdn_ddos.detectors.entropy import EntropyDetector
from sdn_ddos.detectors.random_forest import RandomForestDetector
from sdn_ddos.detectors.threshold import ThresholdDetector
from sdn_ddos.features import counter_rate, traffic_features
from sdn_ddos.flow_stats import (
    FlowRateTracker,
    FlowStatsAssembler,
    cumulative_protocol_packet_counts,
    transport_protocol,
)
from sdn_ddos.mitigation import MitigationManager
from sdn_ddos.traffic import build_synthetic_dataset, validate_lab_traffic


def test_load_config_reads_yaml():
    config = load_config()
    assert config.project_name
    assert config.server_ip == "10.0.0.3"


def test_threshold_detector_flags_high_traffic():
    detector = ThresholdDetector(thresholds={"packet_rate": 80.0, "byte_rate": 60_000.0, "flow_rate": 25.0, "syn_ratio": 0.25, "udp_ratio": 0.15})
    sample = {
        "packet_rate": 150.0,
        "byte_rate": 120_000.0,
        "flow_rate": 50.0,
        "syn_ratio": 0.4,
        "udp_ratio": 0.2,
    }
    result = detector.detect(sample)
    assert result["decision"] == "suspicious"
    assert result["triggered_condition"]


def test_threshold_detector_does_not_flag_udp_ratio_without_sufficient_rate():
    detector = ThresholdDetector(
        thresholds={"packet_rate": 85.0, "byte_rate": 70_000.0, "flow_rate": 30.0, "syn_ratio": 0.25, "udp_ratio": 0.18},
        minimum_packet_rate_for_ratio=20.0,
    )
    result = detector.detect({"packet_rate": 1.0, "udp_ratio": 1.0})
    assert result["decision"] == "normal"
    assert result["triggered_condition"] == []


def test_threshold_detector_uses_protocol_ratio_at_sufficient_rate():
    detector = ThresholdDetector(
        thresholds={"packet_rate": 85.0, "byte_rate": 70_000.0, "flow_rate": 30.0, "syn_ratio": 0.25, "udp_ratio": 0.18},
        minimum_packet_rate_for_ratio=20.0,
    )
    result = detector.detect({"packet_rate": 25.0, "udp_ratio": 1.0})
    assert result["decision"] == "suspicious"
    assert result["triggered_condition"] == [
        {"feature": "udp_ratio", "value": 1.0, "threshold": 0.18}
    ]


def test_entropy_detector_works():
    detector = EntropyDetector(baseline_entropy=2.0, sensitivity=0.6)
    sample = {"source_ip_distribution": {"10.0.0.1": 4, "10.0.0.2": 3, "10.0.0.3": 2}}
    result = detector.detect(sample)
    assert result["measured_values"]["entropy_value"] > 0.0
    assert result["decision"] in {"normal", "suspicious"}


def test_feature_extraction_and_dataset_shape():
    dataset = build_synthetic_dataset(normal_count=25, attack_count=25, attack_type="syn")
    sample = dataset[0]
    features = traffic_features(sample)
    assert "packet_rate" in features
    assert "source_ip_entropy" in features
    assert len(dataset) == 50
    assert traffic_features({"packet_rate": 100, "syn_ratio": 0.4})["syn_ratio"] == 0.4


def test_feature_extraction_uses_udp_protocol_counter_when_udp_count_is_absent():
    features = traffic_features({
        "packet_rate": 100,
        "protocol_distribution": {"UDP": 99},
    })

    assert features["udp_count"] == 99.0
    assert features["udp_ratio"] == 0.99


def test_counter_rate_uses_counter_delta():
    assert counter_rate(150, 100, 5) == 10.0
    assert counter_rate(10, 15, 2) == 0.0


def test_flow_stats_assembler_waits_for_complete_multipart_snapshot():
    assembler = FlowStatsAssembler()

    assert assembler.add_reply(1, 10, ["flow-a"], has_more=True) is None
    assert assembler.add_reply(1, 11, ["other-request"], has_more=False) == ["other-request"]
    assert assembler.add_reply(1, 10, ["flow-b"], has_more=False) == ["flow-a", "flow-b"]


def test_flow_rate_uses_elapsed_time_between_complete_snapshots():
    tracker = FlowRateTracker()

    assert tracker.update(1, ["flow-a", "flow-b"], 10.0) == 0.0
    assert tracker.update(1, ["flow-a", "flow-b", "flow-c"], 11.0) == 1.0
    assert tracker.update(1, ["flow-a", "flow-b", "flow-c"], 12.0) == 0.0
    assert tracker.update(1, ["flow-a", "flow-b"], 12.0) == 0.0


def test_transport_protocol_uses_ip_protocol_or_transport_ports():
    assert transport_protocol({"ip_proto": 17}) == "UDP"
    assert transport_protocol({"udp_dst": 8080}) == "UDP"
    assert transport_protocol({"udp_src": 40000}) == "UDP"
    assert transport_protocol({"ip_proto": "6"}) == "TCP"
    assert transport_protocol({"tcp_dst": 8080}) == "TCP"
    assert transport_protocol({"ipv4_src": "10.0.0.2"}) is None


def test_cumulative_protocol_counts_keep_udp_total_when_interval_is_idle():
    class FlowEntry:
        def __init__(self, match, packet_count):
            self.match = match
            self.packet_count = packet_count

    counts = cumulative_protocol_packet_counts([
        FlowEntry({"eth_type": 0x0800, "ip_proto": 17, "udp_dst": 8080}, 96),
        FlowEntry({"eth_type": 0x0800, "ip_proto": 6, "tcp_dst": 80}, 4),
        FlowEntry({"eth_type": 0x0800, "ipv4_src": "10.0.0.2"}, 100),
    ])

    assert counts["UDP"] == 96
    assert counts["TCP"] == 4


def test_random_forest_pipeline_trains_and_predicts():
    samples = build_synthetic_dataset(normal_count=80, attack_count=80, attack_type="syn")
    detector = RandomForestDetector(random_state=42)
    metrics = detector.evaluate(samples)
    assert set(metrics) >= {"accuracy", "precision", "recall", "f1_score", "false_positive_rate"}
    assert 0.0 <= metrics["accuracy"] <= 1.0


def test_mitigation_manager_tracks_rules():
    manager = MitigationManager(rule_ttl_seconds=5, max_rules=5)
    rule = manager.add_rule(src_ip="10.0.0.2", action="rate_limit", rate_limit_pps=15)
    assert rule.action == "rate_limit"
    assert manager.list_rules()


def test_controller_monitor_collects_and_reports_alerts():
    controller = ControllerMonitor(detector_name="threshold")
    alert = controller.collect_and_analyze(
        {
            "packet_rate": 200.0,
            "byte_rate": 180000.0,
            "flow_count": 60.0,
            "syn_ratio": 0.5,
            "udp_ratio": 0.35,
            "source_ip_distribution": {"10.0.0.2": 10},
            "protocol_distribution": {"TCP": 0.8, "UDP": 0.2},
        }
    )
    assert alert["decision"] == "suspicious"
    assert controller.get_alerts()


def test_controller_can_select_each_detector():
    stats = {
        "packet_rate": 35.0,
        "byte_rate": 30000.0,
        "flow_count": 5.0,
        "syn_ratio": 0.05,
        "udp_ratio": 0.1,
        "source_ip_distribution": {"10.0.0.1": 4, "10.0.0.2": 1},
        "protocol_distribution": {"TCP": 4, "UDP": 1},
    }
    for name in ("threshold", "entropy", "random_forest"):
        result = ControllerMonitor(detector_name=name).collect_and_analyze(stats)
        assert result["detector"] == name


def test_lab_traffic_safety_limits():
    validate_lab_traffic(
        target_ip="10.0.0.3",
        configured_server_ip="10.0.0.3",
        source_ip="10.0.0.2",
        configured_attacker_ip="10.0.0.2",
        duration_seconds=10,
        intensity=100,
        attack_type="udp",
    )
    try:
        validate_lab_traffic(
            target_ip="8.8.8.8",
            configured_server_ip="10.0.0.3",
            source_ip="10.0.0.2",
            configured_attacker_ip="10.0.0.2",
            duration_seconds=10,
            intensity=10,
            attack_type="udp",
        )
    except ValueError:
        pass
    else:
        raise AssertionError("External destinations must be rejected.")
