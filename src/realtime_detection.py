"""
Real-Time Network Intrusion Detection Module
for QUANTUM_NIDS_AI

Flow-based real-time detection using the trained Random Forest model.

Pipeline:

Live Packets
    ↓
Flow Identification
    ↓
Bidirectional Flow Aggregation
    ↓
30 Selected CIC-IDS2017 Features
    ↓
Random Forest
    ↓
BENIGN / ATTACK
    ↓
Intrusion Logging
    ↓
Dashboard-Compatible Records
"""

from pathlib import Path
from collections import deque
from datetime import datetime
from typing import Optional, Dict, List, Tuple
import logging
import time

import numpy as np
import pandas as pd
import joblib

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


# ============================================================
# PATH CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).parent.parent

MODEL_PATH = BASE_DIR / "models" / "best_model.pkl"

LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

INTRUSION_LOG = LOG_DIR / "intrusions.log"
REALTIME_LOG = LOG_DIR / "realtime_detection.log"

RESULTS_DIR = BASE_DIR / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

REALTIME_CSV = RESULTS_DIR / "realtime_predictions.csv"


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(
            REALTIME_LOG,
            encoding="utf-8"
        ),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


# ============================================================
# EXACT 30 MODEL FEATURES
# ============================================================

MODEL_FEATURES = [
    "Destination_Port",
    "Total_Backward_Packets",
    "Total_Length_of_Fwd_Packets",
    "Total_Length_of_Bwd_Packets",
    "Fwd_Packet_Length_Max",
    "Fwd_Packet_Length_Mean",
    "Bwd_Packet_Length_Max",
    "Bwd_Packet_Length_Min",
    "Bwd_Packet_Length_Std",
    "Flow_IAT_Std",
    "Flow_IAT_Max",
    "Fwd_IAT_Total",
    "Fwd_IAT_Mean",
    "Fwd_IAT_Max",
    "Fwd_IAT_Min",
    "Bwd_IAT_Total",
    "Bwd_IAT_Max",
    "Fwd_Packets/s",
    "Max_Packet_Length",
    "Packet_Length_Variance",
    "PSH_Flag_Count",
    "ACK_Flag_Count",
    "Avg_Fwd_Segment_Size",
    "Subflow_Fwd_Bytes",
    "Subflow_Bwd_Packets",
    "Subflow_Bwd_Bytes",
    "Init_Win_bytes_backward",
    "Active_Std",
    "Active_Max",
    "Idle_Max"
]


# ============================================================
# FLOW TIMEOUT CONFIGURATION
# ============================================================

# Remove inactive flows after this many seconds.
FLOW_TIMEOUT = 60.0

# Maximum number of simultaneously tracked flows.
MAX_ACTIVE_FLOWS = 5000

# Minimum packets before performing a normal flow prediction.
MIN_PACKETS_FOR_PREDICTION = 2


# ============================================================
# FLOW FEATURE EXTRACTOR
# ============================================================

class PacketFeatureExtractor:
    """
    Converts live packets into bidirectional flow statistics.
    """

    def __init__(self):

        self.flows: Dict[Tuple, Dict] = {}

        self.packet_history = deque(
            maxlen=1000
        )


    # ========================================================
    # FLOW KEY
    # ========================================================

    @staticmethod
    def get_flow_key(packet) -> Optional[Tuple]:

        if IP not in packet:
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        protocol = int(packet[IP].proto)

        src_port = 0
        dst_port = 0

        if TCP in packet:
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)

        elif UDP in packet:
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)

        endpoint_a = (
            src_ip,
            src_port
        )

        endpoint_b = (
            dst_ip,
            dst_port
        )

        if endpoint_a <= endpoint_b:
            return (
                endpoint_a,
                endpoint_b,
                protocol
            )

        return (
            endpoint_b,
            endpoint_a,
            protocol
        )


    # ========================================================
    # PACKET INFORMATION
    # ========================================================

    def extract_packet_information(
        self,
        packet
    ) -> Optional[Dict]:

        try:

            if IP not in packet:
                return None

            timestamp = time.time()

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            protocol = int(packet[IP].proto)

            src_port = 0
            dst_port = 0

            tcp_flags = 0
            tcp_window = 0

            if TCP in packet:

                src_port = int(
                    packet[TCP].sport
                )

                dst_port = int(
                    packet[TCP].dport
                )

                tcp_flags = int(
                    packet[TCP].flags
                )

                tcp_window = int(
                    packet[TCP].window
                )

            elif UDP in packet:

                src_port = int(
                    packet[UDP].sport
                )

                dst_port = int(
                    packet[UDP].dport
                )

            elif ICMP in packet:

                protocol = 1

            packet_size = len(packet)

            payload_size = 0

            if Raw in packet:
                payload_size = len(
                    packet[Raw].load
                )

            return {
                "timestamp": datetime.now(),
                "_capture_time": timestamp,

                "src_ip": src_ip,
                "dst_ip": dst_ip,

                "src_port": src_port,
                "dst_port": dst_port,

                "protocol": protocol,

                "packet_size": float(
                    packet_size
                ),

                "payload_size": float(
                    payload_size
                ),

                "tcp_flags": tcp_flags,

                "tcp_window": float(
                    tcp_window
                )
            }

        except Exception as e:

            logger.error(
                f"Packet extraction error: {e}"
            )

            return None


    # ========================================================
    # CREATE NEW FLOW
    # ========================================================

    def create_flow(
        self,
        packet_info: Dict,
        flow_key: Tuple
    ) -> Dict:

        return {

            "flow_key": flow_key,

            "src_ip":
                packet_info["src_ip"],

            "dst_ip":
                packet_info["dst_ip"],

            "src_port":
                packet_info["src_port"],

            "dst_port":
                packet_info["dst_port"],

            "protocol":
                packet_info["protocol"],

            "destination_port":
                packet_info["dst_port"],

            "first_timestamp":
                packet_info["_capture_time"],

            "last_timestamp":
                packet_info["_capture_time"],

            "packet_count":
                0,

            "forward_packets":
                [],

            "backward_packets":
                [],

            "all_packets":
                [],

            "forward_timestamps":
                [],

            "backward_timestamps":
                [],

            "all_timestamps":
                [],

            "psh_count":
                0,

            "ack_count":
                0,

            "init_window_backward":
                0
        }


    # ========================================================
    # UPDATE FLOW
    # ========================================================

    def update_flow(
        self,
        packet_info: Dict
    ) -> Tuple[Optional[Dict], bool]:

        flow_key = self.get_flow_key_from_info(
            packet_info
        )

        if flow_key is None:
            return None, False

        if flow_key not in self.flows:

            if len(self.flows) >= MAX_ACTIVE_FLOWS:

                self.cleanup_old_flows()

            self.flows[flow_key] = self.create_flow(
                packet_info,
                flow_key
            )

        flow = self.flows[flow_key]

        timestamp = packet_info["_capture_time"]

        flow["last_timestamp"] = timestamp

        flow["packet_count"] += 1

        flow["all_packets"].append(
            packet_info
        )

        flow["all_timestamps"].append(
            timestamp
        )

        # ----------------------------------------------------
        # Determine direction
        # ----------------------------------------------------

        is_forward = (
            packet_info["src_ip"]
            == flow["src_ip"]
            and
            packet_info["dst_ip"]
            == flow["dst_ip"]
            and
            packet_info["src_port"]
            == flow["src_port"]
            and
            packet_info["dst_port"]
            == flow["dst_port"]
        )

        if is_forward:

            flow["forward_packets"].append(
                packet_info
            )

            flow["forward_timestamps"].append(
                timestamp
            )

        else:

            flow["backward_packets"].append(
                packet_info
            )

            flow["backward_timestamps"].append(
                timestamp
            )

            # First backward TCP window
            if (
                flow["init_window_backward"] == 0
                and
                packet_info["tcp_window"] > 0
            ):

                flow["init_window_backward"] = (
                    packet_info["tcp_window"]
                )

        # ----------------------------------------------------
        # TCP flags
        # ----------------------------------------------------

        flags = int(
            packet_info.get(
                "tcp_flags",
                0
            )
        )

        if flags & 0x08:
            flow["psh_count"] += 1

        if flags & 0x10:
            flow["ack_count"] += 1

        # ----------------------------------------------------
        # Packet history
        # ----------------------------------------------------

        self.packet_history.append(
            packet_info
        )

        return flow, is_forward


    # ========================================================
    # FLOW KEY FROM PACKET INFO
    # ========================================================

    @staticmethod
    def get_flow_key_from_info(
        packet_info: Dict
    ) -> Tuple:

        endpoint_a = (
            packet_info["src_ip"],
            packet_info["src_port"]
        )

        endpoint_b = (
            packet_info["dst_ip"],
            packet_info["dst_port"]
        )

        protocol = packet_info["protocol"]

        if endpoint_a <= endpoint_b:

            return (
                endpoint_a,
                endpoint_b,
                protocol
            )

        return (
            endpoint_b,
            endpoint_a,
            protocol
        )


    # ========================================================
    # CALCULATE IAT
    # ========================================================

    @staticmethod
    def calculate_iats(
        timestamps: List[float]
    ) -> np.ndarray:

        if len(timestamps) < 2:

            return np.array(
                [],
                dtype=float
            )

        timestamps = np.array(
            timestamps,
            dtype=float
        )

        return np.diff(
            timestamps
        )


    # ========================================================
    # CREATE MODEL VECTOR
    # ========================================================

    def create_feature_vector(
        self,
        flow: Dict
    ) -> pd.DataFrame:

        forward_packets = (
            flow["forward_packets"]
        )

        backward_packets = (
            flow["backward_packets"]
        )

        all_packets = (
            flow["all_packets"]
        )

        forward_timestamps = (
            flow["forward_timestamps"]
        )

        backward_timestamps = (
            flow["backward_timestamps"]
        )

        all_timestamps = (
            flow["all_timestamps"]
        )

        # ----------------------------------------------------
        # Packet sizes
        # ----------------------------------------------------

        fwd_sizes = np.array(
            [
                p["packet_size"]
                for p in forward_packets
            ],
            dtype=float
        )

        bwd_sizes = np.array(
            [
                p["packet_size"]
                for p in backward_packets
            ],
            dtype=float
        )

        all_sizes = np.array(
            [
                p["packet_size"]
                for p in all_packets
            ],
            dtype=float
        )

        # ----------------------------------------------------
        # Safe arrays
        # ----------------------------------------------------

        if len(fwd_sizes) == 0:
            fwd_sizes = np.array(
                [0.0]
            )

        if len(bwd_sizes) == 0:
            bwd_sizes = np.array(
                [0.0]
            )

        if len(all_sizes) == 0:
            all_sizes = np.array(
                [0.0]
            )

        # ----------------------------------------------------
        # IAT
        # ----------------------------------------------------

        fwd_iats = self.calculate_iats(
            forward_timestamps
        )

        bwd_iats = self.calculate_iats(
            backward_timestamps
        )

        flow_iats = self.calculate_iats(
            all_timestamps
        )

        # ----------------------------------------------------
        # Flow duration
        # ----------------------------------------------------

        if len(all_timestamps) > 1:

            flow_duration = max(
                all_timestamps[-1]
                - all_timestamps[0],
                1e-6
            )

        else:

            flow_duration = 1e-6

        # ----------------------------------------------------
        # Forward statistics
        # ----------------------------------------------------

        total_fwd_packets = len(
            forward_packets
        )

        total_bwd_packets = len(
            backward_packets
        )

        total_fwd_bytes = float(
            np.sum(fwd_sizes)
        )

        total_bwd_bytes = float(
            np.sum(bwd_sizes)
        )

        # ----------------------------------------------------
        # Flow IAT
        # ----------------------------------------------------

        if len(flow_iats) > 0:

            flow_iat_std = float(
                np.std(flow_iats)
            )

            flow_iat_max = float(
                np.max(flow_iats)
            )

        else:

            flow_iat_std = 0.0
            flow_iat_max = 0.0

        # ----------------------------------------------------
        # Forward IAT
        # ----------------------------------------------------

        if len(fwd_iats) > 0:

            fwd_iat_total = float(
                np.sum(fwd_iats)
            )

            fwd_iat_mean = float(
                np.mean(fwd_iats)
            )

            fwd_iat_max = float(
                np.max(fwd_iats)
            )

            fwd_iat_min = float(
                np.min(fwd_iats)
            )

        else:

            fwd_iat_total = 0.0
            fwd_iat_mean = 0.0
            fwd_iat_max = 0.0
            fwd_iat_min = 0.0

        # ----------------------------------------------------
        # Backward IAT
        # ----------------------------------------------------

        if len(bwd_iats) > 0:

            bwd_iat_total = float(
                np.sum(bwd_iats)
            )

            bwd_iat_max = float(
                np.max(bwd_iats)
            )

        else:

            bwd_iat_total = 0.0
            bwd_iat_max = 0.0

        # ----------------------------------------------------
        # Packet rates
        # ----------------------------------------------------

        fwd_packets_per_second = (
            total_fwd_packets
            / flow_duration
        )

        # ----------------------------------------------------
        # Packet statistics
        # ----------------------------------------------------

        fwd_max = float(
            np.max(fwd_sizes)
        )

        fwd_mean = float(
            np.mean(fwd_sizes)
        )

        bwd_max = (
            float(np.max(bwd_sizes))
            if total_bwd_packets > 0
            else 0.0
        )

        bwd_min = (
            float(np.min(bwd_sizes))
            if total_bwd_packets > 0
            else 0.0
        )

        bwd_std = (
            float(np.std(bwd_sizes))
            if total_bwd_packets > 0
            else 0.0
        )

        max_packet_length = float(
            np.max(all_sizes)
        )

        packet_length_variance = float(
            np.var(all_sizes)
        )

        # ----------------------------------------------------
        # Build exact feature dictionary
        # ----------------------------------------------------

        feature_dict = {

            "Destination_Port":
                float(
                    flow["destination_port"]
                ),

            "Total_Backward_Packets":
                float(
                    total_bwd_packets
                ),

            "Total_Length_of_Fwd_Packets":
                total_fwd_bytes,

            "Total_Length_of_Bwd_Packets":
                total_bwd_bytes,

            "Fwd_Packet_Length_Max":
                fwd_max,

            "Fwd_Packet_Length_Mean":
                fwd_mean,

            "Bwd_Packet_Length_Max":
                bwd_max,

            "Bwd_Packet_Length_Min":
                bwd_min,

            "Bwd_Packet_Length_Std":
                bwd_std,

            "Flow_IAT_Std":
                flow_iat_std,

            "Flow_IAT_Max":
                flow_iat_max,

            "Fwd_IAT_Total":
                fwd_iat_total,

            "Fwd_IAT_Mean":
                fwd_iat_mean,

            "Fwd_IAT_Max":
                fwd_iat_max,

            "Fwd_IAT_Min":
                fwd_iat_min,

            "Bwd_IAT_Total":
                bwd_iat_total,

            "Bwd_IAT_Max":
                bwd_iat_max,

            "Fwd_Packets/s":
                fwd_packets_per_second,

            "Max_Packet_Length":
                max_packet_length,

            "Packet_Length_Variance":
                packet_length_variance,

            "PSH_Flag_Count":
                float(
                    flow["psh_count"]
                ),

            "ACK_Flag_Count":
                float(
                    flow["ack_count"]
                ),

            "Avg_Fwd_Segment_Size":
                fwd_mean,

            "Subflow_Fwd_Bytes":
                total_fwd_bytes,

            "Subflow_Bwd_Packets":
                float(
                    total_bwd_packets
                ),

            "Subflow_Bwd_Bytes":
                total_bwd_bytes,

            "Init_Win_bytes_backward":
                float(
                    flow["init_window_backward"]
                ),

            "Active_Std":
                0.0,

            "Active_Max":
                0.0,

            "Idle_Max":
                0.0
        }

        # ----------------------------------------------------
        # Exact feature order
        # ----------------------------------------------------

        vector = pd.DataFrame(
            [[
                feature_dict[feature]
                for feature in MODEL_FEATURES
            ]],
            columns=MODEL_FEATURES
        )

        # ----------------------------------------------------
        # Safety cleanup
        # ----------------------------------------------------

        vector = vector.replace(
            [np.inf, -np.inf],
            0
        )

        vector = vector.fillna(
            0
        )

        return vector


    # ========================================================
    # CLEANUP OLD FLOWS
    # ========================================================

    def cleanup_old_flows(self):

        current_time = time.time()

        expired_flows = []

        for key, flow in self.flows.items():

            if (
                current_time
                - flow["last_timestamp"]
                > FLOW_TIMEOUT
            ):

                expired_flows.append(
                    key
                )

        for key in expired_flows:

            self.flows.pop(
                key,
                None
            )


    # ========================================================
    # GET FLOW
    # ========================================================

    def get_active_flow_count(self) -> int:

        return len(
            self.flows
        )


# ============================================================
# REAL-TIME DETECTOR
# ============================================================

class RealtimeDetector:
    """
    Performs flow-based real-time network intrusion detection.
    """

    def __init__(
        self,
        model_path: str = None
    ):

        self.model = None

        self.feature_extractor = (
            PacketFeatureExtractor()
        )

        self.detection_queue = deque(
            maxlen=100
        )

        self.is_running = False

        self.packet_count = 0

        self.intrusion_count = 0

        self.flow_prediction_count = 0

        self.load_model(
            model_path or str(
                MODEL_PATH
            )
        )


    # ========================================================
    # LOAD MODEL
    # ========================================================

    def load_model(
        self,
        model_path: str
    ):

        logger.info(
            f"Loading model from: "
            f"{model_path}"
        )

        try:

            self.model = joblib.load(
                model_path
            )

            logger.info(
                "Model loaded successfully"
            )

            if hasattr(
                self.model,
                "n_features_in_"
            ):

                logger.info(
                    f"Model expects "
                    f"{self.model.n_features_in_} features"
                )

                if (
                    self.model.n_features_in_
                    != len(MODEL_FEATURES)
                ):

                    raise ValueError(
                        "Model feature count does "
                        "not match realtime "
                        "feature configuration."
                    )

        except Exception as e:

            logger.error(
                f"Error loading model: {e}"
            )

            raise


    # ========================================================
    # PROCESS PACKET
    # ========================================================

    def process_packet(
        self,
        packet
    ):

        try:

            self.packet_count += 1

            # ------------------------------------------------
            # Extract packet
            # ------------------------------------------------

            packet_info = (
                self.feature_extractor
                .extract_packet_information(
                    packet
                )
            )

            if packet_info is None:
                return None

            # ------------------------------------------------
            # Update flow
            # ------------------------------------------------

            flow, is_forward = (
                self.feature_extractor
                .update_flow(
                    packet_info
                )
            )

            if flow is None:
                return None

            # ------------------------------------------------
            # Predict
            # ------------------------------------------------

            # For the first packet of a flow we still create
            # a vector so that live inference remains active.
            #
            # Normal flow statistics become more meaningful
            # after multiple packets have been observed.

            feature_vector = (
                self.feature_extractor
                .create_feature_vector(
                    flow
                )
            )

            prediction = int(
                self.model.predict(
                    feature_vector
                )[0]
            )

            probability = None

            if hasattr(
                self.model,
                "predict_proba"
            ):

                probabilities = (
                    self.model
                    .predict_proba(
                        feature_vector
                    )[0]
                )

                probability = float(
                    probabilities[1]
                )

            self.flow_prediction_count += 1

            # ------------------------------------------------
            # Detection record
            # ------------------------------------------------

            detection = {

                "timestamp":
                    packet_info.get(
                        "timestamp",
                        datetime.now()
                    ),

                "src_ip":
                    packet_info.get(
                        "src_ip",
                        "N/A"
                    ),

                "dst_ip":
                    packet_info.get(
                        "dst_ip",
                        "N/A"
                    ),

                "src_port":
                    packet_info.get(
                        "src_port",
                        0
                    ),

                "dst_port":
                    packet_info.get(
                        "dst_port",
                        0
                    ),

                "protocol":
                    packet_info.get(
                        "protocol",
                        0
                    ),

                "prediction":
                    prediction,

                "label":
                    (
                        "ATTACK"
                        if prediction == 1
                        else "BENIGN"
                    ),

                "attack_probability":
                    probability,

                "confidence":
                    (
                        probability
                        if prediction == 1
                        else (
                            1 - probability
                            if probability is not None
                            else None
                        )
                    ),

                "packet_size":
                    packet_info.get(
                        "packet_size",
                        0
                    ),

                "flow_packets":
                    flow["packet_count"],

                "forward_packets":
                    len(
                        flow["forward_packets"]
                    ),

                "backward_packets":
                    len(
                        flow["backward_packets"]
                    ),

                "active_flows":
                    self.feature_extractor
                    .get_active_flow_count()
            }

            # ------------------------------------------------
            # Intrusion
            # ------------------------------------------------

            if prediction == 1:

                self.intrusion_count += 1

                self.log_intrusion(
                    detection
                )

                logger.warning(
                    "INTRUSION DETECTED | "
                    f"{detection}"
                )

            # ------------------------------------------------
            # Queue
            # ------------------------------------------------

            self.detection_queue.append(
                detection
            )

            # ------------------------------------------------
            # Persist detection for dashboard
            # ------------------------------------------------

            self.save_detection(detection)

            # ------------------------------------------------
            # Progress
            # ------------------------------------------------

            if (
                self.packet_count % 100
                == 0
            ):

                logger.info(
                    f"Processed "
                    f"{self.packet_count} packets | "
                    f"Predictions: "
                    f"{self.flow_prediction_count} | "
                    f"Intrusions: "
                    f"{self.intrusion_count} | "
                    f"Active flows: "
                    f"{self.feature_extractor.get_active_flow_count()}"
                )

            # ------------------------------------------------
            # Periodic cleanup
            # ------------------------------------------------

            if (
                self.packet_count % 500
                == 0
            ):

                self.feature_extractor.cleanup_old_flows()

            return detection

        except Exception as e:

            logger.error(
                f"Error processing packet: {e}"
            )

            return None


    # ========================================================
    # LOG INTRUSION
    # ========================================================

    def log_intrusion(
        self,
        detection: Dict
    ):

        try:

            with open(
                INTRUSION_LOG,
                "a",
                encoding="utf-8"
            ) as file:

                file.write(
                    f"{detection}\n"
                )

        except Exception as e:

            logger.error(
                f"Error logging intrusion: {e}"
            )

    # ========================================================
    # SAVE DETECTION TO DASHBOARD CSV
    # ========================================================

    def save_detection(self, detection: Dict):
        """
        Persist every real-time detection so that
        data_access.py and dashboard.py can read it.
        """

        try:
            record = {
                "Timestamp": detection.get("timestamp", datetime.now()),
                "src_ip": detection.get("src_ip", "N/A"),
                "dst_ip": detection.get("dst_ip", "N/A"),
                "Source_Port": detection.get("src_port", 0),
                "Destination_Port": detection.get("dst_port", 0),
                "protocol": detection.get("protocol", 0),
                "Prediction": detection.get("prediction", 0),
                "Label": detection.get("label", "BENIGN"),
                "Attack_Probability": detection.get(
                    "attack_probability", 0.0
                ),
                "Confidence": detection.get(
                    "confidence", 0.0
                ),
                "Packet_Size": detection.get(
                    "packet_size", 0.0
                ),
                "Flow_Packets": detection.get(
                    "flow_packets", 0
                ),
                "Forward_Packets": detection.get(
                    "forward_packets", 0
                ),
                "Backward_Packets": detection.get(
                    "backward_packets", 0
                ),
                "Active_Flows": detection.get(
                    "active_flows", 0
                )
            }

            df = pd.DataFrame([record])

            if REALTIME_CSV.exists():
                df.to_csv(
                    REALTIME_CSV,
                    mode="a",
                    header=False,
                    index=False
                )
            else:
                df.to_csv(
                    REALTIME_CSV,
                    mode="w",
                    header=True,
                    index=False
                )

        except Exception as e:
            logger.error(
                f"Error saving detection to CSV: {e}"
            )
    # ========================================================
    # START CAPTURE
    # ========================================================
    def start_capture(
        self,
        interface: Optional[str] = None,
        filter_rule: Optional[str] = None,
        packet_count: int = 50,
        timeout: int = 30
    ):
        """
        Start bounded real-time packet capture.

        Capture stops automatically when either:
        - packet_count packets have been processed, or
        - timeout seconds have elapsed.
        """

        logger.info(
            "============================================================"
        )

        logger.info(
            "STARTING REAL-TIME NETWORK INTRUSION DETECTION"
        )

        logger.info(
            "============================================================"
        )

        logger.info(
            f"Interface: {interface or 'all'}"
        )

        logger.info(
            f"Filter: {filter_rule or 'none'}"
        )

        logger.info(
            f"Packet limit: {packet_count}"
        )

        logger.info(
            f"Timeout: {timeout} seconds"
        )

        self.is_running = True

        started = time.time()

        def packet_callback(packet):
            """
            Process one packet and stop when the requested
            packet count or timeout has been reached.
            """

            if not self.is_running:
                return

            self.process_packet(packet)

            elapsed = time.time() - started

            if self.packet_count >= packet_count:
                logger.info(
                    f"Packet limit reached: "
                    f"{self.packet_count}"
                )
                self.is_running = False

            elif elapsed >= timeout:
                logger.info(
                    f"Capture timeout reached: "
                    f"{timeout} seconds"
                )
                self.is_running = False

        try:

            sniff(
                iface=interface,
                filter=filter_rule,
                prn=packet_callback,
                store=False,
                timeout=timeout,
                stop_filter=lambda packet: (
                    not self.is_running
                    or self.packet_count >= packet_count
                )
            )

        except KeyboardInterrupt:

            logger.info(
                "Packet capture interrupted."
            )

        except Exception as e:

            logger.error(
                f"Error during packet capture: {e}"
            )

            raise

        finally:

            self.is_running = False

            elapsed = time.time() - started

            logger.info(
                "Capture finished | "
                f"Packets: {self.packet_count} | "
                f"Predictions: {self.flow_prediction_count} | "
                f"Intrusions: {self.intrusion_count} | "
                f"Elapsed: {elapsed:.2f}s"
            )
    # ========================================================
    # STOP
    # ========================================================

    def stop_capture(self):

        logger.info(
            "Stopping packet capture"
        )

        self.is_running = False


    # ========================================================
    # STATISTICS
    # ========================================================

    def get_statistics(
        self
    ) -> Dict:

        return {

            "total_packets":
                self.packet_count,

            "total_predictions":
                self.flow_prediction_count,

            "total_intrusions":
                self.intrusion_count,

            "intrusion_rate":
                (
                    self.intrusion_count
                    / self.flow_prediction_count
                    if self.flow_prediction_count > 0
                    else 0
                ),

            "active_flows":
                self.feature_extractor
                .get_active_flow_count(),

            "recent_detections":
                list(
                    self.detection_queue
                )[-10:]
        }


    # ========================================================
    # RECENT DETECTIONS
    # ========================================================

    def get_recent_detections(
        self,
        n: int = 10
    ) -> List[Dict]:

        return list(
            self.detection_queue
        )[-n:]


# ============================================================
# REAL-TIME DETECTION FUNCTION
# ============================================================

def run_realtime_detection(
    model_path: str = None,
    interface: Optional[str] = None,
    filter_rule: Optional[str] = None
):

    detector = RealtimeDetector(
        model_path=model_path
    )

    try:

        detector.start_capture(
            interface=interface or None,
            packet_count=packet_count,
            timeout=timeout
        )

    except KeyboardInterrupt:

        logger.info(
            "Detection stopped by user"
        )

    finally:

        detector.stop_capture()

        stats = (
            detector.get_statistics()
        )

        logger.info(
            "============================================================"
        )

        logger.info(
            f"Final Statistics: {stats}"
        )

        logger.info(
            "============================================================"
        )


# ============================================================
# MODEL / FEATURE COMPATIBILITY TEST
# ============================================================

def test_model_compatibility():

    logger.info("=" * 60)

    logger.info(
        "REAL-TIME FLOW DETECTION COMPATIBILITY TEST"
    )

    logger.info("=" * 60)

    # --------------------------------------------------------
    # Load detector
    # --------------------------------------------------------

    detector = RealtimeDetector()

    logger.info(
        "Model loaded successfully."
    )

    # --------------------------------------------------------
    # Synthetic packets
    # --------------------------------------------------------

    packet_1 = {
        "timestamp": datetime.now(),
        "_capture_time": time.time(),

        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",

        "src_port": 50000,
        "dst_port": 80,

        "protocol": 6,

        "packet_size": 500.0,
        "payload_size": 450.0,

        "tcp_flags": 0x18,
        "tcp_window": 65535.0
    }

    # Backward packet
    packet_2 = {
        "timestamp": datetime.now(),
        "_capture_time": time.time() + 0.01,

        "src_ip": "192.168.1.20",
        "dst_ip": "192.168.1.10",

        "src_port": 80,
        "dst_port": 50000,

        "protocol": 6,

        "packet_size": 300.0,
        "payload_size": 250.0,

        "tcp_flags": 0x18,
        "tcp_window": 32768.0
    }

    # --------------------------------------------------------
    # Create flow
    # --------------------------------------------------------

    flow, _ = (
        detector.feature_extractor
        .update_flow(
            packet_1
        )
    )

    flow, _ = (
        detector.feature_extractor
        .update_flow(
            packet_2
        )
    )

    # --------------------------------------------------------
    # Generate features
    # --------------------------------------------------------

    vector = (
        detector.feature_extractor
        .create_feature_vector(
            flow
        )
    )

    logger.info(
        f"Generated feature vector shape: "
        f"{vector.shape}"
    )

    logger.info(
        f"Expected features: "
        f"{len(MODEL_FEATURES)}"
    )

    # --------------------------------------------------------
    # Verify columns
    # --------------------------------------------------------

    if list(vector.columns) != MODEL_FEATURES:

        raise ValueError(
            "Feature order does not match "
            "the trained model."
        )

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    prediction = detector.model.predict(
        vector
    )[0]

    logger.info(
        f"Test prediction: "
        f"{'ATTACK' if prediction == 1 else 'BENIGN'}"
    )

    if hasattr(
        detector.model,
        "predict_proba"
    ):

        probability = (
            detector.model
            .predict_proba(
                vector
            )[0][1]
        )

        logger.info(
            f"Attack probability: "
            f"{probability:.4f}"
        )

    # --------------------------------------------------------
    # Verify backward flow features
    # --------------------------------------------------------

    logger.info(
        f"Forward packets: "
        f"{len(flow['forward_packets'])}"
    )

    logger.info(
        f"Backward packets: "
        f"{len(flow['backward_packets'])}"
    )

    logger.info(
        f"Forward bytes: "
        f"{sum(p['packet_size'] for p in flow['forward_packets']):.2f}"
    )

    logger.info(
        f"Backward bytes: "
        f"{sum(p['packet_size'] for p in flow['backward_packets']):.2f}"
    )

    logger.info("=" * 60)

    logger.info(
        "REAL-TIME FLOW MODEL COMPATIBILITY TEST PASSED"
    )

    logger.info("=" * 60)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    test_model_compatibility()

    print("\nTesting dashboard CSV persistence...")

    detector = RealtimeDetector()

    packet_1 = (
        IP(
            src="192.168.1.10",
            dst="192.168.1.20"
        )
        / TCP(
            sport=50000,
            dport=80,
            flags="PA",
            window=65535
        )
        / Raw(
            load=b"A" * 450
        )
    )

    packet_2 = (
        IP(
            src="192.168.1.20",
            dst="192.168.1.10"
        )
        / TCP(
            sport=80,
            dport=50000,
            flags="PA",
            window=32768
        )
        / Raw(
            load=b"B" * 250
        )
    )

    result_1 = detector.process_packet(packet_1)
    result_2 = detector.process_packet(packet_2)

    print("Packet 1 detection:", result_1)
    print("Packet 2 detection:", result_2)

    if REALTIME_CSV.exists():
        print("\nCSV persistence test PASSED")
        print("CSV created at:")
        print(REALTIME_CSV)
        print("\nCSV contents:")
        print(pd.read_csv(REALTIME_CSV).tail())
    else:
        print("\nCSV persistence test FAILED")
        print("CSV was not created.")