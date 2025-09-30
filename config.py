# analyzer.py
# Processes raw log data to identify security incidents based on predefined detection rules.

import pandas as pd
import re
from typing import List, Dict, Any, Optional
from datetime import timedelta
import json
import os
from utils.helpers import setup_logging

# Setup logging for this module
logger = setup_logging()

class Analyzer:
    """
    Analyzes Windows and Syslog events to detect security incidents
    based on configured detection rules.
    """
    def __init__(self, detection_rules: Dict[str, Any]) -> None:
        """
        Initializes the Analyzer with detection rules.

        Args:
            detection_rules (Dict[str, Any]): A dictionary containing detection rules
                                               for Windows and Syslog, typically
                                               loaded from a JSON configuration file.
        """
        self.detection_rules = detection_rules
        self._compiled_regex_patterns = self._compile_all_regex_patterns()
        logger.info("Analyzer initialized with detection rules.")

    def _compile_all_regex_patterns(self) -> Dict[str, Any]:
        """
        Compiles all regex patterns from the detection rules for efficiency.
        """
        compiled_patterns = {}
        for os_type, rules in self.detection_rules.items():
            compiled_patterns[os_type] = {}
            for incident_type, rule_config in rules.items():
                compiled_patterns[os_type][incident_type] = {}
                if "patterns" in rule_config:
                    compiled_patterns[os_type][incident_type]["patterns"] = [
                        re.compile(p) for p in rule_config["patterns"]
                    ]
                if "suspicious_cmd_patterns" in rule_config:
                    compiled_patterns[os_type][incident_type]["suspicious_cmd_patterns"] = [
                        re.compile(p, re.IGNORECASE) for p in rule_config["suspicious_cmd_patterns"]
                    ]
                if "malicious_process_patterns" in rule_config:
                    compiled_patterns[os_type][incident_type]["malicious_process_patterns"] = [
                        re.compile(p, re.IGNORECASE) for p in rule_config["malicious_process_patterns"]
                    ]
        return compiled_patterns

    def _detect_windows_failed_login(self, df: pd.DataFrame, rule_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detects failed login attempts in Windows logs."""
        incidents = []
        event_id = rule_config.get("event_id")
        threshold = rule_config.get("threshold")
        time_window = timedelta(minutes=rule_config.get("time_window_minutes", 5))

        if df.empty or not event_id or not threshold:
            return incidents

        failed_logins = df[df['EventID'] == event_id].copy()
        if failed_logins.empty:
            return incidents

        # Ensure 'TimeCreated' is datetime and sort
        failed_logins['TimeCreated'] = pd.to_datetime(failed_logins['TimeCreated'], errors='coerce')
        failed_logins.dropna(subset=['TimeCreated'], inplace=True)
        failed_logins.sort_values(by='TimeCreated', inplace=True)

        # Group by Account Name and Source Network Address (or IpAddress)
        # Note: 'Account Name' and 'IpAddress' are common fields for 4625.
        # We need to ensure these fields are extracted by log_reader.py.
        # If not present, this detection might not be effective.
        for (account_name, ip_address), group in failed_logins.groupby(['Account Name', 'IpAddress']):
            if account_name is None or ip_address is None:
                continue # Skip if key fields are missing

            # Check for consecutive failed attempts within the time window
            failed_attempts_count = 0
            last_attempt_time = None
            for idx, row in group.iterrows():
                current_time = row['TimeCreated']
                if last_attempt_time is None or (current_time - last_attempt_time) <= time_window:
                    failed_attempts_count += 1
                else:
                    # Reset count if outside time window
                    failed_attempts_count = 1
                last_attempt_time = current_time

                if failed_attempts_count >= threshold:
                    incidents.append({
                        "type": "Failed Login Attempts", # English incident type
                        "timestamp": row['TimeCreated'].isoformat(),
                        "source": "Windows",
                        "event_id": event_id,
                        "details": {
                            "account_name": account_name,
                            "ip_address": ip_address,
                            "failed_attempts": failed_attempts_count,
                            "message": row.get('Message', 'N/A')
                        }
                    })
                    # Reset count after detection to avoid re-triggering on same sequence
                    failed_attempts_count = 0
                    last_attempt_time = None # Reset time as well

        logger.info(f"Detected {len(incidents)} Windows failed login incidents.")
        return incidents

    def _detect_windows_privilege_escalation(self, df: pd.DataFrame, rule_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detects privilege escalation attempts in Windows logs."""
        incidents = []
        event_ids = [rule_config.get(k) for k in ["event_id_4672", "event_id_4756", "event_id_4728"] if rule_config.get(k)]
        sensitive_privileges = rule_config.get("sensitive_privileges_patterns", [])
        admin_groups = rule_config.get("admin_groups_patterns", [])

        if df.empty or not event_ids:
            return incidents

        # Filter for relevant event IDs
        escalation_events = df[df['EventID'].isin(event_ids)].copy()
        if escalation_events.empty:
            return incidents

        for idx, row in escalation_events.iterrows():
            incident_detected = False
            details = {
                "event_id": row['EventID'],
                "user": row.get('TargetUserName', row.get('SubjectUserName', 'N/A')),
                "message": row.get('Message', 'N/A')
            }

            if row['EventID'] == rule_config.get("event_id_4672"):
                # Check for sensitive privileges granted (EventID 4672)
                # The message or 'PrivilegeList' field for 4672 contains details
                message = row.get('Message', '')
                for priv in sensitive_privileges:
                    if re.search(r'\b' + re.escape(priv) + r'\b', message, re.IGNORECASE):
                        details["privilege_granted"] = priv
                        incident_detected = True
                        break
            elif row['EventID'] in [rule_config.get("event_id_4756"), rule_config.get("event_id_4728")]:
                # Check for addition to admin groups (EventID 4756, 4728)
                # 'Target Group Name' or 'Member Name' are relevant fields
                target_group = row.get('Target Group Name', '')
                member_name = row.get('Member Name', '')
                for group in admin_groups:
                    if re.search(re.escape(group), target_group, re.IGNORECASE) or \
                       re.search(re.escape(group), member_name, re.IGNORECASE):
                        details["admin_group_added"] = group
                        incident_detected = True
                        break

            if incident_detected:
                incidents.append({
                    "type": "Privilege Escalation", # English incident type
                    "timestamp": row['TimeCreated'].isoformat() if 'TimeCreated' in row and pd.notna(row['TimeCreated']) else 'N/A',
                    "source": "Windows",
                    "details": details
                })
        logger.info(f"Detected {len(incidents)} Windows privilege escalation incidents.")
        return incidents

    def _detect_windows_suspicious_process(self, df: pd.DataFrame, rule_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detects suspicious process activity in Windows logs."""
        incidents = []
        event_id = rule_config.get("event_id")
        suspicious_cmd_patterns = self._compiled_regex_patterns['windows']['suspicious_process'].get('suspicious_cmd_patterns', [])
        standard_paths = rule_config.get("standard_paths", [])

        if df.empty or not event_id:
            return incidents

        process_creation_events = df[df['EventID'] == event_id].copy()
        if process_creation_events.empty:
            return incidents

        for idx, row in process_creation_events.iterrows():
            command_line = row.get('CommandLine', '')
            process_path = row.get('NewProcessName', '') # For EventID 4688, NewProcessName is the path

            # Check for suspicious command line patterns
            for pattern in suspicious_cmd_patterns:
                if pattern.search(command_line):
                    incidents.append({
                        "type": "Suspicious Process Activity", # English incident type
                        "timestamp": row['TimeCreated'].isoformat() if 'TimeCreated' in row and pd.notna(row['TimeCreated']) else 'N/A',
                        "source": "Windows",
                        "event_id": event_id,
                        "details": {
                            "process_name": os.path.basename(process_path),
                            "command_line": command_line,
                            "matched_pattern": pattern.pattern,
                            "user": row.get('SubjectUserName', 'N/A'),
                            "message": row.get('Message', 'N/A')
                        }
                    })
                    break # Only log once per event for this rule

            # Check if process runs from non-standard path
            # This check can be noisy, consider refining based on specific needs
            if process_path and not any(process_path.lower().startswith(p.lower()) for p in standard_paths):
                # Ensure it's not a common temporary or user-specific path that's legitimate
                if not (re.search(r'\\Users\\[^\\]+\\AppData\\Local\\Temp\\', process_path, re.IGNORECASE) or
                        re.search(r'\\Users\\[^\\]+\\Downloads\\', process_path, re.IGNORECASE) or
                        re.search(r'\\Windows\\Temp\\', process_path, re.IGNORECASE)):
                    incidents.append({
                        "type": "Suspicious Process Activity", # English incident type
                        "timestamp": row['TimeCreated'].isoformat() if 'TimeCreated' in row and pd.notna(row['TimeCreated']) else 'N/A',
                        "source": "Windows",
                        "event_id": event_id,
                        "details": {
                            "process_name": os.path.basename(process_path),
                            "command_line": command_line,
                            "reason": "Process running from non-standard path",
                            "process_path": process_path,
                            "user": row.get('SubjectUserName', 'N/A'),
                            "message": row.get('Message', 'N/A')
                        }
                    })

        logger.info(f"Detected {len(incidents)} Windows suspicious process incidents.")
        return incidents

    def _detect_windows_malware_execution(self, df: pd.DataFrame, rule_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detects malware execution indicators in Windows logs."""
        incidents = []
        defender_detect_id = rule_config.get("event_id_defender_detect")
        defender_action_id = rule_config.get("event_id_defender_action")
        process_creation_id = rule_config.get("event_id_process_creation")
        malicious_process_patterns = self._compiled_regex_patterns['windows']['malware_execution'].get('malicious_process_patterns', [])

        if df.empty:
            return incidents

        # 1. Windows Defender Detections (Event ID 1006, 1007)
        defender_events = df[df['EventID'].isin([defender_detect_id, defender_action_id])].copy()
        for idx, row in defender_events.iterrows():
            incidents.append({
                "type": "Malware Execution", # English incident type
                "timestamp": row['TimeCreated'].isoformat() if 'TimeCreated' in row and pd.notna(row['TimeCreated']) else 'N/A',
                "source": "Windows Defender",
                "event_id": row['EventID'],
                "details": {
                    "threat_name": row.get('Threat Name', 'N/A'),
                    "file_path": row.get('Path', 'N/A'),
                    "action_taken": row.get('Action', 'N/A'),
                    "message": row.get('Message', 'N/A')
                }
            })

        # 2. Suspicious Process Creation (Event ID 4688) for known malicious patterns
        process_creation_events = df[df['EventID'] == process_creation_id].copy()
        for idx, row in process_creation_events.iterrows():
            new_process_name = row.get('NewProcessName', '')
            command_line = row.get('CommandLine', '')
            
            for pattern in malicious_process_patterns:
                if pattern.search(new_process_name) or pattern.search(command_line):
                    incidents.append({
                        "type": "Malware Execution", # English incident type
                        "timestamp": row['TimeCreated'].isoformat() if 'TimeCreated' in row and pd.notna(row['TimeCreated']) else 'N/A',
                        "source": "Windows",
                        "event_id": process_creation_id,
                        "details": {
                            "process_name": os.path.basename(new_process_name),
                            "command_line": command_line,
                            "matched_pattern": pattern.pattern,
                            "user": row.get('SubjectUserName', 'N/A'),
                            "message": row.get('Message', 'N/A')
                        }
                    })
                    break # Log once per event for this rule

        logger.info(f"Detected {len(incidents)} Windows malware execution incidents.")
        return incidents

    def _detect_windows_data_exfiltration(self, df: pd.DataFrame, rule_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detects potential data exfiltration attempts in Windows logs (including Sysmon)."""
        incidents = []
        sysmon_raw_access_read_id = rule_config.get("sysmon_id_raw_access_read")
        sysmon_network_connection_id = rule_config.get("sysmon_id_network_connection")
        network_status_change_id = rule_config.get("event_id_network_status_change")
        common_ports = rule_config.get("common_ports", [])
        known_bad_ips = rule_config.get("known_bad_ips", [])

        if df.empty:
            return incidents

        # 1. Sysmon Event ID 9 (RawAccessRead) - Data from Removable Media
        if sysmon_raw_access_read_id:
            raw_access_events = df[(df['EventID'] == sysmon_raw_access_read_id) & (df['ProviderName'] == 'Microsoft-Windows-Sysmon')].copy()
            for idx, row in raw_access_events.iterrows():
                # Look for patterns like \\.\PhysicalDriveX or \\.\Volume{GUID}
                if 'TargetFilename' in row and re.search(r'\\\\\.\\\\(PhysicalDrive|Volume)\{?[\w-]+\}?', row['TargetFilename'], re.IGNORECASE):
                    incidents.append({
                        "type": "Data Exfiltration Attempt", # English incident type
                        "timestamp": row['TimeCreated'].isoformat() if 'TimeCreated' in row and pd.notna(row['TimeCreated']) else 'N/A',
                        "source": "Windows Sysmon (RawAccessRead)",
                        "event_id": sysmon_raw_access_read_id,
                        "details": {
                            "process_name": row.get('Image', 'N/A'),
                            "target_device": row.get('TargetFilename', 'N/A'),
                            "user": row.get('User', 'N/A'),
                            "message": row.get('Message', 'N/A')
                        }
                    })

        # 2. Sysmon Event ID 3 (Network Connection) - Outbound Network Activity
        if sysmon_network_connection_id:
            network_events_sysmon = df[(df['EventID'] == sysmon_network_connection_id) & (df['ProviderName'] == 'Microsoft-Windows-Sysmon')].copy()
            for idx, row in network_events_sysmon.iterrows():
                destination_ip = row.get('DestinationIp', '')
                destination_port = row.get('DestinationPort', '')
                initiated = row.get('Initiated', '') # 'true' or 'false'

                # Check for connections to known bad IPs or unusual ports
                if initiated == 'true': # Only consider initiated outbound connections
                    if destination_ip in known_bad_ips:
                        incidents.append({
                            "type": "Data Exfiltration Attempt", # English incident type
                            "timestamp": row['TimeCreated'].isoformat() if 'TimeCreated' in row and pd.notna(row['TimeCreated']) else 'N/A',
                            "source": "Windows Sysmon (Network Connection)",
                            "event_id": sysmon_network_connection_id,
                            "details": {
                                "process_name": row.get('Image', 'N/A'),
                                "destination_ip": destination_ip,
                                "destination_port": destination_port,
                                "reason": "Connection to known bad IP",
                                "user": row.get('User', 'N/A'),
                                "message": row.get('Message', 'N/A')
                            }
                        })
                    elif destination_port and int(destination_port) not in common_ports and int(destination_port) >= 1024: # High ports often used for C2/exfil
                        incidents.append({
                            "type": "Data Exfiltration Attempt", # English incident type
                            "timestamp": row['TimeCreated'].isoformat() if 'TimeCreated' in row and pd.notna(row['TimeCreated']) else 'N/A',
                            "source": "Windows Sysmon (Network Connection)",
                            "event_id": sysmon_network_connection_id,
                            "details": {
                                "process_name": row.get('Image', 'N/A'),
                                "destination_ip": destination_ip,
                                "destination_port": destination_port,
                                "reason": "Connection to unusual high port",
                                "user": row.get('User', 'N/A'),
                                "message": row.get('Message', 'N/A')
                            }
                        })
                    # Add logic for large data transfers if 'BytesSent' or 'BytesReceived' are available in Sysmon 3
                    # (Sysmon 3 does not typically contain byte counts directly, would need other sources or advanced correlation)

        # 3. Windows Event ID 4004 (Network Status Change) - General Network Activity
        if network_status_change_id:
            network_status_events = df[df['EventID'] == network_status_change_id].copy()
            for idx, row in network_status_events.iterrows():
                # This event is very generic. Need more context from Message or other fields
                # to determine if it's related to exfiltration.
                # For now, just flag if it's a new connection and potentially unusual.
                message = row.get('Message', '')
                if "new network connection" in message.lower() or "network interface connected" in message.lower():
                    # This is a weak indicator on its own, but can be part of correlation
                    incidents.append({
                        "type": "Data Exfiltration Attempt", # English incident type
                        "timestamp": row['TimeCreated'].isoformat() if 'TimeCreated' in row and pd.notna(row['TimeCreated']) else 'N/A',
                        "source": "Windows (Network Status)",
                        "event_id": network_status_change_id,
                        "details": {
                            "message": message,
                            "reason": "New network connection detected (requires further investigation)"
                        }
                    })

        logger.info(f"Detected {len(incidents)} Windows data exfiltration incidents.")
        return incidents

    def _analyze_windows_logs(self, windows_df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Orchestrates the detection of various incident types in Windows logs.
        """
        logger.info("Starting Windows log analysis...")
        all_incidents: List[Dict[str, Any]] = []

        if windows_df.empty:
            logger.info("No Windows logs to analyze.")
            return all_incidents

        # Ensure 'EventID' is treated as string for consistent comparison with config
        if 'EventID' in windows_df.columns:
            windows_df['EventID'] = windows_df['EventID'].astype(str)
        else:
            logger.warning("Windows DataFrame missing 'EventID' column. Skipping Windows analysis.")
            return all_incidents

        # Call individual detection methods based on available rules
        if "failed_login" in self.detection_rules["windows"]:
            all_incidents.extend(self._detect_windows_failed_login(windows_df, self.detection_rules["windows"]["failed_login"]))
        if "privilege_escalation" in self.detection_rules["windows"]:
            all_incidents.extend(self._detect_windows_privilege_escalation(windows_df, self.detection_rules["windows"]["privilege_escalation"]))
        if "suspicious_process" in self.detection_rules["windows"]:
            all_incidents.extend(self._detect_windows_suspicious_process(windows_df, self.detection_rules["windows"]["suspicious_process"]))
        if "malware_execution" in self.detection_rules["windows"]:
            all_incidents.extend(self._detect_windows_malware_execution(windows_df, self.detection_rules["windows"]["malware_execution"]))
        if "data_exfiltration" in self.detection_rules["windows"]:
            all_incidents.extend(self._detect_windows_data_exfiltration(windows_df, self.detection_rules["windows"]["data_exfiltration"]))

        logger.info(f"Finished Windows log analysis. Total incidents detected: {len(all_incidents)}")
        return all_incidents

    def _detect_syslog_failed_login(self, df: pd.DataFrame, rule_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detects failed login attempts in Syslog messages."""
        incidents = []
        patterns = self._compiled_regex_patterns['syslog']['failed_login'].get('patterns', [])
        threshold = rule_config.get("threshold")
        time_window = timedelta(minutes=rule_config.get("time_window_minutes", 5))

        if df.empty or not patterns or not threshold:
            return incidents

        # Filter logs that match any failed login pattern
        failed_login_logs = df[df['Message'].apply(lambda x: any(p.search(x) for p in patterns))].copy()
        if failed_login_logs.empty:
            return incidents

        failed_login_logs['Timestamp'] = pd.to_datetime(failed_login_logs['Timestamp'], errors='coerce')
        failed_login_logs.dropna(subset=['Timestamp'], inplace=True)
        failed_login_logs.sort_values(by='Timestamp', inplace=True)

        # Group by hostname and extract user/IP from message for more granular detection
        # This part assumes a common structure for failed login messages in syslog (e.g., "Failed password for user from IP")
        # Example pattern: Failed password for (invalid user )?(\S+) from (\S+) port
        user_ip_regex = re.compile(r"(?:for (?:invalid user )?(\S+))? from (\S+)")

        from collections import defaultdict # Import here to avoid circular dependency if moved to top
        for (hostname, ), group in failed_login_logs.groupby(['Hostname']):
            temp_incidents = defaultdict(list) # Key: (username, ip_address)
            for idx, row in group.iterrows():
                match = user_ip_regex.search(row['Message'])
                username = match.group(1) if match and match.group(1) else 'UNKNOWN_USER'
                ip_address = match.group(2) if match and match.group(2) else 'UNKNOWN_IP'

                key = (username, ip_address)
                temp_incidents[key].append(row['Timestamp'])

            for (username, ip_address), timestamps in temp_incidents.items():
                timestamps.sort()
                failed_attempts_count = 0
                last_attempt_time = None
                for current_time in timestamps:
                    if last_attempt_time is None or (current_time - last_attempt_time) <= time_window:
                        failed_attempts_count += 1
                    else:
                        failed_attempts_count = 1 # Reset count
                    last_attempt_time = current_time

                    if failed_attempts_count >= threshold:
                        incidents.append({
                            "type": "Failed Login Attempts", # English incident type
                            "timestamp": current_time.isoformat(),
                            "source": "Syslog",
                            "details": {
                                "hostname": hostname,
                                "account_name": username,
                                "ip_address": ip_address,
                                "failed_attempts": failed_attempts_count,
                                "message": row['Message'] # Use the last message that triggered the threshold
                            }
                        })
                        failed_attempts_count = 0 # Reset after logging incident
                        last_attempt_time = None

        logger.info(f"Detected {len(incidents)} Syslog failed login incidents.")
        return incidents

    def _detect_syslog_privilege_escalation(self, df: pd.DataFrame, rule_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detects privilege escalation attempts in Syslog messages."""
        incidents = []
        patterns = self._compiled_regex_patterns['syslog']['privilege_escalation'].get('patterns', [])

        if df.empty or not patterns:
            return incidents

        for idx, row in df.iterrows():
            message = row.get('Message', '')
            for pattern in patterns:
                if pattern.search(message):
                    incidents.append({
                        "type": "Privilege Escalation", # English incident type
                        "timestamp": row['Timestamp'].isoformat() if 'Timestamp' in row and pd.notna(row['Timestamp']) else 'N/A',
                        "source": "Syslog",
                        "details": {
                            "hostname": row.get('Hostname', 'N/A'),
                            "tag": row.get('Tag', 'N/A'),
                            "message": message,
                            "matched_pattern": pattern.pattern
                        }
                    })
                    break # Log once per event for this rule

        logger.info(f"Detected {len(incidents)} Syslog privilege escalation incidents.")
        return incidents

    def _detect_syslog_suspicious_process(self, df: pd.DataFrame, rule_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detects suspicious process activity in Syslog messages."""
        incidents = []
        patterns = self._compiled_regex_patterns['syslog']['suspicious_process'].get('patterns', [])

        if df.empty or not patterns:
            return incidents

        for idx, row in df.iterrows():
            message = row.get('Message', '')
            for pattern in patterns:
                if pattern.search(message):
                    incidents.append({
                        "type": "Suspicious Process Activity", # English incident type
                        "timestamp": row['Timestamp'].isoformat() if 'Timestamp' in row and pd.notna(row['Timestamp']) else 'N/A',
                        "source": "Syslog",
                        "details": {
                            "hostname": row.get('Hostname', 'N/A'),
                            "tag": row.get('Tag', 'N/A'),
                            "message": message,
                            "matched_pattern": pattern.pattern
                        }
                    })
                    break

        logger.info(f"Detected {len(incidents)} Syslog suspicious process incidents.")
        return incidents

    def _detect_syslog_malware_execution(self, df: pd.DataFrame, rule_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detects malware execution indicators in Syslog messages."""
        incidents = []
        patterns = self._compiled_regex_patterns['syslog']['malware_execution'].get('patterns', [])

        if df.empty or not patterns:
            return incidents

        for idx, row in df.iterrows():
            message = row.get('Message', '')
            for pattern in patterns:
                if pattern.search(message):
                    incidents.append({
                        "type": "Malware Execution", # English incident type
                        "timestamp": row['Timestamp'].isoformat() if 'Timestamp' in row and pd.notna(row['Timestamp']) else 'N/A',
                        "source": "Syslog",
                        "details": {
                            "hostname": row.get('Hostname', 'N/A'),
                            "tag": row.get('Tag', 'N/A'),
                            "message": message,
                            "matched_pattern": pattern.pattern
                        }
                    })
                    break

        logger.info(f"Detected {len(incidents)} Syslog malware execution incidents.")
        return incidents

    def _detect_syslog_data_exfiltration(self, df: pd.DataFrame, rule_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detects potential data exfiltration attempts in Syslog messages."""
        incidents = []
        patterns = self._compiled_regex_patterns['syslog']['data_exfiltration'].get('patterns', [])

        if df.empty or not patterns:
            return incidents

        for idx, row in df.iterrows():
            message = row.get('Message', '')
            for pattern in patterns:
                if pattern.search(message):
                    incidents.append({
                        "type": "Data Exfiltration Attempt", # English incident type
                        "timestamp": row['Timestamp'].isoformat(),
                        "source": "Syslog",
                        "details": {
                            "hostname": row.get('Hostname', 'N/A'),
                            "tag": row.get('Tag', 'N/A'),
                            "message": message,
                            "matched_pattern": pattern.pattern
                        }
                    })
                    break

        logger.info(f"Detected {len(incidents)} Syslog data exfiltration incidents.")
        return incidents

    def _analyze_syslog_logs(self, syslog_df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Orchestrates the detection of various incident types in Syslog logs.
        """
        logger.info("Starting Syslog log analysis...")
        all_incidents: List[Dict[str, Any]] = []

        if syslog_df.empty:
            logger.info("No Syslog logs to analyze.")
            return all_incidents

        # Ensure 'Message' column exists for pattern matching
        if 'Message' not in syslog_df.columns:
            logger.warning("Syslog DataFrame missing 'Message' column. Skipping Syslog analysis.")
            return all_incidents

        # Call individual detection methods based on available rules
        if "failed_login" in self.detection_rules["syslog"]:
            all_incidents.extend(self._detect_syslog_failed_login(syslog_df, self.detection_rules["syslog"]["failed_login"]))
        if "privilege_escalation" in self.detection_rules["syslog"]:
            all_incidents.extend(self._detect_syslog_privilege_escalation(syslog_df, self.detection_rules["syslog"]["privilege_escalation"]))
        if "suspicious_process" in self.detection_rules["syslog"]:
            all_incidents.extend(self._detect_syslog_suspicious_process(syslog_df, self.detection_rules["syslog"]["suspicious_process"]))
        if "malware_execution" in self.detection_rules["syslog"]:
            all_incidents.extend(self._detect_syslog_malware_execution(syslog_df, self.detection_rules["syslog"]["malware_execution"]))
        if "data_exfiltration" in self.detection_rules["syslog"]:
            all_incidents.extend(self._detect_syslog_data_exfiltration(syslog_df, self.detection_rules["syslog"]["data_exfiltration"]))

        logger.info(f"Finished Syslog log analysis. Total incidents detected: {len(all_incidents)}")
        return all_incidents

    def analyze_logs(self, windows_df: pd.DataFrame, syslog_df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Main method to analyze both Windows and Syslog DataFrames for security incidents.

        Args:
            windows_df (pd.DataFrame): DataFrame containing parsed Windows event logs.
            syslog_df (pd.DataFrame): DataFrame containing parsed Syslog entries.

        Returns:
            List[Dict[str, Any]]: A consolidated list of all detected incidents.
        """
        logger.info("Starting comprehensive log analysis...")
        
        detected_incidents = []
        
        # Analyze Windows logs if rules exist
        if "windows" in self.detection_rules:
            detected_incidents.extend(self._analyze_windows_logs(windows_df))
        else:
            logger.warning("No Windows detection rules configured. Skipping Windows log analysis.")

        # Analyze Syslog logs if rules exist
        if "syslog" in self.detection_rules:
            detected_incidents.extend(self._analyze_syslog_logs(syslog_df))
        else:
            logger.warning("No Syslog detection rules configured. Skipping Syslog log analysis.")

        logger.info(f"Log analysis complete. Total incidents detected across all logs: {len(detected_incidents)}")
        return detected_incidents

