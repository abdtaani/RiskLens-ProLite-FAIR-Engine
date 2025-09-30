# analyzer.py
# Processes raw log data to identify security incidents based on predefined detection rules.

import pandas as pd
import re
from typing import List, Dict, Any, Optional
from datetime import timedelta
import json
import os
from collections import defaultdict
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
                # Compile whitelist patterns if they exist
                if "whitelist_users" in rule_config:
                    compiled_patterns[os_type][incident_type]["whitelist_users"] = [
                        re.compile(p, re.IGNORECASE) for p in rule_config["whitelist_users"]
                    ]
                if "whitelist_paths" in rule_config:
                    compiled_patterns[os_type][incident_type]["whitelist_paths"] = [
                        re.compile(p, re.IGNORECASE) for p in rule_config["whitelist_paths"]
                    ]
                if "whitelist_ips" in rule_config:
                    compiled_patterns[os_type][incident_type]["whitelist_ips"] = [
                        re.compile(p) for p in rule_config["whitelist_ips"]
                    ]
        return compiled_patterns

    def _detect_windows_failed_login(self, df: pd.DataFrame, rule_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detects failed login attempts in Windows logs and groups consecutive attempts."""
        incidents = []
        event_id = rule_config.get("event_id")
        threshold = rule_config.get("threshold")
        time_window = timedelta(minutes=rule_config.get("time_window_minutes", 5))
        whitelist_users = self._compiled_regex_patterns['windows']['failed_login'].get('whitelist_users', [])
        whitelist_ips = self._compiled_regex_patterns['windows']['failed_login'].get('whitelist_ips', [])


        if df.empty or not event_id or not threshold:
            return incidents

        failed_logins = df[df['EventID'] == event_id].copy()
        if failed_logins.empty:
            return incidents

        failed_logins['TimeCreated'] = pd.to_datetime(failed_logins['TimeCreated'], errors='coerce')
        failed_logins.dropna(subset=['TimeCreated'], inplace=True)
        failed_logins.sort_values(by='TimeCreated', inplace=True)

        # Group by Account Name and Source Network Address
        for (account_name, ip_address), group in failed_logins.groupby(['Account Name', 'IpAddress']):
            if account_name is None or ip_address is None:
                continue

            if any(p.search(account_name) for p in whitelist_users) or \
               any(p.search(ip_address) for p in whitelist_ips):
                logger.debug(f"Skipping failed login for whitelisted user '{account_name}' or IP '{ip_address}'.")
                continue

            current_sequence = []
            for _, row in group.iterrows():
                current_time = row['TimeCreated']
                if not current_sequence or (current_time - current_sequence[-1]['TimeCreated']) <= time_window:
                    current_sequence.append(row)
                else:
                    # Process the previous sequence if it meets the threshold
                    if len(current_sequence) >= threshold:
                        first_attempt_time = current_sequence[0]['TimeCreated']
                        last_attempt_time = current_sequence[-1]['TimeCreated']
                        incidents.append({
                            "type": "Failed Login Attempts",
                            "timestamp": last_attempt_time.isoformat(),
                            "source": "Windows",
                            "event_id": event_id,
                            "severity": "Medium", # Added Severity
                            "details": {
                                "account_name": account_name,
                                "ip_address": ip_address,
                                "failed_attempts_count": len(current_sequence),
                                "time_range": f"{first_attempt_time.strftime('%H:%M:%S')} - {last_attempt_time.strftime('%H:%M:%S')}",
                                "message": f"Multiple failed login attempts ({len(current_sequence)}) for user '{account_name}' from IP '{ip_address}' between {first_attempt_time.strftime('%Y-%m-%d %H:%M:%S')} and {last_attempt_time.strftime('%Y-%m-%d %H:%M:%S')}.",
                                "first_event_message": current_sequence[0].get('Message', 'N/A')
                            },
                            "recommendations": ["Implement account lockout policies.", "Enforce multi-factor authentication (MFA).", "Monitor authentication logs for brute-force attacks."] # Added recommendations
                        })
                    current_sequence = [row] # Start a new sequence with the current row

            # Process any remaining sequence after the loop
            if len(current_sequence) >= threshold:
                first_attempt_time = current_sequence[0]['TimeCreated']
                last_attempt_time = current_sequence[-1]['TimeCreated']
                incidents.append({
                    "type": "Failed Login Attempts",
                    "timestamp": last_attempt_time.isoformat(),
                    "source": "Windows",
                    "event_id": event_id,
                    "severity": "Medium", # Added Severity
                    "details": {
                        "account_name": account_name,
                        "ip_address": ip_address,
                        "failed_attempts_count": len(current_sequence),
                        "time_range": f"{first_attempt_time.strftime('%H:%M:%S')} - {last_attempt_time.strftime('%H:%M:%S')}",
                        "message": f"Multiple failed login attempts ({len(current_sequence)}) for user '{account_name}' from IP '{ip_address}' between {first_attempt_time.strftime('%Y-%m-%d %H:%M:%S')} and {last_attempt_time.strftime('%Y-%m-%d %H:%M:%S')}.",
                        "first_event_message": current_sequence[0].get('Message', 'N/A')
                    },
                    "recommendations": ["Implement account lockout policies.", "Enforce multi-factor authentication (MFA).", "Monitor authentication logs for brute-force attacks."]
                })

        logger.info(f"Detected {len(incidents)} Windows failed login incidents (grouped).")
        return incidents

    def _detect_windows_privilege_escalation(self, df: pd.DataFrame, rule_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detects privilege escalation attempts in Windows logs."""
        incidents = []
        event_ids = [rule_config.get(k) for k in ["event_id_4672", "event_id_4756", "event_id_4728"] if rule_config.get(k)]
        sensitive_privileges = rule_config.get("sensitive_privileges_patterns", [])
        admin_groups = rule_config.get("admin_groups_patterns", [])
        whitelist_users = self._compiled_regex_patterns['windows']['privilege_escalation'].get('whitelist_users', [])


        if df.empty or not event_ids:
            return incidents

        # Filter for relevant event IDs
        escalation_events = df[df['EventID'].isin(event_ids)].copy()
        if escalation_events.empty:
            return incidents

        for idx, row in escalation_events.iterrows():
            user = row.get('TargetUserName', row.get('SubjectUserName', 'N/A'))
            # Apply whitelist: Skip if user is whitelisted
            if any(p.search(user) for p in whitelist_users):
                logger.debug(f"Skipping privilege escalation event for whitelisted user '{user}'.")
                continue

            incident_detected = False
            details = {
                "event_id": row['EventID'],
                "user": user,
                "message": row.get('Message', 'N/A')
            }
            severity = "High" # Default severity for Privilege Escalation

            if row['EventID'] == rule_config.get("event_id_4672"):
                # Check for sensitive privileges granted (EventID 4672)
                message = row.get('Message', '')
                for priv in sensitive_privileges:
                    if re.search(r'\b' + re.escape(priv) + r'\b', message, re.IGNORECASE):
                        details["privilege_granted"] = priv
                        incident_detected = True
                        break
            elif row['EventID'] in [rule_config.get("event_id_4756"), rule_config.get("event_id_4728")]:
                # Check for addition to admin groups (EventID 4756, 4728)
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
                    "type": "Privilege Escalation",
                    "timestamp": row['TimeCreated'].isoformat() if 'TimeCreated' in row and pd.notna(row['TimeCreated']) else 'N/A',
                    "source": "Windows",
                    "severity": severity, # Added Severity
                    "details": details,
                    "recommendations": ["Apply the principle of least privilege.", "Regularly review user and group permissions.", "Deploy Privileged Access Management (PAM) solutions."] # Added recommendations
                })
        logger.info(f"Detected {len(incidents)} Windows privilege escalation incidents.")
        return incidents

    def _detect_windows_suspicious_process(self, df: pd.DataFrame, rule_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detects suspicious process activity in Windows logs."""
        incidents = []
        event_id = rule_config.get("event_id")
        suspicious_cmd_patterns = self._compiled_regex_patterns['windows']['suspicious_process'].get('suspicious_cmd_patterns', [])
        standard_paths = rule_config.get("standard_paths", [])
        whitelist_paths = self._compiled_regex_patterns['windows']['suspicious_process'].get('whitelist_paths', [])


        if df.empty or not event_id:
            return incidents

        process_creation_events = df[df['EventID'] == event_id].copy()
        if process_creation_events.empty:
            return incidents

        for idx, row in process_creation_events.iterrows():
            command_line = row.get('CommandLine', '')
            process_path = row.get('NewProcessName', '')
            user = row.get('SubjectUserName', 'N/A')

            incident_details = {
                "process_name": os.path.basename(process_path),
                "command_line": command_line,
                "user": user,
                "message": row.get('Message', 'N/A')
            }
            severity = "Medium" # Default severity for Suspicious Process Activity
            incident_detected = False

            # Check for suspicious command line patterns
            for pattern in suspicious_cmd_patterns:
                if pattern.search(command_line):
                    incidents.append({
                        "type": "Suspicious Process Activity",
                        "timestamp": row['TimeCreated'].isoformat() if 'TimeCreated' in row and pd.notna(row['TimeCreated']) else 'N/A',
                        "source": "Windows",
                        "event_id": event_id,
                        "severity": severity, # Added Severity
                        "details": {**incident_details, "matched_pattern": pattern.pattern, "reason": "Suspicious command line pattern"},
                        "recommendations": ["Implement Endpoint Detection and Response (EDR) or Extended Detection and Response (XDR) solutions.", "Monitor process behavior anomalies.", "Keep security signatures updated."] # Added recommendations
                    })
                    incident_detected = True
                    break # Only log once per event for this rule

            # Check if process runs from non-standard path and not in whitelist
            if process_path and not incident_detected: # Only proceed if not already detected by command line
                is_standard_path = any(process_path.lower().startswith(p.lower()) for p in standard_paths)
                is_whitelisted_path = any(p.search(process_path) for p in whitelist_paths)

                if not is_standard_path and not is_whitelisted_path:
                    if not (re.search(r'\\Users\\[^\\]+\\AppData\\Local\\Temp\\', process_path, re.IGNORECASE) or
                            re.search(r'\\Users\\[^\\]+\\Downloads\\', process_path, re.IGNORECASE) or
                            re.search(r'\\Windows\\Temp\\', process_path, re.IGNORECASE)):
                        
                        incidents.append({
                            "type": "Suspicious Process Activity",
                            "timestamp": row['TimeCreated'].isoformat() if 'TimeCreated' in row and pd.notna(row['TimeCreated']) else 'N/A',
                            "source": "Windows",
                            "event_id": event_id,
                            "severity": severity, # Added Severity
                            "details": {**incident_details, "reason": "Process running from non-standard path", "process_path": process_path},
                            "recommendations": ["Implement Endpoint Detection and Response (EDR) or Extended Detection and Response (XDR) solutions.", "Monitor process behavior anomalies.", "Keep security signatures updated."]
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
                "type": "Malware Execution",
                "timestamp": row['TimeCreated'].isoformat() if 'TimeCreated' in row and pd.notna(row['TimeCreated']) else 'N/A',
                "source": "Windows Defender",
                "event_id": row['EventID'],
                "severity": "High", # Added Severity
                "details": {
                    "threat_name": row.get('Threat Name', 'N/A'),
                    "file_path": row.get('Path', 'N/A'),
                    "action_taken": row.get('Action', 'N/A'),
                    "message": row.get('Message', 'N/A')
                },
                "recommendations": ["Ensure Antivirus/Endpoint Protection is up-to-date.", "Train users on phishing awareness.", "Implement application whitelisting."] # Added recommendations
            })

        # 2. Suspicious Process Creation (Event ID 4688) for known malicious patterns
        process_creation_events = df[df['EventID'] == process_creation_id].copy()
        for idx, row in process_creation_events.iterrows():
            new_process_name = row.get('NewProcessName', '')
            command_line = row.get('CommandLine', '')
            
            for pattern in malicious_process_patterns:
                if pattern.search(new_process_name) or pattern.search(command_line):
                    incidents.append({
                        "type": "Malware Execution",
                        "timestamp": row['TimeCreated'].isoformat() if 'TimeCreated' in row and pd.notna(row['TimeCreated']) else 'N/A',
                        "source": "Windows",
                        "event_id": process_creation_id,
                        "severity": "High", # Added Severity
                        "details": {
                            "process_name": os.path.basename(new_process_name),
                            "command_line": command_line,
                            "matched_pattern": pattern.pattern,
                            "user": row.get('SubjectUserName', 'N/A'),
                            "message": row.get('Message', 'N/A')
                        },
                        "recommendations": ["Ensure Antivirus/Endpoint Protection is up-to-date.", "Train users on phishing awareness.", "Implement application whitelisting."]
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
        whitelist_ips = self._compiled_regex_patterns['windows']['data_exfiltration'].get('whitelist_ips', [])


        if df.empty:
            return incidents

        # 1. Sysmon Event ID 9 (RawAccessRead) - Data from Removable Media
        if sysmon_raw_access_read_id:
            raw_access_events = df[(df['EventID'] == sysmon_raw_access_read_id) & (df['ProviderName'] == 'Microsoft-Windows-Sysmon')].copy()
            for idx, row in raw_access_events.iterrows():
                # Look for patterns like \\.\PhysicalDriveX or \\.\Volume{GUID}
                if 'TargetFilename' in row and re.search(r'\\\\\.\\\\(PhysicalDrive|Volume)\{?[\w-]+\}?', row['TargetFilename'], re.IGNORECASE):
                    incidents.append({
                        "type": "Data Exfiltration Attempt",
                        "timestamp": row['TimeCreated'].isoformat() if 'TimeCreated' in row and pd.notna(row['TimeCreated']) else 'N/A',
                        "source": "Windows Sysmon (RawAccessRead)",
                        "event_id": sysmon_raw_access_read_id,
                        "severity": "Critical", # Added Severity
                        "details": {
                            "process_name": row.get('Image', 'N/A'),
                            "target_device": row.get('TargetFilename', 'N/A'),
                            "user": row.get('User', 'N/A'),
                            "message": row.get('Message', 'N/A')
                        },
                        "recommendations": ["Deploy Data Loss Prevention (DLP) solutions.", "Monitor outbound network traffic for anomalies.", "Encrypt sensitive data at rest and in transit."] # Added recommendations
                    })

        # 2. Sysmon Event ID 3 (Network Connection) - Outbound Network Activity
        if sysmon_network_connection_id:
            network_events_sysmon = df[(df['EventID'] == sysmon_network_connection_id) & (df['ProviderName'] == 'Microsoft-Windows-Sysmon')].copy()
            for idx, row in network_events_sysmon.iterrows():
                destination_ip = row.get('DestinationIp', '')
                destination_port = row.get('DestinationPort', '')
                initiated = row.get('Initiated', '')

                # Apply whitelist: Skip if IP is whitelisted
                if any(p.search(destination_ip) for p in whitelist_ips):
                    logger.debug(f"Skipping network connection to whitelisted IP '{destination_ip}'.")
                    continue

                # Check for connections to known bad IPs or unusual ports
                if initiated == 'true':
                    if destination_ip in known_bad_ips:
                        incidents.append({
                            "type": "Data Exfiltration Attempt",
                            "timestamp": row['TimeCreated'].isoformat() if 'TimeCreated' in row and pd.notna(row['TimeCreated']) else 'N/A',
                            "source": "Windows Sysmon (Network Connection)",
                            "event_id": sysmon_network_connection_id,
                            "severity": "Critical", # Added Severity
                            "details": {
                                "process_name": row.get('Image', 'N/A'),
                                "destination_ip": destination_ip,
                                "destination_port": destination_port,
                                "reason": "Connection to known bad IP",
                                "user": row.get('User', 'N/A'),
                                "message": row.get('Message', 'N/A')
                            },
                            "recommendations": ["Deploy Data Loss Prevention (DLP) solutions.", "Monitor outbound network traffic for anomalies.", "Encrypt sensitive data at rest and in transit."]
                        })
                    elif destination_port and int(destination_port) not in common_ports and int(destination_port) >= 1024:
                        incidents.append({
                            "type": "Data Exfiltration Attempt",
                            "timestamp": row['TimeCreated'].isoformat() if 'TimeCreated' in row and pd.notna(row['TimeCreated']) else 'N/A',
                            "source": "Windows Sysmon (Network Connection)",
                            "event_id": sysmon_network_connection_id,
                            "severity": "Medium", # Severity can be medium for unusual port
                            "details": {
                                "process_name": row.get('Image', 'N/A'),
                                "destination_ip": destination_ip,
                                "destination_port": destination_port,
                                "reason": "Connection to unusual high port",
                                "user": row.get('User', 'N/A'),
                                "message": row.get('Message', 'N/A')
                            },
                            "recommendations": ["Deploy Data Loss Prevention (DLP) solutions.", "Monitor outbound network traffic for anomalies.", "Encrypt sensitive data at rest and in transit."]
                        })

        # 3. Windows Event ID 4004 (Network Status Change) - General Network Activity
        if network_status_change_id:
            network_status_events = df[df['EventID'] == network_status_change_id].copy()
            for idx, row in network_status_events.iterrows():
                message = row.get('Message', '')
                if "new network connection" in message.lower() or "network interface connected" in message.lower():
                    incidents.append({
                        "type": "Data Exfiltration Attempt",
                        "timestamp": row['TimeCreated'].isoformat() if 'TimeCreated' in row and pd.notna(row['TimeCreated']) else 'N/A',
                        "source": "Windows (Network Status)",
                        "event_id": network_status_change_id,
                        "severity": "Low", # Severity can be low as it's generic
                        "details": {
                            "message": message,
                            "reason": "New network connection detected (requires further investigation)"
                        },
                        "recommendations": ["Deploy Data Loss Prevention (DLP) solutions.", "Monitor outbound network traffic for anomalies.", "Encrypt sensitive data at rest and in transit."]
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

        if 'EventID' in windows_df.columns:
            windows_df['EventID'] = windows_df['EventID'].astype(str)
        else:
            logger.warning("Windows DataFrame missing 'EventID' column. Skipping Windows analysis.")
            return all_incidents

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
        """Detects failed login attempts in Syslog messages and groups consecutive attempts."""
        incidents = []
        patterns = self._compiled_regex_patterns['syslog']['failed_login'].get('patterns', [])
        threshold = rule_config.get("threshold")
        time_window = timedelta(minutes=rule_config.get("time_window_minutes", 5))
        whitelist_users = self._compiled_regex_patterns['syslog']['failed_login'].get('whitelist_users', [])
        whitelist_ips = self._compiled_regex_patterns['syslog']['failed_login'].get('whitelist_ips', [])


        if df.empty or not patterns or not threshold:
            return incidents

        failed_login_logs = df[df['Message'].apply(lambda x: any(p.search(x) for p in patterns))].copy()
        if failed_login_logs.empty:
            return incidents

        failed_login_logs['Timestamp'] = pd.to_datetime(failed_login_logs['Timestamp'], errors='coerce')
        failed_login_logs.dropna(subset=['Timestamp'], inplace=True)
        failed_login_logs.sort_values(by='Timestamp', inplace=True)

        user_ip_regex = re.compile(r"(?:for (?:invalid user )?(\S+))? from (\S+)")

        for (hostname, ), group in failed_login_logs.groupby(['Hostname']):
            temp_sequences = defaultdict(list) # Key: (username, ip_address)
            
            for _, row in group.iterrows():
                match = user_ip_regex.search(row['Message'])
                username = match.group(1) if match and match.group(1) else 'UNKNOWN_USER'
                ip_address = match.group(2) if match and match.group(2) else 'UNKNOWN_IP'

                if any(p.search(username) for p in whitelist_users) or \
                   any(p.search(ip_address) for p in whitelist_ips):
                    logger.debug(f"Skipping syslog failed login for whitelisted user '{username}' or IP '{ip_address}'.")
                    continue

                key = (username, ip_address)
                current_time = row['Timestamp']

                if not temp_sequences[key] or (current_time - temp_sequences[key][-1]['Timestamp']) <= time_window:
                    temp_sequences[key].append(row)
                else:
                    # Process the previous sequence if it meets the threshold
                    if len(temp_sequences[key]) >= threshold:
                        first_attempt_time = temp_sequences[key][0]['Timestamp']
                        last_attempt_time = temp_sequences[key][-1]['Timestamp']
                        incidents.append({
                            "type": "Failed Login Attempts",
                            "timestamp": last_attempt_time.isoformat(),
                            "source": "Syslog",
                            "severity": "Medium", # Added Severity
                            "details": {
                                "hostname": hostname,
                                "account_name": username,
                                "ip_address": ip_address,
                                "failed_attempts_count": len(temp_sequences[key]),
                                "time_range": f"{first_attempt_time.strftime('%H:%M:%S')} - {last_attempt_time.strftime('%H:%M:%S')}",
                                "message": f"Multiple failed login attempts ({len(temp_sequences[key])}) for user '{username}' from IP '{ip_address}' on '{hostname}' between {first_attempt_time.strftime('%Y-%m-%d %H:%M:%S')} and {last_attempt_time.strftime('%Y-%m-%d %H:%M:%S')}.",
                                "first_event_message": temp_sequences[key][0]['Message']
                            },
                            "recommendations": ["Implement account lockout policies.", "Enforce multi-factor authentication (MFA).", "Monitor authentication logs for brute-force attacks."]
                        })
                    temp_sequences[key] = [row] # Start a new sequence with the current row

            # Process any remaining sequence after the loop
            for (username, ip_address), current_sequence in temp_sequences.items():
                if len(current_sequence) >= threshold:
                    first_attempt_time = current_sequence[0]['Timestamp']
                    last_attempt_time = current_sequence[-1]['Timestamp']
                    incidents.append({
                        "type": "Failed Login Attempts",
                        "timestamp": last_attempt_time.isoformat(),
                        "source": "Syslog",
                        "severity": "Medium", # Added Severity
                        "details": {
                            "hostname": hostname,
                            "account_name": username,
                            "ip_address": ip_address,
                            "failed_attempts_count": len(current_sequence),
                            "time_range": f"{first_attempt_time.strftime('%H:%M:%S')} - {last_attempt_time.strftime('%H:%M:%S')}",
                            "message": f"Multiple failed login attempts ({len(current_sequence)}) for user '{username}' from IP '{ip_address}' on '{hostname}' between {first_attempt_time.strftime('%Y-%m-%d %H:%M:%S')} and {last_attempt_time.strftime('%Y-%m-%d %H:%M:%S')}.",
                            "first_event_message": current_sequence[0]['Message']
                        },
                        "recommendations": ["Implement account lockout policies.", "Enforce multi-factor authentication (MFA).", "Monitor authentication logs for brute-force attacks."]
                    })

        logger.info(f"Detected {len(incidents)} Syslog failed login incidents (grouped).")
        return incidents

    def _detect_syslog_privilege_escalation(self, df: pd.DataFrame, rule_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detects privilege escalation attempts in Syslog messages."""
        incidents = []
        patterns = self._compiled_regex_patterns['syslog']['privilege_escalation'].get('patterns', [])
        whitelist_users = self._compiled_regex_patterns['syslog']['privilege_escalation'].get('whitelist_users', [])

        if df.empty or not patterns:
            return incidents

        for idx, row in df.iterrows():
            message = row.get('Message', '')
            user = row.get('User', 'N/A')

            if any(p.search(user) for p in whitelist_users) or \
               (user == 'N/A' and any(p.search(msg) for p in whitelist_users for msg in [message])):
                logger.debug(f"Skipping syslog privilege escalation event for whitelisted user '{user}' or pattern in message.")
                continue

            for pattern in patterns:
                if pattern.search(message):
                    incidents.append({
                        "type": "Privilege Escalation",
                        "timestamp": row['Timestamp'].isoformat() if 'Timestamp' in row and pd.notna(row['Timestamp']) else 'N/A',
                        "source": "Syslog",
                        "severity": "High", # Added Severity
                        "details": {
                            "hostname": row.get('Hostname', 'N/A'),
                            "tag": row.get('Tag', 'N/A'),
                            "message": message,
                            "matched_pattern": pattern.pattern
                        },
                        "recommendations": ["Apply the principle of least privilege.", "Regularly review user and group permissions.", "Deploy Privileged Access Management (PAM) solutions."]
                    })
                    break
        logger.info(f"Detected {len(incidents)} Syslog privilege escalation incidents.")
        return incidents

    def _detect_syslog_suspicious_process(self, df: pd.DataFrame, rule_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detects suspicious process activity in Syslog messages."""
        incidents = []
        patterns = self._compiled_regex_patterns['syslog']['suspicious_process'].get('patterns', [])
        whitelist_paths = self._compiled_regex_patterns['syslog']['suspicious_process'].get('whitelist_paths', [])


        if df.empty or not patterns:
            return incidents

        for idx, row in df.iterrows():
            message = row.get('Message', '')
            
            if any(p.search(message) for p in whitelist_paths):
                logger.debug(f"Skipping syslog suspicious process event due to whitelisted path/pattern in message.")
                continue

            for pattern in patterns:
                if pattern.search(message):
                    incidents.append({
                        "type": "Suspicious Process Activity",
                        "timestamp": row['Timestamp'].isoformat() if 'Timestamp' in row and pd.notna(row['Timestamp']) else 'N/A',
                        "source": "Syslog",
                        "severity": "Medium", # Added Severity
                        "details": {
                            "hostname": row.get('Hostname', 'N/A'),
                            "tag": row.get('Tag', 'N/A'),
                            "message": message,
                            "matched_pattern": pattern.pattern
                        },
                        "recommendations": ["Implement Endpoint Detection and Response (EDR) or Extended Detection and Response (XDR) solutions.", "Monitor process behavior anomalies.", "Keep security signatures updated."]
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
                        "type": "Malware Execution",
                        "timestamp": row['Timestamp'].isoformat() if 'Timestamp' in row and pd.notna(row['Timestamp']) else 'N/A',
                        "source": "Syslog",
                        "severity": "High", # Added Severity
                        "details": {
                            "hostname": row.get('Hostname', 'N/A'),
                            "tag": row.get('Tag', 'N/A'),
                            "message": message,
                            "matched_pattern": pattern.pattern
                        },
                        "recommendations": ["Ensure Antivirus/Endpoint Protection is up-to-date.", "Train users on phishing awareness.", "Implement application whitelisting."]
                    })
                    break

        logger.info(f"Detected {len(incidents)} Syslog malware execution incidents.")
        return incidents

    def _detect_syslog_data_exfiltration(self, df: pd.DataFrame, rule_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detects potential data exfiltration attempts in Syslog messages."""
        incidents = []
        patterns = self._compiled_regex_patterns['syslog']['data_exfiltration'].get('patterns', [])
        whitelist_ips = self._compiled_regex_patterns['syslog']['data_exfiltration'].get('whitelist_ips', [])


        if df.empty or not patterns:
            return incidents

        for idx, row in df.iterrows():
            message = row.get('Message', '')
            
            if any(p.search(message) for p in whitelist_ips):
                logger.debug(f"Skipping syslog data exfiltration event due to whitelisted IP/pattern in message.")
                continue

            for pattern in patterns:
                if pattern.search(message):
                    incidents.append({
                        "type": "Data Exfiltration Attempt",
                        "timestamp": row['Timestamp'].isoformat(),
                        "source": "Syslog",
                        "severity": "Critical", # Added Severity
                        "details": {
                            "hostname": row.get('Hostname', 'N/A'),
                            "tag": row.get('Tag', 'N/A'),
                            "message": message,
                            "matched_pattern": pattern.pattern
                        },
                        "recommendations": ["Deploy Data Loss Prevention (DLP) solutions.", "Monitor outbound network traffic for anomalies.", "Encrypt sensitive data at rest and in transit."]
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

        if 'Message' not in syslog_df.columns:
            logger.warning("Syslog DataFrame missing 'Message' column. Skipping Syslog analysis.")
            return all_incidents

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
        
        if "windows" in self.detection_rules:
            detected_incidents.extend(self._analyze_windows_logs(windows_df))
        else:
            logger.warning("No Windows detection rules configured. Skipping Windows log analysis.")

        if "syslog" in self.detection_rules:
            detected_incidents.extend(self._analyze_syslog_logs(syslog_df))
        else:
            logger.warning("No Syslog detection rules configured. Skipping Syslog log analysis.")

        # Sort incidents by timestamp for timeline view in reports
        detected_incidents.sort(key=lambda x: x.get('timestamp', ''))

        logger.info(f"Log analysis complete. Total incidents detected across all logs: {len(detected_incidents)}")
        return detected_incidents