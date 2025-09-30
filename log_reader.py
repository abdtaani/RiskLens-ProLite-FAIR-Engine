# log_reader.py
# Responsible for reading log files (Windows EVTX and Syslog)

import os
import pandas as pd
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET
import re
# Removed: import subprocess # No longer needed for wevtutil
import json
import logging
from typing import Optional, List, Dict, Any # Added more types
from utils.helpers import setup_logging, get_current_year, get_previous_year

# --- EVTX Specific Imports ---
try:
    # Requires: pip install python-evtx
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
    from xml.etree.ElementTree import fromstring as xml_fromstring
    EVTX_AVAILABLE = True
except ImportError:
    # Set flag to False if the optional dependency is not installed
    EVTX_AVAILABLE = False

# --- Data Source Connector Interface ---
# (A basic interface to extend data source support easily)
class LogSourceConnector:
    """Base interface for all external log source connectors."""
    def fetch_logs(self, query: str, start_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        raise NotImplementedError("Subclasses must implement the fetch_logs method.")

class SplunkConnector(LogSourceConnector):
    """
    Placeholder for a Splunk API connector.
    Implementation would require 'splunk-sdk' or similar.
    """
    def fetch_logs(self, query: str, start_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        # This is where the Splunk API call logic would go
        # Example: connecting to Splunk, running the query, and parsing results.
        logging.warning("Splunk API connection is a placeholder and not implemented.")
        # Simulating an API call that returns a list of log dicts
        return []

class ElasticsearchConnector(LogSourceConnector):
    """
    Placeholder for an Elasticsearch/Elastic API connector.
    Implementation would require 'elasticsearch' package.
    """
    def fetch_logs(self, query: str, start_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        # This is where the Elasticsearch API call logic would go
        # Example: connecting to Elastic, executing a DSL query, and parsing results.
        logging.warning("Elasticsearch API connection is a placeholder and not implemented.")
        # Simulating an API call that returns a list of log dicts
        return []

# Setup logging for this module
logger = setup_logging()

class LogReader:
    """
    Handles the ingestion of log files from various sources,
    including Windows Event Logs (.evtx), Syslog files, and external APIs.
    """
    def __init__(self) -> None:
        # Dictionary to hold initialized connectors
        self.connectors: Dict[str, LogSourceConnector] = {
            "splunk": SplunkConnector(),
            "elastic": ElasticsearchConnector()
        }

    # --- NEW EVTX READER USING python-evtx ---
    def _read_evtx_with_python_evtx(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Reads .evtx files directly using the `python-evtx` library.
        This provides cross-platform compatibility.

        Args:
            file_path (str): The path to the .evtx file.

        Returns:
            list[dict]: A list of dictionaries, where each dictionary represents an event.
                        Returns an empty list if an error occurs.
        """
        if not EVTX_AVAILABLE:
            logger.error("The 'python-evtx' library is not installed. Cannot parse EVTX file.")
            return []

        logger.info(f"Attempting to read EVTX file {file_path} using python-evtx...")
        events = []

        try:
            with Evtx(file_path) as evtx:
                for xml_event, _ in evtx_file_xml_view(evtx.get_file_header()):
                    event_data = {}
                    try:
                        # Parse the XML content for a single event
                        root = xml_fromstring(xml_event)

                        # Define namespaces (similar to wevtutil, but for ElementTree parsing)
                        namespaces = {
                            'win': 'http://schemas.microsoft.com/win/2004/08/events/event',
                            'sys': 'http://schemas.microsoft.com/win/2004/08/events/event/system',
                            'event': 'http://schemas.microsoft.com/win/2004/08/events/event',
                            'data': 'http://schemas.microsoft.com/win/2004/08/events/event/data'
                        }

                        # --- Extract System properties ---
                        system_element = root.find("sys:System", namespaces)
                        if system_element is not None:
                            event_data['EventID'] = system_element.findtext("sys:EventID", namespaces)
                            event_data['Level'] = system_element.findtext("sys:Level", namespaces)
                            # TimeCreated attribute is 'SystemTime'
                            time_created_element = system_element.find("sys:TimeCreated", namespaces)
                            event_data['TimeCreated'] = time_created_element.get("SystemTime") if time_created_element is not None else None
                            provider_element = system_element.find("sys:Provider", namespaces)
                            event_data['ProviderName'] = provider_element.get("Name") if provider_element is not None else None
                            event_data['Computer'] = system_element.findtext("sys:Computer", namespaces)
                            event_data['Channel'] = system_element.findtext("sys:Channel", namespaces)
                            # Extract other system properties as needed (ProcessID, ThreadID, etc.)
                            event_data['ProcessID'] = system_element.findtext("sys:ProcessID", namespaces)
                            event_data['ThreadID'] = system_element.findtext("sys:ThreadID", namespaces)
                            # Security UserID (SID) is complex, often extracted from a Security element
                            security_element = system_element.find("sys:Security", namespaces)
                            event_data['SecurityUserID'] = security_element.get("UserID") if security_element is not None and security_element.get("UserID") else None


                        # --- Extract EventData properties ---
                        event_data_element = root.find("event:EventData", namespaces)
                        if event_data_element is not None:
                            for data_element in event_data_element.findall("data:Data", namespaces):
                                name = data_element.get("Name")
                                value = data_element.text
                                if name:
                                    event_data[name] = value
                        
                        # Add raw XML for full details or fallbacks
                        event_data['RawLog'] = xml_event
                        
                        # --- Message/Description (Often needs specific libraries or templates, skipping for brevity) ---
                        # For now, we construct a message from available data
                        filtered_details = {k: v for k, v in event_data.items() if k not in ['RawLog', 'TimeCreated', 'ProviderName', 'Computer', 'Channel', 'SecurityUserID', 'ProcessID', 'ThreadID', 'Level']}
                        event_data['Message'] = ", ".join(f"{k}: {v}" for k, v in filtered_details.items())
                        if not event_data['Message']:
                            event_data['Message'] = str(event_data)

                        events.append(event_data)

                    except Exception as parse_error:
                        # Log error for a single event and continue
                        logger.warning(f"Error parsing an individual event in {file_path}: {parse_error}. Skipping event. Raw event XML: {xml_event[:200]}...", exc_info=True)
                        continue
            return events

        except FileNotFoundError:
            logger.error(f"EVTX file not found: {file_path}")
            return []
        except Exception as e:
            logger.error(f"An unexpected error occurred while processing EVTX file {file_path}: {e}", exc_info=True)
            return []
    
    # Removed the _read_evtx_with_wevtutil method completely

    def _read_syslog(self, file_path: str) -> list[dict]:
        # <--- NO CHANGES TO SYSLOG READER FOR BREVITY AND FOCUS --->
        """
        Reads a standard Syslog file.
        Parses common BSD syslog format (RFC 3164) and attempts to handle RFC 5424 (modern syslog)
        for basic fields.
        ... [The rest of the _read_syslog method is unchanged] ...
        """
        logger.info(f"Reading Syslog file: {file_path}")
        logs = []

        # Regex for common BSD syslog format (RFC 3164)
        syslog_pattern_rfc3164 = re.compile(
            r"^(?P<month>\w{3})\s+(?P<day>\s*\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"  # 1: Month Day Time
            r"(?P<hostname>\S+)\s+"                                                     # 2: Hostname
            r"(?P<tag>[a-zA-Z0-9_/\.-]+?)(?:\[(?P<pid>\d+)\])?(?::\s*|\s+)(?P<message>.*)$" # 3: Tag, 4: optional PID, 5: Message
        )

        # Basic regex for RFC 5424 (modern syslog)
        syslog_pattern_rfc5424 = re.compile(
            r"^(?:<(\d+)>)?(\d+\s+)?(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+" # Priority, Version, Timestamp
            r"(?P<hostname>\S+)\s+"                                                                                     # Hostname
            r"(?P<app_name>\S+)\s+"                                                                                     # App-Name
            r"(?P<proc_id>\S+)\s+"                                                                                      # ProcID
            r"(?P<msg_id>\S+)\s+"                                                                                       # MsgID
            r"(?P<structured_data>-|\[.*?\])\s+"                                                                        # Structured-Data
            r"(?P<message>.*)$"                                                                                         # Message
        )

        current_year = get_current_year()
        previous_year = get_previous_year()

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                log_entry = {
                    'Priority': None, 'Version': None, 'Timestamp': None, 'Hostname': None,
                    'Tag': None, 'PID': None, 'MessageID': None, 'StructuredData': None,
                    'Message': line.strip(), 'RawLog': line.strip() # Store raw line for debugging
                }

                # Try RFC 5424 first
                match_rfc5424 = syslog_pattern_rfc5424.match(line)
                if match_rfc5424:
                    data = match_rfc5424.groupdict()
                    try:
                        log_entry['Timestamp'] = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
                    except ValueError:
                        logger.warning(f"Could not parse RFC5424 timestamp '{data['timestamp']}' in line {line_num} of {file_path}. Skipping timestamp parsing for this entry.")
                        log_entry['Timestamp'] = None

                    log_entry['Hostname'] = data['hostname']
                    log_entry['Tag'] = data['app_name'] # App-Name maps to Tag in RFC5424 context
                    log_entry['PID'] = data['proc_id'] if data['proc_id'] != '-' else None
                    log_entry['MessageID'] = data['msg_id'] if data['msg_id'] != '-' else None
                    log_entry['StructuredData'] = data['structured_data'] if data['structured_data'] != '-' else None
                    log_entry['Message'] = data['message'].strip()
                    logs.append(log_entry)
                    continue # Move to next line if parsed successfully as RFC 5424

                # If not RFC 5424, try RFC 3164
                match_rfc3164 = syslog_pattern_rfc3164.match(line)
                if match_rfc3164:
                    data = match_rfc3164.groupdict()
                    timestamp_str_part = f"{data['month']} {data['day'].strip()} {data['time']}"

                    parsed_timestamp = None
                    try:
                        # Attempt with current year
                        parsed_timestamp = datetime.strptime(f"{timestamp_str_part} {current_year}", "%b %d %H:%M:%S %Y")
                        # If timestamp is in the future (e.g., log from December, current month is January),
                        # assume it's from the previous year. This handles year rollover.
                        if parsed_timestamp > datetime.now():
                            parsed_timestamp = parsed_timestamp.replace(year=previous_year)
                    except ValueError as e:
                        logger.warning(f"Could not parse RFC3164 timestamp '{timestamp_str_part}' in line {line_num} of {file_path}: {e}. This log entry might not be processed correctly.")
                        parsed_timestamp = None

                    log_entry['Timestamp'] = parsed_timestamp
                    log_entry['Hostname'] = data['hostname']
                    log_entry['Tag'] = data['tag'].strip(':') # Remove trailing colon if present
                    log_entry['PID'] = data['pid']
                    log_entry['Message'] = data['message'].strip()
                    logs.append(log_entry)
                    continue # Move to next line if parsed successfully as RFC 3164

                # If neither pattern matches, log as unparsed
                logger.debug(f"Could not parse Syslog line {line_num} in {file_path}: '{line.strip()}'. Storing as unparsed.")
                logs.append(log_entry) # Append the log_entry with only RawLog and Message (which is raw line)

        return logs

    # --- NEW METHOD FOR API/CONNECTOR LOGS ---
    def fetch_api_logs(self, source_name: str, query: str, start_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Fetches logs from a configured external API source.
        
        Args:
            source_name (str): The name of the connector (e.g., 'splunk', 'elastic').
            query (str): The query string specific to the source API.
            start_time (Optional[datetime]): Time filter.

        Returns:
            list[dict]: A list of log dictionaries.
        """
        connector = self.connectors.get(source_name.lower())
        if connector:
            logger.info(f"Fetching logs from external source: {source_name} with query: {query}")
            return connector.fetch_logs(query, start_time)
        else:
            logger.error(f"Unknown log source connector: {source_name}. Available: {list(self.connectors.keys())}")
            return []

    # --- MODIFIED load_logs_from_directory METHOD ---
    # The new EVTX reader replaces the old one, but the logic remains the same.
    def load_logs_from_directory(self, directory: str, analysis_start_time: Optional[datetime] = None) -> tuple[pd.DataFrame, pd.DataFrame]:
        """
        Loads log files from the specified directory.
        Identifies file types (.evtx, .log, .txt, etc.) and calls appropriate readers.
        Returns two DataFrames: one for Windows logs, one for Syslog logs.
        ... [The rest of the docstring is unchanged] ...
        """
        windows_logs_data = []
        syslog_logs_data = []

        if not os.path.isdir(directory):
            logger.error(f"Log directory '{directory}' does not exist. Please create it or provide a valid path.")
            return pd.DataFrame(), pd.DataFrame()

        # Iterate over files in the specified directory
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)

            # Skip the internal application log file to avoid self-ingestion
            if filename.lower() == "risklens_prolite.log":
                logger.info(f"Skipping internal log file: {filename}")
                continue

            if os.path.isfile(file_path):
                if filename.lower().endswith('.evtx'):
                    # Windows Event Log file: **Uses the new python-evtx reader**
                    logger.info(f"Detected Windows EVTX file: {filename}")
                    evtx_events = self._read_evtx_with_python_evtx(file_path) # <--- CHANGE HERE
                    windows_logs_data.extend(evtx_events)
                elif filename.lower().endswith(('.log', '.txt')) or \
                     'syslog' in filename.lower() or \
                     'auth.log' in filename.lower() or \
                     'kern.log' in filename.lower() or \
                     'messages' in filename.lower(): # Added 'messages' as a common syslog file
                    # Syslog or generic text log file
                    logger.info(f"Detected Syslog/generic log file: {filename}")
                    syslog_events = self._read_syslog(file_path)
                    syslog_logs_data.extend(syslog_events)
                else:
                    logger.info(f"Skipping unsupported file type: {filename}")
            else:
                logger.debug(f"Skipping non-file entry (directory or special file): {filename}")

        # Create DataFrames from the collected log data
        windows_df = pd.DataFrame(windows_logs_data)
        syslog_df = pd.DataFrame(syslog_logs_data)
        
        # Ensure 'TimeCreated' (for Windows) and 'Timestamp' (for Syslog) columns are datetime objects
        # 'errors='coerce' will turn unparseable dates into NaT (Not a Time)
        if 'TimeCreated' in windows_df.columns:
            windows_df['TimeCreated'] = pd.to_datetime(windows_df['TimeCreated'], errors='coerce')
        if 'Timestamp' in syslog_df.columns:
            syslog_df['Timestamp'] = pd.to_datetime(syslog_df['Timestamp'], errors='coerce')
            
        # Filter logs based on analysis_start_time if provided
        if analysis_start_time:
            # Drop rows where TimeCreated/Timestamp is NaT before filtering
            windows_df.dropna(subset=['TimeCreated'], inplace=True)
            syslog_df.dropna(subset=['Timestamp'], inplace=True)

            windows_df = windows_df[windows_df['TimeCreated'] >= analysis_start_time].copy()
            syslog_df = syslog_df[syslog_df['Timestamp'] >= analysis_start_time].copy()
            logger.info(f"Filtered Windows logs: {len(windows_df)} entries remaining after time window filter.")
            logger.info(f"Filtered Syslog logs: {len(syslog_df)} entries remaining after time window filter.")

        logger.info(f"Successfully loaded {len(windows_df)} Windows logs and {len(syslog_df)} Syslog logs.")
        return windows_df, syslog_df
