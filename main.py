# main.py (النسخة المصححة)
# Main entry point for the RiskLens ProLite application.
# Orchestrates log reading, analysis, FAIR calculation, and report generation.

import argparse
import json
import os
from datetime import datetime, timedelta
import logging

from log_reader import LogReader
from analyzer import Analyzer
from fair_engine import FairEngine
from exporter import Exporter
from utils.helpers import setup_logging

# Setup logging for the main application
logger = setup_logging()

def load_config(config_path: str) -> dict:
    """
    Loads the configuration from a specified JSON file.

    Args:
        config_path (str): The path to the configuration JSON file.

    Returns:
        dict: A dictionary containing the loaded configuration.

    Raises:
        FileNotFoundError: If the config file does not exist.
        json.JSONDecodeError: If the config file is not valid JSON.
    """
    if not os.path.exists(config_path):
        logger.error(f"Configuration file not found at: {config_path}")
        raise FileNotFoundError(f"Config file not found: {config_path}")
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        logger.info(f"Configuration loaded successfully from {config_path}")
        return config
    except json.JSONDecodeError as e:
        logger.critical(f"Error decoding JSON from config file {config_path}: {e}")
        raise
    except Exception as e:
        logger.critical(f"An unexpected error occurred while loading config from {config_path}: {e}", exc_info=True)
        raise

def main():
    """
    Main function to run the RiskLens ProLite application.
    Parses command-line arguments, loads configuration, processes logs,
    calculates FAIR risk, and generates reports.
    """
    parser = argparse.ArgumentParser(
        description="RiskLens ProLite: Daily Security Risk Assessment using FAIR model.",
        formatter_class=argparse.RawTextHelpFormatter # For better help message formatting
    )
    parser.add_argument(
        "-l", "--log-dir",
        type=str,
        default="logs/",
        help="Directory containing log files (e.g., .evtx, .log, .txt).\n"
             "Default: 'logs/'"
    )
    parser.add_argument(
        "-c", "--config",
        type=str,
        default="config.json",
        help="Path to the configuration JSON file containing detection rules and FAIR parameters.\n"
             "Default: 'config.json'"
    )
    parser.add_argument(
        "-o", "--output-dir",
        type=str,
        default="reports/",
        help="Directory where generated reports (PDF, JSON, CSV) will be saved.\n"
             "Default: 'reports/'"
    )
    parser.add_argument(
        "-t", "--time-window",
        type=int,
        default=None,
        help="Analyze logs from the last N hours only. If not specified, all available logs are processed.\n"
             "Example: -t 24 for logs from the last 24 hours."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output (DEBUG level logging)."
    )

    args = parser.parse_args()

    # Adjust logging level based on verbose argument
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        for handler in logger.handlers:
            if isinstance(handler, logging.FileHandler):
                handler.setLevel(logging.DEBUG)
            elif isinstance(handler, logging.StreamHandler):
                handler.setLevel(logging.DEBUG) # Also set console to DEBUG for verbose

    logger.info("Starting RiskLens ProLite application...")
    logger.debug(f"Arguments: {args}")

    # Determine the start time for log analysis if time_window is specified
    analysis_start_time = None
    if args.time_window is not None:
        analysis_start_time = datetime.now() - timedelta(hours=args.time_window)
        logger.info(f"Analyzing logs from: {analysis_start_time.strftime('%Y-%m-%d %H:%M:%S')} onwards (last {args.time_window} hours).")
    else:
        logger.info("No time window specified. Processing all available logs in the directory.")
        logger.info("Reminder: For daily assessments, ensure your 'logs/' directory contains recent logs or use the -t/--time-window argument.")


    try:
        # 1. Load Configuration
        config = load_config(args.config)
        detection_rules = config.get("detection_rules", {})
        fair_parameters = config.get("fair_parameters", {})

        if not detection_rules:
            logger.warning("No 'detection_rules' found in config. Analysis might be limited.")
        if not fair_parameters:
            logger.warning("No 'fair_parameters' found in config. FAIR calculations might use defaults or be skipped.")

        # 2. Initialize Components
        log_reader = LogReader()
        analyzer = Analyzer(detection_rules)
        fair_engine = FairEngine(fair_parameters)
        exporter = Exporter()

        # 3. Load Logs
        logger.info(f"Loading logs from directory: {args.log_dir}")
        # Pass the analysis_start_time to the log reader
        windows_logs_df, syslog_logs_df = log_reader.load_logs_from_directory(args.log_dir, analysis_start_time)

        if windows_logs_df.empty and syslog_logs_df.empty:
            logger.warning("No log data loaded. Exiting application.")
            # Generate an empty report indicating no incidents if no logs were loaded
            report_filename = f"RiskReport_NoLogs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            exporter.generate_pdf_report([], [], report_filename) # Pass empty lists for incidents and fair results
            return

        # 4. Analyze Logs
        logger.info("Analyzing loaded logs for security incidents...")
        detected_incidents = analyzer.analyze_logs(windows_logs_df, syslog_logs_df)

        if not detected_incidents:
            logger.info("No security incidents detected. No FAIR analysis or reports will be generated (except a base PDF).")
            # Still generate a PDF report indicating no incidents
            report_filename = f"RiskReport_NoIncidents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            exporter.generate_pdf_report([], [], report_filename) # Pass empty lists for incidents and fair results
            return

        # 5. Calculate FAIR Risk
        logger.info(f"Calculating FAIR risk for {len(detected_incidents)} detected incidents...")
        # ***************************************************************
        # FIX: Changed 'calculate_fair_for_incidents' to 'run_fair_analysis'
        fair_results = fair_engine.run_fair_analysis(detected_incidents) 
        # ***************************************************************

        # 6. Generate Reports
        logger.info("Generating reports...")
        
        # Generate PDF report
        pdf_filename = f"RiskReport_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf_path = exporter.generate_pdf_report(detected_incidents, fair_results, pdf_filename)
        if pdf_path:
            logger.info(f"PDF report saved to: {pdf_path}")
        
        # Export incidents to JSON
        json_incidents_filename = f"incidents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        json_incidents_path = exporter.export_to_json(detected_incidents, json_incidents_filename)
        if json_incidents_path:
            logger.info(f"Incidents JSON saved to: {json_incidents_path}")

        # Export FAIR results to CSV
        csv_fair_filename = f"fair_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        csv_fair_path = exporter.export_to_csv(fair_results, csv_fair_filename)
        if csv_fair_path:
            logger.info(f"FAIR results CSV saved to: {csv_fair_path}")

        logger.info("RiskLens ProLite finished successfully.")

    except FileNotFoundError as e:
        logger.critical(f"Critical error: {e}. Please ensure the specified file exists.")
    except json.JSONDecodeError as e:
        logger.critical(f"Critical error: Invalid JSON in configuration file. {e}")
    except Exception as e:
        logger.critical(f"An unhandled error occurred: {e}", exc_info=True)
        logger.critical("RiskLens ProLite terminated with errors.")

if __name__ == "__main__":
    main()