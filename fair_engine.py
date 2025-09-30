# fair_engine.py
# Implements FAIR model calculations for financial risk quantification using Monte Carlo Simulation.

from collections import defaultdict
from typing import List, Dict, Any, Union
import numpy as np # Import numpy for numerical operations and array generation
from scipy.stats import triang # Import triangular distribution for parameter modeling
from utils.helpers import setup_logging # Assumed to be available in utils/

# Setup logging for this module
logger = setup_logging()

# --- CONSTANTS FOR MONTE CARLO ---
NUM_SIMULATIONS = 10000
CONFIDENCE_LEVEL = 0.90 # P(5) and P(95) percentiles for the Risk Range

class FairEngine:
    """
    A class to implement simplified FAIR (Factor Analysis of Information Risk)
    model calculations for security risk assessment, now using Monte Carlo Simulation
    for more realistic loss quantification.
    """
    def __init__(self, fair_parameters: Dict[str, Any]) -> None:
        """
        Initializes the FairEngine with FAIR parameters, including Monte Carlo setup.
        """
        self.parameters = fair_parameters

        # Default parameters with LM_min, LM_base (Most Likely), and LM_max for Triangular Distribution
        self.default_parameters = {
            "failed_login": {"TEF_base": 0.1, "LEF_base": 0.05, "LM_min": 100, "LM_base": 300, "LM_max": 1000},
            "privilege_escalation": {"TEF_base": 0.05, "LEF_base": 0.2, "LM_min": 5000, "LM_base": 15000, "LM_max": 50000},
            "suspicious_process": {"TEF_base": 0.08, "LEF_base": 0.1, "LM_min": 500, "LM_base": 1500, "LM_max": 5000},
            "data_exfiltration": {"TEF_base": 0.02, "LEF_base": 0.5, "LM_min": 10000, "LM_base": 30000, "LM_max": 250000},
            "malware_execution": {"TEF_base": 0.03, "LEF_base": 0.4, "LM_min": 8000, "LM_base": 25000, "LM_max": 100000},
        }
        
        # --- CORRECTED MAPPING: Links detected incident names (from analyzer.py) to internal FAIR keys ---
        # This fixes the "Skipping FAIR counting" warnings by matching the detected names exactly.
        self.type_mapping: Dict[str, str] = {
            "Failed Login Attempts": "failed_login", 
            "Privilege Escalation": "privilege_escalation",
            "Suspicious Process": "suspicious_process",
            "Malware Execution": "malware_execution",
            "Data Exfiltration": "data_exfiltration",
            
            # Include the internal keys as a fallback for consistency if the analyzer uses them directly
            "failed_login": "failed_login",
            "privilege_escalation": "privilege_escalation",
            "suspicious_process": "suspicious_process",
            "data_exfiltration": "data_exfiltration",
            "malware_execution": "malware_execution",
        }
        
        # Merge provided parameters with defaults, ensuring all keys exist
        for key, defaults in self.default_parameters.items():
            if key not in self.parameters:
                self.parameters[key] = defaults
            else:
                # Merge defaults into provided config if values are missing
                for k, v in defaults.items():
                    if k not in self.parameters[key]:
                        self.parameters[key][k] = v

        logger.info("FairEngine initialized with Monte Carlo simulation enabled.")


    def _get_annual_event_frequency(self, incident_count: int, tef_base: float, lef_base: float) -> np.ndarray:
        """
        Simulates the annual Loss Event Frequency (LEF) using a triangular distribution.
        
        Args:
            incident_count (int): The number of actual incidents detected.
            tef_base (float): The base Threat Event Frequency (TEF) from config (Events per year).
            lef_base (float): The base Vulnerability (LEF | TEF) from config (Probability).

        Returns:
            np.ndarray: An array of simulated LEF values (Loss Events per year).
        """
        # 1. Simulate the Threat Event Frequency (TEF)
        tef_min = tef_base * 0.5
        tef_max = tef_base * 2.0
        # The mode (c) is set to 0.5, meaning it's in the middle of min/max range for a standard estimate
        tef_sims = triang.rvs(c=0.5, loc=tef_min, scale=(tef_max - tef_min), size=NUM_SIMULATIONS)
        
        # 2. Simulate the Probability of Loss Event (PoL) (Vulnerability)
        pol_min = lef_base * 0.5
        pol_max = min(lef_base * 1.5, 1.0) # Cannot exceed 1.0
        # The mode (c) is set to 0.5, meaning it's in the middle of min/max range
        pol_sims = triang.rvs(c=0.5, loc=pol_min, scale=(pol_max - pol_min), size=NUM_SIMULATIONS)

        # 3. Calculate LEF = TEF * PoL
        lef_sims = tef_sims * pol_sims
        
        # 4. Adjustment for Actual Incident Count: If actual incidents were detected,
        if incident_count > 0:
            # We assume a daily analysis or that incident_count reflects a short period.
            # Here we use a blend between the simulated base rate and a simple observed annual rate.
            observed_annual_rate = incident_count * 30 # Rough scaling for a typical analysis window (e.g., last 30 days)
            
            # Blend the simulated LEF with the observed rate (50/50 blend)
            blended_lef = (lef_sims + observed_annual_rate) / 2
            return blended_lef
        
        return lef_sims


    def _get_loss_magnitude(self, lm_min: float, lm_base: float, lm_max: float) -> np.ndarray:
        """
        Simulates the Loss Magnitude (LM) using a Triangular distribution.

        Args:
            lm_min (float): Minimum possible loss magnitude (low estimate).
            lm_base (float): Most likely loss magnitude (modal estimate).
            lm_max (float): Maximum possible loss magnitude (high estimate).

        Returns:
            np.ndarray: An array of simulated LM values (Loss Magnitude per event).
        """
        scale = lm_max - lm_min
        if scale <= 0:
            logger.error("Invalid LM configuration: LM_max must be greater than LM_min.")
            return np.full(NUM_SIMULATIONS, lm_base) # Fallback to base value
            
        c = (lm_base - lm_min) / scale
        
        # Generate random variables from the triangular distribution
        return triang.rvs(c=c, loc=lm_min, scale=scale, size=NUM_SIMULATIONS)


    def calculate_fair_risk(self, incident_type: str, incident_count: int) -> Dict[str, Any]:
        """
        Performs Monte Carlo simulation based on FAIR parameters for a given incident type.

        Args:
            incident_type (str): The display name of the incident type (e.g., 'Failed Login Attempts (Actual)').
            incident_count (int): The number of actual incidents detected.

        Returns:
            Dict[str, Any]: A dictionary containing the incident type and the Monte Carlo results.
        """
        
        # Extract the key name for parameter lookup (e.g., 'failed_login' from 'Failed Login Attempts (Actual)')
        # We need to find the internal key from the display name using the reverse mapping logic
        display_name_only = incident_type.split(' (')[0] # Get 'Failed Login Attempts'
        key = self.type_mapping.get(display_name_only, display_name_only.lower().replace(' ', '_')) # Try mapping first

        params = self.parameters.get(key)
        if not params:
            logger.error(f"Missing FAIR parameters for key: {key} (Derived from {incident_type}). Cannot run simulation.")
            return {"incident_type": incident_type, "Error": "Missing FAIR parameters"}

        try:
            # 1. Simulate Loss Magnitude (LM)
            lm_sims = self._get_loss_magnitude(
                lm_min=params['LM_min'], 
                lm_base=params['LM_base'], # New parameter used for mode
                lm_max=params['LM_max']
            )

            # 2. Simulate Loss Event Frequency (LEF)
            lef_sims = self._get_annual_event_frequency(
                incident_count=incident_count, 
                tef_base=params['TEF_base'], 
                lef_base=params['LEF_base']
            )

            # 3. Calculate Annualized Loss Exposure (ALE) = LEF * LM
            ale_sims = lef_sims * lm_sims

            # 4. Calculate Key Statistical Results
            
            # Expected Loss (Mean ALE)
            expected_loss = float(np.mean(ale_sims))
            
            # Risk Range (Confidence Interval - P5 to P95 for 90% confidence)
            p5 = float(np.percentile(ale_sims, 5)) # 5th percentile
            p95 = float(np.percentile(ale_sims, 95)) # 95th percentile
            
            risk_range_min = p5
            risk_range_max = p95

            logger.info(f"FAIR MC simulation complete for {incident_type}. Expected Loss: ${expected_loss:,.2f}")

            return {
                "incident_type": incident_type,
                "incident_count": incident_count,
                "Expected_Annual_Loss_Exposure": expected_loss, # $ الخسارة السنوية المتوقعة (المتوسط)
                "Risk_Range_Min": risk_range_min, # $ نطاق المخاطر الأدنى (P5)
                "Risk_Range_Max": risk_range_max, # $ نطاق المخاطر الأعلى (P95)
                "Simulations_Run": NUM_SIMULATIONS
            }

        except Exception as e:
            logger.error(f"Monte Carlo simulation failed for {incident_type}: {e}", exc_info=True)
            return {"incident_type": incident_type, "Error": f"Simulation failed: {e}"}


    def run_fair_analysis(self, incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Aggregates incidents by type and calculates the FAIR risk for each type.
        This function iterates over the detected incidents and the base parameters.
        """
        incident_counts = defaultdict(int)
        
        # 1. Count incidents based on the CORRECT internal mapping
        for inc in incidents:
            # inc.get('type') returns names like 'Privilege Escalation'
            detected_type = inc.get('type')
            internal_key = self.type_mapping.get(detected_type)
            
            if internal_key:
                incident_counts[internal_key] += 1
            else:
                # This block should now be hit less frequently due to corrected mapping
                logger.warning(f"Incident type '{detected_type}' not found in type_mapping. Skipping FAIR counting.")

        fair_results: List[Dict[str, Any]] = []
        actual_incident_keys = set(incident_counts.keys()) # Keys that had actual incidents
        
        # 2. Calculate FAIR risk for actual detected incidents
        # Map back to display name for the report output
        reversed_type_mapping = {v: k for k, v in self.type_mapping.items()}

        for internal_key, count in incident_counts.items():
            display_name = reversed_type_mapping.get(internal_key, internal_key)
            fair_results.append(self.calculate_fair_risk(f"{display_name} (Actual)", count))
        
        # 3. Calculate FAIR risk for BASELINE parameters (0 incidents)
        # Includes types configured in FAIR but not seen in the logs.
        for fair_type_key in self.parameters.keys():
            if fair_type_key not in actual_incident_keys:
                # Find the user-friendly name for reporting
                display_name = reversed_type_mapping.get(fair_type_key, fair_type_key)
                
                # Pass incident_count = 0 to simulate the baseline risk
                fair_results.append(self.calculate_fair_risk(f"{display_name} (Base)", 0))

        if not fair_results and incidents:
            logger.warning("No FAIR results generated despite incidents being detected. "
                           "This might indicate an issue with incident type mapping or missing FAIR parameters.")
        elif not incidents:
            logger.info("No incidents detected, so no FAIR calculations performed.")

        return fair_results