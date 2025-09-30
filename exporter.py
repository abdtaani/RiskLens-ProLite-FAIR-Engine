# exporter.py
# Handles exporting results to various formats (PDF, JSON, CSV).

import os
import io
import json
import csv
from typing import List, Dict, Any, Union, Optional
from datetime import datetime

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from reportlab.lib.pagesizes import A4, landscape
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, PageBreak, Image,
    PageTemplate, Frame, flowables
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors

from utils.helpers import setup_logging

logger = setup_logging()

# Global variables for report branding
REPORT_TITLE_STR = "Daily Security Risk Assessment Report"
REPORT_SUBTITLE_STR = "RiskLens ProLite"
REPORT_VERSION = "1.0.0" # You can update this
ORGANIZATION_NAME = "Your Organization Name" # Customize this (e.g., "CyberGuard Solutions")
LOGO_PATH = "pho.jpg" # Path to your logo image (e.g., in the project root)


class Exporter:
    """
    Manages export of detected incidents and FAIR analysis results
    to PDF, JSON, and CSV formats.
    """

    def __init__(self) -> None:
        # Ensure reports directory exists
        self.reports_dir = "reports"
        os.makedirs(self.reports_dir, exist_ok=True)

        # base styles
        self.styles = getSampleStyleSheet()

        # Overwrite key styles for consistency
        self.styles["Normal"].fontName = "Helvetica"
        self.styles["Normal"].fontSize = 10
        self.styles["Normal"].leading = 12
        self.styles["Normal"].alignment = 0  # left

        self.styles["h1"].fontName = "Helvetica-Bold"
        self.styles["h1"].fontSize = 22
        self.styles["h1"].leading = 26
        self.styles["h1"].spaceAfter = 16
        self.styles["h1"].alignment = 1  # center

        self.styles["h2"].fontName = "Helvetica-Bold"
        self.styles["h2"].fontSize = 16
        self.styles["h2"].leading = 20
        self.styles["h2"].spaceAfter = 12
        self.styles["h2"].alignment = 0

        self.styles["h3"].fontName = "Helvetica-Bold"
        self.styles["h3"].fontSize = 12
        self.styles["h3"].leading = 14
        self.styles["h3"].spaceAfter = 8
        self.styles["h3"].alignment = 0

        # Extra style for severity colors
        self.styles.add(
            ParagraphStyle(
                name="SeverityCritical",
                parent=self.styles["Normal"],
                textColor=colors.red,
                fontName="Helvetica-Bold",
                fontSize=10,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="SeverityHigh",
                parent=self.styles["Normal"],
                textColor=colors.darkred,
                fontName="Helvetica-Bold",
                fontSize=10,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="SeverityMedium",
                parent=self.styles["Normal"],
                textColor=colors.orange,
                fontName="Helvetica-Bold",
                fontSize=10,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="SeverityLow",
                parent=self.styles["Normal"],
                textColor=colors.darkgreen,
                fontName="Helvetica-Bold",
                fontSize=10,
            )
        )

        # Extra style for long text (e.g., Message field)
        self.styles.add(
            ParagraphStyle(
                name="LongText",
                parent=self.styles["Normal"],
                fontSize=8,
                leading=10,
                wordWrap="LTR",
            )
        )
        # Style for code/details snippets
        self.styles.add(
            ParagraphStyle(
                name="CodeSnippet",
                parent=self.styles["Normal"],
                fontSize=7,
                leading=9,
                fontName="Courier",
                textColor=colors.darkgrey,
                leftIndent=10,
                rightIndent=10,
                spaceBefore=2,
                spaceAfter=2,
                backColor=colors.lavender,
                borderPadding=2,
            )
        )
        # Style for footer (for legal notice)
        self.styles.add(
            ParagraphStyle(
                name="FooterStyle",
                parent=self.styles["Normal"],
                fontSize=8,
                textColor=colors.grey,
                alignment=1, # Center
            )
        )

    # ---------------- PDF Page Templates ---------------- #
    def _header_footer(self, canvas, doc):
        canvas.saveState()
        # Header (Logo and Title)
        if os.path.exists(LOGO_PATH):
            logo = Image(LOGO_PATH)
            # Scale logo to fit, max height 0.5 inch, max width 1.5 inch
            logo_width = logo.drawWidth
            logo_height = logo.drawHeight
            aspect_ratio = logo_height / logo_width
            if logo_height > 0.5 * inch:
                logo.drawHeight = 0.5 * inch
                logo.drawWidth = logo.drawHeight / aspect_ratio
            if logo.drawWidth > 1.5 * inch:
                logo.drawWidth = 1.5 * inch
                logo.drawHeight = logo.drawWidth * aspect_ratio
            
            # Position the logo in the top-left corner
            logo.wrapOn(canvas, doc.width, doc.topMargin)
            logo.drawOn(canvas, doc.leftMargin, doc.height + doc.topMargin - logo.drawHeight)
        
        # Subtitle in header (aligned right)
        canvas.setFont('Helvetica-Bold', 10)
        canvas.setFillColor(colors.darkblue)
        canvas.drawRightString(doc.width + doc.leftMargin, doc.height + doc.topMargin - 15, REPORT_SUBTITLE_STR)

        # Footer
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.grey)
        # Current time using current local time
        current_time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')
        footer_text = f"{REPORT_SUBTITLE_STR} | Version: {REPORT_VERSION} | Report Generated: {current_time_str} | Page {doc.page}"
        canvas.drawCentredString(A4[0] / 2.0, 0.75 * inch, footer_text)
        canvas.restoreState()

    # ---------------- JSON & CSV helpers ---------------- #

    def export_to_json(
        self, data: List[Dict[str, Any]], filename: str
    ) -> Optional[str]:
        output_path = os.path.join(self.reports_dir, filename)
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            logger.info("Exported JSON -> %s", output_path)
            return output_path
        except Exception as e:
            logger.error("JSON export failed: %s", e, exc_info=True)
            return None

    def export_to_csv(
        self, data: List[Dict[str, Any]], filename: str
    ) -> Optional[str]:
        if not data:
            logger.warning("CSV export skipped (%s): empty dataset", filename)
            return None

        output_path = os.path.join(self.reports_dir, filename)
        try:
            # Flatten dictionary for CSV if 'details' is nested
            flattened_data = []
            for item in data:
                flat_item = item.copy()
                details = flat_item.pop('details', {})
                for k, v in details.items():
                    # Handle lists in details, e.g., if a detail field is a list of items
                    if isinstance(v, list):
                        flat_item[f'details_{k}'] = "; ".join(map(str, v))
                    else:
                        flat_item[f'details_{k}'] = v
                
                # Handle recommendations list
                recommendations = flat_item.pop('recommendations', [])
                if recommendations:
                    flat_item['recommendations'] = "; ".join(recommendations)
                
                flattened_data.append(flat_item)

            if not flattened_data:
                logger.warning("CSV export skipped (%s): empty flattened dataset", filename)
                return None
                
            fieldnames = list(flattened_data[0].keys())
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(flattened_data)
            logger.info("Exported CSV -> %s", output_path)
            return output_path
        except Exception as e:
            logger.error("CSV export failed: %s", e, exc_info=True)
            return None

    # ---------------- Chart helpers ---------------- #

    def _create_fair_chart(
        self, fair_results: List[Dict[str, Union[str, float]]]
    ) -> Optional[io.BytesIO]:
        if not fair_results:
            return None

        df = pd.DataFrame(fair_results)
        # Filter out "Base" incidents from the chart, as they can skew visualization
        df_actual = df[~df['incident_type'].str.contains(r' \(Base\)', regex=True)].copy()
        
        # FIX: Use the 'Expected_Annual_Loss_Exposure' key returned by FairEngine for plotting the mean/expected value.
        df_actual = df_actual.dropna(subset=["Expected_Annual_Loss_Exposure"])
        df_actual = df_actual[df_actual["Expected_Annual_Loss_Exposure"] > 0]
        if df_actual.empty:
            return None

        # Handle potentially very large numbers by converting to millions/billions for readability if scale is huge
        max_loss = df_actual["Expected_Annual_Loss_Exposure"].max()
        scale_factor = 1
        unit = "USD"
        if max_loss >= 1_000_000_000:
            scale_factor = 1_000_000_000
            unit = "Billion USD"
        elif max_loss >= 1_000_000:
            scale_factor = 1_000_000
            unit = "Million USD"
        
        # New scaled column name using the correct key
        df_actual["Loss_Scaled"] = df_actual["Expected_Annual_Loss_Exposure"] / scale_factor
        # Use raw string for regex pattern in replace
        df_actual['incident_type_clean'] = df_actual['incident_type'].str.replace(r' \(Actual\)', '', regex=True)


        df_actual = df_actual.sort_values("Loss_Scaled", ascending=False)

        plt.figure(figsize=(11, 7)) # Adjust figure size for landscape A4 and ensure title fits
        
        disparity = (
            df_actual["Loss_Scaled"].max()
            / df_actual["Loss_Scaled"].min()
        ) if not df_actual["Loss_Scaled"].min() == 0 else float('inf')

        ax = sns.barplot(
            x="Loss_Scaled", # Use the scaled Expected Loss
            y="incident_type_clean",
            data=df_actual,
            palette="viridis",
            hue="incident_type_clean", # Added hue to fix FutureWarning
            legend=False # Added legend=False to prevent a redundant legend
        )
        if disparity > 100 or df_actual["Loss_Scaled"].min() < 1e-3: # Use log scale if disparity is high
            plt.xscale("log")
            plt.xlabel(f"Annual Expected Loss (Log {unit})", fontsize=12)
        else:
            plt.xlabel(f"Annual Expected Loss ({unit})", fontsize=12)

        plt.title("Annual Expected Loss by Incident Type (FAIR)", fontsize=14, pad=20) # Added padding
        plt.ylabel("Incident Type")
        plt.tight_layout(rect=[0, 0, 1, 0.95]) # Adjust layout to prevent title cutoff
        
        buf = io.BytesIO()
        plt.savefig(buf, format="png", bbox_inches="tight")
        plt.close()
        buf.seek(0)
        return buf

    def _create_incident_type_pie_chart(self, incidents: List[Dict[str, Any]]) -> Optional[io.BytesIO]:
        if not incidents:
            return None
        
        incident_df = pd.DataFrame(incidents)
        incident_counts = incident_df['type'].value_counts()

        if incident_counts.empty:
            return None

        plt.figure(figsize=(8, 8))
        # Create an "Others" slice for small percentages to improve readability
        threshold = 0.03 # Group types that are less than 3% into 'Others'
        total = incident_counts.sum()
        
        # Filter for major categories and aggregate others
        major_counts = incident_counts[incident_counts / total >= threshold]
        minor_counts_sum = incident_counts[incident_counts / total < threshold].sum()

        if minor_counts_sum > 0:
            labels = major_counts.index.tolist() + ['Others']
            sizes = major_counts.tolist() + [minor_counts_sum]
        else:
            labels = major_counts.index.tolist()
            sizes = major_counts.tolist()

        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, pctdistance=0.85, wedgeprops=dict(width=0.4))
        plt.title("Distribution of Detected Incident Types", fontsize=14)
        plt.axis('equal') # Equal aspect ratio ensures that pie is drawn as a circle.
        plt.tight_layout()
        
        buf = io.BytesIO()
        plt.savefig(buf, format="png", bbox_inches="tight")
        plt.close()
        buf.seek(0)
        return buf

    def _create_incident_timeline_chart(self, incidents: List[Dict[str, Any]]) -> Optional[io.BytesIO]:
        if not incidents:
            return None

        df = pd.DataFrame(incidents)
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df.dropna(subset=['timestamp'], inplace=True)
        if df.empty:
            return None

        df['time_of_day'] = df['timestamp'].dt.hour + df['timestamp'].dt.minute / 60 # Convert to float for histogram
        
        plt.figure(figsize=(11, 4))
        sns.histplot(df['time_of_day'], bins=24, kde=False, color='skyblue')
        plt.title('Incident Frequency Throughout the Day', fontsize=14)
        plt.xlabel('Hour of Day (24-hour format)', fontsize=12)
        plt.ylabel('Number of Incidents', fontsize=12)
        plt.xticks(range(0, 24)) # Ensure all 24 hours are represented on x-axis
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.tight_layout()

        buf = io.BytesIO()
        plt.savefig(buf, format="png", bbox_inches="tight")
        plt.close()
        buf.seek(0)
        return buf


    # ---------------- PDF report ---------------- #

    def generate_pdf_report(
        self,
        incidents: List[Dict[str, Any]],
        fair_results: List[Dict[str, Union[str, float]]],
        filename: str,
    ) -> Optional[str]:
        # Use landscape A4 for better table/chart fitting
        output_path = os.path.join(self.reports_dir, filename)
        doc = SimpleDocTemplate(output_path, pagesize=landscape(A4),
                                rightMargin=inch, leftMargin=inch,
                                topMargin=inch, bottomMargin=inch)
        
        # Define the page template with header/footer
        # 'normal' frame takes full page space minus margins
        frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height,
                      id='normal')
        doc.addPageTemplates([
            PageTemplate(id='FirstPage', frames=frame, onPage=self._header_footer),
            PageTemplate(id='LaterPages', frames=frame, onPage=self._header_footer)
        ])
        
        story: List[Any] = []

        # ----- Title page -----
        story.append(Paragraph(REPORT_TITLE_STR, self.styles["h1"]))
        story.append(Paragraph(REPORT_SUBTITLE_STR, self.styles["h2"]))
        story.append(Spacer(1, 0.3 * inch))
        story.append(
            Paragraph(
                f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                self.styles["Normal"],
            )
        )
        story.append(
            Paragraph(
                f"Generated by: {ORGANIZATION_NAME} ({REPORT_SUBTITLE_STR} v{REPORT_VERSION})",
                self.styles["Normal"],
            )
        )
        story.append(Spacer(1, 0.7 * inch))
        story.append(Paragraph("Executive Summary", self.styles["h2"]))
        story.append(
            Paragraph(
                """This report provides a daily cybersecurity risk assessment using the FAIR model,
                offering quantitative insight into potential financial exposure from detected security incidents.
                It aims to facilitate informed decision-making for risk mitigation and resource allocation.""",
                self.styles["Normal"],
            )
        )
        story.append(Spacer(1, 0.2 * inch))
        story.append(Paragraph("Key Findings:", self.styles["h3"]))
        if incidents:
            incident_types_counts = pd.DataFrame(incidents)["type"].value_counts()
            story.append(Paragraph(f"• A total of <b>{len(incidents)}</b> security incidents were detected, categorized into {len(incident_types_counts)} distinct types.", self.styles["Normal"]))
            top_incident_type = incident_types_counts.index[0]
            top_incident_count = incident_types_counts.iloc[0]
            story.append(Paragraph(f"• The most prevalent incident type was <b>{top_incident_type}</b>, accounting for <b>{top_incident_count}</b> occurrences.", self.styles["Normal"]))
            
            # Find the incident type with highest Risk_Range_Max for executive summary
            if fair_results:
                fair_df = pd.DataFrame(fair_results)
                # Filter out base cases for this summary
                fair_df_actual = fair_df[~fair_df['incident_type'].str.contains(r' \(Base\)', regex=True)].copy()
                
                # FIX: Change key to the correct one (Risk_Range_Max)
                fair_df_actual['Risk_Range_Max'] = pd.to_numeric(fair_df_actual['Risk_Range_Max'], errors='coerce')
                fair_df_actual.dropna(subset=['Risk_Range_Max'], inplace=True)
                
                if not fair_df_actual.empty:
                    # Find the row with the maximum value of the risk range (highest exposure)
                    max_loss_row = fair_df_actual.loc[fair_df_actual['Risk_Range_Max'].idxmax()]
                    # Ensure incident_type is cleaned for display
                    clean_incident_type = str(max_loss_row['incident_type']).replace(' (Actual)', '')
                    # Report the maximum loss (Risk_Range_Max)
                    story.append(Paragraph(f"• The highest estimated annual financial exposure is projected from <b>{clean_incident_type}</b>, with a maximum annual loss of <b>${max_loss_row['Risk_Range_Max']:,.0f}</b>.", self.styles["Normal"]))
        else:
            story.append(Paragraph("• No security incidents were detected during this reporting period.", self.styles["Normal"]))
        
        story.append(PageBreak())

        # ----- Incident summary and charts -----
        story.append(Paragraph("1. Detected Security Incidents", self.styles["h2"]))
        story.append(Spacer(1, 0.15 * inch))

        if incidents:
            # Pie Chart
            pie_chart_buf = self._create_incident_type_pie_chart(incidents)
            if pie_chart_buf:
                story.append(Paragraph("Distribution of Detected Incident Types", self.styles["h3"]))
                img = Image(pie_chart_buf)
                img.drawWidth = 5 * inch
                img.drawHeight = 5 * inch
                story.append(img)
                story.append(Spacer(1, 0.1 * inch))

            # Timeline Chart
            timeline_chart_buf = self._create_incident_timeline_chart(incidents)
            if timeline_chart_buf:
                story.append(Paragraph("Incident Frequency Throughout the Day", self.styles["h3"]))
                img = Image(timeline_chart_buf)
                # Adjust size to fit landscape A4
                img.drawWidth = 8 * inch
                img.drawHeight = img.drawWidth * (4/11) # Maintain aspect ratio from figsize=(11,4)
                story.append(img)
                story.append(Spacer(1, 0.1 * inch))

            counts_df = pd.DataFrame(incidents)["type"].value_counts().reset_index()
            counts_df.columns = ["Incident Type", "Count"]
            data = [list(counts_df.columns)] + counts_df.values.tolist()

            story.append(Paragraph("Summary of Incident Counts by Type", self.styles["h3"]))
            table = Table(data)
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor('#4A708B')), # Darker blue-grey
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor('#E0FFFF')), # Light cyan
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor('#8B8878')), # Muted grid color
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ]
                )
            )
            story.append(table)
            story.append(Spacer(1, 0.15 * inch))

            story.append(Paragraph("Chronological Summary of Top 10 Detected Security Incidents", self.styles["h3"]))
            for idx, inc in enumerate(incidents[:10], 1):
                story.append(
                    Paragraph(f"<b>{idx}. Type:</b> {inc.get('type', 'N/A')}", self.styles["Normal"])
                )
                # Apply severity color style
                severity_style_name = f"Severity{inc.get('severity', 'Low')}"
                severity_style = self.styles.get(severity_style_name, self.styles["Normal"])
                # Corrected: Use .hexval() to get the hex string of the color object
                story.append(
                    Paragraph(f"<b>Severity:</b> <font color='{severity_style.textColor.hexval()}'>{inc.get('severity', 'N/A')}</font>", self.styles["Normal"])
                )
                story.append(
                    Paragraph(f"<b>Datetime:</b> {inc.get('timestamp', 'N/A')}", self.styles["Normal"])
                )
                story.append(
                    Paragraph(f"<b>Source:</b> {inc.get('source', 'N/A')}", self.styles["Normal"])
                )
                
                # Display relevant details from the 'details' dictionary
                details = inc.get('details', {})
                if details:
                    story.append(Paragraph("<b>Details:</b>", self.styles["Normal"]))
                    for k, v in details.items():
                        # Special handling for 'message' and 'first_event_message'
                        if k == 'message' or k == 'first_event_message': # Handle both new grouped messages and original messages
                            msg_content = str(v).replace("\n", " ").replace("\r", " ")
                            if msg_content:
                                story.append(Paragraph(f"  <b>Message:</b> {msg_content}", self.styles["LongText"]))
                        elif k == 'matched_pattern':
                             story.append(Paragraph(f"  <b>Matched Pattern:</b> <i>{v}</i>", self.styles["CodeSnippet"]))
                        elif isinstance(v, list): # Handle list values in details
                            story.append(Paragraph(f"  <b>{k}:</b> {', '.join(map(str, v))}", self.styles["Normal"]))
                        else:
                            story.append(Paragraph(f"  <b>{k}:</b> {v}", self.styles["Normal"]))
                
                # Display recommendations for the incident if available
                recommendations = inc.get('recommendations', [])
                if recommendations:
                    story.append(Paragraph("<b>Recommendations for this Incident:</b>", self.styles["Normal"]))
                    for rec in recommendations:
                        story.append(Paragraph(f"  • {rec}", self.styles["Normal"]))

                story.append(Spacer(1, 0.05 * inch))
                story.append(Paragraph("-" * 150, self.styles["Normal"])) # Extended separator for landscape
                story.append(Spacer(1, 0.05 * inch))
            if len(incidents) > 10:
                story.append(
                    Paragraph(f"... and {len(incidents) - 10} more incidents.", self.styles["Normal"])
                )
            story.append(PageBreak())
        else:
            story.append(
                Paragraph(
                    "No security incidents were detected in the provided logs for this reporting period.",
                    self.styles["Normal"],
                )
            )
            story.append(PageBreak())

        # ----- FAIR results -----
        story.append(Paragraph("2. FAIR Risk Analysis Results", self.styles["h2"]))
        story.append(Spacer(1, 0.15 * inch))

        if fair_results:
            # Sort fair_results to show "Actual" incidents first, then "Base"
            fair_results.sort(key=lambda x: (x['incident_type'].endswith('(Base)'), x.get('Risk_Range_Max', 0)), reverse=True) # FIX: Use Risk_Range_Max for sorting

            # FIX: Simplified Headers to match available output from FairEngine
            headers = [
                "Incident Type",
                "Count",
                "Expected Annual Loss (Mean)", # Key: Expected_Annual_Loss_Exposure
                "Annual Loss Min (P5)",        # Key: Risk_Range_Min
                "Annual Loss Max (P95)",       # Key: Risk_Range_Max
                "Simulations Run",             # Key: Simulations_Run
            ]
            # Adjusted column widths for landscape A4
            col_widths = [
                2.5 * inch, # Incident Type (increased)
                0.8 * inch, # Count
                2.0 * inch, # Expected Annual Loss (Mean)
                2.0 * inch, # Annual Loss Min (P5)
                2.0 * inch, # Annual Loss Max (P95)
                1.5 * inch  # Simulations Run
            ]
            rows = [headers]
            for r in fair_results:
                rows.append(
                    [
                        r.get("incident_type", "N/A"),
                        f"{r.get('incident_count', 0)}",
                        # FIX: Use the correct keys from fair_engine.py output
                        f"${r.get('Expected_Annual_Loss_Exposure', 0):,.0f}", 
                        f"${r.get('Risk_Range_Min', 0):,.0f}",
                        f"${r.get('Risk_Range_Max', 0):,.0f}",
                        f"{r.get('Simulations_Run', 0):,}",
                    ]
                )

            fair_table = Table(rows, colWidths=col_widths)
            fair_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor('#4A708B')),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor('#E0FFFF')),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor('#8B8878')),
                        ("FONTSIZE", (0, 0), (-1, -1), 7),
                        ("VALIGN", (0,0), (-1,-1), "MIDDLE"), # Vertical align middle
                    ]
                )
            )
            story.append(fair_table)
            story.append(Spacer(1, 0.4 * inch))

            chart_buf = self._create_fair_chart(fair_results)
            if chart_buf:
                story.append(Paragraph("Annual Expected Loss by Incident Type (FAIR)", self.styles["h3"]))
                img = Image(chart_buf)
                avail_width = landscape(A4)[0] - 2 * inch # Page width minus margins
                avail_height = landscape(A4)[1] - 4 * inch # Page height minus top/bottom content
                
                # Scale image to fit within available space while maintaining aspect ratio
                ar = img.imageHeight / img.imageWidth
                if (avail_width * ar) <= avail_height:
                    img.drawWidth = avail_width
                    img.drawHeight = avail_width * ar
                else:
                    img.drawHeight = avail_height
                    img.drawWidth = avail_height / ar
                
                story.append(img)
                story.append(Spacer(1, 0.2 * inch))
            story.append(PageBreak())
        else:
            story.append(Paragraph("No FAIR data available for analysis.", self.styles["Normal"]))
            story.append(PageBreak())

        # ----- Recommendations -----
        story.append(Paragraph("3. General Security Recommendations", self.styles["h2"]))
        story.append(Spacer(1, 0.15 * inch))
        recs = [
            (
                "Failed Login Attempts",
                "Implement account lockout policies, enforce multi-factor authentication (MFA) on all critical accounts, and continuously monitor authentication logs for brute-force or credential stuffing attacks.",
            ),
            (
                "Privilege Escalation",
                "Apply the principle of least privilege, regularly review user and group permissions, and deploy Privileged Access Management (PAM) solutions to control and monitor privileged accounts.",
            ),
            (
                "Suspicious Process Activity",
                "Utilize Endpoint Detection and Response (EDR) or Extended Detection and Response (XDR) solutions. Implement behavior-based monitoring for unusual process execution and ensure security signatures are kept up-to-date.",
            ),
            (
                "Malware Execution",
                "Ensure Antivirus/Endpoint Protection platforms are up-to-date across all endpoints. Conduct regular user training on phishing and social engineering. Implement application whitelisting to prevent unauthorized software execution.",
            ),
            (
                "Data Exfiltration Attempts",
                "Deploy Data Loss Prevention (DLP) solutions to prevent unauthorized data transfers. Monitor outbound network traffic for anomalies and unusual data volumes. Encrypt sensitive data at rest and in transit.",
            ),
        ]
        story.append(Paragraph("The following general recommendations are provided based on common incident types:", self.styles["Normal"]))
        for inc_type, rec in recs:
            story.append(Paragraph(f"• {inc_type}: {rec}", self.styles["Normal"]))
        story.append(Spacer(1, 0.3 * inch))
        story.append(
            Paragraph(
                "<b>Note:</b> These recommendations are general guidelines and should be adapted to your organization’s specific security posture, risk appetite, and technical environment.",
                self.styles["Normal"],
            )
        )
        # Legal Notice/Confidentiality
        story.append(Spacer(1, 0.5 * inch))
        story.append(Paragraph("<b>Confidentiality Notice:</b> This report contains sensitive security information and should be handled with appropriate confidentiality. Unauthorized disclosure is prohibited.", self.styles["FooterStyle"]))


        # ----- Build PDF -----
        try:
            doc.build(story)
            logger.info("Generated PDF -> %s", output_path)
            return output_path
        except Exception as e:
            logger.error("PDF generation failed: %s", e, exc_info=True)
            return None