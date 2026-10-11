"""
Master PDF Compiler for AgentBreak V2 Technical Guide.
Assembles all 14 chapters, attaches the live dashboard screenshot,
builds the PDF document using NumberedCanvas, and verifies output.
"""

import os
import sys
import shutil
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate

from generate_guide_base import setup_styles, NumberedCanvas
from pdf_chapters_1_3 import build_cover_and_toc, build_chapter_1, build_chapter_2, build_chapter_3
from pdf_chapters_4_7 import build_chapter_4, build_chapter_5, build_chapter_6, build_chapter_7
from pdf_chapters_8_11 import build_chapter_8, build_chapter_9, build_chapter_10, build_chapter_11
from pdf_chapters_12_14 import build_chapter_12, build_chapter_13, build_chapter_14

def main():
    print("=" * 70)
    print("STARTING COMPILATION: AgentBreak_Complete_Project_Guide.pdf")
    print("=" * 70)
    
    output_filename = "AgentBreak_Complete_Project_Guide.pdf"
    output_path = os.path.abspath(output_filename)
    
    styles = setup_styles()
    
    # Check screenshot
    screenshot_path = r"C:\Users\Rohit Patil\.gemini\antigravity-ide\brain\6de05c25-8bf5-492f-a642-61c47fd00643\dashboard_light_mode_1791689399601.png"
    if not os.path.exists(screenshot_path):
        print(f"Notice: Screenshot path does not exist: {screenshot_path}")
        screenshot_path = None
    else:
        print(f"Found live dashboard screenshot: {screenshot_path}")

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=45,
        rightMargin=45,
        topMargin=54,
        bottomMargin=54,
        title="AgentBreak V2 - Complete Project Explanation & Defense Guide",
        author="Rohit Patil & ByteForge Team",
        subject="AI Agent Security Testing, Guard Validation, and Adversarial Assurance",
        creator="ReportLab 5.0.1 Document Template"
    )

    story = []

    print("Building Cover & Table of Contents...")
    story.extend(build_cover_and_toc(styles))

    print("Building Chapter 1: Project Foundations & Core Mission...")
    story.extend(build_chapter_1(styles))

    print("Building Chapter 2: Complete Website Walkthrough & UI Guide...")
    story.extend(build_chapter_2(styles, screenshot_path))

    print("Building Chapter 3: Deep Dive into the 4 Security Attacks...")
    story.extend(build_chapter_3(styles))

    print("Building Chapter 4: Defense Mechanisms D1, D2, and D3...")
    story.extend(build_chapter_4(styles))

    print("Building Chapter 5: The Adaptive Adversarial Engine...")
    story.extend(build_chapter_5(styles))

    print("Building Chapter 6: Deterministic Security Analyzer & Verdicts...")
    story.extend(build_chapter_6(styles))

    print("Building Chapter 7: Source Code & System Architecture...")
    story.extend(build_chapter_7(styles))

    print("Building Chapter 8: Dashboard Metrics & Counting Formulas...")
    story.extend(build_chapter_8(styles))

    print("Building Chapter 9: Evidence Integrity & SHA-256 Hash Chain...")
    story.extend(build_chapter_9(styles))

    print("Building Chapter 10: The Security Assessment Report...")
    story.extend(build_chapter_10(styles))

    print("Building Chapter 11: Complete Hackathon Demonstration Guide...")
    story.extend(build_chapter_11(styles))

    print("Building Chapter 12: Hackathon Judge Preparation & 22 Questions...")
    story.extend(build_chapter_12(styles))

    print("Building Chapter 13: Project Limitations, Testing & Future Roadmap...")
    story.extend(build_chapter_13(styles))

    print("Building Chapter 14: PDF Design & Publishing Specifications...")
    story.extend(build_chapter_14(styles))

    print(f"Assembling flowables into PDF canvas ({len(story)} flowable elements)...")
    doc.build(story, canvasmaker=NumberedCanvas)

    if os.path.exists(output_path):
        size_kb = os.path.getsize(output_path) / 1024
        print(f"SUCCESS: Generated {output_path} ({size_kb:.1f} KB)")
        
        # Copy to workspace root as well
        workspace_root = os.path.abspath("..")
        workspace_copy = os.path.join(workspace_root, output_filename)
        try:
            shutil.copy2(output_path, workspace_copy)
            print(f"Copied backup to workspace root: {workspace_copy}")
        except Exception as e:
            print(f"Could not copy to workspace root: {e}")
            
    else:
        print("ERROR: Output PDF was not created!")
        sys.exit(1)

if __name__ == "__main__":
    main()
