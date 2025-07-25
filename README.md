
# ASVS Assessment Tool

A professional, automated static analysis tool for evaluating application source code against the [OWASP Application Security Verification Standard (ASVS) 5.0](https://owasp.org/www-project-application-security-verification-standard/). Designed for security teams, auditors, and developers, this tool generates a CERT-In style HTML report with summary charts, risk matrix, and actionable recommendations.

## Why Use This Tool?

Modern applications face a wide range of security threats. Ensuring compliance with industry standards like OWASP ASVS is critical for reducing risk, meeting regulatory requirements, and building user trust. Manual reviews are time-consuming and error-prone. This tool automates the assessment process, providing:
- Rapid, repeatable, and objective security verification
- Early detection of vulnerabilities and gaps in security controls
- Actionable recommendations for remediation
- Professional, audit-ready reporting for stakeholders

## Importance of ASVS Assessment Tool

The ASVS Assessment Tool bridges the gap between security standards and real-world codebases. It empowers organizations to:
- Benchmark their application security posture against a globally recognized standard
- Identify and prioritize high-risk areas for improvement
- Demonstrate due diligence to customers, partners, and regulators
- Integrate security into the software development lifecycle (SDLC)

By automating ASVS checks, this tool helps teams achieve higher security assurance with less manual effort, supporting both compliance and continuous improvement.

## Features
- Automated static code analysis mapped to ASVS 5.0 requirements
- Professional HTML report with:
  - Executive Summary, Objective, Scope, Methodology, Technical Summary
  - Interactive summary chart and risk matrix
  - Section-by-section findings with evidence and recommendations
- Fine-tuned pattern matching to minimize false positives
- MIT License

## Usage

### Prerequisites
- Python 3.7+
- Place the ASVS CSV file (`OWASP_Application_Security_Verification_Standard_5.0.0_en.csv`) in the same directory as the tool

### Run the Tool
```
python asvs_assessment_tool.py <source_code_directory> --output <report_file.html>
```
Example:
```
python asvs_assessment_tool.py juice-shop-master --output asvs_full_report.html
```

### Output
- Generates a professional HTML report (`asvs_full_report.html` by default) with summary, risk matrix, and detailed findings.

## Report Sections
- Executive Summary
- Objective
- Scope
- Approach & Methodology
- Technical Summary
- Interactive Summary Chart
- Risk Matrix
- Table of Contents
- Detailed Section-by-Section Findings

## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Contributing
Pull requests and suggestions are welcome! Please open an issue to discuss your ideas or report bugs.

## Author
- Developed by BlackkHawkk

---
For more information on ASVS, visit the [OWASP ASVS Project](https://owasp.org/www-project-application-security-verification-standard/).
