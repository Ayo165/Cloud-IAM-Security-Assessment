# Cloud & IAM Security Assessment

## 📝 Objective
This project demonstrates the ability to audit a cloud environment for critical misconfigurations. The primary goal was to take a intentionally vulnerable cloud setup, hunt for over-permissioned Identity and Access Management (IAM) roles and publicly exposed storage buckets, and document the remediation steps necessary to secure the environment.

## 🛠️ Tools & Technologies Used
*   **Cloud Provider:** Amazon Web Services (AWS Free Tier)
*   **Security Automation:** Python (`boto3` library)
*   **Command Line:** AWS CLI
*   **Concepts:** Identity and Access Management (IAM), Principle of Least Privilege (PoLP), Cloud Storage Security

## 🗺️ Assessment Process & Findings

### 1. Misconfiguration Hunting (Automated Auditing)
Instead of manually clicking through the cloud console, I developed a custom Python automation script (`cloud_iam_audit.py`) using the AWS SDK to systematically audit the environment. The script executes two main functions:
*   **Storage Auditing:** Queries the Public Access Block configuration of all S3 buckets to identify storage exposing sensitive data to the public internet.
*   **IAM Auditing:** Enumerates all IAM users and their attached policies to flag any accounts with direct `AdministratorAccess`, which violates the principle of least privilege.

### 2. Privilege Escalation Simulation
During the audit, I identified a vulnerable IAM user role that lacked strict resource boundaries. By analyzing the JSON policy document, I demonstrated how an attacker compromising this low-level account could potentially assign themselves higher privileges (Privilege Escalation) to take full control over the cloud environment.

### 3. Remediation & Hardening
Following the discovery of the misconfigurations, I engineered a remediation plan to secure the architecture:
*   **S3 Buckets:** Applied `Block Public Access` settings at the account level and modified bucket policies to restrict access only to authorized internal VPC endpoints.
*   **IAM Roles:** Stripped direct administrator policies from individual user accounts. Re-architected the access model by creating distinct IAM Groups with strict, task-specific JSON policies, moving all users into these groups to enforce Least Privilege.

## 💡 Conclusion
Cloud security is fundamentally about process optimization and strict access control. By writing custom Python scripts to audit cloud infrastructure, I was able to rapidly identify severe misconfigurations before they could be exploited. This project highlights the critical importance of continuously monitoring IAM policies and ensuring cloud storage defaults are configured securely.
