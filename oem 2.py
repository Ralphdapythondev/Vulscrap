import requests
from bs4 import BeautifulSoup
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

# List of OEM URLs to be monitored
oem_urls = [
    "https://example-oem.com/security/vulnerabilities",  # Replace with actual OEM URLs
    "https://another-oem.com/security-advisories"
]

# Predefined email addresses for reporting
recipient_emails = ["security@example.com"]

# Function to scrape vulnerability information
def scrape_vulnerabilities(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, "lxml")
    
    vulnerabilities = []

    # Example scraping logic (varies by website structure)
    for item in soup.find_all("div", class_="vulnerability-item"):
        severity = item.find("span", class_="severity").text
        if severity.lower() in ["critical", "high"]:
            vuln_id = item.find("a", class_="vuln-id").text
            product = item.find("div", class_="affected-product").text
            description = item.find("div", class_="vuln-description").text
            mitigation = item.find("div", class_="vuln-mitigation").text
            pub_date = item.find("div", class_="publication-date").text
            source = url
            
            vulnerabilities.append({
                "Vulnerability ID": vuln_id,
                "Severity": severity,
                "Affected Product": product,
                "Description": description,
                "Mitigation": mitigation,
                "Publication Date": pub_date,
                "Source": source
            })
    
    return vulnerabilities

# Function to send an email report
def send_email_report(vulnerabilities):
    subject = "Critical/High Severity Vulnerabilities Report"
    body = "Attached is the latest report of Critical and High severity vulnerabilities."
    
    message = MIMEMultipart()
    message["From"] = "no-reply@example.com"
    message["To"] = ", ".join(recipient_emails)
    message["Subject"] = subject
    
    message.attach(MIMEText(body, "plain"))
    
    # Create the report content
    report_content = "Vulnerability Report:\n\n"
    for vuln in vulnerabilities:
        report_content += f"Vulnerability ID: {vuln['Vulnerability ID']}\n"
        report_content += f"Severity: {vuln['Severity']}\n"
        report_content += f"Affected Product: {vuln['Affected Product']}\n"
        report_content += f"Description: {vuln['Description']}\n"
        report_content += f"Mitigation: {vuln['Mitigation']}\n"
        report_content += f"Publication Date: {vuln['Publication Date']}\n"
        report_content += f"Source: {vuln['Source']}\n\n"
    
    # Attach the report
    report = MIMEText(report_content)
    report_filename = "Vulnerability_Report.txt"
    report.add_header("Content-Disposition", f"attachment; filename={report_filename}")
    message.attach(report)
    
    # Send the email via SMTP
    with smtplib.SMTP("smtp.example.com", 587) as server:
        server.starttls()
        server.login("your-email@example.com", "your-password")
        server.send_message(message)
    print(f"Email sent to {', '.join(recipient_emails)}")

# Main function to run the web scraper and send reports
def main():
    all_vulnerabilities = []
    
    for url in oem_urls:
        vulnerabilities = scrape_vulnerabilities(url)
        all_vulnerabilities.extend(vulnerabilities)
    
    if all_vulnerabilities:
        send_email_report(all_vulnerabilities)
    else:
        print("No Critical or High severity vulnerabilities found.")

if __name__ == "__main__":
    main()
