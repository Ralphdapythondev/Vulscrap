import requests
from bs4 import BeautifulSoup
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import time

# List of OEM URLs to scrape
oem_urls = [
    'https://msrc.microsoft.com/update-guide/',
]

# Keywords to look for in the vulnerability reports
keywords = ['Critical', 'High Severity', 'CVE']

# Email configuration
sender_email = 'calista.jaskolski71@ethereal.email'
receiver_email = 'enquiry.ashwin@outlook.com'
email_password = 'D2kWUJt2H7ET5KDtRw'
smtp_server = 'smtp.ethereal.email'
smtp_port = 587

# Function to send an email
def send_email(subject, body):
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(sender_email, email_password)
        text = msg.as_string()
        server.sendmail(sender_email, receiver_email, text)

# Function to scrape vulnerabilities from an OEM website
def scrape_oem_website(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        # Example logic to find relevant sections - this will vary by site structure
        vulnerability_sections = soup.find_all('div', class_='vulnerability-section')

        for section in vulnerability_sections:
            content = section.get_text()

            # Check for critical or high severity keywords
            if any(keyword in content for keyword in keywords):
                send_email(f'Vulnerability Alert from {url}', content)
                print(f'Alert sent for vulnerability found on {url}')

    except requests.exceptions.RequestException as e:
        print(f"Error accessing {url}: {e}")

# Main function to run the scraper periodically
def main():
    while True:
        for url in oem_urls:
            scrape_oem_website(url)
        
        # Wait for a specified time before the next scrape (e.g., every 6 hours)
        time.sleep(21600)  # 6 hours in seconds

if __name__ == "__main__":
    main()
