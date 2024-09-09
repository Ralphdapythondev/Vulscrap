import logging
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import streamlit as st
import pandas as pd
import sqlite3
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from bs4 import BeautifulSoup
import concurrent.futures
import plotly.express as px

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

URLS = {
    "CISA IT": "https://www.cisa.gov/news-events/bulletins/sb23-100",
    "NVD": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20"
}
OUTPUT_FILE = "vulnerabilities.csv"
DB_NAME = 'vulnerabilities.db'

def requests_retry_session(retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504)):
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def extract_vulnerabilities(url, source):
    try:
        response = requests_retry_session().get(url)
        response.raise_for_status()
        vulnerabilities = []

        if source.startswith("CISA"):
            soup = BeautifulSoup(response.content, "html.parser")
            table = soup.find("table")
            if table:
                rows = table.find_all("tr")[1:]
                for row in rows:
                    cols = row.find_all("td")
                    vulnerability = {
                        "source": source,
                        "product": cols[0].text.split("--")[0].strip(),
                        "vendor": cols[0].text.split("--")[1].strip(),
                        "description": cols[1].text.strip(),
                        "published": cols[2].text.strip(),
                        "cvss": cols[3].text.strip(),
                        "cve": cols[4].find("a").text.strip(),
                        "reference": cols[4].find("a").get("href"),
                        "date": cols[2].text.strip()
                    }
                    vulnerabilities.append(vulnerability)
        elif source == "NVD":
            data = response.json()
            for vuln in data.get('vulnerabilities', []):
                cve = vuln['cve']
                vulnerability = {
                    "source": source,
                    "product": cve.get('affected', [{}])[0].get('product', {}).get('name', 'N/A'),
                    "vendor": cve.get('affected', [{}])[0].get('vendor', {}).get('name', 'N/A'),
                    "description": cve.get('descriptions', [{}])[0].get('value', 'N/A'),
                    "published": cve.get('published', 'N/A'),
                    "cvss": cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A'),
                    "cve": cve.get('id', 'N/A'),
                    "reference": f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}",
                    "date": cve.get('published', 'N/A')
                }
                vulnerabilities.append(vulnerability)

        logging.info(f"Successfully retrieved data from {source}")
        return vulnerabilities

    except requests.RequestException as e:
        logging.error(f"Failed to retrieve data from {source}: {e}")
        st.error(f"Failed to retrieve data from {source}: {e}")
        return []
    except Exception as e:
        logging.error(f"Error while processing {source}: {e}")
        st.error(f"Error while processing {source}: {e}")
        return []

def save_to_database(vulnerabilities, db_name=DB_NAME):
    try:
        conn = sqlite3.connect(db_name)
        df = pd.DataFrame(vulnerabilities)
        df.to_sql('vulnerabilities', conn, if_exists='append', index=False)
        logging.info(f"Data saved to database {db_name}")
    except Exception as e:
        logging.error(f"Failed to save to database: {e}")
    finally:
        conn.close()

def save_to_csv(vulnerabilities, file_path=OUTPUT_FILE):
    try:
        df = pd.DataFrame(vulnerabilities)
        df.to_csv(file_path, index=False)
        logging.info(f"Vulnerabilities saved to {file_path}")
    except Exception as e:
        logging.error(f"Failed to save CSV: {e}")

def plot_vulnerabilities(data):
    fig = px.histogram(data, x="CVSS Score", title="CVSS Score Distribution")
    st.plotly_chart(fig)

def format_vulnerabilities(vulnerabilities):
    df = pd.DataFrame([
        {
            "CVE ID": vuln.get("cve", "N/A"),
            "Product": vuln.get("product", "N/A"),
            "Vendor": vuln.get("vendor", "N/A"),
            "Description": vuln.get("description", "N/A"),
            "Published Date": vuln.get("published", "N/A"),
            "CVSS Score": vuln.get("cvss", "N/A"),
            "Reference": vuln.get("reference", "N/A"),
            "Date": vuln.get("date", "N/A")
        }
        for vuln in vulnerabilities
    ])
   
    # Convert all numeric columns to string to prevent serialization issues
    df['CVSS Score'] = df['CVSS Score'].astype(str)
   
    return df

def main():
    st.set_page_config(page_title="VulnWatch Sentinel", layout="wide")
    st.title("VulnWatch Sentinel")
    st.write("This tool scrapes vulnerabilities from multiple sources and provides real-time updates.")
   
    st.sidebar.header("Settings")
    st.sidebar.write("Select the sources you want to scrape vulnerabilities from:")
    selected_sources = st.sidebar.multiselect(
        "Sources",
        list(URLS.keys()),
        default=list(URLS.keys())
    )

    st.sidebar.write("Click the button to start scraping.")
    if st.sidebar.button("Start Scraping"):
        progress_bar = st.progress(0)
        status_text = st.empty()
       
        source_vulnerabilities = {}
       
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_source = {executor.submit(extract_vulnerabilities, URLS[source], source): source for source in selected_sources}

            for i, future in enumerate(concurrent.futures.as_completed(future_to_source)):
                source = future_to_source[future]
                status_text.text(f"Scraping {source} vulnerabilities...")
                try:
                    vulnerabilities = future.result()
                    source_vulnerabilities[source] = vulnerabilities
                except Exception as exc:
                    st.error(f"{source} generated an exception: {exc}")
                    logging.error(f"{source} generated an exception: {exc}")
               
                progress = (i + 1) / len(selected_sources)
                progress_bar.progress(progress)
       
        all_vulnerabilities = [vuln for vulns in source_vulnerabilities.values() for vuln in vulns]
        save_to_database(all_vulnerabilities)
        save_to_csv(all_vulnerabilities, OUTPUT_FILE)
       
        if all_vulnerabilities:
            st.success(f"Vulnerabilities scraped and saved to {OUTPUT_FILE}")
            st.write("### Extracted Vulnerabilities")
            for source, vulnerabilities in source_vulnerabilities.items():
                if vulnerabilities:
                    st.subheader(f"{source} Vulnerabilities")
                    df = format_vulnerabilities(vulnerabilities)
                    st.dataframe(df)
                    plot_vulnerabilities(df)
                else:
                    st.warning(f"No vulnerabilities found for {source}.")
           
            st.download_button(
                label="Download CSV",
                data=pd.DataFrame(all_vulnerabilities).to_csv(index=False).encode('utf-8'),
                file_name=OUTPUT_FILE,
                mime='text/csv'
            )
        else:
            st.warning("No vulnerabilities found.")

    st.sidebar.info("Supported sources: CISA IT and NVD. More sources may be added in future updates.")

if __name__ == "__main__":
    main()
