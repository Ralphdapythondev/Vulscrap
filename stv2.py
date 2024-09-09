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
import json

# Google News URL
NEWS_URL = 'https://news.google.com/topics/CAAqJggKIiBDQkFTRWdvSUwyMHZNRFZxYUdjU0FtVnpHZ0pGVXlnQVAB?hl=es&gl=ES&ceid=ES%3Aes'

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

# News fetching function
def fetch_news():
    try:
        response = requests.get(NEWS_URL)
        response.raise_for_status()  # Ensure the request was successful
        soup = BeautifulSoup(response.content, 'html.parser')
        news_items = []

        # Loop through each article and extract details
        for article in soup.find_all('article'):
            title = article.get_text()
            link = article.find('a')['href']
            image = article.find('img')['srcset'] if article.find('img') else None

            news_items.append({
                'title': title,
                'link': f'https://news.google.com{link}',
                'image': image
            })

        # Convert list of news items to JSON and return it
        return news_items

    except requests.RequestException as e:
        logging.error(f"Error fetching news: {e}")
        return []

# Function to display news in Streamlit
def display_news(news_items):
    st.header("Latest News from Google")
    for news in news_items:
        st.subheader(news['title'])
        st.write(f"[Read more]({news['link']})")
        if news['image']:
            st.image(news['image'], use_column_width=True)

# Existing CVE scraping code here (extract_vulnerabilities, save_to_database, etc.)

def main():
    st.set_page_config(page_title="VulnWatch Sentinel + News", layout="wide")
    st.title("VulnWatch Sentinel + Latest News")
    st.write("This tool scrapes vulnerabilities from multiple sources and provides real-time updates, along with the latest news from Google.")

    st.sidebar.header("Settings")
    st.sidebar.write("Select the sources you want to scrape vulnerabilities from:")
    selected_sources = st.sidebar.multiselect(
        "Sources",
        list(URLS.keys()),
        default=list(URLS.keys())
    )

    # Fetch and display the news
    news_items = fetch_news()
    if news_items:
        display_news(news_items)
    else:
        st.warning("No news available at this time.")

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
