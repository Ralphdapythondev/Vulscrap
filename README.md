Here’s the updated `.md` file content for your project:

---

# VulnWatch Sentinel

**Author:** Ralph  
**Date:** August 26, 2024

## Introduction

**VulnWatch Sentinel** is a Python-based web scraping tool designed to extract and process vulnerability data from various sources. Built with Streamlit, this tool offers real-time updates, data visualization, and export features. It incorporates advanced functionalities like logging, retry mechanisms, asynchronous processing, database storage, and email notifications to ensure robust and efficient operation.

## Key Features

### 1. Logging and Error Handling
- Utilizes Python's `logging` module to provide detailed logs of the scraping process.
- Captures and reports errors and exceptions to maintain the tool's reliability.

### 2. Retry Mechanism
- Implemented using `requests.adapters.HTTPAdapter` and `requests.packages.urllib3.util.retry.Retry`.
- Ensures data retrieval by retrying requests for unreliable or slow sources, even if the first attempt fails.

### 3. Asynchronous Processing
- Uses `asyncio` and `aiohttp` for non-blocking HTTP requests.
- Enhances efficiency by allowing concurrent data fetching from multiple sources.

### 4. Enhanced User Interface
- Streamlit-based UI allows users to:
  - Select data sources.
  - Visualize data using `plotly.express`.
  - Filter vulnerabilities by various criteria.
- The interface is designed to be intuitive and user-friendly.

### 5. Database Integration
- Stores scraped vulnerabilities in a SQLite database (`vulnerabilities.db`).
- Enables persistent storage and facilitates historical data analysis.

### 6. Notifications
- Includes an email notification system that alerts users when new vulnerabilities are detected.
- Helps keep security teams informed in real-time.

## Installation and Setup

### Prerequisites
Ensure the following are installed:
- Python 3.x
- Pip

### Steps to Set Up

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/Ralphdapythondev/Vulscrap.git
   cd Vulscrap
   ```

2. **Install Required Packages:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Streamlit App:**
   ```bash
   streamlit run vulnwatch_sentinel.py
   ```

### Usage

- **Start the Scraper:** Use the Streamlit interface to select sources, start scraping, and monitor the process.
- **Visualize Data:** View the scraped data in tables or visualize it through interactive charts.
- **Download Data:** Export the scraped data to a CSV file for further analysis.

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Open a Pull Request.
