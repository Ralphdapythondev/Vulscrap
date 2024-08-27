# VulnWatch Sentinel

**Author:** Ralph  
**Date:** `August 26, 2024`

## Introduction

The **VulnWatch Sentinel** is a Python-based web scraping tool built with Streamlit. It is designed to extract and process vulnerability data from various sources, providing real-time updates, visualization, and data export features. This tool integrates advanced functionalities like logging, retry mechanisms, asynchronous processing, database storage, and email notifications.

## Key Features

### 1. Logging and Error Handling
- The tool utilizes Python's `logging` module to provide detailed logs of the scraping process.
- Errors and exceptions are captured and reported to ensure the tool's robustness.

### 2. Retry Mechanism
- Implemented using `requests.adapters.HTTPAdapter` and `requests.packages.urllib3.util.retry.Retry`.
- Handles unreliable or slow sources by retrying requests, ensuring data is fetched even if the first attempt fails.

### 3. Asynchronous Processing
- Uses `asyncio` and `aiohttp` for asynchronous HTTP requests.
- Improves the efficiency and speed of the scraping process by fetching data from multiple sources concurrently.

### 4. Enhanced User Interface
- Built with Streamlit, allowing users to:
  - Select data sources.
  - Visualize data using `plotly.express`.
  - Filter vulnerabilities by various criteria.
- The interface is intuitive and user-friendly.

### 5. Database Integration
- Scraped vulnerabilities are stored in a SQLite database (`vulnerabilities.db`).
- Allows for persistent storage and historical data analysis.

### 6. Notifications
- Includes an email notification system that alerts users when new vulnerabilities are detected.
- Useful for keeping security teams informed in real-time.

## Installation and Setup

### Prerequisites
Ensure you have the following installed:
- Python 3.x
- Pip

### Steps to Set Up

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/Ralphdapythondev/Vulscrap.git
   cd Vulscrap
