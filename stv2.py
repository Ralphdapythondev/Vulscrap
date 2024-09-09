from bs4 import BeautifulSoup
import requests, pprint, sys, datetime, re
from argparse import ArgumentParser
import pandas as pd
from pandas import ExcelWriter
import calendar

# Arrays to store scraped data
cveIDNumber = []
summaryText = []
publishDate = []
softwareType = []
vendor = []
product = []
version = []
cvssScore = []
confidentialityImpact = []
integrityImpact = []
availibilityImpact = []
accessComplexity = []
authentication = []
gainedAccess = []
vulnType = []

# Function for parsing command-line arguments
def parse_arguments():
    parser = ArgumentParser(description='A small python script used for scraping the CVE Details website for collating information')
    parser.add_argument('-smin', help='Minimum Severity Rating', default=7)
    parser.add_argument('-smax', help='Maximum Severity Rating', default=10)
    parser.add_argument('-m', help='Month in Number viz 1-12', default=datetime.date.today().month)
    parser.add_argument('-y', help='Year in YYYY', default=datetime.date.today().year)
    args = parser.parse_args()
    return args

# Function to create the URL based on filters
def createFullUrl(smin, smax, year, month, page):
    url = "http://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page=" + str(page) + "&cvssscoremin=" + str(smin) + "&cvssscoremax=" + str(smax) + "&year=" + str(year) + "&month=" + str(month) + "&order=3"
    return url

# Fetch and parse the HTML content
def getSoupHTML(url):
    response = requests.get(url)
    html = response.content
    soup = BeautifulSoup(html, "html.parser")
    return soup

# Extract CVE IDs from the web page
def getCVEIds(soup, cveArray):
    table = soup.find('table', attrs={'class', 'searchresults'})
    for a in table.find_all('a', href=True):
        m = re.search("CVE-\d{4}-\d{4,7}", a['href'])
        if m:
            cveArray.append(m.group(0))

# Handle pagination and collect page URLs
def getCVEPages(soup):
    cveIDPages = []
    items = soup.find_all('div', class_="paging")
    for item in items:
        links = item.find_all('a')
        for link in links:
            cveIDPages.append("http://www.cvedetails.com/" + str(link['href']))
    return cveIDPages

# Get detailed CVE information
def getCVEDetails(cveid):
    cveUrl = 'http://www.cvedetails.com/cve/' + cveid + '/'
    soup = getSoupHTML(cveUrl)
    if not soup:
        return
    cveIDNumber.append(cveid)
    table = soup.find(id='vulnprodstable')
    cvssTable = soup.find(id='cvssscorestable')
    summarySoup = soup.find('div', class_="cvedetailssummary")
    summaryText.append(summarySoup.text.split("\n")[1])
    dateStr = summarySoup.text.split("\n")[3]
    publishDate.append(dateStr.split("\t")[1].split(":")[1])
    
    # Parse product details and CVSS scores
    productData = []
    for row in table.findAll('tr')[::-1]:
        cols = row.findAll('td')
        for i in range(len(cols)):
            productData.append(cols[i].text.strip())
    softwareType.append(productData[1])
    vendor.append(productData[2])
    product.append(productData[3])
    version.append(productData[4])
    
    cvssData = []
    for row in cvssTable.findAll('tr'):
        cols = row.findAll('td')
        for i in range(len(cols)):
            cvssData.append(cols[i].text.strip())
    cvssScore.append(cvssData[0])
    confidentialityImpact.append(cvssData[1].split("\n")[0])
    integrityImpact.append(cvssData[2].split("\n")[0])
    availibilityImpact.append(cvssData[3].split("\n")[0])
    accessComplexity.append(cvssData[4].split("\n")[0])
    authentication.append(cvssData[5].split("\n")[0])
    gainedAccess.append(cvssData[6].split("\n")[0])
    vulnType.append(cvssData[7])

# Write the scraped data into an Excel file
def writeToExcel(fileName):
    print "Writing to Excel File : " + fileName
    data = {'CVE ID Number': cveIDNumber, 'Summary Text': summaryText, 'Publish Date': publishDate, 'Software Type': softwareType, 'Vendor': vendor, 'Product': product, 'Version': version, 'CVSS Score': cvssScore, 'Confidentiality Impact': confidentialityImpact, 'Integrity Impact': integrityImpact, 'Availibility Impact': availibilityImpact, 'Access Complexity': accessComplexity, 'Authentication': authentication, 'Gained Access': gainedAccess, 'Vulnerability Type': vulnType}
    df = pd.DataFrame(data)
    writer = ExcelWriter(fileName)
    df.to_excel(writer, 'CVE Details', index=False)
    writer.save()
    print "Completed."

# Main function to orchestrate the scraping
def main():
    args = parse_arguments()
    month = int(args.m)
    year = int(args.y)
    smin = float(args.smin)
    smax = float(args.smax)
    
    fileName = "Security_Advisory_" + calendar.month_name[month] + "_" + str(year) + ".xlsx"
    fullUrl = createFullUrl(smin, smax, year, month, 1)
    soupObject = getSoupHTML(fullUrl)
    cvePagesArray = getCVEPages(soupObject)
    cveArray = []
    
    # Iterate through pages and get CVE IDs
    for cvePage in cvePagesArray:
        soupObject = getSoupHTML(cvePage)
        getCVEIds(soupObject, cveArray)
    
    count = 0
    # Fetch detailed information for each CVE ID
    for cve in cveArray:
        getCVEDetails(cve)
        count += 1
        print "Getting Details for CVE ID: " + cve + ". Completed " + str(count) + " Out of " + str(len(cveArray))
    
    writeToExcel(fileName)

if __name__ == '__main__':
    main()
