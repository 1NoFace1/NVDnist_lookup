#!/usr/bin/env python
# coding: utf-8
### DESCRIPTION ###
# Inputs: Comma separated list of software packages
# Expected Outputs: CVE, Vulnerability Score
# Written By: Bryant Renfroe
# Date: 3/11/2022

# Currently supported naming formats include:
# [CPE], [Product Version], [Vendor Product Version], [Target_Software Product 'plugin' Version]

# Import libraries
import requests
from bs4 import BeautifulSoup
import re

# Take input from user for software to lookup and parse
def query():
    
    # Request for input
    software = input("Enter the name(s) of the software package(s) to query.\nSeparate multiple packages by with commas.\nSoftware: ")
    
    # Parse input
    software = software.split(',')
    
    # Standardize input format
    for s in software:
        
        # Check if already in CPE format
        if re.match(r'cpe:2.3:a:((.)+:){9}(.)+',s):
            continue
            
        else:
            parse = s.split(" ")
            
            # Target_sw is optional, version and product are not
            target_sw = "*"
            vendor = "*"
                
            # Match product and version where only product and version supplied
            if len(parse) == 2 and re.match(r'([\d]+\.){1,3}[\d]+',parse[-1]):
                product = parse[0]
                version = re.match(r'([\d]+\.){1,3}[\d]+',parse[-1]).group()
                
            # Match vendor, product, and version
            if len(parse) == 3 and re.match(r'([\d]+\.){1,3}[\d]+',parse[-1]):
                vendor = parse[0]
                product = parse[1]
                version = re.match(r'([\d]+\.){1,3}[\d]+',parse[-1]).group()

            # Match product and target_sw where software name includes key word "plugin"
            elif len(parse) == 4 and 'plugin' == str(parse[2]).lower():
                product = parse[1]
                target_sw = parse[0]
                version = re.match(r'([\d]+\.){1,3}[\d]+',parse[-1]).group()
            
            try:
                # Generate CPE
                CPE_criteria = {
                    "CPE_version": "2.3",
                    "part" : "a",
                    "vendor" : vendor,
                    "product" : product,
                    "version" : version,
                    "update" : "*",
                    "edition" : "*",
                    "language" : "*",
                    "sw_edition" : "*",
                    "target_sw" : target_sw,
                    "target_hw" : "*",
                    "other" : "*"
                }
                delim = ":"
                CPE = "cpe:"
                for c in CPE_criteria:
                    CPE = CPE + str(CPE_criteria[c]) + delim
                CPE = CPE[:-1]
            
                software[software.index(s)] = CPE
            except:
                print('Failed to convert "'+str(s)+'" into CPE format. Skipping results for "'+str(s)+'".')
                continue
    
    return software

# Search cvedetails for data
def NVDnist(software):
    print("Searching https://nvd.nist.gov/vuln/search for reported vulnerabilities...")
    results = []
    
    # Iterate through software list
    for s in software:
        
        # Parse CPE
        parse = s.split(":")
        product = parse[4]
        version = parse[5]
        
        # Establish page size and starting position
        pageSize = 20
        index = 0
        
        # Fetch results and determine results
        form = "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query="+str(s).replace(":","%3A")+"&search_type=all&isCpeNameSearch=false"        
        r = requests.get(form)
        soup = BeautifulSoup(r.text,'html.parser')
        records = int(soup.find("strong",attrs={"data-testid":"vuln-matching-records-count"}).string.replace(",",""))
        vulnerabilities = soup.body.find_all("div")[60].div.tbody.find_all("tr")
        
        # Handle no vulnerabilities found
        if records == 0:
            results.append([str(s),'https://nvd.nist.gov/vuln/search','No Results Found','NA','NA','NA'])
            print("No records found for "+str(product)+" "+str(version)+".")
        
        # Status update
        print("Searching "+str(records)+" records for applicable vulnerabilities to "+str(product)+" "+str(version)+".")
        
        # Loop through list of vulnerabilities
        while True:
            
            # Add current page of vulnerabilities to results
            for vuln in vulnerabilities:
                CVE = vuln.strong.a.string
                try:
                    cvss3 = vuln.find('span',attrs={"id":"cvss3-link"}).a.string
                except:
                    cvss3 = "NA"
                try:
                    cvss2 = vuln.find('span',attrs={"id":"cvss2-link"}).a.string
                except:
                    cvss2 = "NA"
                date = vuln.span.string
                summary = vuln.p.string
                results.append([str(s),form,CVE,summary,cvss3,cvss2,date])
                
            # Determine if more results exists
            nextPage = soup.find("a",text=">")
            if nextPage == None:
                break
            else:
                index = index + 1
                newPage = index * pageSize
                r = requests.get(str(form)+"&startIndex="+str(newPage))
                soup = BeautifulSoup(r.text,'html.parser')
                vulnerabilities = soup.body.find_all("div")[60].div.tbody.find_all("tr")
                
    return results

# Export results as csv
def makecsv(results):
    
    # Create the file
    data = "CPE,Source,CVE,Summary,CVSS3,CVSS2,Date Discovered\n"
    delim = ","
    for r in results:
        for x in r:
            data = data + "\""  + str(x) + "\"" +delim
        data = data[:-1] + "\n"
    
    # Write to file
    try:
        with open("Vulnerabilities.csv",'w') as file:
                file.write(data)
                print('Saved results as "Vulnerabilities.csv"')
    except Exception as e:
        print("Failed to save results with the following error message:",e,sep="\n")

# Execute the script
print("### NVDnist_lookup ###\n\
Identify vulnerabilities in software as recorded at https://nvd.nist.gov.")
software = query()
results = NVDnist(software)
makecsv(results)