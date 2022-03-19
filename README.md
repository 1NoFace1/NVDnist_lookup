# NVDnist_lookup
A simple python script for locating software CVE's and exporting them as a csv file.

# Dependencies
- requests
- bs4
- re

# Summary
Identifies common vulnerabilities from a comma separated list of software utilizing https://nvd.nist.gov/vuln/search and exports results as a simple csv file.

# Expected Input
A comma separated list utilizing one of the following formats:
- CPE v2.3
- Product Version (i.e. SWAMP 1.2.6)
- Vendor Product Version (i.e. jenkins SWAMP 1.2.6)
- Target_SW Product "plugin" Version (i.e. Jenkins SWAMP plugin 1.2.6)

# Expected Outputs
A csv file containing the following columns for each CVE identified.
