# problem with this is that it prints multiple json lists ie
# [{key1, value1}],
# [{key2, value2}]
# can use non relational database
import requests
import json
import time

def output_to_file(cves):
    # Print and format the fetched JSON data

    formatted_json = json.dumps(cves, indent=2)

    with open('output.json', 'a') as f:
        f.write(formatted_json)

def fetch_cve_list(start_index, results_per_page=2000):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
    params = {
        "resultsPerPage": results_per_page,
        "startIndex": start_index
    }

    try:
        response = requests.get(base_url, params=params)
        response.raise_for_status()  # Check for HTTP errors

        cve_data = response.json()
        vulnerabilities = cve_data.get("vulnerabilities", [])

        return vulnerabilities

    except requests.exceptions.RequestException as e:
        print(f"Error fetching CVE data: {e}")
        return None

def fetch_all_cves(results_per_page=2000):
    # Start fetching CVEs from index 0
    start_index = 0

    while True:
        print(start_index)
        cves = fetch_cve_list(start_index, results_per_page)

        if not cves:
            return -1  # Stop if there's an error fetching CVEs

        output_to_file(cves)

        # Update start_index for the next batch
        start_index += results_per_page

        # Check if there are more CVEs to fetch
        if start_index >= 4000:
            print('condition met')
            break

        time.sleep(10)

    return start_index

if __name__ == "__main__":
    # reset file
    open('output.json', 'w').close()

    # fetch cves
    numFetched = fetch_all_cves()
    
    if numFetched != -1:
        print(f"Total CVEs fetched: {numFetched}")
    else:
        print("Failed to fetch CVEs.")
