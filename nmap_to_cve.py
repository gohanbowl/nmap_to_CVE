import requests, nmap3, sys, json
from colorama import init
from termcolor import colored

nmap = nmap3.Nmap()

def host_scan(host):
    results = nmap.nmap_version_detection(host, arg="-sV -T5 -p-")
    d={}
    key = results[host]['ports']
    for a,b in enumerate(key):
        d[a + 1] = {}
        try:
            print(colored("Port: {0} \t State:{1} \t Version: {2} {3}".format(key[a]['portid'], key[a]['state'], key[a]['service']['product'], key[a]['service']['version']),"green"))
            d[a + 1]['Product'] = key[a]['service']['product']
            d[a + 1]['Version'] = key[a]['service']['version']
        except:
            print(colored("{0}\t {1}\t No version information returned".format(key[a]['portid'],key[a]['service']['name']),"red"))
    return(d)

def get_cve(data):
     for a,b in enumerate(data):
         if len(data[a+1]) != 0:
            print(data[a+1]['Product'] + data[a+1]['Version'])
            prod = data[a+1]['Product']
            ver = data[a+1]['Version']
            ver = ver.replace(" ","+")
            url = "https://services.nvd.nist.gov/rest/json/cves/1.0?resultsPerPage=20&keyword="
            r=requests.get(url + prod + "+" + ver)
            s = r.content.decode("utf-8")
            x = json.loads(s)
            if "error" in x:
                print(colored("No CVEs returned for this product version"), "on_yellow")
            else:
                cve_data = x['result']['CVE_Items']
                for a,b in enumerate(cve_data):
                    print(colored(cve_data[a]['cve']['CVE_data_meta']['ID']), "on_green")
                    print(cve_data[a]['cve']['description']['description_data'][0]['value']+"\n")
         else:
             continue
def welcome():
    print('''Choose one of the options below:\n
    1. Scan Target for CVEs\n
    2. Search for CVEs by keyword\n''')

    answ = input("Enter Option")


if __name__ == "__main__":
    #host = sys.argv[1]
    out = host_scan('192.168.0.55')
    #print(out)
    get_cve(out)
