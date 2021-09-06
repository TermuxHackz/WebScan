#Coded by AnonyminHack5
#Whatsapp: +2349033677589
import requests
import os
import time
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
from termcolor import colored
from colorama import Fore

#SqlScanner


#Displayes banner
banner = """____   ______    ___        ________  ______        __      _____  ___   _____  ___    _______   _______   
\033[1;36m  __   __  ___   _______  _______        ________  ______        __      _____  ___   _____  ___    _______   _______   
|"  |/  \|  "| /"     "||   _  "\      /"       )/" _  "\      /""\    (\"   \|"  \ (\"   \|"  \  /"     "| /"      \  
|'  /    \:  |(: ______)(. |_)  :)    (:   \___/(: ( \___)    /    \   |.\\   \    ||.\\   \    |(: ______)|:        | 
|: /'        | \/    |  |:     \/      \___  \   \/ \        /' /\  \  |: \.   \\  ||: \.   \\  | \/    |  |_____/   ) 
 \//  /\'    | // ___)_ (|  _  \\       __/  \\  //  \ _    //  __'  \ |.  \    \. ||.  \    \. | // ___)_  //      /  
 /   /  \\   |(:      "||: |_)  :)     /" \   :)(:   _) \  /   /  \\  \|    \    \ ||    \    \ |(:      "||:  __   \  
|___/    \___| \_______)(_______/     (_______/  \_______)(___/    \___)\___|\____\) \___|\____\) \_______)|__|  \___) 
\033[1;36m
-----------------------------
\033[1;94mName: WebScan
Coded by: AnonyminHack5
Version: 1.0\033[0m
----------------------------
WebScan is a web vulnerability Scanning tool, which scans sites for SQL injection and XSS vulnerabilities
Which is a great tool for web pentesters. Coded in python, CLI.
------------------------------------------------------------------------------------
"""


#SQLbanner

sqlbanner = """________   ______    ___        ________  ______        __      _____  ___   _____  ___    _______   _______   
\033[1;37m /"       ) /    " \  |"  |      /"       )/" _  "\      /""\    (\"   \|"  \ (\"   \|"  \  /"     "| /"      \  
(:   \___/ // ____  \ ||  |     (:   \___/(: ( \___)    /    \   |.\\   \    ||.\\   \    |(: ______)|:        | 
 \___  \  /  /    )  )|:  |      \___  \   \/ \        /' /\  \  |: \.   \\  ||: \.   \\  | \/    |  |_____/   ) 
  __/  \\(: (____/ //  \  |___    __/  \\  //  \ _    //  __'  \ |.  \    \. ||.  \    \. | // ___)_  //      /  
 /" \   :)\         \ ( \_|:  \  /" \   :)(:   _) \  /   /  \\  \|    \    \ ||    \    \ |(:      "||:  __   \  
(_______/  \"____/\__\ \_______)(_______/  \_______)(___/    \___)\___|\____\) \___|\____\) \_______)|__|  \___)
\033[0m
"""

def clear_screen():
	os.system("cls || clear")


def menu():
	print(Fore.CYAN + "\t\u0332 SQlScanner Menu")
	print("")
	print(Fore.YELLOW + "{1} Scan site For Sql injection")
	print(Fore.YELLOW + "{2} Scan site for XSS vuln")
	print(Fore.YELLOW + "{3} Exit")
	print("")
	y = input("""\033[1;34m--\033[0m(kali@AnonyminHack5\033[0m)-[\033[1;34m~/home/SqlScan\033[0m]
$ \033[1;94mChoose an Option\033[0m: \033[1;36m""")
	if(y == "1"):
		print(sqlbanner)
		if __name__ == "__main__":
			url = input("Enter Site to test for SQLinjection: \033[1;34m")
			scan_sql_injection(url) 
	elif(y == "2"):
		print(xssbanner)
		if __name__ == "__main__":
			url = input("Enter Site to test for XSS: \033[1;34m")
			print(scan_xss(url))
	elif(y == "3"):
		print(Fore.RED + "[x] Exiting from WebScan ... [x]")
		time.sleep(1)
		exit
	else:
		print(Fore.RED + "Wrong Option dude, try again")
		time.sleep(1)
		os.system("python3 webscan.py")
		  

# initialize an HTTP session & set the browser
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36, Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1, Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36, Mozilla/5.0 (Linux; Android 6.0.1; SM-G920V Build/MMB29K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.98 Mobile Safari/537.36"

def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    # get the form action (target url)
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def is_vulnerable(response):
    """A simple boolean function that determines whether a page 
    is SQL Injection vulnerable from its `response`"""
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    for error in errors:
        # if you find one of these errors, return True
        if error in response.content.decode().lower():
            return True
    # no error detected
    return False
    
def scan_sql_injection(url):
    # test on URL
    for c in "\"'":
        # add quote/double quote character to the URL
        new_url = f"{url}{c}"
        print("[!] Trying", new_url)
        # make the HTTP request
        res = s.get(new_url)
        if is_vulnerable(res):
            # SQL Injection detected on the URL itself, 
            # no need to preceed for extracting forms and submitting them
            print(Fore.GREEN + "[+] SQL Injection vulnerability detected, link:", new_url)
            return
    # test on HTML forms
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            # the data body we want to submit
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    # any input form that is hidden or has some value,
                    # just use it in the form body
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    # all others except submit, use some junk data with special character
                    data[input_tag["name"]] = f"test{c}"
            # join the url with the action (form request URL)
            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)
            # test whether the resulting page is vulnerable
            if is_vulnerable(res):
                print(Fore.GREEN + "[+] SQL Injection vulnerability detected, link:", url)
                print(Fore.BLUE + "[+] Form:")
                pprint(form_details)
                break   
                      

#XSS Scanner
xssbanner = """

 ___  ___   ________  ________       ________  ______        __      _____  ___   _____  ___    _______   _______   
|"  \/"  | /"       )/"       )     /"       )/" _  "\      /""\    (\"   \|"  \ (\"   \|"  \  /"     "| /"      \  
 \   \  / (:   \___/(:   \___/     (:   \___/(: ( \___)    /    \   |.\\   \    ||.\\   \    |(: ______)|:        | 
  \\  \/   \___  \   \___  \        \___  \   \/ \        /' /\  \  |: \.   \\  ||: \.   \\  | \/    |  |_____/   ) 
  /\.  \    __/  \\   __/  \\        __/  \\  //  \ _    //  __'  \ |.  \    \. ||.  \    \. | // ___)_  //      /  
 /  \   \  /" \   :) /" \   :)      /" \   :)(:   _) \  /   /  \\  \|    \    \ ||    \    \ |(:      "||:  __   \  
|___/\___|(_______/ (_______/      (_______/  \_______)(___/    \___)\___|\____\) \___|\____\) \_______)|__|  \___) 
                                                                                                                    
"""

def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")
    
def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    # get the form action (target url)
    action = form.attrs.get("action").lower()
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):
    """
    Submits a form given in `form_details`
    Params:
        form_details (list): a dictionary that contain form information
        url (str): the original URL that contain that form
        value (str): this will be replaced to all text and search inputs
    Returns the HTTP Response after form submission
    """
    # construct the full URL (if the url provided in action is relative)
    target_url = urljoin(url, form_details["action"])
    # get the inputs
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        # replace all text and search values with `value`
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            # if input name and value are not None, 
            # then add them to the data of form submission
            data[input_name] = input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        # GET request
        return requests.get(target_url, params=data)


def scan_xss(url):
    """
    Given a `url`, it prints all XSS vulnerable forms and 
    returns True if any is vulnerable, False otherwise
    """
    # get all the forms from the URL
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    js_script = "<Script>alert('XSS detected!!')</scripT>"
    # returning value
    is_vulnerable = False
    # iterate over all forms
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"[+] XSS Detected on {url}")
            print(f"[*] Form details:")
            pprint(form_details)
            is_vulnerable = True
            # won't break because we want to print available vulnerable forms
    return is_vulnerable

#Checks for internet connection
def check_internet():
	print(Fore.BLUE + "Checking if your connected to the internet >>>>> [Checking]")
	time.sleep(2)
	url_site = "https://github.com/TermuxHackz"
	timeout = 5
	try:
		request = requests.get(url_site, timeout=timeout)
		print(Fore.GREEN + "##########################")
		print(Fore.GREEN + "[!] Connected to the Internet[!]")
		print("##########################")
		time.sleep(1)
		clear_screen()               
		print(banner)              
		menu() 
	except (requests.ConnectionError, requests.Timeout) as exception:
		print(Fore.RED + "##########################")
		print(Fore.RED + "[x] No internet Connection [x] ")
		print(Fore.RED + "Connect to internet and run script again")
		print("##########################")
		time.sleep(1)
		exit

clear_screen()
check_internet()

