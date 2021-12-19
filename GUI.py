import requests
import re
from bs4 import BeautifulSoup
from nltk.stem import WordNetLemmatizer
import tkinter as tk


def cleanWebsiteText(plain_html):
    soup = BeautifulSoup(plain_html, "lxml")
    plaintext = soup.get_text()

    delimiters = "<", "\"", ">", "-", "?", "!", ".", ",", "|", "\n", "\t", " "
    regexPattern = '|'.join(map(re.escape, delimiters))

    wordList = re.split(regexPattern, plaintext)
    wordList = [item for item in wordList if item]  # for eliminating empty elements
    wordList = [item.lower() for item in wordList]

    lemmatizer = WordNetLemmatizer()
    root_words = [lemmatizer.lemmatize(word) for word in wordList]
    filtered_words = [word for word in root_words if word.isalpha()]

    return filtered_words


def getCountRatio(wordlist):
    counter = 0
    for word in cybersecurity_keywords:
        if word in wordlist:
            counter += 1

    return counter / len(cybersecurity_keywords)


def predictWebsite():
    try:
        websiteUrl = e1.get()
        url = "https://www." + websiteUrl
        headers = {"Accept-Language": "en-US,en;q=0.5"}
        r = requests.get(url, headers=headers, timeout=10)

        if "lang=\"en" in r.text:
            wordList = cleanWebsiteText(r.text)
            keyword_ratio = getCountRatio(wordList)

            if keyword_ratio > 0.18:
                T.insert(tk.END, websiteUrl + " is Cyber Security Related; Level 3\n")

            elif keyword_ratio > 0.12:
                T.insert(tk.END, websiteUrl + " is Cyber Security Related; Level 2\n")

            elif keyword_ratio > 0.06:
                T.insert(tk.END, websiteUrl + " is Cyber Security Related; Level 1\n")

            else:
                T.insert(tk.END, websiteUrl + " is not Cyber Security Related; Level 0\n")

            T.insert(tk.END, "Score:" + str(keyword_ratio) + "\n")
            T.insert(tk.END, "**************************************************" + "\n")
        else:
            T.insert(tk.END, "Algorithm only works for English!\n")

    except Exception as e:
        T.insert(tk.END, "Given URL is not working with the program!\n")
        print(e.args)


master = tk.Tk()
master.geometry("500x250")
tk.Label(master, text="Enter Web URL to Check" + "\n" + "(https://www. is automatically added): ",
         font=("Arial", 10)).grid(row=0)

e1 = tk.Entry(master, width="40")
e1.grid(row=0, column=1, padx=5, pady=10, ipady=3)

tk.Button(master,
          text='Quit',
          command=master.quit).grid(row=1,
                                    column=0,
                                    sticky=tk.W,
                                    pady=4, padx=100)

tk.Button(master, text='Evaluate', command=predictWebsite).grid(row=1,
                                                                column=1,
                                                                sticky=tk.W,
                                                                pady=4, padx=90)

T = tk.Text(master, width=61, height=10)
T.grid(row=2, columnspan=3)

cybersecurity_keywords = [
    'threat', 'attack', 'blockcipher', 'ssh', 'whitelist', 'sandboxing', 'encode', 'scam', 'cyberattack',
    'honeypot', 'theft', 'apt', 'darkweb', 'eavesdropping', 'breach', 'fbi', 'cve', 'private', 'scada', 'cia',
    'blocklist', 'password', 'phishing', 'dns', 'cryptocurrency', 'fraud', 'captcha', 'vulnerability', 'malvertising',
    'wormhole', 'worm', 'socket', 'telnet', 'atp', 'byod', 'keylogger', 'secaas', 'soc', 'allowlist', 'restore',
    'cryptography', 'sniffing', 'cracker', 'software', 'penetration', 'integrity', 'security', 'byol', 'spyware',
    'soar', 'siem', 'spam', 'cot', 'ip', 'owasp', 'sec', 'ciphertext', 'denial', 'hacker', 'malware', 'domain',
    'cyberbullying', 'decryption', 'api', 'privacy', 'victim', 'pki', 'clientless', 'ransomware', 'lan', 'zombie',
    'clickjacking', 'news', 'iam', 'skimmer', 'antivirus', 'scareware', 'layer', 'spoofing', 'certificate', 'rootkit',
    'remote', 'authentication', 'mitre', 'anti', 'dlp', 'ioc', 'authentification', 'exploit', 'jboh', 'virus', 'iaa',
    'trojan', 'cybersecurity', 'adware', 'botnet', 'cyber', 'po', 'manipulate', 'cyberespionage', 'engineering',
    'authorized', 'firewall', 'plaintext', 'encryption', 'saas', 'paas', 'vpn', 'byoc', 'dmz', 'spear', 'isp',
    'social', 'blacklist', 'secure', 'sensitive', 'patch', 'backdoor', 'decrypt', 'denylist', 'malicious', 'data',
    'authorization', 'bot', 'unauthorized', 'ssl', 'hacktivism', 'iot', 'ddos', 'spoof', 'cloud', 'deepfake',
    'bcp', 'access', 'key', 'crpyojacking', 'wifi', 'pii', 'cnd', 'outsourcing', 'risktool', 'brute', 'fido',
    'greylist', 'vishing', 'sandbox'
]

false_positive_keywords = ["commercial", "business", "wage", "pricing", "sale", "cart", "university", "consumer",
                           "corporate", "buy", "weather", "sports", "store", "game", "music", "campus", "marketplace",
                           "vaccine", "pandemic",
                           "covid-19"]

cybersecurity_keywords = [item.lower() for item in cybersecurity_keywords]

master.mainloop()
