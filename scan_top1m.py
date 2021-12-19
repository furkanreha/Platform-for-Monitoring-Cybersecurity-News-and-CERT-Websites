import requests
import csv
import re
import joblib
import pandas as pd
import numpy as np
import threading
from bs4 import BeautifulSoup
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from tqdm import tqdm

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
lemmatizer = WordNetLemmatizer()
cybersecurity_keywords = [lemmatizer.lemmatize(word) for word in cybersecurity_keywords]

false_positive_keywords = [item.lower() for item in false_positive_keywords]
# lemmatizer = WordNetLemmatizer()
false_positive_keywords = [lemmatizer.lemmatize(word) for word in false_positive_keywords]
# print(cybersecurity_keywords)
# df = pd.read_csv("website_classification.csv")
level1_sites = []
level2_sites = []
level3_sites = []

with open("top-1m.csv", newline="") as csvfile:
    websites = csv.reader(csvfile, delimiter=",")
    sites = list(websites)


def cleanWebsiteText(plain_html):
    soup = BeautifulSoup(plain_html, "lxml")
    plaintext = soup.get_text()
    # print(plaintext)
    delimiters = "<", "\"", ">", "-", "?", "!", ".", ",", "|", "\n", "\t", " "
    regexPattern = '|'.join(map(re.escape, delimiters))

    wordList = re.split(regexPattern, plaintext)
    wordList = [item for item in wordList if item]  # for eliminating empty elements
    wordList = [item.lower() for item in wordList]

    # for lemmatizion of the plaintext
    lemmatizer = WordNetLemmatizer()
    root_words = [lemmatizer.lemmatize(word) for word in wordList]
    filtered_words = [word for word in root_words if word.isalpha()]
    return filtered_words


def predictWebsite(wordlist):
    cnt = 0
    for word in cybersecurity_keywords:
        if word in wordlist:
            cnt += 1

    for word in false_positive_keywords:
        if word in wordlist:
            cnt -= 1

    return cnt / len(cybersecurity_keywords)


def runParallelScan(threadId):
    for i in tqdm(range(threadId, len(sites), 40)):
        row = sites[i]
        try:
            url = "https://www." + row[1]
            headers = {"Accept-Language": "en-US,en;q=0.5"}
            r = requests.get(url, headers=headers, timeout=10)

            if "lang=\"en" in r.text:  # for only scanning english websites
                wordList = cleanWebsiteText(r.text)
                keyword_ratio = predictWebsite(wordList)
                # print(url , keyword_ratio)
                if keyword_ratio > 0.18:
                    level3_sites.append([url, keyword_ratio])
                elif keyword_ratio > 0.12:
                    level2_sites.append([url, keyword_ratio])
                elif keyword_ratio > 0.06:
                    level1_sites.append([url, keyword_ratio])

        except:
            pass


def runSequentialScan():
    cnt = 0
    # print(list(websites)[0])
    for row in tqdm(sites):

        try:
            url = "https://www." + row[1]
            headers = {"Accept-Language": "en-US,en;q=0.5"}
            r = requests.get(url, headers=headers, timeout=10)

            if "lang=\"en" in r.text:  # for only scanning english websites
                wordList = cleanWebsiteText(r.text)
                keyword_ratio = predictWebsite(wordList)
                # print(url , keyword_ratio)
                if keyword_ratio > 0.18:
                    level3_sites.append([url, keyword_ratio])
                elif keyword_ratio > 0.12:
                    level2_sites.append([url, keyword_ratio])
                elif keyword_ratio > 0.06:
                    level1_sites.append([url, keyword_ratio])

        except:
            pass

        cnt += 1

        if cnt == 1000:
            break


def writeToFile():
    lvl_1 = "LVL1_list.txt"
    lvl_2 = "LVL2_list.txt"
    lvl_3 = "LVL3_list.txt"
    with open(lvl_1, 'w') as lvl1file, open(lvl_2, 'w') as lvl2file, open(lvl_3, 'w') as lvl3file:
        for url in level1_sites:
            lvl1file.write(str(url) + "\n")
        for url in level2_sites:
            lvl2file.write(str(url) + "\n")
        for url in level3_sites:
            lvl3file.write(str(url) + "\n")


def main():
    threads = []
    for i in range(40):
        t = threading.Thread(target=runParallelScan, args=(i,))
        t.daemon = True
        threads.append(t)

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    # print("lvl 1 sites: ",level1_sites)
    # print("lvl 2 sites: ",level2_sites)
    # print("lvl 3 sites: ",level3_sites)

    writeToFile()


if __name__ == "__main__":
    main()

    # runSequentialScan()
