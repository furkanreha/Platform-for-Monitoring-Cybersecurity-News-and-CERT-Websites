import requests
import re
from bs4 import BeautifulSoup
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
plain_url = "https://us-cert.cisa.gov"
url = "https://us-cert.cisa.gov/ncas/alerts/2021"

# list of common words between news, doesn't help us much when it comes to labeling
# those news
# TO DO: ask orçun hoca for possible additions
common_words = ['cisa', 'actor', 'use', 'using', 'version',"cyber","cybersecurity"]


def getText(req):
    # takes a request to a page and converts its html into plaintext
    # by removing tags
    html_string = req.text
    plainText = []
    soup = BeautifulSoup(html_string,"lxml")
    paragraphs = soup.select("p")
    for para in paragraphs:
        inner_soup = BeautifulSoup(str(para),"lxml")
        for elem in inner_soup(['style', 'script', 'a href','strong']):
            inner_soup.decompose() 
            # eliminate tags
        plainText.append(' '.join(inner_soup.stripped_strings))
  
    # return data by retrieving the tag content
    return ' '.join(plainText)


def filterText(output):
    # remove any links remain in the plain text output of the page
    # also removes stop words from plaintext.
    regex_output = re.sub(r'http\S+', ' ', output,
        flags=re.MULTILINE).strip()
     
    wordList = regex_output.split()
    wordList = map(str.lower, wordList)
    
    stops = set(stopwords.words("english"))
    
    #print(stops)
    filtered_words = [word for word in wordList if not word in stops]
    filtered_words = [word for word in filtered_words if word.isalpha()]
    return filtered_words


def lemmatizeText(wordList):
    lemmatizer = WordNetLemmatizer()
    root_words = [lemmatizer.lemmatize(word) for word in wordList]
    # apply another filter to remove commonly used words in cybersecurity news
    filtered_words = [word for word in root_words if not word in common_words]
    return filtered_words


def getWordFrequency(wordList):
    tmp = {i:wordList.count(i) for i in wordList}
    return {k: v for k, v in sorted(tmp.items(), key=lambda item: item[1], reverse=True)}

r = requests.get(url)
html_string = r.text

soup = BeautifulSoup(html_string,"lxml")
paragraphs = soup.select("li")
headlines = BeautifulSoup(str(paragraphs), "lxml").select("a")
delimiters = "<" , "\"" , ">" 
regexPattern = '|'.join(map(re.escape, delimiters))

for para in headlines:
    if "hreflang=" in str(para):
        parsed_para = re.split(regexPattern, str(para))
        #print(parsed_para[2], parsed_para[6]) # 2 is for url and 6 is header
        tmp = parsed_para[2]
        tmp2 = parsed_para[6]

        print(tmp2)
        r = requests.get(plain_url + tmp)
        output = getText(r)
        wordList = filterText(output)
        lemmatized_words = lemmatizeText(wordList)
        frequency = getWordFrequency(lemmatized_words)
        print(list(frequency.items())[0:10])




