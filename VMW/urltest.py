import nltk
from urllib import urlopen

url = "http://#######"
html = urlopen(url).read()
raw = nltk.clean_html(html)
print(raw)