import requests
import numpy as np
import pandas as pd
from bs4 import BeautifulSoup
import matplotlib.pyplot as plt
import re
import  tldextract
import urllib.parse
import urllib3
from urllib.parse import urlparse,quote,unquote,urljoin,urlencode
import tld
from tld import get_tld, is_tld
import string
from collections import Counter
import whois
from datetime import datetime
from xml.etree import ElementTree
import dns.resolver
import csv
from tqdm import tqdm
from time import sleep
import time
from numba import njit, prange
import json

input_url = ["www.google.com"]

def initialize(features):
  features = {
      "url" : None,

      "scheme" : None,
      "hostname" : None,
      "path" : None,
      "netloc" : None,
      "domain" : None,
      "subdomains" : None,
      "tld" : None,

      "length_url" : None,
      "length_hostname" : None,
      'ip' : None,
      'path_extension' : None,

      "nb_dots" : None,
      "nb_hyphens" : None,
      "nb_at" : None,
      "nb_qm" : None,
      "nb_and" : None,
      "nb_or" : None,
      "nb_eq" : None,
      "nb_underscore" : None,
      "nb_tilde" : None,
      "nb_percent" : None,
      "nb_slash" : None,
      "nb_star" : None,
      "nb_colon" : None,
      "nb_comma" : None,
      "nb_semicolumn" : None,
      "nb_dollar" : None,
      "nb_space" : None,
      "nb_www" : None,
      "nb_com" : None,
      "nb_dslash" : None,
      "nb_spl" : None,


      "http_in_path" : None,
      "https_token" : None,
      "ratio_digits_url" : None,
      "ratio_digits_host" : None,
      "punycode" : None,
      "port" : None,
      "tld_in_path" : None,
      "tld_in_subdomain" : None,
      "abnormal_subdomain" : None,
      "nb_subdomains" : None,
      "prefix_suffix" : None,
      "random_domain" : None,
      "shortening_service" : None,

      "length_words_raw" : None,
      "char_repeat" : None,
      "shortest_words_raw" : None,
      "shortest_word_host" : None,
      "shortest_word_path" : None,
      "longest_words_raw" : None,
      "longest_word_host" : None,
      "longest_word_path" : None,
      "avg_words_raw" : None,
      "avg_word_host" : None,
      "avg_word_path" : None,

      "phish_hints" : None,
      "domain_in_brand" : None,
      "brand_in_subdomain" : None,
      "brand_in_path" : None,
      "suspicious_tld" : None,

      "nb_hyperlinks" : None,
      "ratio_intHyperlinks" : None,
      "ratio_extHyperlinks" : None,
      "ratio_nullHyperlinks" : None,
      "ratio_safe_anchors" : None,
      "nb_extCSS" : None,

      "onmouseover": None,
      "right_click_disabled": None,
      "empty_title": None,
      "domain_in_title": None,
      "domain_with_copyright": None,

      "whois_registered_domain": None,
      "domain_registration_length": None,
      "domain_age": None,

      "web_traffic": None,
      "dns_record": None,
      "google_index": None,

      "sfh" : None,
      "iframe" : None,
      "popup_window" : None,

      "login_form": None,
      "external_favicon": None,
      "links_in_tags": None,
      "submit_email": None,
      "ratio_intMedia": None,
      "ratio_extMedia": None
    }
  return features

"""## Feature Extractions
"""

def extract_url_components(features_overall, listOrDict=False):
  features = {
      "scheme" : None,
      "hostname" : None,
      "path" : None,
      "netloc" : None,
      "domain" : None,
      "subdomains" : None,
      "tld" : None
  }
  try:
    url = features_overall["url"]
    parsed_url = urllib.parse.urlparse(url)
    features["scheme"] = parsed_url.scheme
    features["hostname"] = parsed_url.hostname


    features["path"] = parsed_url.path
    features["netloc"] = parsed_url.netloc


    extracted_info = tldextract.extract(url)
    features["domain"] = extracted_info.domain
    subdomain = extracted_info.subdomain
    features["subdomains"] = subdomain.split('.')
    features["tld"] = extracted_info.suffix




  except requests.RequestException as e:
    print(e)
  if listOrDict:
    return features.values()
  else:
    features_overall.update(features) # Directly updates overall dictionary with current features
    return features #Returns only current features

def get_url_features(features_overall, listOrDict=False):
  features = {
      "length_url" : None,
      "length_hostname" : None,
      'ip' : None,
      'path_extension' : None,

  }
  try:
    url = features_overall["url"]
    features["length_url"] = len(url)
    features["length_hostname"] = len(features_overall["hostname"])

    ip_pattern = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'  # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        '[0-9a-fA-F]{7}', url)  # Ipv6
    if ip_pattern:
      features['ip'] = 1
    else:
      features['ip'] = 0

    path = features_overall["path"]
    if '.' in path:
        extension = path.split('.')[-1]
    else:
        extension = None
    if extension:
      features['path_extension'] = 1
    else:
      features['path_extension'] = 0

  except requests.RequestException as e:
    print(e)
  if listOrDict:
    return features.values()
  else:
    features_overall.update(features) # Directly updates overall dictionary with current features
    return features #Returns only current features

def url_char_count(features_overall, listOrDict=False):#default return datatype is dict
  features = {
      "nb_dots" : None,
      "nb_hyphens" : None,
      "nb_at" : None,
      "nb_qm" : None,
      "nb_and" : None,
      "nb_or" : None,
      "nb_eq" : None,
      "nb_underscore" : None,
      "nb_tilde" : None,
      "nb_percent" : None,
      "nb_slash" : None,
      "nb_star" : None,
      "nb_colon" : None,
      "nb_comma" : None,
      "nb_semicolumn" : None,
      "nb_dollar" : None,
      "nb_space" : None,
      "nb_www" : None,
      "nb_com" : None,
      "nb_dslash" : None,
      "nb_spl" : None
  }
  try:
    url = features_overall["url"]
    features["nb_dots"] = url.count('.')
    features["nb_hyphens"] = url.count('-')
    features["nb_at"] = url.count('@')
    features["nb_qm"] = url.count('?')
    features["nb_and"] = url.count('&')
    features["nb_or"] = url.count('|')
    features["nb_eq"] = url.count('=')
    features["nb_underscore"] = url.count('_')
    features["nb_tilde"] = url.count('~')
    features["nb_percent"] = url.count('%')
    single_slash = re.compile(r'[^/]/[^/]')
    features["nb_slash"] = len(re.findall(single_slash, url))
    features["nb_star"] = url.count('*')
    features["nb_colon"] = url.count(':')
    features["nb_comma"] = url.count(',')
    features["nb_semicolumn"] = url.count(';')
    features["nb_dollar"] = url.count('$')
    features["nb_space"] = url.count(' ') + url.count('%20')
    features["nb_www"] = url.count('www')
    features["nb_com"] = f"{features_overall['domain'] + features_overall['path']}".count('.com')
    features["nb_com"] += 1 if 'com' in features_overall['subdomains'] else 0
    dslash_list=[x.start(0) for x in re.finditer('//', url)]
    if dslash_list[len(dslash_list)-1]>6:
        features["nb_dslash"] = 1
    else:
        features["nb_dslash"] = 0
    features["nb_spl"] = sum(c in "!@#$%^&*()_+=-`~[]{}|;:'\",.<>?/" for c in url)
  except requests.RequestException as e:
    print(e)
  if listOrDict:
    return features.values()
  else:
    features_overall.update(features) # Directly updates overall dictionary with current features
    return features #Returns only current features

def get_redirection_and_error_features(features_overall, listOrDict=False):#default return datatype is dict
    features = {
        "nb_redirection" : None,
        "ratio_intRedirection": 0.0,
        "ratio_extRedirection": 0.0,
        "ratio_intErrors": 0.0,
        "ratio_extErrors": 0.0,
        "total_requests": 0,
        "int_redirections": 0,
        "ext_redirections": 0,
        "int_errors": 0,
        "ext_errors": 0
    }

    def is_internal(url, base_hostname):
        return urlparse(url).hostname == base_hostname

    def analyze_url(url, base_hostname):
        try:
            response = requests.get(url, allow_redirects=True)
            features["total_requests"] += 1
            features["nb_redirection"] = len(response.history)

            if response.history:
                for resp in response.history:
                    if 300 <= resp.status_code < 400:
                        if is_internal(resp.url, base_hostname):
                            features["int_redirections"] += 1
                        else:
                            features["ext_redirections"] += 1

            final_url = response.url
            if 400 <= response.status_code < 600:
                if is_internal(final_url, base_hostname):
                    features["int_errors"] += 1
                else:
                    features["ext_errors"] += 1

        except requests.RequestException as e:
            print(f"Request failed: {e}")
            features["total_requests"] += 1  # Count the failed request
            if is_internal(url, base_hostname):
                features["int_errors"] += 1
            else:
                features["ext_errors"] += 1

    try:
        url = features_overall["url"]
        path = features_overall["path"]
        base_hostname = features_overall["hostname"]

        analyze_url(url, base_hostname)

        ImpFeatures={}
        total_requests = features["total_requests"] if features["total_requests"] > 0 else 1  # Avoid division by zero

        ImpFeatures["url"] = url
        ImpFeatures["ratio_intRedirection"] = features["int_redirections"] / total_requests
        ImpFeatures["ratio_extRedirection"] = features["ext_redirections"] / total_requests
        ImpFeatures["ratio_intErrors"] = features["int_errors"] / total_requests
        ImpFeatures["ratio_extErrors"] = features["ext_errors"] / total_requests


    except requests.RequestException as e:
        print(e)
    if listOrDict:
        return features.values()
    else:
        features_overall.update(features) # Directly updates overall dictionary with current features
        return features #Returns only current features

def path_hostname_features(features_overall, listOrDict=False):
  features = {
      "http_in_path" : None,
      "https_token" : None,
      "ratio_digits_url" : None,
      "ratio_digits_host" : None,
      "punycode" : None,
      "port" : None,
      "tld_in_path" : None,
      "tld_in_subdomain" : None,
      "abnormal_subdomain" : None,
      "nb_subdomains" : None,
      "prefix_suffix" : None,
      "random_domain" : None,
      "shortening_service" : None
  }
  try:
    url = features_overall["url"]
    path = features_overall["path"]
    scheme = features_overall["scheme"]
    hostname = features_overall["hostname"]
    domain = features_overall["domain"]
    subdomains = features_overall["subdomains"]

    features["http_in_path"] = 'http' in path
    features["https_token"] = 'https' in scheme

    total_chars_url = len(url)
    digit_count_url = sum(c.isdigit() for c in url)
    features["ratio_digits_url"] = digit_count_url / total_chars_url if total_chars_url > 0 else 0

    total_chars_host = len(hostname)
    digit_count_host = sum(c.isdigit() for c in hostname)
    features["ratio_digits_host"] = digit_count_host / total_chars_host if total_chars_host > 0 else 0

    features["punycode"] = 'xn--' in hostname

    features["port"] = urllib.parse.urlparse(url).port is not None


    tlds = ['.com', '.org', '.net', '.info', '.biz', '.gov', '.edu', '.co', '.us']
    tlds.append(f"{features_overall['tld']}")
    features["tld_in_path"] = any(tld in path for tld in tlds)

    features["tld_in_subdomain"] = any(tld in subdomain for subdomain in subdomains for tld in tlds)

    features["abnormal_subdomain"] = bool(re.search('(http[s]?://(w[w]?|\d))([w]?(\d|-))',url))

    features["nb_subdomains"] = len(subdomains)

    features["prefix_suffix"] = '-' in hostname

    features["random_domain"] = bool(re.match(r'^[a-z0-9]{10,}$', domain))

    shortening_services = [
        'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'cli.gs',
        'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc', 'url4.eu', 'twit.ac',
        'su.pr', 'twurl.nl', 'snipurl.com', 'short.to', 'budurl.com',
        'ping.fm', 'post.ly', 'just.as', 'bkite.com', 'snipr.com', 'fic.kr',
        'loopt.us', 'doiop.com', 'short.ie', 'b33.fr', 'u.nu', 'sp2.ro',
        'tr.im', 'u.im', 'j.mp', 'bit.do', 'lnkd.in', 'db.tt', 'qr.ae',
        'adf.ly', 'bitly.com', 'cur.lv', 'ity.im', 'q.gs', 'po.st', 'bc.vc',
        'twitthis.com', 'u.to', 'j2j.de', 'dlvr.it', 'oo.gl', 'v.gd', 'link.zip.net'
    ]
    features["shortening_service"] = any(service in hostname for service in shortening_services)



  except requests.RequestException as e:
    print(e)
  if listOrDict:
    return features.values()
  else:
    features_overall.update(features) # Directly updates overall dictionary with current features
    return features #Returns only current features

def word_features(features_overall, listOrDict=False):
  features = {
      "length_words_raw" : None,
      "char_repeat" : None,
      "shortest_words_raw" : None,
      "shortest_word_host" : None,
      "shortest_word_path" : None,
      "longest_words_raw" : None,
      "longest_word_host" : None,
      "longest_word_path" : None,
      "avg_words_raw" : None,
      "avg_word_host" : None,
      "avg_word_path" : None
  }

  def get_word_stats(text):
        words = re.findall(r'\w+', unquote(text))
        if not words:
            return 0, 0, 0, 0
        total_length = sum(len(word) for word in words)
        shortest_word_length = min(len(word) for word in words)
        longest_word_length = max(len(word) for word in words)
        avg_word_length = total_length / len(words)
        return total_length, shortest_word_length, longest_word_length, avg_word_length
  def __all_same(items):
        return all(x == items[0] for x in items)

  try:
    url = features_overall["url"]
    path = features_overall["path"] or ''
    hostname = features_overall["hostname"] or ''

    total_length, shortest_word_length, longest_word_length, avg_word_length = get_word_stats(url)
    _, shortest_word_host, longest_word_host, avg_word_host = get_word_stats(hostname)
    _, shortest_word_path, longest_word_path, avg_word_path = get_word_stats(path)

    features["length_words_raw"]=total_length

    repeat = {'2': 0, '3': 0, '4': 0, '5': 0}
    part = [2, 3, 4, 5]

    for word in url:
        for char_repeat_count in part:
            for i in range(len(word) - char_repeat_count + 1):
                sub_word = word[i:i + char_repeat_count]
                if __all_same(sub_word):
                    repeat[str(char_repeat_count)] = repeat[str(char_repeat_count)] + 1
    features["char_repeat"]=sum(list(repeat.values()))
    features["shortest_words_raw"]=shortest_word_length
    features["shortest_word_host"]=shortest_word_host
    features["shortest_word_path"]=shortest_word_path
    features["longest_words_raw"]=longest_word_length
    features["longest_word_host"]=longest_word_host
    features["longest_word_path"]=longest_word_path
    features["avg_words_raw"]=avg_word_length
    features["avg_word_host"]=avg_word_host
    features["avg_word_path"]=avg_word_path



  except requests.RequestException as e:
    print(e)
  if listOrDict:
    return features.values()
  else:
    features_overall.update(features) # Directly updates overall dictionary with current features
    return features #Returns only current features

def phish_identity_features(features_overall, listOrDict=False):
  features = {
      "phish_hints" : None,
      "domain_in_brand" : None,
      "brand_in_subdomain" : None,
      "brand_in_path" : None,
      "suspicious_tld" : None,
  }
  try:
    url = features_overall["url"]
    path = features_overall["path"]
    scheme = features_overall["scheme"]
    hostname = features_overall["hostname"]
    domain = features_overall["domain"]
    subdomains = features_overall["subdomains"]
    tld = features_overall["tld"]

    phishing_hints = ['login', 'verify', 'secure', 'account', 'update', 'banking', 'signin', 'password',
                      'urgent', 'verification required', 'invoice', 'important', 'action required']
    phishing_hints.extend(['wp', 'includes', 'admin', 'content', 'site', 'images', 'js',
                           'alibaba', 'css', 'myaccount', 'dropbox', 'themes', 'plugins', 'view'])
    count = 0
    for hint in phishing_hints:
        count += url.lower().count(hint)
    features["phish_hints"] = count

    brands = ['accenture', 'activisionblizzard', 'adidas', 'adobe', 'adultfriendfinder', 'agriculturalbankofchina',
              'akamai', 'alibaba', 'aliexpress', 'alipay', 'alliance', 'alliancedata', 'allianceone', 'allianz', 'alphabet',
              'amazon', 'americanairlines', 'americanexpress', 'americantower', 'andersons', 'apache', 'apple', 'arrow',
              'ashleymadison', 'audi', 'autodesk', 'avaya', 'avisbudget', 'avon', 'axa', 'badoo', 'baidu', 'bank', 'bankofamerica',
              'bankofchina', 'bankofnewyorkmellon', 'barclays', 'barnes', 'bbc', 'bbt', 'bbva', 'bebo', 'benchmark', 'bestbuy',
              'bim', 'bing', 'biogen', 'blackstone', 'blogger', 'blogspot', 'bmw', 'bnpparibas', 'boeing', 'booking', 'broadcom',
              'burberry', 'caesars', 'canon', 'cardinalhealth', 'carmax', 'carters', 'caterpillar', 'cheesecakefactory',
              'chinaconstructionbank', 'cinemark', 'cintas', 'cisco', 'citi', 'citigroup', 'cnet', 'coca-cola', 'colgate',
              'colgate-palmolive', 'columbiasportswear', 'commonwealth', 'communityhealth', 'continental', 'dell', 'deltaairlines',
              'deutschebank', 'disney', 'dolby', 'dominos', 'donaldson', 'dreamworks', 'dropbox', 'eastman', 'eastmankodak', 'ebay',
              'edison', 'electronicarts', 'equifax', 'equinix', 'expedia', 'express', 'facebook', 'fedex', 'flickr', 'footlocker',
              'ford', 'fordmotor', 'fossil', 'fosterwheeler', 'foxconn', 'fujitsu', 'gap', 'gartner', 'genesis', 'genuine',
              'genworth', 'gigamedia', 'gillette', 'github', 'global', 'globalpayments', 'goodyeartire', 'google', 'gucci',
              'harley-davidson', 'harris', 'hewlettpackard', 'hilton', 'hiltonworldwide', 'hmstatil', 'honda', 'hsbc', 'huawei',
              'huntingtonbancshares', 'hyundai', 'ibm', 'ikea', 'imdb', 'imgur', 'ingbank', 'insight', 'instagram', 'intel',
              'jackdaniels', 'jnj', 'jpmorgan', 'jpmorganchase', 'kelly', 'kfc', 'kindermorgan', 'lbrands', 'lego', 'lennox',
              'lenovo', 'lindsay', 'linkedin', 'livejasmin', 'loreal', 'louisvuitton', 'mastercard', 'mcdonalds', 'mckesson',
              'mckinsey', 'mercedes-benz', 'microsoft', 'microsoftonline', 'mini', 'mitsubishi', 'morganstanley', 'motorola',
              'mrcglobal', 'mtv', 'myspace', 'nescafe', 'nestle', 'netflix', 'nike', 'nintendo', 'nissan', 'nissanmotor', 'nvidia',
              'nytimes', 'oracle', 'panasonic', 'paypal', 'pepsi', 'pepsico', 'philips', 'pinterest', 'pocket', 'pornhub', 'porsche',
              'prada', 'rabobank', 'reddit', 'regal', 'royalbankofcanada', 'samsung', 'scotiabank', 'shell', 'siemens', 'skype',
              'snapchat', 'sony', 'soundcloud', 'spiritairlines', 'spotify', 'sprite', 'stackexchange', 'stackoverflow', 'starbucks',
              'swatch', 'swift', 'symantec', 'synaptics', 'target', 'telegram', 'tesla', 'teslamotors', 'theguardian', 'homedepot',
              'piratebay', 'tiffany', 'tinder', 'tmall', 'toyota', 'tripadvisor', 'tumblr', 'twitch', 'twitter', 'underarmour',
              'unilever', 'universal', 'ups', 'verizon', 'viber', 'visa', 'volkswagen', 'volvocars', 'walmart', 'wechat', 'weibo',
              'whatsapp', 'wikipedia', 'wordpress', 'yahoo', 'yamaha', 'yandex', 'youtube', 'zara', 'zebra', 'iphone', 'icloud',
              'itunes', 'sinara', 'normshield', 'bga', 'sinaralabs', 'roksit', 'cybrml', 'turkcell', 'n11', 'hepsiburada', 'migros']
    features["domain_in_brand"] = any(brand in domain for brand in brands)

    features["brand_in_subdomain"] = any(('.' + brand + '.') in subdomain for subdomain in subdomains for brand in brands)

    features["brand_in_path"] = any(('.' + brand + '.') in path for brand in brands)

    suspecious_tlds = ['cn', 'ru', 'cf', 'gq',
        'fit','tk', 'gp', 'ga', 'work', 'ml', 'date', 'wang', 'men', 'icu', 'online', 'click', # Spamhaus
        'country', 'stream', 'download', 'xin', 'racing', 'jetzt',
        'ren', 'mom', 'party', 'review', 'trade', 'accountants',
        'science', 'work', 'ninja', 'xyz', 'faith', 'zip', 'cricket', 'win',
        'accountant', 'realtor', 'top', 'christmas', 'gdn', # Shady Top-Level Domains
        'link', # Blue Coat Systems
        'asia', 'club', 'la', 'ae', 'exposed', 'pe', 'go.id', 'rs', 'k12.pa.us', 'or.kr',
        'ce.ke', 'audio', 'gob.pe', 'gov.az', 'website', 'bj', 'mx', 'media', 'sa.gov.au' # statistics
        ]
    features["suspicious_tld"] = not(is_tld(tld))

  except requests.RequestException as e:
    print(e)
  if listOrDict:
    return features.values()
  else:
    features_overall.update(features) # Directly updates overall dictionary with current features
    return features #Returns only current features

def hyperlink_css_feaures(features_overall, soup, listOrDict=False):
  features = {
      "nb_hyperlinks" : None,
      "ratio_intHyperlinks" : None,
      "ratio_extHyperlinks" : None,
      "ratio_nullHyperlinks" : None,
      "ratio_safe_anchors" : None,
      "nb_extCSS" : None
  }
  try:
    url = features_overall["url"]

    links = soup.find_all('a')
    features["nb_hyperlinks"] = len(links)

    internal_links = []
    external_links = []
    null_links = []
    safe_anchors = []

    base_url = f'://{features_overall["netloc"]}'

    for link in links:
        href = link.get('href')
        if not href or href.strip() == '':
            null_links.append(href)
        else:
            if href.startswith('#'):
                safe_anchors.append(href)
            if href.startswith('/') or base_url in href or href.startswith('#'):
                internal_links.append(href)
            else:
                external_links.append(href)
    features["ratio_intHyperlinks"] = len(internal_links) / features["nb_hyperlinks"] if features["nb_hyperlinks"] > 0 else 0
    features["ratio_extHyperlinks"] = len(external_links) / features["nb_hyperlinks"] if features["nb_hyperlinks"] > 0 else 0
    features["ratio_nullHyperlinks"] = len(null_links) / features["nb_hyperlinks"] if features["nb_hyperlinks"] > 0 else 0
    features["ratio_safe_anchors"] = len(safe_anchors) / features["nb_hyperlinks"] if features["nb_hyperlinks"] > 0 else 0


    ext_css_links = []
    for link in soup.find_all('link', rel='stylesheet'):
        dots = [x.start(0) for x in re.finditer('\.', link['href'])]
        if not (features_overall["hostname"] in link['href'] or features_overall["domain"] in link['href'] or len(dots) == 1 or not link['href'].startswith('http')):
            ext_css_links.append(link['href'])

    features["nb_extCSS"] = len(ext_css_links)

  except requests.RequestException as e:
    print(e)
  if listOrDict:
    return features.values()
  else:
    features_overall.update(features) # Directly updates overall dictionary with current features
    return features #Returns only current features

def interaction_features(features_overall, response, listOrDict=False):
  features = {
        "onmouseover": None,
        "right_click_disabled": None,
        "empty_title": None,
        "domain_in_title": None,
        "domain_with_copyright": None
  }
  try:
    url = features_overall["url"]

    '''
    response = requests.get(url)
    response.raise_for_status()  # Raise an error for bad status codes
    '''
    soup = BeautifulSoup(response.text, 'html.parser')

    content = soup.get_text()
    features["onmouseover"] = ('onmouseover="window.status=' in str(content).lower().replace(" ",""))


    if "contextmenu" in response.text or soup.find_all(oncontextmenu=True):
        features["right_click_disabled"] = True
    else:
        features["right_click_disabled"] = False

    title = ""
    try:
        title = soup.title.string
        if not title or not title.strip():
            features["empty_title"] = True
        else:
            features["empty_title"] = False
    except:
        features["empty_title"] = True

    domain = features_overall['domain']
    if domain and title and domain in title:
        features["domain_in_title"] = True
    else:
        features["domain_in_title"] = False

    try:
        content = str(content)
        m = re.search(u'(\N{COPYRIGHT SIGN}|\N{TRADE MARK SIGN}|\N{REGISTERED SIGN})', content)
        _copyright = content[m.span()[0]-50:m.span()[0]+50]
        if domain.lower() in _copyright.lower():
            features["domain_with_copyright"] = False
        else:
            features["domain_with_copyright"] = True
    except:
        features["domain_with_copyright"] = False


  except requests.RequestException as e:
    print(e)
  if listOrDict:
    return features.values()
  else:
    features_overall.update(features) # Directly updates overall dictionary with current features
    return features #Returns only current features

import json

def whois_features(features_overall, listOrDict=False):
  features = {
      "whois_registered_domain": None,
      "domain_registration_length": None,
      "domain_age": None
  }
  try:
    url = features_overall["url"]

    domain_with_tld = features_overall["domain"] + "." + features_overall["tld"]
    domain = whois.whois(domain_with_tld)
    features["whois_registered_domain"] = True
    if type(domain.domain_name) == list:
            for host in domain.domain_name:
                if re.search(host.lower(), domain_with_tld):
                    features["whois_registered_domain"] = False
                    break
    else:
        if re.search(domain.domain_name.lower(), domain_with_tld):
              features["whois_registered_domain"] = False

    if domain.creation_date:
        if type(domain.creation_date)==list:
          creation_date=domain.creation_date[0]
        else:
          creation_date=domain.creation_date

    if domain.expiration_date:
        try:
          if type(domain.expiration_date)==list:
            expiration_date = min(domain.expiration_date)
          else:
            expiration_date = domain.expiration_date



          std_date = datetime.strptime("2024-08-01", '%Y-%m-%d')
          registration_length = abs((expiration_date - std_date).days)

          features["domain_registration_length"] = registration_length
        except Exception as e:
          print(e)
          features["domain_registration_length"] = -1
    else:
        features["domain_registration_length"] = 0

    if domain.creation_date:
        today = datetime.now()
        domain_age = (today - creation_date).days
        features["domain_age"] = domain_age



  except requests.RequestException as e:
    print(e)
  except:
    pass
  if listOrDict:
    return features.values()
  else:
    features_overall.update(features) # Directly updates overall dictionary with current features
    return features #Returns only current features

def get_web_traffic_and_index_features(features_overall, listOrDict=False):
    features = {
      "web_traffic": None,
      "dns_record": None,
      "google_index": None,
    }

    url = features_overall["url"]
    domain = features_overall["hostname"]

    try:
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
        features["web_traffic"] = int(rank)
    except:
        features["web_traffic"] = 0



    domain_with_tld = features_overall["domain"] + "." + features_overall["tld"]
    try:
        nameservers = dns.resolver.query(domain_with_tld, 'NS')
        if len(nameservers) > 0:
            features["dns_record"] = False
        else:
            features["dns_record"] = True
    except:
        features["dns_record"] = True


    user_agent =  'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'
    headers = {'User-Agent' : user_agent}
    query = {'q': 'site:' + url}
    google = "https://www.google.com/search?" + urlencode(query)
    data = requests.get(google, headers=headers)
    data.encoding = 'ISO-8859-1'
    soup = BeautifulSoup(str(data.content), "html.parser")
    try:
        if 'Our systems have detected unusual traffic from your computer network.' in str(soup):
            features["google_index"] = -1
        else:
            check = soup.find(id="rso").find("div").find("div").find("a")
            if check and check['href']:
                features["google_index"] = 0
            else:
                features["google_index"] = 1
    except AttributeError:
        features["google_index"] = 1


    if listOrDict:
      return features.values()
    else:
      features_overall.update(features) # Directly updates overall dictionary with current features
      return features #Returns only current features

def script_frame_features(features_overall, soup, listOrDict=False):
  features = {
      "sfh" : None,
      "iframe" : None,
      "popup_window" : None
  }
  try:
    url = features_overall["url"]
    baseurl = f'://{features_overall["netloc"]}'
    forms = soup.find_all('form')
    sfh = 0 # Legitimate
    for form in forms:
      action = form.get('action')
      if action in [None, "", "about:blank", "javascript::void(0)", "javascript::void(0);", "javascript::;", "javascript"]:
        sfh = 1 # Phishing
        break
      elif not (baseurl in action or action.startswith('/')):
        sfh = 0.5 # Suspicious
    features["sfh"] = sfh


    features["iframe"] = False
    for iframe in soup.find_all('iframe', width=True, height=True, frameborder=True):
      if iframe['width'] == "0" and iframe['height'] == "0" and iframe['frameborder'] == "0":
        features["iframe"] = True
        break
    if not features["iframe"]:
      for iframe in soup.find_all('iframe', width=True, height=True, border=True):
        if iframe['width'] == "0" and iframe['height'] == "0" and iframe['border'] == "0":
          features["iframe"] = True
          break
    if not features["iframe"]:
      for iframe in soup.find_all('iframe', width=True, height=True, style=True):
        if iframe['width'] == "0" and iframe['height'] == "0" and iframe['style'] == "0":
          features["iframe"] = True
          break

    scripts = soup.find_all('script')
    features["popup_window"] = False
    features["popup_window"] = any('window.open' in script.text for script in scripts)
    if not features["popup_window"]:
      content = soup.get_text()
      if "prompt(" in str(content).lower():
        features["popup_window"] = True

  except requests.RequestException as e:
    print(e)
  if listOrDict:
    return features.values()
  else:
    features_overall.update(features) # Directly updates overall dictionary with current features
    return features #Returns only current features

def get_page_features(features_overall, soup, listOrDict=False):
  features = {
      "login_form": None,
      "external_favicon": False,
      "links_in_tags": None,
      "submit_email": False,
      "ratio_intMedia": None,
      "ratio_extMedia": None
  }
  try:
    url = features_overall["url"]

    forms = soup.find_all('form', action=True)
    for form in forms:
        input_types = [input_.get('type', '').lower() for input_ in form.find_all('input')]
        if 'password' in input_types or 'pass' in input_types:
            features["login_form"] = True
            break
        features["login_form"] = False

    favicon_link = soup.find('link', rel=lambda x: x and 'icon' in x.lower())
    if favicon_link:
        favicon_url = favicon_link.get('href')
        if favicon_url:
            parsed_favicon_url = urlparse(favicon_url)
            if parsed_favicon_url.netloc and parsed_favicon_url.netloc != urlparse(url).netloc:
                features["external_favicon"] = True


    features["links_in_tags"] = len(soup.find_all('a'))

    for form in forms:
        action = form.get('action')
        if (action and 'mailto:' in action) or "mailto:" in form or "mail()" in form:
            features["submit_email"] = True
            break

    media_tags = soup.find_all(['img', 'audio', 'video', 'source', 'embed', 'iframe'])
    internal_media = 0
    external_media = 0
    domain = urlparse(url).netloc

    for tag in media_tags:
        media_url = tag.get('src') or tag.get('data-src')
        if media_url:
            media_url = urljoin(url, media_url)
            media_domain = urlparse(media_url).netloc
            if media_domain == domain:
                internal_media += 1
            else:
                external_media += 1

    total_media = internal_media + external_media
    if total_media > 0:
        features["ratio_intMedia"] = internal_media / total_media
        features["ratio_extMedia"] = external_media / total_media

  except requests.RequestException as e:
    print(e)
  if listOrDict:
    return features.values()
  else:
    features_overall.update(features) # Directly updates overall dictionary with current features
    return features #Returns only current features

def extract_features_per_url(index, url):
  try:
    features_overall = {}
    features_overall = initialize(features_overall)
    features_overall['index'] = index
    features_overall['url'] = url
    extract_url_components(features_overall, False)
    get_url_features(features_overall, False)
    url_char_count(features_overall, False)
    path_hostname_features(features_overall, False)
    word_features(features_overall, False)
    phish_identity_features(features_overall, False)
    whois_features(features_overall, False)
    get_web_traffic_and_index_features(features_overall, False)


    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    interaction_features(features_overall, response, False)
    hyperlink_css_feaures(features_overall, soup, False)
    get_page_features(features_overall, soup, False)
    script_frame_features(features_overall, soup, False)
  except:
    pass
  return features_overall # Directly updates overall dictionary with current features

def final_features_extraction(input_url):
  fieldnames = [
        "index", "url", "scheme", "hostname", "path", "netloc", "domain", "subdomains", "tld",
        "length_url", "length_hostname", 'ip', 'path_extension',
        "nb_dots", "nb_hyphens", "nb_at", "nb_qm", "nb_and", "nb_or", "nb_eq", "nb_underscore", "nb_tilde", "nb_percent", "nb_slash", "nb_star", "nb_colon", "nb_comma", "nb_semicolumn", "nb_dollar", "nb_space", "nb_www", "nb_com", "nb_dslash", "nb_spl",
        "http_in_path", "https_token", "ratio_digits_url", "ratio_digits_host", "punycode", "port", "tld_in_path", "tld_in_subdomain", "abnormal_subdomain", "nb_subdomains", "prefix_suffix", "random_domain", "shortening_service",
        "length_words_raw", "char_repeat", "shortest_words_raw", "shortest_word_host", "shortest_word_path", "longest_words_raw", "longest_word_host", "longest_word_path", "avg_words_raw", "avg_word_host", "avg_word_path",
        "phish_hints", "domain_in_brand", "brand_in_subdomain", "brand_in_path", "suspicious_tld",
        "nb_hyperlinks", "ratio_intHyperlinks", "ratio_extHyperlinks", "ratio_nullHyperlinks", "ratio_safe_anchors", "nb_extCSS",
        "onmouseover", "right_click_disabled", "empty_title", "domain_in_title", "domain_with_copyright",
        "whois_registered_domain", "domain_registration_length", "domain_age",
        "web_traffic", "dns_record", "google_index",
        "sfh", "iframe", "popup_window",
        "login_form", "external_favicon", "links_in_tags", "submit_email", "ratio_intMedia", "ratio_extMedia"
      ]
  currentTime = datetime.now()
  features_overall_list = []
  for url_index in (range(len(input_url))):
    sleep(.1)
    try:
      url = input_url[url_index]
      features_overall = {}
      features_overall = extract_features_per_url(url_index, url)
      features_overall_list.append(features_overall)
      json_out = json.dumps(features_overall)
      print(json_out)
      return json_out
    except:
      pass

  print("Done!")
    
print("done")
