import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import jaccard_score
from sklearn.metrics import f1_score
from sklearn.metrics import log_loss
from sklearn.metrics import classification_report,confusion_matrix,accuracy_score
import sklearn.metrics as metrics
from sklearn.inspection import permutation_importance
from scipy.stats import randint, uniform
import pickle
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
from sklearn.tree import DecisionTreeClassifier, export_graphviz, plot_tree, export_text
import joblib
import json

def extract(feature_dict):
  relevant_features_notnull = ['length_url', 'length_hostname', 'ip', 'path_extension', 'nb_dots', 'nb_hyphens', 'nb_at', 'nb_qm', 'nb_and', 'nb_eq', 'nb_slash','nb_colon', 'nb_semicolumn', 'nb_www', 'nb_com', 'nb_dslash', 'nb_spl', 'https_token', 'ratio_digits_url', 'ratio_digits_host','tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain', 'nb_subdomains', 'prefix_suffix', 'shortening_service', 'shortest_words_raw','shortest_word_host', 'shortest_word_path', 'longest_words_raw', 'longest_word_host', 'longest_word_path', 'avg_words_raw', 'avg_word_host','avg_word_path', 'phish_hints', 'domain_in_brand', 'suspicious_tld', 'dns_record']
  df=pd.DataFrame([feature_dict])
  df = df[relevant_features_notnull]
  return df
