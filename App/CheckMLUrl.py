from functools import wraps
from flask import Flask
from flask import request, Response
from subprocess import call
from flask import render_template

from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
import pandas as pd
import numpy as np
import random
from sklearn.feature_extraction.text import TfidfVectorizer
import sys
import os
from sklearn.linear_model import LogisticRegression
import json
import math
from collections import Counter
from pathlib import Path
import logging

def read_url_data(filepath):
    return pd.read_csv(
        filepath,
        delimiter=',',
        on_bad_lines='skip'  # Updated parameter
    )

class malicious_url_ML:

    def __init__(self, url):
        self.url = url
        self.current_dir = os.path.dirname(os.path.abspath(__file__))
        self.base_dir = os.path.dirname(self.current_dir)  # Go up one level from App/
        self.data_file = os.path.join(self.base_dir, 'data', 'data.csv')
        
        # Setup logging
        logging.basicConfig(level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"Data file path: {self.data_file}")

    def entropy(self,s):
        p, lns = Counter(s), float(len(s))
        return -sum( count/lns * math.log(count/lns, 2) for count in p.values())
        

    def run(self):
        try:
            # Verify file existence
            if not os.path.exists(self.data_file):
                alt_path = os.path.join(os.getcwd(), 'data', 'data.csv')
                if os.path.exists(alt_path):
                    self.data_file = alt_path
                else:
                    raise FileNotFoundError(f"Data file not found in either {self.data_file} or {alt_path}")

            vectorizer, lgs, score = self.TL()
            X_predict = [str(self.url)]  # Use self.url instead of self.path
            X_predict = vectorizer.transform(X_predict)
            y_Predict = lgs.predict(X_predict)

            # Return results as dictionary
            results = {
                "url": self.url,  # Changed from path to url
                "prediction": str(y_Predict[0]),
                "confidence": str(round(score * 100, 2))
            }
            
            return results

        except Exception as e:
            self.logger.error(f"Error in run(): {str(e)}")
            raise


    def getTokens(self ,input):
        tokensBySlash = str(input.encode('utf-8')).split('/')	#get tokens after splitting by slash
        allTokens = []
        for i in tokensBySlash:
            tokens = str(i).split('-')	#get tokens after splitting by dash
            tokensByDot = []
            for j in range(0,len(tokens)):
                tempTokens = str(tokens[j]).split('.')	#get tokens after splitting by dot
                tokensByDot = tokensByDot + tempTokens
            allTokens = allTokens + tokens + tokensByDot
        allTokens = list(set(allTokens))	#remove redundant tokens
        if 'com' in allTokens:
            allTokens.remove('com')	#removing .com since it occurs a lot of times and it should not be included in our features
        #print(allTokens)
        return allTokens

    def TL(self):
        try:
            if not os.path.exists(self.data_file):
                raise FileNotFoundError(f"Data file not found at: {self.data_file}")
            
            # Read and process data
            allurlsdata = pd.read_csv(self.data_file, delimiter=',', on_bad_lines='skip')
            allurlsdata = np.array(allurlsdata)
            random.shuffle(allurlsdata)
            
            # Extract URLs and labels
            urls = [d[0] for d in allurlsdata]
            y = [d[1] for d in allurlsdata]
            
            # Initialize and fit vectorizer
            vectorizer = TfidfVectorizer(tokenizer=self.getTokens)
            X = vectorizer.fit_transform(urls)
            
            # Initialize and train logistic regression
            lgs = LogisticRegression(max_iter=1000)
            lgs.fit(X, y)
            
            # Calculate score
            score = lgs.score(X, y)
            
            return vectorizer, lgs, score
            
        except Exception as e:
            self.logger.error(f"Error in TL(): {str(e)}")
            raise
