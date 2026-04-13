from sklearn.ensemble import RandomForestClassifier
import joblib
import json
import redis
import time
from classify import extract

RedisPort = 6379
redisClient = redis.Redis("localhost", RedisPort)

rf_classifier = joblib.load("rf.joblib")

def predict(features_df):
    prediction = rf_classifier.predict(features_df)
    result = "legit" if not prediction[0] else "phishing"
    print(result)
    return result

if __name__ == "__main__":
    while True:
        if(redisClient.llen("paramsQueue") > 0):
            json_str = redisClient.lpop("paramsQueue")
            features = extract(json.loads(json.loads(json_str)))
            fts = json.loads(json.loads(json_str))
            print(features)
            print(features.head())
            print(fts['url'])

            
            prediction = predict(features)
            
            redisClient.hset("url_predictions", fts['url'], prediction)
