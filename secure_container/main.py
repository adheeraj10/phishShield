import json
import redis
import threading
from getparams import final_features_extraction

RedisPort=6379
redisClient=redis.Redis("localhost",RedisPort)




if __name__ =="__main__":
    print(redisClient.info())
    print("helloworld")
    while True:
        if(redisClient.llen("UrlQueue")>0):
            currentUrlJsonString= redisClient.lpop("UrlQueue")
            urlDict=json.loads(currentUrlJsonString)
            url=[]
            url.append(urlDict.get("url"))
            print(url)
            params_dict=final_features_extraction(url)
            print(params_dict)
            redisClient.rpush("paramsQueue",json.dumps(params_dict))
            

    
