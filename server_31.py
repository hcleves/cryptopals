from flask import Flask
from flask import request
import time
from Crypto import Random
import hashlib

secret_key = Random.get_random_bytes(16);
print(secret_key)
app = Flask(__name__)

@app.route("/")
def hello():
    return "Hello World!there"

def insecure_compare(filename,signature):
    mac = hashlib.sha1(secret_key + open(filename,'r').read().encode('ascii')).digest().hex()
    print(mac)
    #return mac
    if len(mac)!=len(signature):
        raise Exception('size not equal')
    for i in zip(mac,signature):
        if i[0] != i[1]:
            raise Exception()
            break;
        time.sleep(0.05)
    else:
        return 'mac correto'
    

@app.route("/test")
def test():
    filename = request.args.get('file')
    signature = request.args.get('signature')
    #print(arquivo.read())
    #arquivo.seek(0)
    return insecure_compare(filename,signature)

app.run(port=9000,use_reloader=False)
