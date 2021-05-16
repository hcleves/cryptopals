from flask import Flask
from flask import request
import time
from Crypto import Random
import hashlib

secret_key = Random.get_random_bytes(16);
print(secret_key)
app = Flask(__name__)

mac = hashlib.sha1(secret_key + open('31.txt','r').read().encode('ascii')).digest().hex()
print(mac)
@app.route("/")
def hello():
    return "Hello World!there"

def insecure_compare(filename,signature):
    mac = hashlib.sha1(secret_key + open(filename,'r').read().encode('ascii')).digest().hex()
    #return mac
    if len(mac)!=len(signature):
        raise Exception('size not equal')
    for i in zip(mac,signature):
        if i[0] != i[1]:
            break;
        time.sleep(0.005)
    else:
        return 'right mac'
    return 'wrong mac'
    

@app.route("/test")
def test():
    arquivo_nome = request.args.get('file')
    signature = request.args.get('signature')
    #print(arquivo.read())
    #arquivo.seek(0)
    return insecure_compare(arquivo_nome,signature)

app.run(port=9000,use_reloader=False)
