from flask import Flask
from flask import request
import time
import hashlib
import random as rnd

#Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3
email = 'cryptopals@gmail.com'
password = 'secret_password'

class networknode():
    def __init__(self,N,g,k,password):
        self.N = N
        self.g = g
        self.k = k
        self.password = password
        self.salt = None
        self.v = None
        self.private = rnd.randint(0,99999999)
        self.A = None
        self.B = None
        self.u = None
        self.K = None
        
    def send_public_key(self):
        return pow(self.g,self.private,self.N)
    
    def compute_hash_sum(self):
        ##Compute string uH = SHA256(A|B), u = integer of uH
        uH = hashlib.sha256((str(self.A)+str(self.B)).encode('ascii')).hexdigest()
        self.u = int(uH,16)
        
    def send_k(self):
        return hashlib.sha256((str(self.K)+str(self.salt)).encode('ascii')).hexdigest()
    
    def verify_k(self,k):
        return k == self.send_k()

class server(networknode):
    def first_step(self):
        #Generate salt as random integer
        self.salt = rnd.randint(0,999999);
        #Generate string xH=SHA256(salt|password)
        xH = hashlib.sha256((str(self.salt) + self.password).encode('ascii')).hexdigest()        
        #Convert xH to integer x somehow (put 0x on hexdigest)
        x = int(xH,16)
        #Generate v=g**x % N
        self.v = pow(self.g,x,self.N)
        #Save everything but x, xH

        ## this is supposed to be in the send_salt function but I needed to change it
        self.B = self.k*self.v + self.send_public_key()
        
    def receive_public_key(self,public_key):
        self.A = public_key
        
    def send_salt(self):
        #Send salt, B=kv + g**b % N
        # not necessary right now
        # self.B = self.k*self.v + self.send_public_key()
        return [self.salt,self.B]
    
    def final_step(self):
        #Generate S = (A * v**u) ** b % N
        S = pow(self.A*pow(self.v,self.u,self.N),self.private,self.N)
        print('Server S',S) ## to visualize the attack, in reality the server S is hidden
        #Generate K = SHA256(S)
        self.K = hashlib.sha256(str(S).encode('ascii')).hexdigest()

server_obj = server(N,g,k,password)

app = Flask(__name__)

@app.route("/")
def hello():
    return "Hello World!there"
    

@app.route("/test")
def test():
    
    if request.args.get('reset'): 
        global server_obj 
        server_obj = server(N,g,k,password)
        return 'resetted'

    if request.args.get('init'):
        server_obj.first_step()
    
    if request.args.get('public_key'):
        public_key = request.args.get('public_key')
        public_key=int(public_key)
        server_obj.receive_public_key(public_key)
        server_obj.compute_hash_sum()
        server_obj.final_step()
        salt = server_obj.send_salt()
        return ','.join(map(str,salt))
    
    if request.args.get('k'):
        K=request.args.get('k')
        return str(server_obj.verify_k(K))

    return "something is wrong in the sintax"

app.run(port=9000,use_reloader=False)