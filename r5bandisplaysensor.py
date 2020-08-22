import errno
import socket
import time
import random
import hmac


from time import clock
from collections import OrderedDict
from ecc.Key import Key
from hashlib import sha256,md5
from ecc.elliptic import mul,add,neg
from time import clock
from getCPU import getMemCpu, main

DOMAINS = {
    # Bits : (p, order of E(GF(P)), parameter b, base point x, base point y)

    256: (0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffL,
          0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551L,
          0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bL,
          0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296L,
          0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5L)
}

if __name__== '__main__':

    global Ra,Tb,p,n,b,x,y,c_p,c_q,c_n,M1,M2,M3,Ka,macb
    server_ip = '192.168.137.225'
    server_port = 6633

    # initialization
    p, n, b, x, y = DOMAINS[256]
    c_p = 3
    c_n = p
    c_q = p - b
    idA='00000001'
    idB='00000002'
    token=0


    # TCP connection to responder B
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(1)
    print('begin connection')
    sock.connect((server_ip, server_port))

    try:
        while (token==0):
            print('connection up')
            print ('connected')
            # 1. A side: send M1=(B,A,Na,PKax,PKay) to B
            time1=time.time()
            # 1.1) generate my (A) keypair PKa SKa
            keypair = Key.generate(256)
            PKax = keypair._pub[1][0]
            PKay = keypair._pub[1][1]
            PKa = (PKax,PKay)
            SKa = keypair._priv[1]
            # 1.2) generate my (A) nonce Na
            Na=random.randint(000000,999999)
            # 1.3) compute ca
            stringca=str(Na)+idA+idB+str(PKax)+str(PKay)
            newmd5=md5()
            newmd5.update(stringca)
            ca=newmd5.hexdigest()
            time1=time.time()-time1
            # 1.4) A->B: M1=(B,A,ca,PKax,PKay)
            M1=idA+','+idB+','+ca+','+str(PKax)+','+str(PKay)
            sock.send(M1)


            main()
            # 3. A side: 1)receive M2, 2)compute Ka, 3)compute maca,macb_check 4)send M3 5)compute and show diga
            # 3.1) receive M2 from B, M2=(A,B,Nb,PKbx,PKby)
            M2 = sock.recv(1024)
            Nb = M2.split(',')[2]
            PKbx = M2.split(',')[3]
            PKby = M2.split(',')[4]
            macb=M2.split(',')[5]
            PKb = (long(PKbx),long(PKby))
            # 3.2) compute Ka
            time2=time.time()
            Ka=mul(c_p,c_q,c_n,PKb,SKa)
            # 3.3) compute maca,macb_check
            hmac_stringb=idA+idB+str(ca)+Nb
            newhash=hmac.new(str(Ka[0]),'',sha256)
            newhash.update(hmac_stringb)
            macb_check=newhash.hexdigest()
            if macb_check==macb:
                hmac_stringa=idB+idA+Nb+str(ca)
                newhash=hmac.new(str(Ka[0]),'',sha256)
                newhash.update(hmac_stringa)
                maca=newhash.hexdigest()
                time2=time.time()-time2
                # 3.4) A->B: M3=(Na,maca)
                M3=str(Na)+','+maca
                sock.send(M3)
                main()
                # 3.5) compute and show diga
                time3=time.time()
                hmac_stringa=str(Na)+str(Nb)
                newhash=hmac.new(str(Ka[0]),'',sha256)
                newhash.update(hmac_stringa)
                diga=newhash.hexdigest()[0:4]
                print ('digest is',diga)
                time3=time.time()-time3
                print ('computation time on A is', time1+time2+time3)
                main()
            else:
                print 'macb is invalid, protocol fails'

            token=1

    except KeyboardInterrupt:
        s.close()
        print("KeyboardInterrupt")
    #sys.exit(0)
