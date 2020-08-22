#import serial
import socket
import time
import random
import hmac

from collections import OrderedDict
from ecc.Key import Key
from hashlib import sha256,md5
from ecc.elliptic import mul,add,neg
from ecc.curves import get_curve
from time import clock
from secret_code import SKb, refresh
from getCPU import getMemCpu, main

DOMAINS = {
    # Bits : (p, order of E(GF(P)), parameter b, base point x, base point y)
    192: (0xfffffffffffffffffffffffffffffffeffffffffffffffffL,
          0xffffffffffffffffffffffff99def836146bc9b1b4d22831L,
          0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1L,
          0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012L,
          0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811L),

    224: (0xffffffffffffffffffffffffffffffff000000000000000000000001L,
          0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3dL,
          0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4L,
          0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21L,
          0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34L),

    256: (0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffL,
          0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551L,
          0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bL,
          0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296L,
          0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5L),

    384: (0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffL,
          0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973L,
          0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefL,
          0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7L,
          0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fL),

    521: (0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffL,
          0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409L,
          0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00L,
          0x0c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66L,
          0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650L)
}

if __name__ == '__main__':
    global Ta,Rb,p,n,b,x,y,c_p,c_q,c_n,M1,M2,M3,Kb
    HOST = '192.168.1.52'
    PORT = 6633

    # initialization
    #domains can be: 192, 224, 256, 384, 521.
    p, n, b, x, y=DOMAINS[384]
    c_p=3
    c_n=p
    c_q=p-b
    idB='00000002'
    token=0
    '''
    # hold my (B responder) public and private key before protocol (now192)
    PKbx = '1349658467515320701921659752732152240354375423855739690674'
    PKby = '4515325918432594848595639212143663437016019324829317013809'
    #SKb =  '2537671920264247347511294305317194211631119753181094714165'
    # hold opposite (A inintiator) public key before protocol
    PKax = '2186307416692821602444406316960632900784642693461264017317'
    PKay = '4937537242014238987973323999068482274203061546240678451951'
    '''

    '''
    # hold my (B responder) public and private key before protocol (now224)
    PKbx = '14863750220269932860620908117452438020456565468374300958784903497732'
    PKby = '25294879033850335409156854085896585664562146735245673957699322498746'
    #SKb =  '25817389882830585410204201385303085920389903136831081254892352935156'
    # hold opposite (A inintiator) public key before protocol
    PKax = '11522381640785911886488352922736175261022497145074929857020088567392'
    PKay = '14180707140750524244641858785676749145242447161785060390799732582487'
    '''


    '''
    # hold my (B responder) public and private key before protocol(now256)
    PKbx = '70499151004428948375443964276462167005180379916095893136035080585036319412993'
    PKby = '89159314490905239990291927449646392727158132606153429307077101942859474650551'
    #SKb =  '51413945648215324392114854853632631663994365249529413551068690885355810089324'
    # hold opposite (A inintiator) public key before protocol
    PKax = '58200100553285754909435931111358550742513155648664913327079108046354304627314'
    PKay = '58146441060549666708606022895109493355305616466548478734029438001714766503670'
    '''

    # hold my (B responder) public and private key before protocol (now384)
    PKbx = '27369108195799027719434407505819944483080826175793687060361788028028935089393694378890064466968244317857634139521981'
    PKby = '33262142114729326980607654126872414691937290263466399428431277941309713650051154129957606162524628979585456761397516'
    #SKb =  '34288621456883794577355939905532148832267232723655012712919697571141442900355296218117839127319349574442586185936464'
    # hold opposite (A inintiator) public key before protocol
    PKax = '28093510272340221828783178606777853348731733555737112229002056994444156223201620068061425193756507916216446535887326'
    PKay = '21600223195349114159230709608980599371505952942573382988644793923819311082521908617225355731751194973296480823540573'

    '''
    # hold my (B responder) public and private key before protocol (now521)
    PKbx = '5595010114488083113799033702886857011260512711101092510187706598082174710777221757366676479336523181858756364025126179169435943053166905711741908148360152928'

    PKby = '2662767361277878650053481099078901484354881461092329548514192443323774416160217024181693404931341022608638058584287980507869467496714598021835253803235413986'
    #SKb =  '313084650164140890762939337889357276991779455878898781458971668332846920676596562521144704685076285478407589388108394471213981464945584795693477075080660702'

    # hold opposite (A inintiator) public key before protocol
    PKax = '5485111885875635368168906262488623433781738211163600874844991094423877024876049251560711484037894221441129302962213183788827485949993025729032538333323633743'
    PKay = '4784215812224727228042498285087001514075387140315185495472567667504070259072550875759877620107881269619648888401169801825026366013897181131496245149414640954'
    '''

    '''# generate my keypair (be commented during connection)
    keypair = Key.generate(521)


    #PK
    print 'public keypair'
    print keypair._pub
    PKx = keypair._pub[1][0]
    PKy = keypair._pub[1][1]
    print 'PKx, PKy:', PKx, PKy

    #SK
    print 'private key'
    print keypair._priv

    print keypair._priv[0]
    print keypair._priv[1]
    SK = keypair._priv[1] '''
    #public key (PK) and private key (SK) has been replaced by Rn and Ln from 'storage.txt'

    f = open('storage.txt', 'r')
    sk = f.read()
    skList = sk.split(',')
    tup = refresh(skList[0],skList[1])
    Rn = tup[0]
    Ln = tup[1]

    #print skList
    #print Rn
    #print Ln
    #print Rn + Ln
    #print(getMemCpu())
    with open('storage.txt','w')as f:
        f.write(str(Rn)+","+str(Ln))

    print('Begin')

    #TCP link
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.bind((HOST,PORT))

    print('Listen to the connection from client...')
    sock.listen(5)
    try:
        while (token==0):
            connection, address = sock.accept()
            print'Connected. Got connection from ', address

            # 2. B side: 1)receive M1 from A, 2)compute cb 3)send M2
            M1=connection.recv(1024)
            idA=M1.split(',')[0]
            PKax=M1.split(',')[1]
            PKay=M1.split(',')[2]
            ca=M1.split(',')[3]
            PKa=(long(PKax),long(PKay))
            time1=time.time()
            Rb=random.randint(10000000,999999999)
            #Ub=Rb+long(SKb)

            Ub1=Rb+Rn
            Ub = Ub1 + Ln

            Tb=mul(c_p,c_q,c_n,(x,y),long(Ub))
            stringcb=idB+str(PKbx)+str(PKby)+str(Tb[0])+str(Tb[1])
            md5b=md5()
            md5b.update(stringcb)
            cb=md5b.hexdigest()
            time1=time.time()-time1

            M2=idB+','+str(PKbx)+','+str(PKby)+','+cb
            connection.send(M2)

            # 4. 1)receive M3, 2)verify ca, 3)send Ta, 4)compute K, 5)compute and show digest
            M3=connection.recv(1024)
            Ua=long(M3)
            time2=time.time()
            stringca=idA+str(PKax)+str(PKay)+str(Ua)
            md5a=md5()
            md5a.update(stringca)
            ca_check=md5a.hexdigest()
            if ca_check==ca:
                time2=time.time()-time2

                M4=str(Tb[0])+','+str(Tb[1])
                connection.send(M4)
                time3=time.time()
                Ta=mul(c_p,c_q,c_n,(x,y),Ua)
                negPKa=neg(PKa, c_n) # -PKa

                sum=add(c_p,c_q,c_n,negPKa,Ta) # Ta-PKa
                Kb=mul(c_p,c_q,c_n,sum,Rb) # Rb*(Ta-PKa)

                hmac_stringb=idA+idB+PKax+PKay+str(PKbx)+str(PKby)+str(Ua)+str(Tb[0])+str(Tb[1])
                newhash=hmac.new(str(Kb[0]),'',sha256)
                newhash.update(hmac_stringb)
                digb=newhash.hexdigest()[0:4]
                print 'digest is', digb
                time3=time.time()-time3

                print 'computation time on B is', time1+time2+time3

            else:
                print 'commita is invalid, protocol fails'

            token=1

    except KeyboardInterrupt:
        print('>>>quit')
    #sys.exit(0)
