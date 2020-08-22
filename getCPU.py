import psutil
import os,datetime,time

def getMemCpu():

        data = psutil.virtual_memory()
        total = data.total
        free = data.available
        #memory =  "Memory usage:%d"%(int(round(data.percent)))+"%"+"  "
        cpu = "CPU:%0.2f"%psutil.cpu_percent(interval=1)+"%"
        return cpu

def main():
    #print datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    info = getMemCpu()
    print(info)
if __name__=="__main__":



    main()
    #fullInfor()
