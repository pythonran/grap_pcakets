import daemon
from scapy.all import *
import MySQLdb
import connectdb,readfilter
import time
import exceptions
import signal

s = None
testcode = False

class single_sniff(daemon.Daemon):

    def __init__(self, sfilter="", count=-1, pktcs=0, filesize=0):

        super(single_sniff,self).__init__()
        self.sfilter = sfilter
        self.id = 0
        self.pkt_count = 0
        self.pktcs = pktcs
        self.stime = 0
        self.otime = 0
        self.drop_count = 0
        self.filename = ''
        self.filepath = ''
        self.count = count
        self.filesize = filesize
        self.nowtimesamp = time.time()


    def run(self):

        print "=" * 150
        print "\n\tStart monite time: %s\n" % time.strftime("%Y-%m-%d %H-%M-%S",time.localtime(self.nowtimesamp))
        os.chdir("/tmp/.EasyScapy")

        if not os.path.exists("/tmp/.EasyScapy/pcapfiles"):

            os.system("mkdir pcapfiles")
            os.chdir("/tmp/.EasyScapy/pcapfiles")
            self.filepath = "/tmp/.EasyScapy/pcapfiles/"

        else:

            self.filepath = "/tmp/.EasyScapy/pcapfiles/"

        try:

            #print self.sfilter,"1"

            if self.sfilter != '':

                print self.sfilter,"2"
                sniff(filter=self.sfilter, prn = self.wto_pcap)

            else:

                #print self.sfilter,"3"
                sniff(prn = self.wto_pcap)

        except exceptions.Exception,e:

            print e

    def stop(self,signalnum,handler):

        if self.count == 0:

            print "\n~~~~~~~The process exited beacause of sniff_count is zero~~~~~~~~~~"

        else:

            print "The sniffer stop, receive a stop signal"

        #deal with some data that can't arrive the count of pktcs


        if self.pkt_count < self.pktcs and self.filename != '':

            print "Dropped %d packages \n" % self.drop_count

            print "\n=====>Truncted pktcs = %d" % self.pkt_count

            truncted_size = os.path.getsize(self.filename)
            putdb(self.id + 1,self.filename,self.stime,self.otime,truncted_size,self.pkt_count)

            print "=====>The Truncted pcapifle has been put into database!"
        else:
            pass

        print "\n\tStop montie time:%s" % time.strftime("%Y-%m-%d %H-%M-%S",time.localtime(time.time()))
        print "=" * 150

        super(single_sniff,self).stop()


    def wto_pcap(self,pkt):

        #check the tiemscamp
        try:

            if connectdb.localhost not in (pkt[IP].src,pkt[IP].dst):

                filter_ip = (pkt[IP].src,pkt[IP].dst)
                filter_ip = set(filter_ip)
                s1 = filter_ip | set(['test'])
            else:
                filter_ip = set([0])
                s1 = set(['test'])

        except:

            filter_ip = set(["ipv6 or arp"])
            s1 = filter_ip | set(['test'])
        #print testcode
        if not testcode:
            s1 = set(readfilter.readfilter()["ip"])

        if pkt.time < self.nowtimesamp or not filter_ip < s1:

                self.drop_count += 1

        else:#valid packets

            self.count -= 1
            self.pkt_count += 1

            if self.pkt_count % self.pktcs == 1:

                self.stime = pkt.time
                self.filename = self.filepath + "%s.pcap"  % self.stime
                wrpcap(self.filename,pkt,append=True)

            elif not self.pkt_count % self.pktcs:# when pkt_count is integer times of pktcs ,will put in storage

                self.id += 1                     #pcap files id auto increment 1
                self.otime = pkt.time
                wrpcap(self.filename,pkt,append=True)
                self.filesize = os.path.getsize(self.filename)
                putdb(self.id,self.filename,self.stime,self.otime,self.filesize,self.pkt_count)
                self.filename = ''
                self.pkt_count = 0

            else:

                self.otime = pkt.time # perhaps will be truncted,the time will be the over time
                wrpcap(self.filename,pkt,append=True)


            if self.count == 0:
                self.stop(0,0)
            else:
                pass


def putdb(id,f,s,o,fs,pc):

    conn = connectdb.connection()
    filepath = "'" + f.split('/')[-1] + "'"
    cur = conn.cursor()
    maxid_sql = "select max(id) from EasyScapy;"
    ids = id

    while 1:

        try:

            insert_sql = "insert into EasyScapy values(%d,%s,%f,%f,%d,%d);" % (ids,filepath,s,o,fs,pc)
            cur.execute(insert_sql)
            conn.commit()
            cur.close()
            conn.close()
            break

        except MySQLdb.DatabaseError,de:

            if de[0] == 1062:
                cur.execute(maxid_sql)
                for a in cur.fetchone():
                    ids = a + 1
                continue
            else:
                print de


def manage(*args):

    global s,testcode

    filter = ''
    pktcs = 0
    count = -1
    filesize = 0
    main_params = args[0][1]


    if len(args[0]) > 2:

        for params in args[0][2:]:

            if "filter" in params:

                exec(params.split('=')[0] + '=' + "'" + params.split("=")[1] + "'")

            elif "count" in params:

                exec(params)

            elif "pktcs" in params:

                exec(params)

            elif "filesize" in params:

                exec(params)
                if filesize > 0:

                    filesize = filesize * 1024 * 1024
            elif "test" in params:
                 #print testcode
                 testcode = True
                 #print "changed--->",testcode

            else:

                raise SyntaxError("python start_sniff.py start | stop | restart [filter=""] [count=] [pktcs=]")

    if pktcs and filesize:

        print "pktcs or filesize,only one choice!"
        pktcs = 200
        filesize = 0

    elif not pktcs and not filesize:

        print "pktcs doesn't set,will use default 1000"
        pktcs = 1000
        filesize = 0

    else:
        pass

    s = single_sniff(filter,count,pktcs,filesize)
    signal.signal(signal.SIGUSR1,s.stop)

    if main_params == 'start':

        s.start()

    elif main_params == 'stop':

        pass

    elif main_params == 'restart':

        s.start()

    else:

        raise SyntaxError("python start_sniff.py start | stop | restart [filter=""] [count=] [pktcs=]")


def send_stop():

    print "stop signal"

    if os.path.exists("/tmp/.EasyScapy/expid.pid"):

        try:

            fp = open("/tmp/.EasyScapy/expid.pid","r")
            pid = int(fp.read().strip())
            fp.close()

        except IOError,err:

            pid = None
            print err
            sys.exit(1)

        os.kill(pid,signal.SIGUSR1)

    else:

        print "not exsit,not running!\n"


if __name__ == "__main__":

    if len(sys.argv) >= 2:

        if sys.argv[1] == 'start':

            manage(sys.argv)

        elif sys.argv[1] == 'stop':

            send_stop()

        elif sys.argv[1] == 'restart':

            send_stop()
            manage(sys.argv)

        else:

            raise SyntaxError("python start_sniff.py start | stop | restart [filter=""] [count=] [pktcs=]")

    else:

        raise SyntaxError("python start_sniff.py start | stop | restart [filter=""] [count=] [pktcs=]")

