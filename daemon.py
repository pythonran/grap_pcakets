from scapy.all import *
from django.http import HttpResponse
import os,sys,atexit,signal

class Daemon(object):

    def __init__(self,\
                    pidfile='/tmp/.EasyScapy/expid.pid',\
                    stdin='/dev/stdin',\
                    stdout='/tmp/.EasyScapy/outsniff.log',\
                    stderr='/tmp/.EasyScapy/stderror'):

        self.pidfile = pidfile

        os.chdir("/tmp/")

        if not os.path.exists("/tmp/.EasyScapy/"):

            os.system("mkdir .EasyScapy")

        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.saveout = sys.stdout
        self.saveerr = sys.stderr


    def _daemonize(self):

        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError,e:
            sys.stderr.write('fork #1 failed: %d (%s)\n' % (e.errno,e.strerror))
            sys.exit(1)

        os.chdir('/')
        os.setsid()
        os.umask(0)

        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
            pass
        except OSError,e:
            sys.stderr.write('fork #2 failed: %d (%s)' % (e.errno,e.strerror))
            sys.exit(1)

        sys.stdout.flush()
        sys.stderr.flush()
        si = file(self.stdin,'r')
        
        self.so = file(self.stdout,'a+')
        self.se = file(self.stderr,'a+',0)
        sys.stdout = self.so
        sys.stderr = self.se

        atexit.register(self.delpid)
        pid = str(os.getpid())
        fp = file(self.pidfile,'w+')
        fp.write('%s \n' %  pid)

    def delpid(self):

        try:
            os.remove(self.pidfile)
            print "delpid sucsessfully!"

        except:

            pass

    def start(self):

        self._daemonize()
        self.run()
        pass

    def stop(self):
	
        sys.stdout = self.saveout
        sys.stderr = self.saveerr
        self.so.close()
        self.se.close()

        try:

            pf = file(self.pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
            os.remove(self.pidfile)

        except IOError:
            pid = None

        if not pid:
            message = 'pidfile %s does not exist. Daemon not running!\n'
            sys.write(message % self.pidfile)
            return
        try:
            while 1:
                os.kill(pid,signal.SIGTERM)
                time.sleep(0.1)
        except OSError, err:
            err = str(err)
            if err.find('No such process') > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                print str(err)
                sys.exit(1)
        pass

    def restart(self):
        self.stop()
        self.start()
        pass

    def run(self):
        '''Subclass must .


        '''
