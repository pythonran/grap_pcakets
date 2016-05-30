import os,sys

def readfilter():

    if os.path.exists("/tmp/.EasyScapy/filter.dat"):

        filter = {}

        for line in open("/tmp/.EasyScapy/filter.dat","r+"):

            line = line.strip()

            if "ip" in line:

                filter["ip"] = []
                continue

            elif "port" not in line and "port" not in filter.keys():

                filter["ip"].append(line)
                continue

            elif "port" not in line:

                filter["port"].append(line)
                continue

            else:

                filter["port"] = []

        return filter

    else:

        print "Please make sure the filter configuration file path is correct!\
                /tmp/.EasyScapy/filter.dat!"

#print readfilter()












