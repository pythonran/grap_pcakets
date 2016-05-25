import os,sys
import MySQLdb

table_not_exist = 1146
db_not_exist = 1049
account_error = (2005,1044,1045,2003)
localhost = '127.0.0.1'

def connection(host='127.0.0.1',user='root',passwd='',db='EasyCloud'):

    params = [host,user,passwd,db]

    while 1:

        try:
            conn = MySQLdb.connect(host=params[0],user=params[1],passwd=params[2],db=params[3])
            break

        except MySQLdb.DatabaseError,de:

            if de[0] == db_not_exist:

                print de[1],"Auto create %s" % db
                create_db(params)
                continue

            elif de[0] in account_error:

                params = read_account()

            if params == -1:

                return -1

            else:

                print de,"The sniff exit..."
                sys.exit(1)

    cur = conn.cursor()
    select_sql = "select * from EasyScapy"

    while 1:

        try:
            cur.execute(select_sql)
            break

        except MySQLdb.DatabaseError,de:

            if de[0] == table_not_exist:

                print de[1],"Auto create table EasyScapy"
                create_table(cur)
                continue

    return conn

def create_db(p):

    conn = MySQLdb.connect(host=p[0],user=p[1],passwd=p[2])
    create_sql = "create database %s;" % p[3]
    cur = conn.cursor()
    cur.execute(create_sql)


def create_table(curs):

    table_sql = "create table EasyScapy(\
                id int(10) not null primary key auto_increment,\
                filepath char(200) not null,\
                stime double(30,15) not null,\
                otime double(30,15) not null,\
                size int(10) not null,\
                pcakage_counts int(10) not null);"

    curs.execute(table_sql)

def read_account():

    params_list = []

    try:

        fp = open("/tmp/.EasyScapy/db.log","r")

    except IOError,er:

        print er,'''\nplease set /tmp/.db.log file to connect db.Ex:
			                host="127.0.0.1
			                user="root"
			                passwd=""
			                db="ex"
	                    '''
        sys.exit(0)

    for s in fp.read().strip().split('\n'):

        params_list.append(s.split("=")[1])

    fp.close()
    return params_list


