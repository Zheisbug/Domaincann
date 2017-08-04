#coding=utf-8

import urllib2
import MySQLdb
import re
import sys
import time
import Queue
import requests, json

q=Queue.Queue()



def dbmysql(url_,title_,http_,powred_):
    db = MySQLdb.connect(user='root',passwd='usbw',host='localhost',db='userscan',port=3306,charset="gbk")
    cursor = db.cursor()
    sql = """insert into webappscan_userdbs(url,title,server,Powered) values('%s','%s','%s','%s')""" % (url_,title_,http_,powred_)
    print sql
    try:
        cursor.execute(sql)
        db.commit()
    except:
        db.rollback()
    db.close()

class Domain:
    def __init__(self,url):
        self.url=url
        self.http=['http://','https://']

    def url_html(self,url_t_t):
        urlt=urllib2.urlopen(url_t_t,timeout=1)
        return urlt

    def url_cT(self,url_t_t):
        urlt=urllib2.urlopen(url_t_t,timeout=0.1)
        url_t=urlt.read()
        re_s=re.compile(r"<title>(.+?)</title>")
        re_=re.findall(re_s,url_t)
        return re_

    def url_urlcc(self,user_opens,re_re):
        try:
            if re_re:
                re_s=re_re.decode('utf-8').encode('gbk')
                print re_re.decode('utf-8').encode('gbk'),
            if 'Server':
                headurl=self.url_html(user_opens).headers['Server']
                print self.url_html(user_opens).headers['Server'],

            if 'X-Powered-By':
                urltt=self.url_html(user_opens).headers['X-Powered-By']

            dbmysql(user_opens,re_s,headurl,urltt)
            dbmysql(user_opens,re_s,headurl,"NULL")
            dbmysql(user_opens,re_s,"NULL","NULL")
            time.sleep(0.1)
        except:
            dbmysql(user_opens,re_s,headurl,"NULL")
            dbmysql(user_opens,re_s,"NULL","NULL")
            time.sleep(0.1)
            print "success"

    def url_open(self):
        for user_opens in open("subnames.txt",'r'):
            for Http in self.http:
                try:
                    url_t_t=Http+user_opens.strip()+"."+self.url
                    print url_t_t+"\r"
                    for re_re in self.url_cT(url_t_t):
                        self.url_urlcc(url_t_t,re_re)
                except Exception,e:
                    pass

    def user_api(self):
        result =  requests.get("https://www.threatcrowd.org/searchApi/v2/domain/report/", params = {"domain": self.url})
        j = json.loads(result.text)
        for ids in range(9999):
            for Http in self.http:
                try:
                    url_T=Http+j['subdomains'][ids]
                    print url_T
                    for re_re in self.url_cT(url_T):
                        self.url_urlcc(url_T,re_re)
                except Exception,e:
                    pass

if __name__ ==  '__main__':
    dns_user=Domain(sys.argv[1])
    dns_user.url_open()
    dns_QC=Domain(sys.argv[1])
    dns_QC.user_api()
