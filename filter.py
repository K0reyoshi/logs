# -*- coding: utf-8 -*-
import os
import re
import time
from datetime import datetime, date, timedelta

def get_file():

	return filename

def filters():

	output = os.popen('ls /data/logs/nginx').read()
	yesterday = (date.today() + timedelta(days = -1)).strftime("%Y%m%d")
	preg_name = '10-249-255-104.nginx.error.log.'+ yesterday + '(.*?).cut'
	logfile = re.search(preg_name,output).group(0)
	return logfile
	
def exec_code():

	global filename
	filename = time.strftime('%Y%m%d%H%M',time.localtime(time.time()))
	logfile = filters()
	#code = "cat 10-249-255-104.nginx.error.log | awk -F',' '{if($3 ~ /rule_id/){print $0}}' >> ./waf_logs/%s" % (filename)
	code = "cat /data/logs/nginx/%s | awk -F',' '{if($3 ~ /rule_id/){print $0}}' >> /data/logs/nginx/waf_logs/%s" % (logfile,filename)
	os.system(code)
	return filename

