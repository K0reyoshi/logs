#!/usr/bin/env python
# -*- coding: utf-8 -*
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import re
import json
import time
import pickle
import requestsa
import smtplib
from email import encoders
from email.header import Header
from email.mime.text import MIMEText
from email.utils import parseaddr, formataddr
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def difftime():

	desTime = int(time.time())
	if desTime - curTime > 3600 :
		return True
	return False

def _format_addr(s):

    name, addr = parseaddr(s)
    return formataddr(( \
        Header(name, 'utf-8').encode(), \
        addr.encode('utf-8') if isinstance(addr, unicode) else addr))

def send_mail(record_name='',add='',remove=''):

	from_addr = 'email'
	password = ''
	to_addr = 'toemail'
	smtp_server = 'smtp.xxxx.com'
	add_log = u'���������¿��Ŷ˿���Ϣ�� \n' 
	remove_log = u'���������ѹرն˿���Ϣ�� \n'
	for _ in add:
		add_log = add_log + _ + '\n'

	for _ in remove:
		remove_log = remove_log + _ + '\n'

	content = ''
	for ip in get_record(record_name):
		num = int(len(ip))
		for i in range(num):
			content = content + '[+] IP :' + ip[i] + '  \n'
	content = '\n' + content + add_log + remove_log
	print content
	send_time = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))

	msg = MIMEText(send_time + '  Network Security Monitor Record : \n' + content, 'plain', 'utf-8')
	msg['From'] = _format_addr(u'Security Monitor <%s>' % from_addr)
	msg['To'] = _format_addr(u'����Ա <%s>' % to_addr)
	msg['Subject'] = Header(u'�����������Ŷ˿ڼ���ձ�', 'utf-8').encode()

	server = smtplib.SMTP(smtp_server, 25)
	server.set_debuglevel(1)
	server.login(from_addr, password)
	server.sendmail(from_addr, [to_addr], msg.as_string())
	server.quit()

def diff_port(result,result1):

	yesday = set() 
	today = set()

	#result = get_record()
	for i in result :
		for _ in i:
			yesday.add(_)
	for i in result1:
		for _ in i:
			today.add(_)

	add = list(today-yesday)
	remove = list(yesday-today)
	return add,remove 


def get_token():

	global cookie
	url = 'http://10.249.250.33/login'
	r = requests.get(url,headers=headers)
	content = r.text
	regex = re.compile(r'name="csrf_token" value="(.*?)"/>')
	data = re.search(regex,content)
	cookie = r.headers['Set-Cookie'].replace('; HttpOnly; Path=/','')
	return data.group(1).strip()

def get_login(token):

	result = []
	data = {
			'csrf_token':token,
			'account':'username',
			'password':'password'
			}
	url_login = 'http://10.249.250.33/login'
	s = requests.Session()
	headers = {
				'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
				'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
				'Accept-Encoding': 'gzip, deflate',
				'Cache-Control': 'max-age=0',
				'Connection': 'keep-alive',
				'Content-Length': '163',
				'Content-Type': 'application/x-www-form-urlencoded',
				'Origin': 'http://10.249.250.33',
				'Referer': 'http://10.249.250.33/login',
				'Upgrade-Insecure-Requests': '1',
				'Cookie': cookie,
				'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36'
			}
	#print cookie
	rlogin = s.post(url_login,data=data,headers=headers)
	#print headers
	full_ips = network_config(s)
	print full_ips
	for _ in full_ips:
		Cport = monitor_port(s,_)
		print Cport
		result.append(Cport)
	print result	

	record_name = record_port(result)
	#print record_name
	result = get_record(record_name)
	return result,record_name

def record_port(result):

	record_time = time.strftime('%Y-%m-%d-%H.%M',time.localtime(time.time()))
	filename = record_time + '-port.txt'
	with open(filename, 'wb') as f:
		pickle.dump(result, f)
	print filename
	return filename

def get_record(record_name):

	try:
		with open(record_name, 'rb') as f:
			arr_port = pickle.load(f)
		return arr_port
	except:
		return False

def network_config(s):

	ips = set()
	url = 'http://10.249.250.33/config?config=nascan'
	content = s.get(url).text
	regex = re.compile(r'<textarea class="form-control" name=Scan_list>(.*?)</textarea>',re.S)
	ip = re.search(regex,content).group(1)
	arr_ips = ip.split('\n')
	for _ in arr_ips:
		ip = _.split('-')[0]
		ips.add(ip[:-1])
	return ips

def monitor_port(s,ips):

	global curTime
	curTime = int(time.time())
	url_port = 'http://10.249.250.33/?q=ip%3A' + ips
	regex = re.compile(r'infoid="(.*?)"></ a>')
	rport = s.get(url_port).text.encode("GBK","ignore")
	cport = re.findall(regex,rport)
	return cport

if __name__ == '__main__':

	global curTime
	global cookie
	cookie = ''
	headers = {
				'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
				'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
				'Accept-Encoding': 'gzip, deflate',
				'Cache-Control': 'max-age=0',
				'Connection': 'keep-alive',
				'Content-Length': '163',
				'Content-Type': 'application/x-www-form-urlencoded',
				'Origin': 'http://10.249.250.33',
				'Referer': 'http://10.249.250.33/login',
				'Upgrade-Insecure-Requests': '1',
				'Cookie': cookie,
				'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36'
			}
	token = get_token()
	r_login = get_login(token)
	result = r_login[0]
	record_name = r_login[1]
	send_mail(record_name)
	while True:
		if difftime():
			token = get_token()
			l_login = get_login(token)
			result1 = l_login[0]
			record_name = l_login[1]
			diff_result = diff_port(result,result1)
			add = diff_result[0]
			remove = diff_result[1]
			send_mail(record_name,add,remove)
			result = result1