# -*- coding: utf-8 -*-

import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
import smtplib
import traceback
import waf

def getYesterday():
    today = datetime.date.today()
    oneday = datetime.timedelta(days=1)
    yesterday = today - oneday
    yesterdaystr = yesterday.strftime('%Y-%m-%d')
    return yesterdaystr

def create_email(email_from, email_to, email_Subject, email_text, annex_path, annex_name):
    message = MIMEMultipart()
    message.attach(MIMEText(email_text, 'plain', 'utf-8'))
    message['From'] = Header(email_from, 'utf-8')
    message['To'] = Header(email_to, 'utf-8')
    message['Subject'] = Header(email_Subject, 'utf-8')
    att1 = MIMEText(open(annex_path, 'rb').read(), 'base64', 'utf-8')
    att1["Content-Type"] = 'application/octet-stream'
    att1["Content-Disposition"] = 'attachment; filename=' + annex_name
    message.attach(att1)
    return message

def send_email(sender, password, receiver, msg):
    try:
        server = smtplib.SMTP_SSL("smtp.smzdm.com", 994) 
        server.ehlo()
        server.login(sender, password) 
        server.sendmail(sender, receiver, msg.as_string())  
        print("邮件发送成功")
        server.quit()  
    except Exception:
        print(traceback.print_exc())
        print("邮件发送失败")

def main():
	my_email_from = '来自WAF拦截日志'
	my_email_to = '安全部'
	my_email_Subject = 'waf security logs ' + getYesterday()
	my_email_text = "Dear all,\n\n\t附件为每日waf拦截数据报表，请查收！\n\n来自IP:10.249.255.104 "
	my_annex_path = waf.get_file()
	my_annex_name = my_annex_path.split('/')[-1].replace('-','').replace('.xls','')+'-waf_logs.xls'
	my_sender = 'yangkunlong@smzdm.com'
	my_password = '@kunlong!Q@W#E$R'
	my_receiver = ['qijunwen@smzdm.com','yangkunlong@smzdm.com']
	my_msg = create_email(my_email_from, my_email_to, my_email_Subject,
                          my_email_text, my_annex_path, my_annex_name)
	send_email(my_sender, my_password, my_receiver, my_msg)

if __name__ == '__main__':
	
	waf.main() 
	main()

