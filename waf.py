# -*- coding: utf-8 -*-
from xlwt import *
import os
import re
import json 
import time
import sys
import ast
import filter
from datetime import datetime, date, timedelta 
reload(sys)  
sys.setdefaultencoding('utf8')  


def create_xls():
    try:

        file = Workbook(encoding='utf-8')
        table = {}
        application = u'Waf拦截扫描详情'
        sheet_name = file.add_sheet(application)
        table[application] = sheet_name
        table[application + 'row'] = 1

        pattern = Pattern()  # Create the Pattern
        pattern.pattern = Pattern.SOLID_PATTERN
        pattern.pattern_fore_colour = 21

        borders = Borders()
        borders.left = Borders.THIN
        borders.right = Borders.THIN
        borders.top = Borders.THIN
        borders.bottom = Borders.THIN

        alignment = Alignment()
        alignment.horz = Alignment.HORZ_CENTER  
        alignment.vert = Alignment.VERT_TOP

        style = XFStyle()  # Create the Pattern
        style.pattern = pattern  # Add Pattern to Style
        style.borders = borders
        style.alignment = alignment

        sheet_name.write(0, 0, u'请求时间', style)
        sheet_name.write(0, 1, u'风险目标', style)
        sheet_name.write(0, 2, u'风险等级', style)
        sheet_name.write(0, 3, u'风险类型', style)
        sheet_name.write(0, 4, u'客户端IP', style)
        sheet_name.write(0, 5, u'风险请求request', style)

        current = 0  
        waf_data = handle_waf()
        count_num = len(waf_data)
        records = [ [] for i in range(count_num)]

        col_width = []
        for result in waf_data:
            records[current].append(result['http_request_time'])
            records[current].append(result['http_request_host'])
            records[current].append(result['rule_serverity'])
            records[current].append(result['rule_detail'])
            records[current].append(result['rule_remote_ip'])
            records[current].append(result['rule_url'])
            current += 1
        col_width = row_size(count_num,records)
        for i in range(len(col_width)):
            if col_width[i] > 10:
		lager = 256 * (col_width[i] + 1)
		if lager > 65535:
                	table[application].col(i).width = 32000
		else:
                	table[application].col(i).width = 256 * (col_width[i] + 1)
                        
        for risk in waf_data:
            try:
                row = table[application + 'row']
                table[application].write(row, 0, risk['http_request_time'])
                table[application].write(row, 1, risk['http_request_host'])
                table[application].write(row, 2, risk['rule_serverity'])
                table[application].write(row, 3, risk['rule_detail'])
                table[application].write(row, 4, risk['rule_remote_ip'])
                table[application].write(row, 5, risk['rule_url'])
                table[application + 'row'] += 1

            except Exception, e:
                
                print 'create xls false'

	filename = save_file()
        file.save(filename)

    except Exception, e:
        print 'create file false'

def save_file():

	global filename
	filename = get_file()
	if os.path.exists(filename):
		os.remove(filename)
	return filename

def get_file():
	yesterday = (date.today() + timedelta(days = -1)).strftime("%Y-%m-%d")
	filename = '/root/reports/%s.xls' % yesterday
	return filename

def handle_waf():
    waf_data = []
    str_change = ['\'','"','}','{']
    encode_str = ['%27','%22','%\7d','%7b']
    #full_file = '/data/logs/nginx/waf_logs/201904041114'
    full_file = '/data/logs/nginx/waf_logs/' + filter.get_file().strip()
    file_waf = open(full_file,'r')
    for fw in file_waf:
        content = re.search(u'{(.*?)} while logging request',fw)
        if(content):
            preg_waf = content.group(0)
            http_request_time = re.search('"http_request_time":"(.*?)"',preg_waf).group(0)
            http_request_host = re.search('"http_request_host":"(.*?)"',preg_waf).group(0)
            rule_serverity = re.search('"rule_serverity":"(.*?)"',preg_waf).group(0)
            rule_detail = re.search('"rule_detail":"(.*?)"',preg_waf).group(0)
            rule_remote_ip = re.search('"rule_remote_ip":"(.*?)"',preg_waf).group(0)
            rule_url = re.search('"rule_url":"(.*?)","{1,}',preg_waf).group(1)
            for i in range(len(str_change)):
                rule_url = rule_url.replace(str_change[i],encode_str[i])
            arrs = [http_request_time,http_request_host,rule_serverity,rule_detail,rule_remote_ip]
            result = '{'
            for flag in arrs:
                result = result + flag + ','  
            result = result + '"rule_url":"'+rule_url+'"}'
            result = ast.literal_eval(result)
            waf_data.append(result)
    return waf_data

def row_size(num,records):

    col_width = []
    for i in range(num):
        for j in range(len(records[i])):
            if i == 0:
                col_width.append(len_byte(records[i][j]))
            else:
                if col_width[j] < len_byte(str(records[i][j])):
                    col_width[j] = len_byte(records[i][j])
    return col_width

def len_byte(value):
    length = len(value)
    utf8_length = len(value.encode('utf-8'))
    length = (utf8_length - length) / 2 + length
    return int(length)

def main():

	filter.exec_code()
	create_xls()

if __name__ == '__main__':
	
	main()
