import asyncio
import aiohttp
import aiodns
import socket
import json
import argparse
from urllib.parse import urlparse

#Creating Arguments
parser = argparse.ArgumentParser(description='WeebDNS (>O_O)> DNS Enumeration Tool With Asynchronicity', usage='%(prog)s http(s)://example.com [options]')
parser.add_argument('url', help="url of target")
parser.add_argument('--dnsapi', action='store_true', help='dns-api.org results')
parser.add_argument('--exana', action='store_true', help='exana.io results')
parser.add_argument('--google', action='store_true', help='dns.google.com results')
args = parser.parse_args()

#Setting connector to be used for aiohttp
conn = aiohttp.TCPConnector(
        family=socket.AF_INET,
        verify_ssl=False
    )

#Defining colors for output
purple = '\x1b[38;5;165m'
blue = '\x1b[38;5;33m'
red = '\x1b[38;5;196m'
green = '\x1b[38;5;118m'
grey = '\x1b[38;5;0m'
pink = '\x1b[38;5;199m'

#ascii art
print(f'''{grey}
	                               ,▄▄▄▄▄╓,
                   ,,▄▄▄▄▓█████████████████████▓▓▄▄▄▄,,
                 ▀▀████████████████████████████████████████▓▄▄▄▄▄▄▄,
                ▄▄██████████████████████████████████████████████▌▄╓▄∩
             ▄██▀▀████████████████████████████████████████████████▄,     '
            `   ▄█████████{pink}▓{grey}████{pink}▓▓▓▓▓▓▓▓▓{grey}███████{pink}▓{grey}██████████████████████▄▄L,
              ▄██████████{pink}▓{grey}███{pink}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓{grey}████{pink}▓{grey}█████████████████████████▀
             └▀╙ ▓██████{pink}▓{grey}██{pink}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓{grey}███{pink}▓▓▓{grey}█████████████████████▀╙`
                ,███████{pink}▓{grey}██{pink}▓▓▓▓▓▓{grey}████{pink}▓▓▓▓▓▓▓▓▓{grey}██{pink}▓{grey}████████████████████████▓▀
                ▓██████████{pink}▓▓▓▓▓▓{grey}█████{pink}▓▓▓▓▓▓▓▓{grey}██{pink}▓{grey}████████████████████████▓▓m
                ████████{pink}▓{grey}████{pink}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓{grey}████████████████████████████▌,
               J█████████{pink}▓{grey}████{pink}▓▓▓▓▓▓▓▓▓▓▓▓▓▓{grey}███{pink}▓{grey}████████████████████████▀╙
               ╟█████████████{pink}▓▓▓▓▓▓▓▓▓▓▓▓▓{grey}████{pink}▓{grey}██████████████████████▀
             {pink} ▄▓▓{grey}████████████{pink}▓▓▓{grey}█████████████████████████████████▀{pink}╨
             Φ▌▓▓▓{grey}███████████████████████████████████████{pink}▓▓▓▓▌Å"`
              ⌐'╫▓▓▓▓▓▓▓▓▓▓▓▓▓{grey}███████████████████████{pink}▓▓▓▓▓▓▓Ñ`
              `  "▌░╟╫╨╢║╣▀▓▓▓▀▀▀▓▓▓▓▓▓▓▓▓▓▓▓▓▓▌▀▀▀▀╣ÖÅ`╠░║▓:
             `    ▌ "╫. j  ▓▓▒" ``╟╫M` ```└```     ╙⌂║. "Ñ▓▌
                 ▐M `╨H ¿ "▓▓╫    ╣Ñ      j         ╣╬   ║▓
                 ╬   :Ñ"  ╫▓╣Ü    ╣░      j         ╙▌   ╣▌
                 ''')

#Record Lists
aiodns_records = ['A','AAAA','CNAME','MX','NAPTR','NS','SOA','SRV','TXT']
dnsapi_records = ['A','AAAA','CNAME','MX','NS','PTR','SOA','TXT']
exana_records = ['A','AAAA','CNAME','MX','NS','SPF','CERT','TXT','DNSKEY','DLV','IPSECKEY']
google_records = ['A','AAAA','CAA','CDS','CERT','CNAME','DNAME','DNSKEY','DS','HINFO','IPSECKEY','NS','NSEC','NSEC3PARAM','PTR','RP','RRSIG','SOA','SPF','SRV','SSHFP','TLSA','TXT','WKS']

##########~aiodns~##########
async def aiodns_request(name, query_type, resolver):
    try:

        results = await resolver.query(name, query_type)
        if len(results) == 0:
        	print(f'{purple}Record Found But Empty: {query_type}')
        else:
        	print(f'{blue}{query_type} record results:')
        if query_type == 'A' or query_type == 'AAAA' or query_type == 'NS':
        	for result in results:
        		print(f'{green}host[{result.host}] ttl[{result.ttl}]')
        elif query_type == 'CNAME':
        	print(f'{green}cname[{results.cname}] ttl[{results.ttl}]')
        elif query_type == 'MX':
        	for result in results:
        		print(f'{green}host[{result.host}] priority[{result.priority}] ttl[{result.ttl}]')
        elif query_type == 'NAPTR':
        	for result in results:
        		print(f''''{green}order[{result.order}] preference[{result.preference}] flags[{result.flags}] service[{result.service}]
        			\rregex[{result.regex}] replacement[{result.replacement}] ttl[{result.ttl}]''')
        elif query_type == 'SOA':
        	print(f'''{green}name[{results.nsname}] hostmaster[{results.hostmaster}] serial[{results.serial}]
        		\rrefresh[{results.refresh}] retry[{results.retry}] expires[{results.expires}] minttl[{results.minttl}] ttl[{results.ttl}]''')
        elif query_type == 'SRV':
        	for result in results:
        		print(f'{green}host[{result.host}] port[{result.port}] priority[{result.priority}] weight[{result.weight}] ttl[{result.ttl}]')
        elif query_type == 'TXT':
        	for result in results:
        		print(f'{green}host[{result.text.decode("utf-8")}] ttl[{result.ttl}]')

    except aiodns.error.DNSError:
        print(f'{red}Record Not Found: {query_type}')

async def aiodns_query(resolver):
    for query_type in aiodns_records:
        await aiodns_request(target, query_type, resolver)

##########~dns-api.org~##########
async def dnsapi_request(session, dnsapi_url, record):
	async with session.get(dnsapi_url) as response:
		text = await response.text()
		response_list = json.loads(text)
		print(f'{blue}{record} record results:')
		for answer in response_list:
			if answer == 'error':
				print(f'{red}Record Not Found: {record}')
			else:
				data_list = []
				for key in answer:
					data_list.append(f'{green}{key}[{answer[key]}]')
				print(' '.join(data_list))
		

async def dnsapi_query():
	async with aiohttp.ClientSession(connector=conn) as session:
		for record in dnsapi_records:
			dnsapi_url = f'https://dns-api.org/{record}/{target}'
			await dnsapi_request(session, dnsapi_url, record)

##########~exana.io~##########
async def exana_request(session, exana_url, record):
	async with session.get(exana_url) as response:
		text = await response.text()
		j = json.loads(text)
		try:
			answer = j['answer']
			if answer != None:
				print(f'{blue}{record} record results:')
				for result in answer:
					data_list = []
					for key in result:
						data_list.append(f'{green}{key}[{result[key]}]')
					print(' '.join(data_list))
			else:
				print(f'{red}Record Not Found: {record}')
		except KeyError:
			print(f'{purple}An error has occured please make sure you typed the url correctly!')
			exit()

async def exana_query():
	async with aiohttp.ClientSession(connector=conn) as session:
		for record in exana_records:
			exana_url = f'https://api.exana.io/dns/{target}/{record}'
			await exana_request(session, exana_url, record)

##########~dns.google.com~##########
async def google_request(session, google_url, record):
	async with session.get(google_url) as response:
		text = await response.text()
		j = json.loads(text)
		try:
			answers = j['Answer']
			print(f'{blue}{record} record results:')
			for answer in answers:
				data_list = []
				for key in answer:
					data_list.append(f'{green}{key}[{answer[key]}]')
				print(' '.join(data_list))
		except KeyError:
			print(f'{red}Record Not Found: {record}')
		

async def google_query():
	async with aiohttp.ClientSession(connector=conn) as session:
		for record in google_records:
			google_url = f'https://dns.google.com/resolve?name={target}&type={record}'
			await google_request(session, google_url, record)

#Defining loops
def default_loop():
	loop = asyncio.get_event_loop()
	resolver = aiodns.DNSResolver(loop=loop)
	run = loop.run_until_complete(aiodns_query(resolver))

def api_loop(query_option):
	loop = asyncio.get_event_loop()
	run = loop.run_until_complete(query_option())

#Setting variables and loops to be used based on the argument(s) given
if args.url.startswith(('http://','https://')):
	target = urlparse(args.url).netloc
else:
	print('Please specify http:// or https:// ')
	exit()

if args.dnsapi:
	query_option = dnsapi_query
	api_loop(query_option)
elif args.exana:
	query_option = exana_query
	api_loop(query_option)
elif args.google:
	query_option = google_query
	api_loop(query_option)
else:
	default_loop()
