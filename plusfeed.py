import sys
import re
import logging
import traceback

import simplejson as json

from cgi import escape
from datetime import datetime
from datetime import timedelta
from time import mktime
from time import sleep
from string import Template
from htmlentitydefs import name2codepoint
from os import environ

import webapp2
from google.appengine.api import urlfetch
from google.appengine.api import memcache


td = timedelta(hours=7)

allurls = re.compile(r'/(.*)')
idurls = re.compile(r'[0-9]+')
remtags = re.compile(r'<.*?>')
remspaces = re.compile(r'\s+')
se_break = re.compile('[.!?:]\s+', re.VERBOSE)
charrefpat = re.compile(r'&(#(\d+|x[\da-fA-F]+)|[\w.:-]+);?')


HTTP_DATE_FMT = "%a, %d %b %Y %H:%M:%S GMT"
ATOM_DATE = "%Y-%m-%dT%H:%M:%SZ"

homepagetext = """
	<html>
		<head>
		<title>dlvritPlus - Unofficial Google+ User Feeds</title>
		<link rel="stylesheet" type="text/css" href="/style.css">
		<script type="text/javascript" src="https://apis.google.com/js/plusone.js"></script>
		</head>
		<body>
			<div id="gb">
				<span>$countmsg</span>
				<a href="http://plus.google.com/">Google+</a>
			</div>
			<div id="header">
				<h1>dlvritPlus</h1>
				<h2>Unofficial Google+ User Feeds</h2>
				<span id="plusone"><g:plusone size="tall"></g:plusone></span>
			</div>
			<div id="content">
				<div id="intro">
					<h2>
					Want a <span class="stress">feed</span> for your Google+ posts?
					</h2>
					<div id="inst">
					    <p>
						Simply add a Google+ user number to the end of this site's URL to get an Atom feed of <em>public</em> posts.
					    </p>
					    <p>
						Example: <a href="$base_url/111091089527727420853">$base_url/<strong>111091089527727420853</strong></a>
					    </p>
					    <p>
						<br/>
						dlvritPlus feeds are for use with <a href="http://dlvr.it/">dlvr.it</a>. Other uses of dlvitPlus feeds may be rate limited.
					    </p>
					    <p>
					    <small>
						<em>Originally created by <a href="http://www.russellbeattie.com">Russell Beattie</a></em><br/>
						You can grab the source for this app on GitHub <a href="https://github.com/signe/plusfeed">here</a>.
					    </small>
					    </p>
					</div>
				</div>
			</div>
			<script type="text/javascript">
			  var _gaq = _gaq || [];
			  _gaq.push(['_setAccount', 'UA-24604146-1']);
			  _gaq.push(['_trackPageview']);
			  (function() {
				var ga = document.createElement('script'); ga.type = 'text/javascript'; ga.async = true;
				ga.src = ('https:' == document.location.protocol ? 'https://ssl' : 'http://www') + '.google-analytics.com/ga.js';
				var s = document.getElementsByTagName('script')[0]; s.parentNode.insertBefore(ga, s);
			  })();
			</script>
		</body>
	  </html>
	"""
homepage = Template(homepagetext)

noitemstext = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>No Public Items Found</title>
  <updated>$up</updated>
  <id>$base_url/$p</id>
  <entry>
    <title>No Public Items Found</title>
    <link href="http://plus.google.com/$p"/>
    <id>$base_url/$p?noitems</id>
    <updated>$up</updated>
    <summary>Google+ user $p has not made any posts public.</summary>
  </entry>
</feed>
"""

noitems = Template(noitemstext)

ratelimittext = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Rate Limited</title>
  <updated>$up</updated>
  <id>$base_url/$p</id>
  <entry>
    <title>Rate Limited</title>
    <link href="http://plus.google.com/$p"/>
    <id>$base_url/$p?ratelimited</id>
    <updated>$up</updated>
    <summary type="html">
        &lt;h1&gt;Whoops!&lt;/h1&gt;

	&lt;strong&gt;You've exceeded the feed retrieval limits for this feed.&lt;/strong&gt;

	&lt;div&gt;Don't worry, dlvr.it can still access and post your Google+ updates.&lt;/div&gt;

	&lt;div&gt;Start using &lt;a href="http://dlvr.it"&gt;dlvr.it&lt;/a&gt; to distribute your Google+
	updates to Twitter, Facebook and more. &lt;br/&gt;&lt;br/&gt;

        &lt;a href="http://support.dlvr.it/entries/20312856-how-to-automatically-send-your-google-posts-to-twitter-and-facebook&gt;Details&lt;/a&gt;&lt;/div&gt;
    </summary>
  </entry>
</feed>
"""

ratelimit = Template(ratelimittext)


class MainPage(webapp2.RequestHandler):

	def get(self, p):
		
		res = self.response
		out = res.out
		base_url = self.request.application_url
		debug = False

		# Rate Limit check

		if p == '':
			self.doHome()
			return
		
		ip = environ['REMOTE_ADDR']
		unrestricted = False

		if not debug:

			# Skip IPv6 Addresses - always treat them as restricted
			if ip.find(':') == -1:
			    host, net = ipToNetAndHost(ip, 27)
			    if net == '198.145.117.96':
				    unrestricted = True
		else:
			unrestricted = True

		# Rate Limit checks
		# 5 per userid, 10 per ip - per 12 hours
		now = datetime.today()
		upstr = now.strftime(ATOM_DATE)
		if not unrestricted:
			if debug:
				logging.debug('Beginning rate limit check for ' + str(ip))
			if p != '111091089527727420853':
				req_count = None
				try:
					req_count = memcache.incr("ratelimit:" + p)
				except:
					req_count = None
				
				if req_count:
					if req_count > 5:
						if debug:
							logging.debug('rate limited - returning 403 - ' + str(p) + " __ " + str(req_count))
						res.set_status(403)
						out.write(ratelimit.substitute(up = upstr, p = p, base_url = base_url))
						return
				else:
					memcache.set("ratelimit:" + p, 1, 43200)

			
			ip = environ['REMOTE_ADDR']
			req_count = None
			try:
				req_count = memcache.incr("ratelimit:" + ip)
			except:
				req_count = None
			
			if req_count:
				if req_count > 10:
					if debug:
						logging.debug('rate limited - returning 403 - ' + str(ip) + " __ " + str(req_count))
					res.set_status(403)
					out.write(ratelimit.substitute(up = upstr, p = p, base_url = base_url))
					return
			else:
				memcache.set("ratelimit:" + ip, 1, 43200)

		if p == 'showall' and unrestricted:
			posts = memcache.get('posts')
			for k,post in sorted(posts.iteritems(), reverse=True):
				out.write('<p>' + str(k) + ': <a href="' + post['permalink'] + '">Posted on ' + (post['updated'] - td).strftime('%B %d, %Y - %I:%M %p') + ' PST by ' + post['author'] + '</a> <br/>' + post['title'] + '</p>\n')
			return

		if p == 'reset' and unrestricted:
			memcache.flush_all()
			out.write('reset')
			return	

		if idurls.match(p):
		
			# If Modified Since check

			if 'If-Modified-Since' in self.request.headers:
				try:
					ud = memcache.get('time_' + p)
					uds = datetime.strftime(ud, HTTP_DATE_FMT)

					ud = datetime.strptime(uds, HTTP_DATE_FMT)
					last_seen = datetime.strptime(self.request.headers['If-Modified-Since'], HTTP_DATE_FMT)
				
					if ud and last_seen and ud <= last_seen:
						if debug:
							logging.debug('returning 304')
						res.set_status(304)
						return
				except:
					sys.exc_clear()
			
			op = memcache.get(p)
			if op is not None:
				if debug:
					logging.debug('delivering from cache')
				res.headers['Content-Type'] = 'application/atom+xml'
				out.write(op)
				return



			self.doFeed(p, debug)
			return
		
		# No matches 
		self.error(404)
		out.write('<h1>404 Not Found</h1>')
		

	def doHome(self):

		res = self.response
		out = res.out
		base_url = self.request.application_url

		msg = ''
		list = memcache.get('list')
		if list:
			msg = ' Serving ' + str(len(list)) + ' feeds in the past 24 hours';

		out.write(homepage.substitute(countmsg = msg, base_url = base_url))     


	
	def doFeed(self, p, debug):
		apiKey = '<insert your Google API Key Here>'

		res = self.response
		out = res.out
	
		try:
			if debug:
				logging.debug('re-requesting feed')
			
			url = 'https://www.googleapis.com/plus/v1/people/' + p + '/activities/public?key=' + apiKey
			
			result = ''
			
			try:
			
				result = urlfetch.fetch(url, deadline=10)
			
			except urlfetch.Error:
			
				try:
			
					result = urlfetch.fetch(url, deadline=10)
			
				except urlfetch.Error, err:
					self.error(500)
					out.write('<h1>500 Server Error</h1><p>' + str(err) + '</p>')
					logging.error(err)
					return
			
			if result.status_code == 200:

				base_url = self.request.application_url

				try:
					obj = json.loads(result.content)
				except json.JSONDecodeError, err:
					logging.error('JSON Decoding Error')
					self.error(500)
					out.write('<h1>500 Server Error</h1><p>There was an error decoding the JSON object from Google</p>')
					return
				
				posts = obj['items']

				if not posts:
					#self.error(400)
					#out.write('<h1>400 - No Public Items Found</h1>')
					if debug:
						logging.debug('No public items found')
					res.headers['Content-Type'] = 'application/atom+xml'
					updated = datetime.today()
					upstr = updated.strftime(ATOM_DATE)
					out.write(noitems.substitute(up = upstr, 
								     p = p, 
								     base_url = base_url))
					
					return


				author = posts[0]['actor']['displayName']
				authorimg = posts[0]['actor']['image']['url']
				updated = datetime.strptime(obj['updated'], '%Y-%m-%dT%H:%M:%S.%fZ')

				feed = '<?xml version="1.0" encoding="UTF-8"?>\n'
				feed += '<feed xmlns="http://www.w3.org/2005/Atom" xml:lang="en">\n'
				feed += '<title>' + author + ' - Google+ User Feed</title>\n'
				feed += '<logo>' + authorimg + '</logo>\n'
				feed += '<link href="https://plus.google.com/' + p + '" rel="alternate"></link>\n'
				feed += '<link href="' + base_url + '/' + p + '" rel="self"></link>\n'
				feed += '<id>https://plus.google.com/' + p + '</id>\n'
				feed += '<updated>' + updated.strftime(ATOM_DATE) + '</updated>\n'
				feed += '<author><name>' + author + '</name></author>\n'
				
				count = 0
				
				for post in posts:
					
					count = count + 1
					if count > 10:
						break
					
					
					dt = datetime.strptime(post['updated'], '%Y-%m-%dT%H:%M:%S.%fZ')
					permalink = post['url']
					id = permalink.replace('https://plus.google.com/', '')
					
					desc = ''

					if post.get('annotation') is not None and post['annotation']:
						desc = post['annotation']
					elif post['object'].get('content') is not None and post['object']['content']:
						desc = post['object']['content']				
					elif post.get('title') is not None and post['title'] and post['verb'] != 'share':
						desc = post['title']

					if post['verb'] == 'share':
						desc = desc + ' <br/><br/><a href="https://plus.google.com/' + post['object']['actor']['id'] + '">' + post['object']['actor']['displayName'] + '</a> originally shared this post: ';
					
					if post['object'].get('attachments') is not None and len(post['object']['attachments']) > 0:
						
						if post['object']['attachments'][0]['objectType'] == 'article':
							desc = desc + ' <br/><br/><a href="' + post['object']['attachments'][0]['url'] + '">' + post['object']['attachments'][0]['displayName'] + '</a>'
							if len(post['object']['attachments']) > 1 and post['object']['attachments'][1]['objectType'] == 'photo':
								desc = desc + ' <p><a href="' + post['object']['attachments'][1]['fullImage']['url'] + '"><img src="' + post['object']['attachments'][1]['image']['url'] + '"/></a></p>'

						elif post['object']['attachments'][0]['objectType'] == 'video':
							if post['object']['attachments'][0].get('displayName') is not None:
								desc = desc + ' <br/><br/><a href="' + post['object']['attachments'][0]['url'] + '">' + post['object']['attachments'][0]['displayName'] + '</a>'
							else:
								desc = desc + ' <br/><br/><a href="' + post['object']['attachments'][0]['url'] + '">' + post['object']['attachments'][0]['url'] + '</a>'

						elif post['object']['attachments'][0]['objectType'] == 'photo':
							desc = desc + ' <p><a href="' + post['object']['attachments'][0]['fullImage']['url'] + '"><img src="' + post['object']['attachments'][0]['image']['url'] + '"/></a></p>'

					
					if desc == '':
						ptitle = permalink					
					else: 
						ptitle = self.htmldecode(desc)
						ptitle = remtags.sub(' ', ptitle)
						ptitle = remspaces.sub(' ', ptitle)

					if ptitle is None:
						ptitle = u""

					sentend = 75
					
					m = se_break.split(ptitle)
					if m:
						sentend = len(m[0]) + 1
					
					if sentend < 5 or sentend > 75:
						sentend = 75

					feed += '<entry>\n'
					feed += '<title>' + escape(ptitle[:sentend]) + '</title>\n'
					feed += '<link href="' + permalink + '" rel="alternate"></link>\n'
					feed += '<updated>' + dt.strftime(ATOM_DATE) + '</updated>\n'
					feed += '<id>tag:plus.google.com,' + dt.strftime('%Y-%m-%d') + ':/' + id + '/</id>\n'
					feed += '<summary type="html">' + escape(desc) + '</summary>\n'
					feed += '<content type="html">' + escape(desc) + '</content>\n'
					feed += '</entry>\n'
				  
				feed += '</feed>\n'
				
				memcache.set(p, feed, 30 * 60)
				memcache.set('time_' + p, updated)
				
				mlist = memcache.get('list')
				if mlist:
					if p not in mlist:
						mlist.append(p)
				else:
					mlist = []
					mlist.append(p)
				
				memcache.set('list', mlist, 60 * 60 * 24)
				
				res.headers['Last-Modified'] = updated.strftime(HTTP_DATE_FMT)
				res.headers['Content-Type'] = 'application/atom+xml'

				out.write(feed)

			
			else:
				self.error(503)
				res.headers['Retry-After'] = str(600)
				out.write('<h1>Google API returned error ' + str(result.status_code) + ' - Unable to process request for UID ' + p + '</h1>')
				logging.error('Google API returned error ' + str(result.status_code) + ' - Unable to process request for UID ' + p)
		
		except Exception, err:
			self.error(500)
			out.write('<h1>500 Server Error</h1><p>' + str(err) + '</p>')
			logging.error(err)
			traceback.print_exc()



	def htmldecode(self, text):

			if type(text) is unicode:
				uchr = unichr

			else:
				uchr = lambda value: value > 255 and unichr(value) or chr(value)

			def entitydecode(match, uchr=uchr):
				entity = match.group(1)
				if entity is None:
					return match.group(0);
				elif entity.startswith('#x'):
					return uchr(int(entity[2:], 16))
				elif entity.startswith('#'):
					return uchr(int(entity[1:]))
				elif entity in name2codepoint:
					return uchr(name2codepoint[entity])
				else:
					return match.group(0)
			
			return charrefpat.sub(entitydecode, text)


####

import socket, struct
 
def dottedQuadToNum(ip):
	"convert decimal dotted quad string to long integer"
	return struct.unpack('>L',socket.inet_aton(ip))[0]
 
def numToDottedQuad(n):
	"convert long int to dotted quad string"
	return socket.inet_ntoa(struct.pack('>L',n))
 
def makeMask(n):
	"return a mask of n bits as a long integer"
	return (0xffffffff << (32 - n))
 
def ipToNetAndHost(ip, maskbits):
	"returns tuple (network, host) dotted-quad addresses given IP and mask size"
	 
	n = dottedQuadToNum(ip)
	m = makeMask(maskbits)
	 
	host = n & m
	net = n - host
	 
	return numToDottedQuad(net), numToDottedQuad(host)

app = webapp2.WSGIApplication([(r'/(.*)', MainPage)],debug=True)
