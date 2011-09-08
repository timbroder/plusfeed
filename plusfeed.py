import sys
import re
import logging

import simplejson as json

from cgi import escape
from datetime import datetime
from datetime import timedelta
from time import mktime
from time import sleep
from string import Template
from htmlentitydefs import name2codepoint
from os import environ

from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.api import urlfetch
from google.appengine.api import memcache


td = timedelta(hours=7)

allurls = re.compile(r'/(.*)')
idurls = re.compile(r'[0-9]+')
remtags = re.compile(r'<.*?>')
remspaces = re.compile(r'\s+')
commas = re.compile(',,',re.M)
se_break = re.compile('[.!?:]\s+', re.VERBOSE)
charrefpat = re.compile(r'&(#(\d+|x[\da-fA-F]+)|[\w.:-]+);?')


HTTP_DATE_FMT = "%a, %d %b %Y %H:%M:%S GMT"
ATOM_DATE = "%Y-%m-%dT%H:%M:%SZ"

homepagetext = """
	<html>
		<head>
		<title>PlusFeed - Unofficial Google+ User Feeds</title>
		<link rel="stylesheet" type="text/css" href="/style.css">
		<script type="text/javascript" src="https://apis.google.com/js/plusone.js"></script>
		</head>
		<body>
			<div id="gb">
				<span>$countmsg</span>
				<a href="http://plus.google.com">Google+</a>
			</div>
			<div id="header">
				<h1>PlusFeed</h1>
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
				   Example: <a href="http://dlvritplus.appspot.com/104961845171318028721">http://dlvritplus.appspot.com/<strong>104961845171318028721</strong></a>
					</p>
					<p>
					<br/>
					You can grab the source for this app on GitHub <a href="https://github.com/signe/plusfeed">here</a>.
					</p>
					<p>
					<em>Originally created by <a href="http://www.russellbeattie.com">Russell Beattie</a></em>
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
  <id>http://dlvritplus.appspot.com/$p</id>
  <entry>
    <title>No Public Items Found</title>
    <link href="http://plus.google.com/$p"/>
    <id>http://dlvritplus.appspot.com/$p?noitems</id>
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
  <id>http://dlvritplus.appspot.com/$p</id>
  <entry>
    <title>Rate Limited</title>
    <link href="http://plus.google.com/$p"/>
    <id>http://dlvritplus.appspot.com/$p?ratelimited</id>
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


class MainPage(webapp.RequestHandler):

	def get(self, p):
		
		res = self.response
		out = res.out
		
		# Rate Limit check
		
		if p == '':
			self.doHome()
			return
		
		ip = environ['REMOTE_ADDR']
		host, net = ipToNetAndHost(ip, 27)
		
		unrestricted = False
		if net == '198.145.117.96':
			unrestricted = True

		# Rate Limit checks
		# 5 per userid, 20 per ip - per 12 hours
		now = datetime.today()
		upstr = now.strftime(ATOM_DATE)
		if not unrestricted:
			logging.debug('Beginning rate limit check for ' + str(ip))
			req_count = None
			try:
				req_count = memcache.incr("ratelimit:" + p)
			except:
				req_count = None
			
			if req_count:
				if req_count > 5:
					logging.debug('rate limited - returning 403 - ' + str(p) + " __ " + str(req_count))
					res.set_status(403)
					out.write(ratelimit.substitute(up = upstr, p = p))
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
				if req_count > 20:
					logging.debug('rate limited - returning 403 - ' + str(ip) + " __ " + str(req_count))
					res.set_status(403)
					out.write(ratelimit.substitute(up = upstr, p = p))
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
						logging.debug('returning 304')
						res.set_status(304)
						return
				except:
					sys.exc_clear()
			
			op = memcache.get(p)
			if op is not None:
				logging.debug('delivering from cache')
				res.headers['Content-Type'] = 'application/atom+xml'
				out.write(op)
				return



			self.doFeed(p)
			return
		
		# No matches 
		self.error(404)
		out.write('<h1>404 Not Found</h1>')
		

	def doHome(self):

		res = self.response
		out = res.out

		msg = ''
		list = memcache.get('list')
		if list:
			msg = ' Serving ' + str(len(list)) + ' feeds in the past 24 hours';

		out.write(homepage.substitute(countmsg = msg))	   


	
	def doFeed(self, p):

		res = self.response
		out = res.out
	
		try:
			logging.debug('re-requesting feed')
			
			url = 'https://plus.google.com/_/stream/getactivities/' + p + '/?sp=[1,2,"' + p + '",null,null,null,null,"social.google.com",[]]'
			
			result = ''
			
			try:
			
				result = urlfetch.fetch(url, deadline=10)
			
			except urlfetch.Error:
			
				try:
			
					result = urlfetch.fetch(url, deadline=10)
			
				except urlfetch.Error:
					self.error(500)
					out.write('<h1>500 Server Error</h1><p>' + str(err) + '</p>')
					logging.error(err)
					return
			
			if result.status_code == 200:

				txt = result.content
				txt = txt[5:]
				txt = commas.sub(',null,',txt)
				txt = commas.sub(',null,',txt)
				txt = txt.replace('[,','[null,')
				txt = txt.replace(',]',',null]')
				obj = json.loads(txt)
				
				posts = obj[1][0]

				if not posts:
					#self.error(400)
					#out.write('<h1>400 - No Public Items Found</h1>')
					logging.debug('No public feeds found')
					res.headers['Content-Type'] = 'application/atom+xml'
					updated = datetime.today()
					upstr = updated.strftime(ATOM_DATE)
					out.write(noitems.substitute(up = upstr, p = p))
					
					return


				author = posts[0][3]
				authorimg = 'https:' + posts[0][18]
				updated = datetime.fromtimestamp(float(posts[0][5])/1000)

				feed = '<?xml version="1.0" encoding="UTF-8"?>\n'
				feed += '<feed xmlns="http://www.w3.org/2005/Atom" xml:lang="en">\n'
				feed += '<title>' + author + ' - Google+ User Feed</title>\n'
				feed += '<link href="https://plus.google.com/' + p + '" rel="alternate"></link>\n'
				feed += '<link href="http://dlvritplus.appspot.com/' + p + '" rel="self"></link>\n'
				feed += '<id>https://plus.google.com/' + p + '</id>\n'
				feed += '<updated>' + updated.strftime(ATOM_DATE) + '</updated>\n'
				feed += '<author><name>' + author + '</name></author>\n'
				
				count = 0
				
				for post in posts:
					
					count = count + 1
					if count > 10:
						break
					
					
					dt = datetime.fromtimestamp(float(post[5])/1000)
					id = post[21]
					permalink = "https://plus.google.com/" + post[21]
					
					desc = ''
					
					if post[47]:
						desc = post[47]					
					elif post[4]:
						desc = post[4]

					if post[44]:
						desc = desc + ' <br/><br/><a href="https://plus.google.com/' + post[44][1] + '">' + post[44][0] + '</a> originally shared this post: ';
					
					if post[66]:
						
						if post[66][0][1]:						
							desc = desc + ' <br/><br/><a href="' + post[66][0][1] + '">' + post[66][0][3] + '</a>'

						if post[66][0][6]:
							if post[66][0][6][0][1].find('image') > -1:
								desc = desc + ' <p><img src="http:' + post[66][0][6][0][2] + '"/></p>'
							else:
								try:
									desc = desc + ' <a href="' + post[66][0][6][0][8] + '">' + post[66][0][6][0][8] + '</a>'
								except:
									sys.exc_clear()
					
					if desc == '':
						desc = permalink					
					
					
					ptitle = self.htmldecode(desc)
					ptitle = remtags.sub(' ', ptitle)
					ptitle = remspaces.sub(' ', ptitle)
					
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
					feed += '</entry>\n'
				  
				feed += '</feed>\n'
				
				memcache.set(p, feed, 15 * 60)
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
				self.error(404)
				out.write('<h1>404 - Not Found</h1>')
				logging.debug(p + ' Not Found')
		
		except Exception, err:
			self.error(500)
			out.write('<h1>500 Server Error</h1><p>' + str(err) + '</p>')
			logging.error(err)



	def htmldecode(self, text):

			if type(text) is unicode:
				uchr = unichr

			else:
				uchr = lambda value: value > 255 and unichr(value) or chr(value)

			def entitydecode(match, uchr=uchr):
				entity = match.group(1)
				if entity.startswith('#x'):
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

application = webapp.WSGIApplication([(r'/(.*)', MainPage)],debug=True)

def main():
	run_wsgi_app(application)

if __name__ == "__main__":
	main()
	
	
