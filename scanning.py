## this is a threaded port scanner and service scanner. I'm probably going
## to make two of these with the same API:
## this one written by me for extensible custom code.
## the other will extend python-nmap

### deps:
# https://github.com/phihag/ipaddress

from __future__ import unicode_literals
import ipaddress

import socket
import threading
import Queue
import sys

def scan_host(host): ## checks if host is up
	try:
		ip = socket.gethostbyname(host)
		return True
	except:
		return False
	try:
		name = socket.gethostbyaddr(host)
		return True
	except:
		return False

def scan_port(host,port,timeout): ## checks if port is open
	try:
		s = socket.create_connection((host,port),timeout)
		s.close()
		return True
	except:
		return False

def scan_service(host,port,timeout): ## same as scan_port, but grabs headers
	try:
		s = socket.create_connection((host,port),timeout)
		s.sendall('ping\r\n')
		a = s.recv(128)
		s.close()
		if not a:
			a = "___???___"
		return a
	except:
		return False

ROUND_ROBIN = 1
SEGMENTED = 2
EXIT_ = 7777777777777777 ## definitely not a port

class fast_service_scan:
	def __init__(self,host,ports,numthreads=4,mode=ROUND_ROBIN,timeout=2,func=scan_service):
		# func to run to check, file uri line separated, num threads, boolean to continue if found a correct, mode to distribute passwords
		self.host = host
		self.func = func ## can change to scan_port
		self.ports = ports
		self.numthreads = numthreads
		self.mode = mode
		self.timeout = timeout
		self.printqueue = Queue.Queue()

	def worker_thread(self,queue,tid):
		r = True
		while r:
			port = queue.get()
			if port == EXIT_:
				r = False
				break
			ret = self.func(self.host,port,self.timeout) ## func must return a boolean if correct
			if ret:
				self.printqueue.put(('_FIND_',port,ret))
			queue.task_done()
		self.printqueue.put(("_EXIT_",tid))

	def run(self):
		self.threads = []
		self.queues = []
		for i in range(self.numthreads):
			nq = Queue.Queue()
			self.queues.append(nq)
			th = threading.Thread(target=self.worker_thread,args=(self.queues[i],i))
			self.threads.append(th)
			th.start()

		if self.mode == ROUND_ROBIN:
			current = 0
			for i in self.ports:
				self.queues[current].put(i)
				current += 1
				if current >= self.numthreads:
					current = 0
		elif self.mode == SEGMENTED:
			seg_length = len(self.ports) / self.numthreads
			current = 0
			for i in [self.ports[x:x+seg_length] for x in range(0,len(self.ports),seg_length)]: ## http://stackoverflow.com/a/1218810/2635662
				for j in i:
					self.queues[z].put(j)
				current += 1
				if current >= self.numthreads:
					current = 0
		for q in self.queues: #
			q.put(EXIT_)
		## now wait for the print queues to populate:
		runningt = [True]*self.numthreads
		passes = []
		while True in runningt:
			n = self.printqueue.get()
			if n[0] == '_EXIT_':
				#print "Exited thread {}".format(n.split()[-1])
				runningt[n[-1]] = False  ## idk if this is the best way to do this..
			elif n[0] == '_FIND_':
				port = n[1]
				service = n[-1]
				if service == '___???___':
					service = ''
				print port, ' : ', service
				passes.append((port,service))
			else:
				print n
		#print "Done"
		return passes

def resolve_ip_mask(mask): ## iterator of all the ip addresses within mask
	if not '/' in mask:
		yield mask
	else:
		a = ipaddress.ip_network(mask)
		for i in a.hosts():
			yield str(i)

def resolve_port_mask(mask): ## iterator for simple port lists
	for i in mask.split(','):
		if '-' in i: #range
			a = i.split('-')
			for z in range(int(a[0]),int(a[-1])+1):
				yield z
		else:
			yield int(i)

def scan_service_range(ips,ports,threads=32):
	iptoscan = []
	for i in ips:
		if scan_host(i):
			iptoscan.append(i)
	for i in iptoscan:
		print "Scanning " + i
		a = ports
		s = fast_service_scan(i,a,numthreads=threads)
		s.run()

class threaded_service_range_scan:
	def __init__(self,hosts,ports,numthreads=4,mode=ROUND_ROBIN,timeout=2,func=scan_service):
		# func to run to check, file uri line separated, num threads, boolean to continue if found a correct, mode to distribute passwords
		self.hosts = hosts
		self.func = func ## can change to scan_port
		self.ports = ports
		self.numthreads = numthreads
		self.mode = mode
		self.timeout = timeout
		self.printqueue = Queue.Queue()

	def worker_thread(self,queue,tid):
		r = True
		while r:
			host = queue.get()
			if host == EXIT_:
				r = False
				break
			for port in self.ports:
				ret = self.func(host,port,self.timeout) ## func must return a boolean if correct
				if ret:
					self.printqueue.put(('_FIND_',port,host,ret))
			queue.task_done()
		self.printqueue.put(("_EXIT_",tid))

	def run(self):
		self.threads = []
		self.queues = []
		for i in range(self.numthreads):
			nq = Queue.Queue()
			self.queues.append(nq)
			th = threading.Thread(target=self.worker_thread,args=(self.queues[i],i))
			self.threads.append(th)
			th.start()
		iptoscan = []
		for i in self.hosts:
			if scan_host(i):
				iptoscan.append(i)
		print "Hosts up: " + str(len(iptoscan))
		if self.mode == ROUND_ROBIN:
			current = 0
			for i in iptoscan:
				self.queues[current].put(i)
				current += 1
				if current >= self.numthreads:
					current = 0
		elif self.mode == SEGMENTED:
			seg_length = len(iptoscan) / self.numthreads
			current = 0
			for i in [iptoscan[x:x+seg_length] for x in range(0,len(iptoscan),seg_length)]: ## http://stackoverflow.com/a/1218810/2635662
				for j in i:
					self.queues[z].put(j)
				current += 1
				if current >= self.numthreads:
					current = 0
		for q in self.queues: #
			q.put(EXIT_)
		## now wait for the print queues to populate:
		runningt = [True]*self.numthreads
		passes = []
		while True in runningt:
			n = self.printqueue.get()
			if n[0] == '_EXIT_':
				#print "Exited thread {}".format(n.split()[-1])
				runningt[n[-1]] = False  ## idk if this is the best way to do this..
			elif n[0] == '_FIND_':
				port = n[1]
				host = n[2]
				service = n[-1]
				if service == '___???___':
					service = ''
				print host, port, ':', service
				passes.append((port,service))
			else:
				print n
		#print "Done"
		return passes
