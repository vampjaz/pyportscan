## this is going to get really messy
## to cheer you up:
## http://i.stack.imgur.com/akAgV.jpg

from __future__ import unicode_literals # have to do this in any file that passes args to scanning.resolve_ip_mask(
import scanning
import sys
import random

#hostm = '192.168.225.0/24'
hostm = unicode(sys.argv[1])
portm = sys.argv[2]

hosts = list(scanning.resolve_ip_mask(hostm))
ports = list(scanning.resolve_port_mask(portm))

random.shuffle(hosts)

print "Scanning {} hosts ({} ports per host)".format(len(hosts),len(ports))

##scanning.scan_service_range(hosts,ports)

s = scanning.threaded_service_range_scan(hosts,ports,numthreads=32)
s.run()
