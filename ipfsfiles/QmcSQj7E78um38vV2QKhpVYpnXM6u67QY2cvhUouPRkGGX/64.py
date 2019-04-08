import re
import sys

strings = str(sys.argv[1])
f = open(strings, 'r')
w = open('base64'+sys.argv[1],'w')

pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)')
for l in f.readlines():
    if pattern.search(l):
        print l.rstrip('\n')
        w.write(l)

w.close()
f.close()
