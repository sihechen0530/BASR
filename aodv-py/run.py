import sys, aodv

ip = sys.argv[1]

app = aodv.aodv(ip)

if ip == '10.0.56.2' or ip == '10.0.56.6':
    app.runmal()
else:
    app.runsrc()
