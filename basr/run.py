import sys, basr

ip = sys.argv[1]

app = basr.basr(ip)

if ip == '10.0.56.2' or ip == '10.0.56.6':
    app.runmal()
else:
    app.runsrc()

