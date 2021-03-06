#apns-sim : Apple Push Notification Service (APNS) Simulator
========

APNS simulator implementes [APNS Specs] (https://developer.apple.com/library/ios/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Chapters/CommunicatingWIthAPS.html)   for a simple and an enhanced push notification.

Prerequisite:

1.  LuaJit : http://luajit.org/download.html

2.  LuaSec : https://github.com/brunoos/luasec 

3.  LuaLogging: http://keplerproject.org/lualogging/

4.  copas:  http://keplerproject.github.io/copas/


<pre>
Once you have downloaded/installed LuaJit and luarocks, other dependencies can be installed using luarocks
e.g.
luarocks install copas

luarocks install LuaSec

luarocks install LuaLogging
</pre>


<pre>
Usage:   apns-sim.lua -t ssl_enabled [ -k ssl_key -c ssl_cert] [ -s server -p port -l loglevel -]

Here ssl_key  and ssl_cert fields are mandatory if ssl_enabled is set to true.  

ssl_enabled :  defaul false
server : default value is 127.0.0.1

port  :  default 8080

loglevel : default value is 'warn'

e.g. for ssl connection:
lua  apns-sim.lua -t true -k ./key.pem -c ./cert.pem

for non-ssl connection:  lua  apns-sim.lua 
</pre>
When client connect to this simulator and send a push notification, you will see log entries on console.

<pre>
Wed Oct 15 09:16:13 2014 INFO Received client connection  from '127.0.0.1:53444':
Wed Oct 15 09:16:13 2014 INFO Received notification: command=1; id=21; expiry=1413382573; token=adf3b210e7adf35f540f45b2697760d9d41081569dc4509ee98bb4d4c92a72ae; payload={"aps":{"alert":{"body":"Hello World"}}}
</pre>



 



