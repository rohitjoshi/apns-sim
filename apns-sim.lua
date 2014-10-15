#!/usr/bin/lua
-------------------------------------------------------------------------------
--
-- @script: apns-sim.lua
--
-- @author:  Rohit Joshi
--
-- @copyright Joshi Ventures LLC ? 2012
--
-- @license Apache License, Version 2.0
--
-- VERSION HISTORY:
-- 0.1 10/115/2014 - Initial release
--
-------------------------------------------------------------------------------
-- Purpose: Apple Push Notification Service simulator



local copas =  require("copas")
require "logging.console"
local socket = require("socket")
require("ssl")


local logger = logging.console()
--logger:setLevel (logging.DEBUG)

local server_socket


local ssl_enabled = false

local params = { }
  


------------------------------------------------------------------------------
--- convert bytes to hex string
-- @param string bytes
------------------------------------------------------------------------------
function bytes_to_hex_str(str)
	local s = {}
    local len = string.len(str)
		for i = 1,len do
        local b = string.byte(str, i)
		--print(string.format("%02x%s",b, ""))
        table.insert(s,  string.format("%02x%s",b, ""))
        
	end
	-- print(table.concat(s))
	return table.concat(s)
end

------------------------------------------------------------------------------
--- convert bytes to string
-- @param string bytes
------------------------------------------------------------------------------
function bytes_to_str(str)
	local s = {}
    local len = string.len(str)
		for i = 1,len do
        local b = string.byte(str, i)
		--print(string.format("%02c%s",b, ""))
        table.insert(s,  string.format("%c%s",b, ""))
        
	end
	-- print(table.concat(s))
	return table.concat(s)
end


------------------------------------------------------------------------------
--- convert string bytes to number
-- @param string bytes
------------------------------------------------------------------------------
local function strbytes_to_num(str)
	local num = 0
	local len = #str
	for i = 1,len do
		num = num + string.byte(str,i) * 256^(len-i)
	end
	return num
end
------------------------------------------------------------------------------
--- Run client handler
-- @param socket clinet
-- @param number of messages to send
------------------------------------------------------------------------------
local function client_handler(skt, host, port)

	local peername =  host .. ":" .. port
	logger:info ("Received client connection  from '%s':" , peername)
	skt:setoption('tcp-nodelay', true)
	
	--skt:settimeout(1)
	if ssl_enabled == true then
		skt = ssl.wrap(skt, params)
	
		local ok,message = skt:dohandshake()
		if not ok then
           logger.error (' ssl handshake failed with:' .. message)
           return
    		end
	end 

	local client = copas.wrap(skt)
	
	
	while true do

		local command = read_command(client)
		if not command  then
			return;
		end

		
		local id, expiry, status
		if command == 1 then
		 	
		 	id = read_id(client)
		 	if not id then				
				return;
		 	end

		 	expiry, status = read_expiry(client)
		
		 	if(status == "closed") then
				return;
		 	end
			
		elseif 	command ~= 0  then
		   logger:error("Unknown command: " .. command)
			return
		end
		-- token
		
		
		local token = read_length_val(client, 2, true)
		if not token then
			logger:error("Failed to receive token")
			return
		end
		
		local payload = read_length_val(client, 2, false)
		if not token then
		 	logger:error("Failed to receive payload")
			return
		end
		

		logger:info (string.format("Received notification: command=%d; id=%d; expiry=%d; token=%s; payload=%s",
		     command, id, expiry, token,payload ))
			
		reply(client, id)
	end

	skt:close()

	return;
end

------------------------------------------------------------------------------
--- read_command
-- @param socket
------------------------------------------------------------------------------
function read_command (client)
	local size_to_read = 1
	local command, status = client:receive(size_to_read)
	if (status ~= nil and status == "closed") then
		logger:warn ("Connection closed by foreign host. Failed to read command.")
		return;
	end
	if command == nil then		 
		logger:error ("command is nil" )
		return nil;
	end
	 
		
	return string.byte(command)
end

------------------------------------------------------------------------------
--- read_id
-- @param socket
------------------------------------------------------------------------------
function read_id (client)
	local size_to_read = 4
	local id, status = client:receive(size_to_read)
	if(status == "closed") then
		logger:error("Connection closed by foreign host. Failed to read id")
		return nil;
	end
	return strbytes_to_num(id)
end

------------------------------------------------------------------------------
--- read_expiry
-- @param socket
------------------------------------------------------------------------------
function read_expiry (client)
	local size_to_read = 4
	local expiry, status = client:receive(size_to_read)
	if(status == "closed") then
		logger:error("Connection closed by foreign host. Failed to read expiry ")
		return nil;
	end
	return strbytes_to_num(expiry)
end

------------------------------------------------------------------------------
--- read_length_val
-- @param socket
------------------------------------------------------------------------------
function read_length_val (client, size_to_read, hex_str)
	local data_len, status = client:receive(size_to_read)
	if(status == "closed") then
		logger:error("Connection closed by foreign host. Failed to read data_len")
		return;
	end
	data_len = strbytes_to_num(data_len)
    
	local data, status = client:receive(data_len)
	if(status == "closed") then
		logger:error("Connection closed by foreign host. Failed to read data")
		return;
	end
	if hex_str == true then
	  return bytes_to_hex_str(data)
	else
	 return bytes_to_str(data)
	end
end
------------------------------------------------------------------------------
--- reply
-- @param socket
------------------------------------------------------------------------------
function reply (client, id)
--[=====[
	local bytes_sent, status =  client:send(8)
	if(status == "closed") then
		logger:error("Connection closed by foreign host. Failed to send response")
		return;
	end
		
	local bytes_sent, status =  client:send(0)
	if(status == "closed") then
		logger:error("Connection closed by foreign host. Failed to send response")
		return;
	end
		
	local bytes_sent, status =  client:send(id)
	if(status == "closed") then
		logger:error("Connection closed by foreign host. Failed to send response")
		return;
	end
--]=====]
end
------------------------------------------------------------------------------
--- Get command line optipo
-- @param args
-- @param options
------------------------------------------------------------------------------
function getopt( arg, options )
  local tab = {}
  for k, v in ipairs(arg) do
    if string.sub( v, 1, 2) == "--" then
      local x = string.find( v, "=", 1, true )
      if x then tab[ string.sub( v, 3, x-1 ) ] = string.sub( v, x+1 )
      else      tab[ string.sub( v, 3 ) ] = true
      end
    elseif string.sub( v, 1, 1 ) == "-" then
      local y = 2
      local l = string.len(v)
      local jopt
      while ( y <= l ) do
        jopt = string.sub( v, y, y )
        if string.find( options, jopt, 1, true ) then
          if y < l then
            tab[ jopt ] = string.sub( v, y+1 )
            y = l
          else
            tab[ jopt ] = arg[ k + 1 ]
          end
        else
          tab[ jopt ] = true
        end
        y = y + 1
      end
    end
  end
  return tab
end
------------------------------------------------------------------------------
--- Validate arguments
-- @return host, port and task_file
------------------------------------------------------------------------------
local function validate_args(arg)
   local usage = "Usage apns-sim.lua -t ssl_enabled [ -k ssl_key -c ssl_cert] [ -s server -p port -l loglevel ]"
   local opts = getopt( arg, "tkchspl" )

   if(opts["h"] ~= nil) then
       print(usage)
       return;
   end

    local loglevel = opts["l"]
	if(loglevel == nil) then
		loglevel = "info"
	elseif(loglevel ~= "debug" and loglevel ~= "info" and loglevel ~= "warn" and loglevel ~= "error") then
		print("Error: Invalid loglevel: " .. loglevel .. ". Valid options are debug, info, warn or error")
		return;
	end
 
   if  not opts["t"] or  opts["t"] == false then
  		ssl_enabled = false
		logger:info("SSL is disabled")
   else	
        logger:info("SSL is enabled")
   end
   local ssl_key = opts["k"]
   if not ssl_key and ssl_enabled then
        logger:error("ssl_key is mandatory")
    		print(usage)
       return;
    end
	
   local ssl_cert = opts["c"]
   if not ssl_cert and ssl_enabled then
         logger:error("ssl_key is mandatory")("ssl_cert is mandatory")
    		print(usage)
       return;
    end
	
	
   local host = opts["s"]
   if(host == nil) then host = "127.0.0.1" end
   
   local port = opts["p"]
   if(port == nil ) then port = "8080" end

  
	params = {
  		mode = "server",
  		protocol = "tlsv1",
  		key = ssl_key,
  		certificate = ssl_cert,
  		-- cafile = "/etc/certs/CA.pem",
 		-- verify = {"peer", "fail_if_no_peer_cert"},
  		options = {"all", "no_sslv2"},
  		ciphers = "ALL:!ADH:@STRENGTH",
	}
  

  

  

   return host, port, loglevel

end

------------------------------------------------------------------------------
--- set the log level
------------------------------------------------------------------------------
local function set_loglevel(logger, level)
  if("debug" == level) then logger:setLevel (logging.DEBUG)
  elseif("info" == level) then logger:setLevel (logging.INFO)
  elseif("warn" == level) then logger:setLevel (logging.WARN)
  elseif("error" == level) then logger:setLevel (logging.ERROR)
  else logger:setLevel (logging.ERROR)
  end

end
------------------------------------------------------------------------------
--- main function (entry point)
-- @return content of the task file
------------------------------------------------------------------------------
local function main()
    -- parse command line args and validate
	
	local host, port, loglevel = validate_args(arg)
	if(host == nil or port == nil or loglevel == nil) then return end
   

    
	set_loglevel(logger, loglevel)


    logger:debug("Binding to " .. host .. ":" .. port)
	server_socket = socket.bind(host, port)
	copas.addserver(server_socket,
			function(c) return client_handler(c, c:getpeername()) end
		)

	copas.loop(0.1)
end

---- start main
main()
