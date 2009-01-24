function handle(r)
   local host = r.headers_in['host']
   r:debug(host)
   r:puts(host)
   r.headers_out['wombat'] = 'lua'
end
