function handle(r)
   if r.is_https then
      r:puts("yep")
   else
      r:puts("nope")
   end
end
