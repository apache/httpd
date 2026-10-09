function handle(r)
    r.headers_out["X-Header"] = "yes"
    r.headers_out["X-Host"]   = r.headers_in["Host"]
end
