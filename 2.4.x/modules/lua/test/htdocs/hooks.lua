require 'string'
require 'apache2'

function translate_name(r)
    if r.uri == "/translate-name" then
        r.uri = "/find_me.txt"
        return apache2.DECLINED
    end
    return apache2.DECLINED
end

function translate_name2(r)
    if r.uri == "/translate-name2" then
        r.uri = "/find_me.txt"
        return apache2.DECLINED
    end
    return apache2.DECLINED
end

function fixups_test(r)
  -- r:err("KABAZ")
  if r.uri == "/test_fixupstest" then
    -- r:err("KABIZ")
    r.status = 201
    return apache2.OK
  end
  -- r:err("ZIBAK")
  return apache2.DECLINED
end