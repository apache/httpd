function filter(r)
    -- Declines on every single call: never yields, so
    -- lua_setup_filter_ctx() treats the request as "not interested" and
    -- the coroutine it created should not be left rooted on the cached
    -- VM's stack.
    return
end
