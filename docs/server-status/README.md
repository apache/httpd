server-status
=============

`mod_lua` version of the Apache httpd's mod_status using dynamic charts

## What does it do? ##
This script is an extended version of the known mod_status statistics page for httpd.
It uses the simple Quokka Chart API to visualize many of the elements that are sometimes hard 
to properly diagnose using plain text information.

Take a look at https://www.apache.org/server-status to see how it works.

## Requirements ##
* Apache httpd 2.4.6 or higher
* mod_lua (with either Lua 5.1, 5.2 or LuaJIT)
* mod_status loaded (for enabling traffic statistics)

## Installing ##
First, install mod_lua (you can enable this during configure time with --enable-lua)

### Installing as a handler:
To install it as a handler, add the following to your httpd.conf in the appropriate VirtualHost:

    LuaMapHandler ^/server-status$ /path/to/server-status.lua
    
### Installing as a web app:
To install as a plain web-app, enable .lua scripts to be handled by mod_lua, by adding the following 
to your appropriate VirtualHost configuration:

    AddHandler lua-script .lua

Then just put the `.lua` script somewhere in your document root and visit the page.

## Configuring
There are a few options inside the Lua script that can be set to `true` or `false`:

- `show_warning`: Whether or not to show a notice that this page is there on purpose.
- `redact_ips`: Whether or not to replace the last few bits of every IP with 'x.x'
- `show_modules`: Whether to show the list of loaded modules or not
- `show_threads`: Whether to show thread details or not.
