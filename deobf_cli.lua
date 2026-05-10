-- This Script is Part of the Prometheus Obfuscator by levno-710
--
-- deobf_cli.lua
--
-- This Script contains the Code for the Prometheus Deobfuscator CLI

local function script_path()
    local str = debug.getinfo(2, "S").source:sub(2)
    return str:match("(.*[/%\\])") or ""
end
package.path = script_path() .. "?.lua;" .. package.path

require("src.deobf_cli")
