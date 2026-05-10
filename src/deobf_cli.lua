-- This Script is Part of the Prometheus Obfuscator by levno-710
--
-- src/deobf_cli.lua
--
-- This Script contains the Logic for the Prometheus Deobfuscator CLI

local function script_path()
    local str = debug.getinfo(2, "S").source:sub(2)
    return str:match("(.*[/%\\])") or ""
end
package.path = script_path() .. "?.lua;" .. script_path() .. "?/init.lua;" .. package.path

local deobf = require("prometheus.deobf")

local inputFile  = arg[1]
local outputFile = arg[2]

if not inputFile then
    print("Usage: lua deobf_cli.lua input.lua [output.lua]")
    os.exit(1)
end

local f = io.open(inputFile, "r")
if not f then
    print("Error: cannot open '" .. inputFile .. "'")
    os.exit(1)
end
local source = f:read("*a")
f:close()

local result, err = deobf:run(source, { verbose = true })
if not result then
    print("Deobfuscation failed: " .. tostring(err))
    os.exit(1)
end

if outputFile then
    local out = io.open(outputFile, "w")
    if not out then
        print("Error: cannot write to '" .. outputFile .. "'")
        os.exit(1)
    end
    out:write(result)
    out:close()
    print("Written to: " .. outputFile)
else
    print(result)
end
