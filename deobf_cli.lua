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
package.path = script_path() .. "src/?.lua;" .. script_path() .. "src/?/init.lua;" .. package.path

local deobf = require("prometheus.deobf")

local inputFile  = arg[1]
local outputFile = arg[2]

if not inputFile then
    print("Usage: lua deobf_cli.lua input.lua [output.lua]")
    os.exit(1)
end

-- Read input file
local f = io.open(inputFile, "r")
if not f then
    print("Error: cannot open '" .. inputFile .. "'")
    os.exit(1)
end
local source = f:read("*a")
f:close()

-- Run deobfuscator
local result, err = deobf:run(source, { verbose = true })

if not result then
    print("Deobfuscation failed: " .. tostring(err))
    os.exit(1)
end

-- Write or print output
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
