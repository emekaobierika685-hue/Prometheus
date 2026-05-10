-- deobf_cli.lua
-- Usage: lua deobf_cli.lua input.lua output.lua

package.path = "./?.lua;./?/init.lua;" .. package.path

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
