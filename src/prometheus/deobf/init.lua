-- prometheus/deobf/init.lua
--
-- Entry point for the Prometheus deobfuscator.
-- Parses obfuscated source, runs all reverse passes in correct order,
-- and returns pretty-printed readable Lua.
--
-- Usage:
--   local deobf   = require("prometheus.deobf")
--   local readable = deobf:run(obfuscatedSource)
--   print(readable)
--
-- Or from CLI:
--   lua deobf/cli.lua input.lua output.lua

local Pipeline       = require("prometheus.deobf.pipeline")
local ReverseAnti    = require("prometheus.deobf.passes.ReverseAntiTamper")
local ReverseNumbers = require("prometheus.deobf.passes.ReverseNumbersToExpressions")
local ConstantFold   = require("prometheus.deobf.passes.ConstantFold")
local ReverseSplit   = require("prometheus.deobf.passes.ReverseSplitStrings")
local ReverseConst   = require("prometheus.deobf.passes.ReverseConstantArray")
local ReverseEncrypt = require("prometheus.deobf.passes.ReverseEncryptStrings")
local ReverseVmify   = require("prometheus.deobf.passes.ReverseVmify")
local Parser         = require("prometheus.parser")
local Enums          = require("prometheus.enums")
local Unparser       = require("prometheus.unparser")

local deobf = {}

-- Build and return the default reverse pipeline.
-- Passes run in reverse order of the obfuscation pipeline:
--
--   Obfuscation order (from optimal config):
--     1  WrapInFunction
--     2  AddVararg
--     3  EncryptStrings
--     4  SplitStrings
--     5  ConstantArray
--     6  NumbersToExpressions
--     7  ProxifyLocals          <- AST-only structural change, no dedicated pass needed
--     8  Vmify
--     9  AntiTamper
--     10 WatermarkCheck         <- simple string guard, removed by ReverseAntiTamper heuristic
--
--   Deobfuscation order (innermost first):
--     1  ReverseAntiTamper      <- remove guard blocks first (outermost layer)
--     2  ReverseVmify           <- detect and annotate VM wrapper
--     3  ReverseNumbersToExpressions + ConstantFold  <- normalize all numbers
--     4  ConstantFold           <- second fold pass after numbers are clean
--     5  ReverseSplitStrings    <- rejoin split strings
--     6  ReverseConstantArray   <- inline constant array accesses
--     7  ReverseEncryptStrings  <- decrypt encrypted strings
--     8  ConstantFold           <- final cleanup fold

function deobf:buildPipeline()
    local p = Pipeline:new()
    p.verbose = true

    -- Layer 1: remove protection layers first
    p:addPass(ReverseAnti:new())

    -- Layer 2: annotate VM (cannot fully decompile without compiler defs)
    p:addPass(ReverseVmify:new())

    -- Layer 3: normalize all numeric expressions
    p:addPass(ReverseNumbers:new())
    p:addPass(ConstantFold:new())

    -- Layer 4: rejoin split strings
    p:addPass(ReverseSplit:new())

    -- Layer 5: resolve constant array accesses
    p:addPass(ReverseConst:new())

    -- Layer 6: decrypt encrypted strings
    p:addPass(ReverseEncrypt:new())

    -- Layer 7: final constant folding cleanup
    p:addPass(ConstantFold:new())

    return p
end

-- Parse source string into AST.
-- Returns ast, or nil + error message on parse failure.
function deobf:parse(source)
    local ok, result = pcall(function()
        local parser = Parser:new({ LuaVersion = Enums.LuaVersion.Lua51 })
        return parser:parse(source)
    end)
    if not ok then
        return nil, tostring(result)
    end
    return result, nil
end

-- Run the full deobfuscation pipeline on source string.
-- Returns readable Lua string, or nil + error message on failure.
function deobf:run(source, options)
    options = options or {}

    print("[deobf] Parsing source...")
    local ast, err = self:parse(source)
    if not ast then
        return nil, "Parse error: " .. err
    end
    print("[deobf] Parse OK.")

    local pipeline = self:buildPipeline()
    pipeline.verbose = options.verbose ~= false

    print("[deobf] Running reverse pipeline...")
    ast = pipeline:run(ast)
    print("[deobf] Pipeline complete.")

    print("[deobf] Unparsing to readable Lua...")
    local ok2, output = pcall(function()
        return Unparser:unparse(ast, { PrettyPrint = true })
    end)
    if not ok2 then
        return nil, "Unparse error: " .. tostring(output)
    end

    print("[deobf] Done.")
    return output, nil
end

return deobf
