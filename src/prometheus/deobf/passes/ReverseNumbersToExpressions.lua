-- prometheus/deobf/passes/ReverseNumbersToExpressions.lua
--
-- Reverses the NumbersToExpressions obfuscation step.
--
-- The obfuscator transforms number literals into nested arithmetic expressions
-- using addition, subtraction, and modulo, and optionally represents the leaf
-- numbers in hex, binary, or scientific notation.
--
-- Patterns reversed:
--   (29 + 13)                       -> 42
--   (0xC8 + 0x37)                   -> 255
--   (0b11001010 ~ 0b00110101)       -> 255
--   (2.55e2 + 0xFF)                 -> 510
--   ((7 + 5) + (3 + 10))            -> 25  (deeply nested)
--   (lhs % rhs)                     -> lhs % rhs evaluated
--
-- Strategy:
--   1. Normalize all non-standard number formats to plain numbers first
--   2. Fold all constant binary expressions bottom-up using multi-pass
--   3. ConstantFold handles the actual math; this pass handles normalization
--      and any XOR binary patterns specific to the custom xor representation
--
-- Edge cases:
--   - Binary literals require custom parser (tonumber does not handle 0b...)
--   - XOR (~) requires Lua 5.3+; pcall-guarded
--   - Deeply nested expressions require multiple passes
--   - Non-integer results are preserved as floats
--   - NaN and infinity are left untouched

local Pass     = require("prometheus.deobf.passes.Pass")
local Ast      = require("prometheus.ast")
local visitast = require("prometheus.visitast")
local AstKind  = Ast.AstKind

local ReverseNumbers = Pass:extend()
ReverseNumbers.Name  = "ReverseNumbersToExpressions"
ReverseNumbers.Description = "Reverses NumbersToExpressions obfuscation, collapsing arithmetic back to literals"

-- Parse any supported number literal format into a Lua number
local function parseNumber(val)
    if type(val) == "number" then return val end
    if type(val) ~= "string" then return nil end

    -- Binary: 0b... or 0B...
    if val:match("^0[bB][01]+$") then
        local n = 0
        for i = 3, #val do
            n = n * 2 + (val:sub(i, i) == "1" and 1 or 0)
        end
        return n
    end

    -- Hex (0x...), scientific (1e5), plain decimal
    return tonumber(val)
end

local function isSafe(result)
    if type(result) ~= "number" then return false end
    if result ~= result then return false end
    if result == math.huge or result == -math.huge then return false end
    return true
end

local function tryFoldNode(node)
    if not node.lhs or not node.rhs then return nil end

    local function val(n)
        if n.kind == AstKind.NumberExpression then
            return parseNumber(n.value)
        end
        return nil
    end

    local lv = val(node.lhs)
    local rv = val(node.rhs)
    if lv == nil or rv == nil then return nil end

    local result

    if node.kind == AstKind.AddExpression then
        result = lv + rv
    elseif node.kind == AstKind.SubExpression then
        result = lv - rv
    elseif node.kind == AstKind.MulExpression then
        result = lv * rv
    elseif node.kind == AstKind.DivExpression then
        if rv == 0 then return nil end
        result = lv / rv
    elseif node.kind == AstKind.ModExpression then
        if rv == 0 then return nil end
        result = lv % rv
    elseif node.kind == AstKind.PowExpression then
        result = lv ^ rv
    elseif node.kind == AstKind.BXorExpression then
        -- XOR: custom representation added to obfuscator
        -- Only valid for integers
        if lv ~= math.floor(lv) or rv ~= math.floor(rv) then return nil end
        local ok, r = pcall(function() return math.tointeger(lv) ~ math.tointeger(rv) end)
        if not ok then
            -- Lua 5.2 fallback using bit32 if available
            if bit32 then
                result = bit32.bxor(lv, rv)
            else
                return nil
            end
        else
            result = r
        end
    else
        return nil
    end

    if not isSafe(result) then return nil end
    return result
end

function ReverseNumbers:apply(ast)
    local changed = true

    while changed do
        changed = false

        visitast(ast, nil, function(node)

            -- Step 1: normalize non-standard number literal strings
            if node.kind == AstKind.NumberExpression then
                if type(node.value) == "string" then
                    local v = parseNumber(node.value)
                    if v ~= nil then
                        changed = true
                        return Ast.NumberExpression(v)
                    end
                end
                return
            end

            -- Step 2: fold constant binary expressions
            local result = tryFoldNode(node)
            if result ~= nil then
                changed = true
                return Ast.NumberExpression(result)
            end
        end)
    end

    return ast
end

return ReverseNumbers
