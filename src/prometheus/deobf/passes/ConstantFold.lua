-- prometheus/deobf/passes/ConstantFold.lua
--
-- Folds constant arithmetic and string expressions into single literals.
-- This is a prerequisite for most other reverse passes since obfuscated
-- code is full of expressions like (200 + 55) that should just be 255.
--
-- Patterns reversed:
--   (a + b)        where a, b are number literals  -> single NumberExpression
--   (a - b)        where a, b are number literals  -> single NumberExpression
--   (a * b)        where a, b are number literals  -> single NumberExpression
--   (a / b)        where a, b are number literals  -> single NumberExpression
--   (a % b)        where a, b are number literals  -> single NumberExpression
--   (a ^ b)        where a, b are number literals  -> single NumberExpression
--   (a ~ b)        where a, b are number literals  -> single NumberExpression (Lua 5.3+)
--   ("a" .. "b")   where a, b are string literals  -> single StringExpression
--
-- Edge cases handled:
--   - Division by zero is skipped (left as-is)
--   - NaN results are skipped
--   - Infinite results are skipped
--   - Non-standard number formats (hex, binary, scientific) are normalized first
--   - Multiple passes run until no further folding is possible

local Pass     = require("prometheus.deobf.passes.Pass")
local Ast      = require("prometheus.ast")
local visitast = require("prometheus.visitast")
local AstKind  = Ast.AstKind

local ConstantFold = Pass:extend()
ConstantFold.Name  = "ConstantFold"
ConstantFold.Description = "Folds constant arithmetic and string expressions into literals"

-- Parse any number literal format into a Lua number.
-- Handles: plain, hex (0x...), binary (0b...), scientific (1e5).
local function parseNumber(val)
    if type(val) == "number" then return val end
    if type(val) ~= "string" then return nil end

    -- Binary literal: 0b... or 0B...
    if val:match("^0[bB][01]+$") then
        local n = 0
        for i = 3, #val do
            local bit = val:sub(i, i)
            n = n * 2 + (bit == "1" and 1 or 0)
        end
        return n
    end

    -- Everything else: tonumber handles hex and scientific
    return tonumber(val)
end

local function getConstantValue(node)
    if node.kind == AstKind.NumberExpression then
        return parseNumber(node.value)
    end
    if node.kind == AstKind.StringExpression then
        return node.value
    end
    return nil
end

local function isNumber(v)  return type(v) == "number" end
local function isString(v)  return type(v) == "string" end

local function isSafe(result)
    if type(result) ~= "number" then return true end
    if result ~= result then return false end           -- NaN
    if result == math.huge or result == -math.huge then return false end
    return true
end

local function tryFold(node)
    if not node.lhs or not node.rhs then return nil end
    local lv = getConstantValue(node.lhs)
    local rv = getConstantValue(node.rhs)
    if lv == nil or rv == nil then return nil end

    local result

    if node.kind == AstKind.AddExpression then
        if not isNumber(lv) or not isNumber(rv) then return nil end
        result = lv + rv

    elseif node.kind == AstKind.SubExpression then
        if not isNumber(lv) or not isNumber(rv) then return nil end
        result = lv - rv

    elseif node.kind == AstKind.MulExpression then
        if not isNumber(lv) or not isNumber(rv) then return nil end
        result = lv * rv

    elseif node.kind == AstKind.DivExpression then
        if not isNumber(lv) or not isNumber(rv) then return nil end
        if rv == 0 then return nil end
        result = lv / rv

    elseif node.kind == AstKind.ModExpression then
        if not isNumber(lv) or not isNumber(rv) then return nil end
        if rv == 0 then return nil end
        result = lv % rv

    elseif node.kind == AstKind.PowExpression then
        if not isNumber(lv) or not isNumber(rv) then return nil end
        result = lv ^ rv

    elseif node.kind == AstKind.BXorExpression then
        -- Lua 5.3+ bitwise XOR
        if not isNumber(lv) or not isNumber(rv) then return nil end
        if lv ~= math.floor(lv) or rv ~= math.floor(rv) then return nil end
        local ok, r = pcall(function() return lv ~ rv end)
        if not ok then return nil end
        result = r

    elseif node.kind == AstKind.StrCatExpression then
        if not isString(lv) or not isString(rv) then return nil end
        result = lv .. rv

    else
        return nil
    end

    if not isSafe(result) then return nil end
    return result
end

function ConstantFold:apply(ast)
    local changed = true

    while changed do
        changed = false

        visitast(ast, nil, function(node)
            -- Normalize non-standard number literal formats to plain numbers
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

            -- Try folding binary expressions
            local result = tryFold(node)
            if result == nil then return end

            changed = true
            if type(result) == "string" then
                return Ast.StringExpression(result)
            else
                return Ast.NumberExpression(result)
            end
        end)
    end

    return ast
end

return ConstantFold
