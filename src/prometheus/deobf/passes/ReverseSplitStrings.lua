-- prometheus/deobf/passes/ReverseSplitStrings.lua
--
-- Reverses the SplitStrings obfuscation step.
--
-- The obfuscator splits string literals into chunks and reconstructs them
-- at runtime using one of three concatenation strategies:
--
--   1. strcat:  "hel" .. "lo" .. " wo" .. "rld"
--   2. table:   table.concat({"hel", "lo", " wo", "rld"})
--   3. custom:  customFunc({2,1,3, "lo", "hel", "rld"})
--              or customFunc({{2,1,3}, {"lo","hel","rld"}})
--
-- Patterns reversed:
--
--   StrCat chain:
--     "hel" .. "lo" .. "world"  ->  "hello world"
--
--   table.concat call:
--     table.concat({"hel", "lo"})  ->  "hello"
--
--   custom variant 1:
--     customFunc({2,1, {"lo","hel"}})  ->  "hello"
--     (indices reference into the string subtable appended at end)
--
--   custom variant 2:
--     customFunc({2,1,"lo","hel"})  ->  "hello"
--     (first half are indices, second half are strings)
--
-- Strategy:
--   1. Detect StrCat chains where all operands are string literals -> join
--   2. Detect table.concat({...}) calls with all-string tables -> join
--   3. Detect custom function patterns by shape:
--      - Single table argument
--      - Contains a mix of NumberExpressions and StringExpressions
--      - Or contains a nested table of strings at the end
--   4. Run multiple passes until stable
--
-- Limitations:
--   - Custom function detection is heuristic; relies on argument shape
--   - If custom function is used with non-literal arguments, skipped safely
--   - table.concat with separator argument is not reversed (non-default)
--   - Variable name of custom function is obfuscated; detected by shape only

local Pass     = require("prometheus.deobf.passes.Pass")
local Ast      = require("prometheus.ast")
local visitast = require("prometheus.visitast")
local AstKind  = Ast.AstKind

local ReverseSplitStrings = Pass:extend()
ReverseSplitStrings.Name  = "ReverseSplitStrings"
ReverseSplitStrings.Description = "Reverses SplitStrings obfuscation, rejoining split string literals"

-- Collect a full StrCat chain into a flat list of nodes
local function collectStrCatChain(node, out)
    if node.kind == AstKind.StrCatExpression then
        collectStrCatChain(node.lhs, out)
        collectStrCatChain(node.rhs, out)
    else
        table.insert(out, node)
    end
end

-- Check if all nodes in a list are string literals
local function allStrings(nodes)
    for _, n in ipairs(nodes) do
        if n.kind ~= AstKind.StringExpression then return false end
    end
    return true
end

-- Join a list of StringExpression nodes into one string
local function joinStrings(nodes)
    local parts = {}
    for _, n in ipairs(nodes) do
        table.insert(parts, n.value)
    end
    return table.concat(parts)
end

-- Check if a TableConstructorExpression contains only string entries
local function isAllStringTable(node)
    if node.kind ~= AstKind.TableConstructorExpression then return false end
    for _, entry in ipairs(node.entries) do
        if entry.kind ~= AstKind.TableEntry then return false end
        if entry.value.kind ~= AstKind.StringExpression then return false end
    end
    return true
end

-- Extract string values from an all-string table
local function extractStringTable(node)
    local parts = {}
    for _, entry in ipairs(node.entries) do
        table.insert(parts, entry.value.value)
    end
    return parts
end

-- Detect and reverse custom variant 1:
-- customFunc({idx1, idx2, ..., {str1, str2, ...}})
-- Last entry of outer table is a subtable of strings
-- Earlier entries are number indices into that subtable
local function tryReverseCustomVariant1(callNode)
    if #callNode.args ~= 1 then return nil end
    local arg = callNode.args[1]
    if arg.kind ~= AstKind.TableConstructorExpression then return nil end
    if #arg.entries < 2 then return nil end

    -- Last entry must be a TableEntry containing an all-string table
    local lastEntry = arg.entries[#arg.entries]
    if lastEntry.kind ~= AstKind.TableEntry then return nil end
    if not isAllStringTable(lastEntry.value) then return nil end

    local stringTable = extractStringTable(lastEntry.value)

    -- All other entries must be number indices
    local indices = {}
    for i = 1, #arg.entries - 1 do
        local entry = arg.entries[i]
        if entry.kind ~= AstKind.TableEntry then return nil end
        if entry.value.kind ~= AstKind.NumberExpression then return nil end
        local idx = entry.value.value
        if type(idx) ~= "number" or math.floor(idx) ~= idx then return nil end
        if idx < 1 or idx > #stringTable then return nil end
        table.insert(indices, idx)
    end

    -- Reconstruct string from indices
    local parts = {}
    for _, idx in ipairs(indices) do
        table.insert(parts, stringTable[idx])
    end
    return table.concat(parts)
end

-- Detect and reverse custom variant 2:
-- customFunc({idx1, idx2, ..., str1, str2, ...})
-- First half are indices, second half are strings
-- #entries must be even; first half are numbers, second half are strings
local function tryReverseCustomVariant2(callNode)
    if #callNode.args ~= 1 then return nil end
    local arg = callNode.args[1]
    if arg.kind ~= AstKind.TableConstructorExpression then return nil end
    local n = #arg.entries
    if n < 2 or n % 2 ~= 0 then return nil end

    local half = n / 2
    local indices = {}
    local strings = {}

    for i = 1, half do
        local entry = arg.entries[i]
        if entry.kind ~= AstKind.TableEntry then return nil end
        if entry.value.kind ~= AstKind.NumberExpression then return nil end
        local idx = entry.value.value
        if type(idx) ~= "number" or math.floor(idx) ~= idx then return nil end
        table.insert(indices, idx)
    end

    for i = half + 1, n do
        local entry = arg.entries[i]
        if entry.kind ~= AstKind.TableEntry then return nil end
        if entry.value.kind ~= AstKind.StringExpression then return nil end
        table.insert(strings, entry.value.value)
    end

    -- Validate indices are in range
    for _, idx in ipairs(indices) do
        if idx < 1 or idx > #strings then return nil end
    end

    -- Reconstruct
    local parts = {}
    for _, idx in ipairs(indices) do
        table.insert(parts, strings[idx])
    end
    return table.concat(parts)
end

function ReverseSplitStrings:apply(ast)
    local changed = true

    while changed do
        changed = false

        visitast(ast, nil, function(node)

            -- Pattern 1: StrCat chain of all string literals
            if node.kind == AstKind.StrCatExpression then
                local chain = {}
                collectStrCatChain(node, chain)
                if allStrings(chain) and #chain > 1 then
                    changed = true
                    return Ast.StringExpression(joinStrings(chain))
                end
                return
            end

            -- Pattern 2: table.concat({...}) with all-string table
            if node.kind == AstKind.FunctionCallExpression then
                -- Detect table.concat style:
                -- IndexExpression(VariableExpression("table"), StringExpression("concat"))
                local func = node.func
                if func and func.kind == AstKind.IndexExpression then
                    local idx = func.index
                    if idx and idx.kind == AstKind.StringExpression and idx.value == "concat" then
                        -- One argument, must be an all-string table, no separator
                        if #node.args == 1 and isAllStringTable(node.args[1]) then
                            local parts = extractStringTable(node.args[1])
                            changed = true
                            return Ast.StringExpression(table.concat(parts))
                        end
                    end
                end

                -- Pattern 3: custom variant 1
                local r1 = tryReverseCustomVariant1(node)
                if r1 then
                    changed = true
                    return Ast.StringExpression(r1)
                end

                -- Pattern 4: custom variant 2
                local r2 = tryReverseCustomVariant2(node)
                if r2 then
                    changed = true
                    return Ast.StringExpression(r2)
                end
            end
        end)
    end

    return ast
end

return ReverseSplitStrings
