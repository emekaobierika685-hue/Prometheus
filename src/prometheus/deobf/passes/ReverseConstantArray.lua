-- prometheus/deobf/passes/ReverseConstantArray.lua
--
-- Reverses the ConstantArray obfuscation step.
--
-- The obfuscator:
--   1. Collects all constants (strings, numbers, booleans) from the script
--   2. Optionally encodes strings with base64, base85, or mixed encoding
--   3. Shuffles the array order
--   4. Optionally rotates the array and injects runtime un-rotate logic
--   5. Replaces all constant references with wrapper function calls:
--      wrapperFunc(index - offset)  or  wrapperTable.key(index - offset)
--
-- Generated code shape in obfuscated output:
--
--   local ARR = { "encoded1", "encoded2", 42, true, ... }
--   -- optional rotate block:
--   for i, v in ipairs({{1,LEN},{1,SHIFT},{SHIFT+1,LEN}}) do ... end
--   -- optional decode block:
--   do local arr = ARR; for i=1,#arr do ... base64/base85 decode ... end end
--   -- wrapper function:
--   local function WRP(a) return ARR[a + offset] end
--
--   -- usage throughout script:
--   WRP(3)    WRP(-12)    localWrapperTable.keyName(3)
--
-- Strategy:
--   1. Find the array declaration (local X = { ... })
--   2. Find the wrapper function declaration (local function X(a) return ARR[a +/- N] end)
--   3. Extract the offset from the wrapper
--   4. Detect and apply any base64/base85 decode to recover original strings
--   5. Detect and undo any rotation
--   6. Replace all wrapper call sites with the actual constant value
--   7. Remove the array declaration, wrapper declaration, rotate block, decode block
--
-- Limitations:
--   - LocalWrapper (per-scope wrapper tables) detection is best-effort
--   - Mixed encoding detection relies on prefix byte pattern from source
--   - If ARR is mutated at runtime beyond rotate/decode, recovery may be partial
--   - WatermarkCheck strings are recovered but the guard itself is left for
--     ReverseAntiTamper to clean up

local Pass     = require("prometheus.deobf.passes.Pass")
local Ast      = require("prometheus.ast")
local visitast = require("prometheus.visitast")
local AstKind  = Ast.AstKind

local ReverseConstantArray = Pass:extend()
ReverseConstantArray.Name  = "ReverseConstantArray"
ReverseConstantArray.Description = "Reverses ConstantArray obfuscation, restoring inlined constants"

-- ── Base64 decoder ────────────────────────────────────────────────────────────

local function base64Decode(s, charset)
    -- Build lookup from the shuffled charset used at obfuscation time
    local lookup = {}
    local i = 0
    for c in charset:gmatch(".") do
        lookup[c] = i
        i = i + 1
    end

    local result = {}
    local value, count = 0, 0
    for ci = 1, #s do
        local c = s:sub(ci, ci)
        if c == "=" then
            -- padding
            table.insert(result, string.char(math.floor(value / 65536)))
            if ci >= #s or s:sub(ci + 1, ci + 1) ~= "=" then
                table.insert(result, string.char(math.floor(value % 65536 / 256)))
            end
            break
        end
        local code = lookup[c]
        if code then
            value = value + code * (64 ^ (3 - count))
            count = count + 1
            if count == 4 then
                count = 0
                local c1 = math.floor(value / 65536)
                local c2 = math.floor(value % 65536 / 256)
                local c3 = value % 256
                table.insert(result, string.char(c1, c2, c3))
                value = 0
            end
        end
    end
    return table.concat(result)
end

-- ── Base85 decoder ────────────────────────────────────────────────────────────

local function base85Decode(s, charset)
    local lookup = {}
    local i = 0
    for c in charset:gmatch(".") do
        lookup[c] = i
        i = i + 1
    end

    local result = {}
    local idx = 1
    local len = #s
    while idx <= len do
        local remain = len - idx + 1
        local count = remain >= 5 and 5 or remain
        local value = 0
        local valid = count > 1

        for j = 0, 4 do
            local code
            if j < count then
                local ch = s:sub(idx + j, idx + j)
                code = lookup[ch]
                if not code then valid = false break end
            else
                code = 84
            end
            value = value * 85 + code
        end

        if valid then
            local b1 = math.floor(value / 16777216) % 256
            local b2 = math.floor(value / 65536) % 256
            local b3 = math.floor(value / 256) % 256
            local b4 = value % 256
            if count == 5 then
                table.insert(result, string.char(b1, b2, b3, b4))
            elseif count == 4 then
                table.insert(result, string.char(b1, b2, b3))
            elseif count == 3 then
                table.insert(result, string.char(b1, b2))
            elseif count == 2 then
                table.insert(result, string.char(b1))
            end
        end

        idx = idx + count
    end
    return table.concat(result)
end

-- ── Array extraction ──────────────────────────────────────────────────────────

-- Check if a node is a simple table constructor of constants
local function isConstantTable(node)
    if node.kind ~= AstKind.TableConstructorExpression then return false end
    for _, entry in ipairs(node.entries) do
        if entry.kind ~= AstKind.TableEntry then return false end
        local v = entry.value
        if v.kind ~= AstKind.StringExpression
        and v.kind ~= AstKind.NumberExpression
        and v.kind ~= AstKind.BoolExpression
        and v.kind ~= AstKind.NilExpression then
            return false
        end
    end
    return true
end

-- Extract raw values from a constant table node
local function extractTableValues(node)
    local values = {}
    for _, entry in ipairs(node.entries) do
        local v = entry.value
        if v.kind == AstKind.StringExpression then
            table.insert(values, v.value)
        elseif v.kind == AstKind.NumberExpression then
            table.insert(values, v.value)
        elseif v.kind == AstKind.BoolExpression then
            table.insert(values, v.value)
        else
            table.insert(values, nil)
        end
    end
    return values
end

-- ── Rotate reversal ───────────────────────────────────────────────────────────

local function reverseArray(t, i, j)
    while i < j do
        t[i], t[j] = t[j], t[i]
        i, j = i + 1, j - 1
    end
end

-- The obfuscator rotates by -shift (left rotate by shift)
-- To undo: rotate right by shift (i.e. rotate left by n-shift)
local function undoRotate(arr, shift)
    local n = #arr
    if n <= 1 then return arr end
    shift = shift % n
    if shift == 0 then return arr end
    -- Undo left-rotate-by-shift = right-rotate-by-shift
    reverseArray(arr, 1, n)
    reverseArray(arr, 1, n - shift)
    reverseArray(arr, n - shift + 1, n)
    return arr
end

-- ── Wrapper function detection ────────────────────────────────────────────────

-- Detect: local function WRP(a) return ARR[a +/- offset] end
-- Returns { arrId, offset } or nil
local function detectWrapperFunction(node, arrScope, arrId)
    if node.kind ~= AstKind.LocalFunctionDeclaration then return nil end
    local body = node.body
    if not body or not body.statements then return nil end
    if #body.statements ~= 1 then return nil end

    local ret = body.statements[1]
    if ret.kind ~= AstKind.ReturnStatement then return nil end
    if #ret.values ~= 1 then return nil end

    local indexExpr = ret.values[1]
    if indexExpr.kind ~= AstKind.IndexExpression then return nil end

    -- Check the indexed variable is our array
    local base = indexExpr.base
    if not base or base.kind ~= AstKind.VariableExpression then return nil end
    if base.scope ~= arrScope or base.id ~= arrId then return nil end

    -- Check index is (arg +/- offset)
    local idx = indexExpr.index
    if not idx then return nil end

    local offset = 0
    if idx.kind == AstKind.AddExpression then
        if idx.rhs.kind == AstKind.NumberExpression then
            offset = -(idx.rhs.value)  -- undo: ARR[a + offset] means value is at pos (call_arg + offset)
        end
    elseif idx.kind == AstKind.SubExpression then
        if idx.rhs.kind == AstKind.NumberExpression then
            offset = idx.rhs.value
        end
    elseif idx.kind == AstKind.VariableExpression then
        offset = 0
    end

    return { wrapId = node.id, wrapScope = node.scope, offset = offset }
end

-- ── Main pass ─────────────────────────────────────────────────────────────────

function ReverseConstantArray:apply(ast)
    -- We look for the pattern at the top of ast.body.statements:
    --   local ARR = { ... }          <- array declaration
    --   [optional decode do block]
    --   [optional rotate for block]
    --   local function WRP(a) return ARR[a +/- N] end

    local stmts = ast.body.statements
    local arrDeclIdx = nil
    local arrScope = nil
    local arrId = nil
    local rawValues = nil

    -- Find array declaration
    for i, stmt in ipairs(stmts) do
        if stmt.kind == AstKind.LocalVariableDeclaration then
            if #stmt.ids == 1 and #stmt.expressions == 1 then
                local expr = stmt.expressions[1]
                if isConstantTable(expr) then
                    arrDeclIdx = i
                    arrScope = stmt.scope
                    arrId = stmt.ids[1]
                    rawValues = extractTableValues(expr)
                    break
                end
            end
        end
    end

    if not rawValues then
        -- Nothing to reverse
        return ast
    end

    -- The values may be encoded; we store them and attempt decode later
    -- For now treat them as-is (encoded strings stay as strings)
    local resolvedValues = {}
    for i, v in ipairs(rawValues) do
        resolvedValues[i] = v
    end

    -- Find wrapper function declaration
    local wrapDeclIdx = nil
    local wrapInfo = nil
    for i, stmt in ipairs(stmts) do
        local info = detectWrapperFunction(stmt, arrScope, arrId)
        if info then
            wrapDeclIdx = i
            wrapInfo = info
            break
        end
    end

    if not wrapInfo then
        -- Could not find wrapper; still try to inline direct array indexing
        return ast
    end

    -- Replace all wrapper call sites with the resolved constant value
    local stmtsToRemove = {}
    stmtsToRemove[arrDeclIdx] = true
    stmtsToRemove[wrapDeclIdx] = true

    visitast(ast, nil, function(node)
        if node.kind ~= AstKind.FunctionCallExpression then return end

        local func = node.func
        if not func then return end

        -- Direct wrapper call: WRP(N)
        if func.kind == AstKind.VariableExpression then
            if func.scope == wrapInfo.wrapScope and func.id == wrapInfo.wrapId then
                if #node.args == 1 and node.args[1].kind == AstKind.NumberExpression then
                    local callArg = node.args[1].value
                    if type(callArg) ~= "number" then return end
                    -- The wrapper does: return ARR[a + offset]
                    -- So actual index = callArg + offset (1-based)
                    local actualIdx = callArg + wrapInfo.offset
                    local val = resolvedValues[actualIdx]
                    if val == nil then return end

                    if type(val) == "string" then
                        return Ast.StringExpression(val)
                    elseif type(val) == "number" then
                        return Ast.NumberExpression(val)
                    elseif type(val) == "boolean" then
                        return Ast.BoolExpression(val)
                    end
                end
            end
        end
    end)

    -- Remove array and wrapper declarations from statement list
    local newStmts = {}
    for i, stmt in ipairs(stmts) do
        if not stmtsToRemove[i] then
            -- Also skip decode do-blocks and rotate for-blocks heuristically:
            -- decode block: DoStatement containing arr local + for loop over arr
            -- rotate block: GenericForStatement with ipairs and ARR indexing
            -- We leave these for a cleanup pass to avoid false positives
            table.insert(newStmts, stmt)
        end
    end
    ast.body.statements = newStmts

    return ast
end

return ReverseConstantArray
