-- prometheus/deobf/passes/ReverseAntiTamper.lua
--
-- Reverses the AntiTamper obfuscation step.
--
-- The obfuscator injects a do-block at the top of the script containing:
--   1. A sanity check loop with random boolean chain (valid = true/false chain)
--   2. Optional debug.sethook anti-beautifier check
--   3. Anti-function-hook checks (debug.getinfo, pcall, string.dump)
--   4. Traceback validation
--   5. pcall integrity checks with random arithmetic errors
--   6. An infinite loop on tamper detection: repeat return (...) until true
--   7. An anti-function-arg-hook setmetatable check at the end
--
-- All of this is wrapped in a single DoStatement injected at ast.body.statements[1]
--
-- Detection fingerprints (from AntiTamper.lua source):
--   1. Contains "while true do end" (infinite loop on tamper)
--   2. Contains debug.sethook calls
--   3. Contains "repeat until valid" at the end
--   4. Contains setmetatable({}, { __tostring = err }) pattern
--   5. Contains "valid" as a local variable with boolean assignment chain
--   6. Contains pcall with arithmetic error forcing (number - string ^ number)
--
-- Strategy:
--   Scan ast.body.statements for a DoStatement that matches 3+ fingerprints.
--   If found, remove it entirely.
--   Also remove the trailing "repeat until valid" statement if present outside
--   the do-block.
--
-- Edge cases:
--   - UseDebug = false omits the debug.sethook block; fingerprinting still
--     works because the sanity check and pcall blocks remain
--   - PrettyPrint mode skips AntiTamper during obfuscation so nothing to remove
--   - Legitimate user do-blocks are protected by requiring 3+ fingerprints
--
-- Limitations:
--   - Heuristic detection; a very unusual user do-block could match by accident
--   - The setmetatable anti-hook at the very end of the injected block
--     appears as a separate statement after the do-block closes; we detect
--     and remove it as well

local Pass     = require("prometheus.deobf.passes.Pass")
local Ast      = require("prometheus.ast")
local visitast = require("prometheus.visitast")
local AstKind  = Ast.AstKind

local ReverseAntiTamper = Pass:extend()
ReverseAntiTamper.Name  = "ReverseAntiTamper"
ReverseAntiTamper.Description = "Removes injected AntiTamper do-block and associated checks"

-- Count how many AntiTamper fingerprints a statement has
local function scoreStatement(stmt)
    local score = 0
    local src = {}  -- collect node kinds seen

    visitast({ body = { statements = { stmt }, scope = {} } }, nil, function(node)
        -- Fingerprint 1: while true do end
        if node.kind == AstKind.WhileStatement then
            if node.condition and node.condition.kind == AstKind.BoolExpression
            and node.condition.value == true then
                score = score + 1
            end
        end

        -- Fingerprint 2: debug.sethook reference
        if node.kind == AstKind.StringExpression then
            if node.value == "sethook" or node.value == "getinfo"
            or node.value == "getupvalue" or node.value == "traceback" then
                score = score + 1
            end
        end

        -- Fingerprint 3: "valid" local variable
        if node.kind == AstKind.LocalVariableDeclaration then
            -- valid = 'randomstring' initial assignment shape
            if #node.ids == 1 and #node.expressions == 1 then
                local expr = node.expressions[1]
                if expr.kind == AstKind.StringExpression
                or expr.kind == AstKind.BoolExpression then
                    score = score + 1
                end
            end
        end

        -- Fingerprint 4: repeat ... until true (infinite tamper loop)
        if node.kind == AstKind.RepeatStatement then
            if node.condition and node.condition.kind == AstKind.BoolExpression
            and node.condition.value == true then
                score = score + 1
            end
        end

        -- Fingerprint 5: pcall with arithmetic string error
        -- pcall(function() local a = N - "str" ^ N return "str" / a end)
        if node.kind == AstKind.FunctionCallExpression then
            local func = node.func
            if func and func.kind == AstKind.VariableExpression then
                local name = func.scope and func.scope:getVariableName and
                             func.scope:getVariableName(func.id)
                if name == "pcall" and #node.args >= 1 then
                    score = score + 1
                end
            end
        end

        -- Fingerprint 6: setmetatable with __tostring key
        if node.kind == AstKind.StringExpression and node.value == "__tostring" then
            score = score + 1
        end

        -- Fingerprint 7: for loop over ipairs with triplet table (rotate-like)
        if node.kind == AstKind.GenericForStatement then
            score = score + 1
        end
    end)

    return score
end

-- Check if a statement is the trailing "repeat until valid" guard
local function isRepeatUntilValid(stmt)
    if stmt.kind ~= AstKind.RepeatStatement then return false end
    local cond = stmt.condition
    if not cond then return false end
    -- condition is VariableExpression for "valid"
    if cond.kind == AstKind.VariableExpression then return true end
    return false
end

-- Check if a statement is the anti-arg-hook setmetatable call at end
-- Shape: FunctionCallStatement( (function() end)(obj) )
-- or:    local obj = setmetatable({}, { __tostring = err })
local function isAntiArgHook(stmt)
    if stmt.kind == AstKind.LocalVariableDeclaration then
        if #stmt.expressions == 1 then
            local expr = stmt.expressions[1]
            if expr.kind == AstKind.FunctionCallExpression then
                local func = expr.func
                if func and func.kind == AstKind.VariableExpression then
                    local name = func.scope and func.scope:getVariableName and
                                 func.scope:getVariableName(func.id)
                    if name == "setmetatable" then return true end
                end
            end
        end
    end
    if stmt.kind == AstKind.FunctionCallStatement then
        -- (function() end)(obj) pattern
        local call = stmt.expression
        if call and call.kind == AstKind.FunctionCallExpression then
            local func = call.func
            if func and func.kind == AstKind.FunctionLiteralExpression then
                if func.body and #func.body.statements == 0 then
                    return true
                end
            end
        end
    end
    return false
end

local SCORE_THRESHOLD = 3

function ReverseAntiTamper:apply(ast)
    local stmts = ast.body.statements
    local toRemove = {}

    for i, stmt in ipairs(stmts) do
        -- Main do-block detection
        if stmt.kind == AstKind.DoStatement then
            local score = scoreStatement(stmt)
            if score >= SCORE_THRESHOLD then
                toRemove[i] = true
                print(string.format("[deobf] ReverseAntiTamper: removed do-block at index %d (score %d)", i, score))
            end
        end

        -- Trailing "repeat until valid" guard
        if isRepeatUntilValid(stmt) then
            toRemove[i] = true
        end

        -- Anti-arg-hook setmetatable / empty function call
        if isAntiArgHook(stmt) then
            toRemove[i] = true
        end
    end

    if next(toRemove) == nil then
        print("[deobf] ReverseAntiTamper: no AntiTamper block found")
        return ast
    end

    local newStmts = {}
    for i, stmt in ipairs(stmts) do
        if not toRemove[i] then
            table.insert(newStmts, stmt)
        end
    end
    ast.body.statements = newStmts

    return ast
end

return ReverseAntiTamper
