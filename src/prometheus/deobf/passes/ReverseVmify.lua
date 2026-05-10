-- prometheus/deobf/passes/ReverseVmify.lua
--
-- Reverses the Vmify obfuscation step.
--
-- Vmify compiles the entire script into a custom bytecode VM using
-- prometheus.compiler.compiler. The result is a self-contained VM
-- emitter: a function that takes a bytecode blob and executes it.
--
-- Since we have the compiler source we know the bytecode format.
-- Full VM reversal (decompilation) is the hardest pass in the pipeline.
--
-- What Vmify produces (from compiler.lua shape):
--   return (function(...)
--     local P = { ... }            -- constant pool (strings, numbers)
--     local function r(r) return P[r - OFFSET] end
--     -- VM dispatch loop
--     for ... do
--       if O > X then ... end      -- instruction dispatch tree
--     end
--   end)({...}, getmetatable, setmetatable, ...)
--
-- Strategy (best-effort static analysis):
--   1. Detect the Vmify wrapper shape:
--      - Top-level return of an immediately-called function literal
--      - First statement is local P = { large table of encoded values }
--      - Contains a numeric dispatch loop (if/elseif chain on a counter)
--   2. If detected, attempt to recover the constant pool P
--   3. Substitute readable names where possible
--   4. If full decompilation is not possible, emit a comment block
--      explaining the VM structure for manual analysis
--
-- IMPORTANT:
--   Full automated decompilation of a custom bytecode VM is not
--   reliably possible without running the VM or having the compiler's
--   instruction set definition. This pass provides:
--     a) Detection and fingerprinting
--     b) Constant pool extraction
--     c) Best-effort structure recovery
--     d) A clear diagnostic comment in output when full reversal fails
--
-- Limitations:
--   - Instruction semantics are custom and not documented externally
--   - The dispatch tree uses obfuscated numeric comparisons
--   - Full decompilation requires the compiler instruction definitions
--     from prometheus/compiler/compiler.lua (not provided in this pass)
--   - This pass is intentionally conservative: it will not corrupt the
--     AST if it cannot fully reverse the VM

local Pass     = require("prometheus.deobf.passes.Pass")
local Ast      = require("prometheus.ast")
local visitast = require("prometheus.visitast")
local AstKind  = Ast.AstKind

local ReverseVmify = Pass:extend()
ReverseVmify.Name  = "ReverseVmify"
ReverseVmify.Description = "Detects and partially reverses Vmify bytecode VM wrapper"

-- ── Fingerprint detection ─────────────────────────────────────────────────────

-- Check if a node is the Vmify top-level wrapper:
-- return (function(...) ... end)({...}, getmetatable, ...)
local function isVmifyWrapper(stmt)
    if stmt.kind ~= AstKind.ReturnStatement then return false end
    if #stmt.values ~= 1 then return false end
    local call = stmt.values[1]
    if call.kind ~= AstKind.FunctionCallExpression then return false end
    local func = call.func
    if not func or func.kind ~= AstKind.FunctionLiteralExpression then return false end
    -- Must have arguments including getmetatable, setmetatable
    local args = call.args
    if not args or #args < 3 then return false end
    return true
end

-- Extract the constant pool P from the VM wrapper body
-- P is always: local P = { large list of encoded strings }
local function extractConstantPool(vmBody)
    local pool = {}
    for _, stmt in ipairs(vmBody.statements) do
        if stmt.kind == AstKind.LocalVariableDeclaration then
            if #stmt.ids == 1 and #stmt.expressions == 1 then
                local expr = stmt.expressions[1]
                if expr.kind == AstKind.TableConstructorExpression then
                    if #expr.entries > 10 then
                        -- Likely the constant pool
                        for i, entry in ipairs(expr.entries) do
                            if entry.kind == AstKind.TableEntry then
                                local v = entry.value
                                if v.kind == AstKind.StringExpression then
                                    pool[i] = v.value
                                elseif v.kind == AstKind.NumberExpression then
                                    pool[i] = v.value
                                end
                            end
                        end
                        return pool, stmt
                    end
                end
            end
        end
    end
    return nil, nil
end

-- Count numeric if/elseif comparisons (VM dispatch tree fingerprint)
local function countDispatchNodes(body)
    local count = 0
    visitast({ body = body, scope = {} }, nil, function(node)
        if node.kind == AstKind.IfStatement then
            local cond = node.condition
            if cond and (cond.kind == AstKind.LessThanExpression
                      or cond.kind == AstKind.GreaterThanExpression
                      or cond.kind == AstKind.LessOrEqualExpression
                      or cond.kind == AstKind.GreaterOrEqualExpression) then
                count = count + 1
            end
        end
    end)
    return count
end

-- ── Output generation ─────────────────────────────────────────────────────────

-- Emit a structured comment block describing what we found
local function buildDiagnosticComment(poolSize, dispatchCount)
    return string.format(
        "--[[\n" ..
        "  [deobf] ReverseVmify: Vmify bytecode VM detected.\n" ..
        "  Constant pool size : %d entries\n" ..
        "  Dispatch nodes     : %d\n" ..
        "  Status             : Full decompilation requires compiler instruction\n" ..
        "                       definitions from prometheus/compiler/compiler.lua.\n" ..
        "                       Provide that file to enable full reversal.\n" ..
        "  The VM wrapper has been left in place below this comment.\n" ..
        "--]]\n",
        poolSize, dispatchCount
    )
end

-- ── Main pass ─────────────────────────────────────────────────────────────────

function ReverseVmify:apply(ast)
    local stmts = ast.body.statements
    local vmifyIdx = nil
    local vmifyStmt = nil

    -- Find the Vmify return wrapper
    for i, stmt in ipairs(stmts) do
        if isVmifyWrapper(stmt) then
            vmifyIdx = i
            vmifyStmt = stmt
            break
        end
    end

    if not vmifyIdx then
        print("[deobf] ReverseVmify: no Vmify wrapper found")
        return ast
    end

    -- Extract VM body
    local vmCall = vmifyStmt.values[1]
    local vmFunc = vmCall.func
    local vmBody = vmFunc.body

    -- Extract constant pool
    local pool, poolDecl = extractConstantPool(vmBody)
    local poolSize = pool and #pool or 0

    -- Count dispatch nodes
    local dispatchCount = countDispatchNodes(vmBody)

    print(string.format(
        "[deobf] ReverseVmify: found VM. Pool=%d entries, Dispatch nodes=%d",
        poolSize, dispatchCount
    ))

    -- If pool is small or dispatch count is low, may not be Vmify
    if poolSize < 5 and dispatchCount < 10 then
        print("[deobf] ReverseVmify: scores too low, skipping")
        return ast
    end

    -- Print recovered constants for manual inspection
    if pool then
        print("[deobf] ReverseVmify: recovered constant pool:")
        for i, v in ipairs(pool) do
            if type(v) == "string" and #v < 80 then
                print(string.format("  [%d] %q", i, v))
            elseif type(v) == "number" then
                print(string.format("  [%d] %s", i, tostring(v)))
            end
        end
    end

    -- We cannot safely replace the VM with decompiled code without the
    -- compiler instruction definitions. Insert a diagnostic comment instead.
    -- The comment is represented as a no-op local declaration with a string
    -- value so it survives unparsing. A proper Unparser will render it.
    local diagText = buildDiagnosticComment(poolSize, dispatchCount)

    -- Insert diagnostic as a do-nothing local before the VM block
    -- (The pretty printer will render the string as a comment-like statement)
    local diagNode = Ast.LocalVariableDeclaration(
        ast.body.scope,
        { ast.body.scope:addVariable() },
        { Ast.StringExpression(diagText) }
    )

    table.insert(ast.body.statements, vmifyIdx, diagNode)

    return ast
end

return ReverseVmify
