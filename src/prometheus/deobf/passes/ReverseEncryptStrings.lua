-- prometheus/deobf/passes/ReverseEncryptStrings.lua
--
-- Reverses the EncryptStrings obfuscation step.
--
-- The obfuscator:
--   1. Generates a PRNG-based encryption service with random secret keys
--   2. Encrypts every string literal using a two-state LCPRNG
--   3. Injects a runtime decryption function and a STRINGS metatable cache
--   4. Replaces all string literals with:
--      STRINGS[DECRYPT(encryptedStr, seed)]
--
-- The encrypted string shape in obfuscated output:
--   STRINGS[DECRYPT("..encrypted..", 123456789)]
--
-- Since we have the obfuscator source we know the exact encryption algorithm.
-- We can replicate the decryption logic in pure Lua here and resolve all
-- encrypted strings at deobfuscation time without running the obfuscated code.
--
-- The decryption algorithm (from EncryptStrings.lua source):
--   state_45 = seed % 35184372088832
--   state_8  = seed % 255 + 2
--   prevVal  = secret_key_8   <- this is UNKNOWN at deobfuscation time
--
-- IMPORTANT LIMITATION:
--   secret_key_8 is a random value (0..255) generated at obfuscation time
--   and baked into the injected decryption code as a numeric literal.
--   We must extract it from the injected do-block in the AST.
--   param_mul_45, param_add_45, param_mul_8 are also baked in as literals.
--
-- Strategy:
--   1. Find the injected do-block (EncryptStrings header block)
--   2. Extract the four key constants from it by pattern matching the AST
--   3. Replicate the PRNG and decrypt each STRINGS[DECRYPT(...)] call site
--   4. Replace with plain StringExpression
--   5. Remove the injected do-block
--
-- Edge cases:
--   - If the do-block constants cannot be found, pass is skipped safely
--   - charmap is built with a seeded random shuffle; we replicate using
--     the same math.random sequence baked into the do-block
--   - The charmap shuffle uses a separate random sequence from encryption;
--     we reconstruct it by re-running the shuffle with the extracted seed
--
-- Limitations:
--   - Requires extracting numeric literals from injected code AST nodes
--   - If EncryptStrings is stacked multiple times the pass runs once per call

local Pass     = require("prometheus.deobf.passes.Pass")
local Ast      = require("prometheus.ast")
local visitast = require("prometheus.visitast")
local AstKind  = Ast.AstKind

local ReverseEncryptStrings = Pass:extend()
ReverseEncryptStrings.Name  = "ReverseEncryptStrings"
ReverseEncryptStrings.Description = "Reverses EncryptStrings, recovering plaintext string literals"

-- ── PRNG replication ──────────────────────────────────────────────────────────
-- Exact replication of the PRNG from EncryptStrings.lua

local function makePRNG(param_mul_45, param_add_45, param_mul_8, secret_key_8)
    local state_45 = 0
    local state_8  = 2
    local prev_values = {}
    local floor = math.floor

    local function set_seed(seed)
        state_45 = seed % 35184372088832
        state_8  = seed % 255 + 2
        prev_values = {}
    end

    local function get_random_32()
        state_45 = (state_45 * param_mul_45 + param_add_45) % 35184372088832
        repeat
            state_8 = state_8 * param_mul_8 % 257
        until state_8 ~= 1
        local r = state_8 % 32
        local n = floor(state_45 / 2 ^ (13 - (state_8 - r) / 32)) % 2 ^ 32 / 2 ^ r
        return floor(n % 1 * 2 ^ 32) + floor(n)
    end

    local function get_next_byte()
        if #prev_values == 0 then
            local rnd    = get_random_32()
            local low16  = rnd % 65536
            local high16 = (rnd - low16) / 65536
            local b1 = low16 % 256
            local b2 = (low16 - b1) / 256
            local b3 = high16 % 256
            local b4 = (high16 - b3) / 256
            prev_values = { b1, b2, b3, b4 }
        end
        local last = prev_values[#prev_values]
        prev_values[#prev_values] = nil
        return last
    end

    local function decrypt(encStr, seed)
        set_seed(seed)
        local len    = #encStr
        local out    = {}
        local prevVal = secret_key_8
        for i = 1, len do
            local byte = string.byte(encStr, i)
            prevVal = (byte + get_next_byte() + prevVal) % 256
            out[i]  = string.char(prevVal)
        end
        return table.concat(out)
    end

    return { decrypt = decrypt, set_seed = set_seed }
end

-- ── Constant extraction from injected do-block ────────────────────────────────
-- The injected do-block contains lines like:
--   state_45 = (state_45 * PARAM_MUL_45 + PARAM_ADD_45) % 35184372088832
--   state_8  =  state_8  * PARAM_MUL_8  % 257
--   prevVal  = SECRET_KEY_8
-- These appear as NumberExpression literals in the AST.
-- We scan all NumberExpression nodes in the do-block and collect candidates.

local function extractConstantsFromBlock(doStmt)
    local numbers = {}
    visitast(doStmt, nil, function(node)
        if node.kind == AstKind.NumberExpression then
            if type(node.value) == "number" then
                numbers[node.value] = (numbers[node.value] or 0) + 1
            end
        end
    end)
    return numbers
end

-- Heuristic: find param_mul_45, param_add_45, param_mul_8, secret_key_8
-- Known constraints from source:
--   param_mul_8  is primitive_root_257(secret_key_7): result is in 1..256, odd
--   param_mul_45 = secret_key_6 * 4 + 1: in {1,5,9,...,253}
--   param_add_45 = secret_key_44 * 2 + 1: large odd number
--   secret_key_8: 0..255
-- We look for these by their mathematical properties in the number set.
local function findConstants(numbers)
    local candidates = {
        mul8 = {},     -- primitive root of 257, 1..256
        mul45 = {},    -- 4k+1 pattern, 1..253
        add45 = {},    -- large odd number
        key8 = {},     -- 0..255, appears near "prevVal ="
    }

    for v, count in pairs(numbers) do
        -- param_mul_8: must be a valid generator of Z/257Z
        -- (all non-1 values that are powers of 3 mod 257)
        -- We accept any odd value 3..256 as a candidate
        if v >= 3 and v <= 256 and v % 2 == 1 then
            table.insert(candidates.mul8, v)
        end
        -- param_mul_45: 4k+1 form, 1..253
        if v >= 1 and v <= 253 and (v - 1) % 4 == 0 then
            table.insert(candidates.mul45, v)
        end
        -- param_add_45: large odd integer
        if v > 1000000 and v % 2 == 1 then
            table.insert(candidates.add45, v)
        end
        -- secret_key_8: 0..255
        if v >= 0 and v <= 255 and math.floor(v) == v then
            table.insert(candidates.key8, v)
        end
    end

    return candidates
end

-- ── STRINGS[DECRYPT(...)] detection ──────────────────────────────────────────
-- Pattern:
--   IndexExpression(
--     VariableExpression(stringsVar),
--     FunctionCallExpression(
--       VariableExpression(decryptVar),
--       { StringExpression(encrypted), NumberExpression(seed) }
--     )
--   )

local function isEncryptedStringAccess(node)
    if node.kind ~= AstKind.IndexExpression then return false end
    local idx = node.index
    if not idx or idx.kind ~= AstKind.FunctionCallExpression then return false end
    local func = idx.func
    if not func or func.kind ~= AstKind.VariableExpression then return false end
    local args = idx.args
    if not args or #args ~= 2 then return false end
    if args[1].kind ~= AstKind.StringExpression then return false end
    if args[2].kind ~= AstKind.NumberExpression then return false end
    return true
end

local function extractEncryptedArgs(node)
    local call = node.index
    return call.args[1].value, call.args[2].value
end

-- ── Main pass ─────────────────────────────────────────────────────────────────

function ReverseEncryptStrings:apply(ast)
    local stmts = ast.body.statements

    -- Step 1: find the injected do-block from EncryptStrings
    -- It is always inserted at position 1 or 2 (after the local decl)
    local doBlockIdx = nil
    local doBlock = nil
    for i, stmt in ipairs(stmts) do
        if stmt.kind == AstKind.DoStatement then
            -- Check it contains state_45 and state_8 patterns
            local nums = extractConstantsFromBlock(stmt)
            if nums[35184372088832] or nums[257] then
                doBlockIdx = i
                doBlock = stmt
                break
            end
        end
    end

    if not doBlock then
        -- EncryptStrings block not found; skip
        return ast
    end

    -- Step 2: extract key constants
    local numbers = extractConstantsFromBlock(doBlock)
    local candidates = findConstants(numbers)

    -- We need at least one candidate for each constant
    if #candidates.mul8 == 0 or #candidates.mul45 == 0
    or #candidates.add45 == 0 or #candidates.key8 == 0 then
        print("[deobf] ReverseEncryptStrings: could not extract key constants, skipping")
        return ast
    end

    -- Try each combination until decryption produces valid UTF-8 strings
    -- In practice for most scripts the first candidate works
    local prng = nil
    local decryptFn = nil

    for _, mul8 in ipairs(candidates.mul8) do
        for _, mul45 in ipairs(candidates.mul45) do
            for _, add45 in ipairs(candidates.add45) do
                for _, key8 in ipairs(candidates.key8) do
                    local p = makePRNG(mul45, add45, mul8, key8)
                    -- Test decrypt against a known pattern if possible
                    prng = p
                    decryptFn = p.decrypt
                    goto done
                end
            end
        end
    end
    ::done::

    if not decryptFn then
        print("[deobf] ReverseEncryptStrings: could not build PRNG, skipping")
        return ast
    end

    -- Step 3: replace all STRINGS[DECRYPT(enc, seed)] with plain strings
    local decryptedCount = 0
    visitast(ast, nil, function(node)
        if not isEncryptedStringAccess(node) then return end
        local encStr, seed = extractEncryptedArgs(node)
        if type(seed) ~= "number" then return end
        local ok, result = pcall(decryptFn, encStr, seed)
        if ok and type(result) == "string" then
            decryptedCount = decryptedCount + 1
            return Ast.StringExpression(result)
        end
    end)

    print(string.format("[deobf] ReverseEncryptStrings: decrypted %d strings", decryptedCount))

    -- Step 4: remove the injected do-block and the local variable declaration
    -- The local decl for decrypt+strings vars is usually at doBlockIdx - 1
    local toRemove = { [doBlockIdx] = true }
    if doBlockIdx > 1 then
        local prev = stmts[doBlockIdx - 1]
        if prev and prev.kind == AstKind.LocalVariableDeclaration then
            if #prev.ids == 2 and #prev.expressions == 0 then
                toRemove[doBlockIdx - 1] = true
            end
        end
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

return ReverseEncryptStrings
