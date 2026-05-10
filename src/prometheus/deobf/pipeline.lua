-- prometheus/deobf/pipeline.lua
--
-- Deobfuscation pipeline runner.
-- Holds a list of passes and runs them sequentially against an AST.
-- Mirrors the structure of the Prometheus obfuscation pipeline.

local Pipeline = {}
Pipeline.__index = Pipeline

function Pipeline:new()
    local o = setmetatable({}, self)
    o.passes  = {}
    o.verbose = true
    return o
end

function Pipeline:addPass(pass)
    table.insert(self.passes, pass)
end

function Pipeline:run(ast)
    for i, pass in ipairs(self.passes) do
        if self.verbose then
            print(string.format(
                "[deobf] (%d/%d) Running: %s",
                i, #self.passes, pass.Name or "Unknown"
            ))
        end

        local ok, err = pcall(function()
            ast = pass:apply(ast) or ast
        end)

        if not ok then
            print(string.format(
                "[deobf] Pass '%s' encountered an error: %s",
                pass.Name or "Unknown", tostring(err)
            ))
        else
            if self.verbose then
                print(string.format("[deobf] (%d/%d) Done:    %s", i, #self.passes, pass.Name or "Unknown"))
            end
        end
    end

    return ast
end

return Pipeline
