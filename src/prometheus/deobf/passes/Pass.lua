-- prometheus/deobf/passes/Pass.lua
-- Base class for all deobfuscation passes
-- Mirrors the pattern used by prometheus.step

local Pass = {}
Pass.__index = Pass
Pass.Name = "BasePass"
Pass.Description = "Base deobfuscation pass"

function Pass:extend()
    local cls = setmetatable({}, { __index = self })
    cls.__index = cls
    function cls:new(settings)
        local o = setmetatable({}, cls)
        o.settings = settings or {}
        if o.init then o:init(settings) end
        return o
    end
    return cls
end

function Pass:init(_) end

-- Override in subclass. Must return ast (modified or not).
function Pass:apply(ast)
    return ast
end

return Pass
