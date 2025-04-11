------------- 请去以下路径更改脚本内容,文件内的更改可以不需要五国 --------------------- 

                  -- /dp2/script/Work_Reload.lua --
				  
------------- 请去以上路径更改脚本内容,文件内的更改可以不需要五国 --------------------- 











local luv = require("luv")
local dp = _DP
local dpx = _DPX
local game = require("df.game")
local logger = require("df.logger")
local item_handler = { }
local frida = require("df.frida")

local lfs = require("lfs") --这个包用于检查脚本文件的时间戳
local filename = "/dp2/script/Work_Reload.lua" --要读取的文件
local filepacket --用来保存函数的变量
------------- 以下代码使用上方子程序功能的启动代码[前面加了--是代表不生效的意思，如需要某项功能，删除前面的--即可]--------------------- !
dpx.set_max_level(70)-- 设置服务端等级上限 !
frida.load()-- 镶嵌、幸运值、深渊播报等
------------- 以上代码使用上方子程序功能的启动代码[前面加了--是代表不生效的意思，如需要某项功能，删除前面的--即可]--------------------- !

-- 创建一个新的 _ENV 变量表
local new_env = {}
--将Lua基础函数和全局环境包括进去 如果禁用这一条,会导致类似string  tonumber等基础Lua函数无法使用
setmetatable(new_env, {__index = _G}) 
--要共享的变量  注释掉的是尝试将本脚本全部变量导入,好像会出错?
--[[
for k, v in pairs(_G) do
    new_env[k] = v
end
]]
-- 与该文件共享的变量在这里添加,热加载的脚本会共享这些变量
-- 右边是当前脚本变量名 ,左边的new_env是表名.后面的是要传递给新脚本的变量名
-- 类似frida这种 多次重载会崩溃
new_env.frida = frida
-- 类似dpx dp game world logger 你需要继承这些来让新脚本能获取user表等东西
new_env.logger = logger
new_env.dp = dp
new_env.dpx = dpx
new_env.game = game
new_env.world = world
local luv = require("luv")
-- 类似item_handler你需要继承这些来让新脚本能获取在这个脚本创建的道具的钩子表
new_env.item_handler = item_handler

-- ↑为了方便存入这些变量,该热加载脚本最好放置在本脚本文件尾

local function reload_script()
  package.loaded[filename] = nil --清空导入包
  local ok, err = pcall(function()
  --将脚本文件的内容保存在变量filepacket编译为函数,并且导入环境变量表new_env
    filepacket = loadfile(filename,"t",new_env) 
end)
  if not ok then
	logger.info("读取文件-失败")
	logger.info("File:%s", err)
	else
	logger.info("读取文件-成功")
  end
  ok, err = pcall(filepacket) --执行脚本内容(成为函数后的filepacket)
  if not ok then
	logger.info("执行脚本-失败，请检查脚本内容是否出错!")
	logger.info("File:%s", err)
	else
	file_modification_time = lfs.attributes(filename, "modification")
	logger.info("执行脚本-成功，脚本内容已重新加载!")
  end
end

local function script_modified()
  if lfs.attributes(filename, "modification") ~= file_modification_time then --检测脚本文件时间戳
    reload_script()
  end
end

local file_modification_time --时间戳记录
local AutoTimer = luv.new_timer()
AutoTimer:start(10000, 5000, script_modified) --5000是刷新间隔5秒 10000是多久后开始执行
--file_modification_time = lfs.attributes(filename, "modification") -- 这是用来记录最初该文件的修改日期
--reload_script()  


--每隔多久检查一次文件是否被修改 1000为1秒

-----------------------------------------------------------以上为热加载Lua脚本
