//需要开启或者关闭什么功能就搜索什么。比如搜索“定时邮件”、“镶嵌”、“装备镶嵌”、“史诗播报”、“副本时间播报”、“Hi,Boy提示”、
//“随机强化”、“装备继承”、“口令红包”、“跨界”、“点券充值额外赠送”、“口令码”、“战力榜”、“心悦任务”、“副本增强”、“忽略副本门口禁止摆摊”、“多买多送”
//“每日深渊活动”、“进入指定副本参与抽奖”、“装扮潜能<2675818>”、“自定义副本翻牌”、“商店购买限制”、“十连魔盒”、
//总控制菜单在最下面

//本地时间戳
function get_timestamp() {
	var date = new Date();
	date = new Date(date.setHours(date.getHours() + 0)); //转换到本地时间
	var year = date.getFullYear().toString();
	var month = (date.getMonth() + 1).toString();
	var day = date.getDate().toString();
	var hour = date.getHours().toString();
	var minute = date.getMinutes().toString();
	var second = date.getSeconds().toString();
	var ms = date.getMilliseconds().toString();
	return year + '-' + month + '-' + day + ' ' + hour + ':' + minute + ':' + second;
}

//linux创建文件夹
function api_mkdir(path) {
	var opendir = new NativeFunction(Module.getExportByName(null, 'opendir'), 'int', ['pointer'], { "abi": "sysv" });
	var mkdir = new NativeFunction(Module.getExportByName(null, 'mkdir'), 'int', ['pointer', 'int'], { "abi": "sysv" });
	var path_ptr = Memory.allocUtf8String(path);
	if (opendir(path_ptr))
		return true;
	return mkdir(path_ptr, 0x1FF);
}


//服务器环境
var G_CEnvironment = new NativeFunction(ptr(0x080CC181), 'pointer', [], { "abi": "sysv" });
//获取当前服务器配置文件名
var CEnvironment_get_file_name = new NativeFunction(ptr(0x80DA39A), 'pointer', ['pointer'], { "abi": "sysv" });
//获取当前频道名
function api_CEnvironment_get_file_name() {
	var filename = CEnvironment_get_file_name(G_CEnvironment());
	return filename.readUtf8String(-1);
}

//文件记录日志
var frida_log_dir_path = '/dp2/frida/frida_log/'
var f_log = null;
var log_day = null;
function log(msg) {
	var date = new Date();
	date = new Date(date.setHours(date.getHours() + 0)); //转换到本地时间
	var year = date.getFullYear().toString();
	var month = (date.getMonth() + 1).toString();
	var day = date.getDate().toString();
	var hour = date.getHours().toString();
	var minute = date.getMinutes().toString();
	var second = date.getSeconds().toString();
	var ms = date.getMilliseconds().toString();
	//日志按日期记录
	if ((f_log == null) || (log_day != day)) {
		api_mkdir(frida_log_dir_path);
		f_log = new File(frida_log_dir_path + 'frida_' + api_CEnvironment_get_file_name() + '_' + year + '_' + month + '_' + day + '.log', 'a+');
		log_day = day;
	}
	//时间戳
	var timestamp = year + '-' + month + '-' + day + ' ' + hour + ':' + minute + ':' + second + '.' + ms;
	//控制台日志
	console.log('[' + get_timestamp() + '] [frida] [info] ' + msg + '\n');
	//文件日志
	f_log.write('[' + timestamp + ']' + msg + '\n');
	//立即写日志到文件中
	f_log.flush();
}

//内存十六进制打印
function bin2hex(p, len) {
	var hex = '';
	for (var i = 0; i < len; i++) {
		var s = p.add(i).readU8().toString(16);
		if (s.length == 1)
			s = '0' + s;
		hex += s;
		if (i != len - 1)
			hex += ' ';
	}
	return hex;
}


//xq
var CEquipItem_GetItemType = new NativeFunction(ptr(0x08514D26), 'int', ['pointer'], { "abi": "sysv" });
var CInventory_MakeItemPacket = new NativeFunction(ptr(0x084FC6BC), 'int', ['pointer', 'int', 'int', 'pointer'], { "abi": "sysv" });

function lengthCutting(str, ystr, num, maxLength) {//ByteArray转十六进制文本数据
	var strArr = '';
	var length = str.length;
	while (str.length < maxLength) {
		str = '0'.concat(str)
	}
	for (var i = 0; i < str.length; i += num) {
		strArr = str.slice(i, i + num).concat(strArr)
	}
	return ystr + strArr;
}
function api_get_jewel_socket_data(mysql, id) {//获取徽章数据,存在返回徽章数据,不存在返回空字节数据
	api_MySQL_exec(mysql, 'SELECT jewel_data FROM data where equ_id = ' + id + ';')
	var v = Memory.alloc(30);
	v.add(0).writeU8(0)
	if (MySQL_get_n_rows(mysql) == 1) {
		if (MySQL_fetch(mysql)) {
			MySQL_get_binary(mysql, 0, v, 30)
		}
	}
	return v;
}
function api_exitjeweldata(id) {//0代表不存在,存在返回1
	api_MySQL_exec(mysql_frida, 'SELECT index_flag FROM data where equ_id = ' + id + ';')
	var exit = 0;
	if (MySQL_get_n_rows(mysql_frida) == 1) {
		if (MySQL_fetch(mysql_frida)) {
			exit = api_MySQL_get_int(mysql_frida, 0);
		}
	}
	return exit;
}
function save_equiment_socket(socket_data, id) {//0代表保存失败 成功返回1
	if (api_MySQL_exec(mysql_frida, 'UPDATE data SET jewel_data = 0x' + socket_data + ' WHERE equ_id = ' + id + ';') == 1) {
		return 1;
	}
	return 0;
}
function api_InterfacePacketBuf_put_string(packet_guard, s) {
	var p = Memory.allocUtf8String(s);
	var len = strlen(p);
	InterfacePacketBuf_put_int(packet_guard, len);
	InterfacePacketBuf_put_binary(packet_guard, p, len);

	return;
}
function send_windows_pack_233(CUser, string) {//233窗口呼出，客户端要处理才能正常。不然会闪退掉或是卡住。
	var packet_guard = api_PacketGuard_PacketGuard();
	InterfacePacketBuf_put_header(packet_guard, 0, 233);
	InterfacePacketBuf_put_byte(packet_guard, 1);
	InterfacePacketBuf_put_byte(packet_guard, 5);
	api_InterfacePacketBuf_put_string(packet_guard, string)
	InterfacePacketBuf_put_byte(packet_guard, 1);
	InterfacePacketBuf_finalize(packet_guard, 1);
	CUser_Send(CUser, packet_guard);
	Destroy_PacketGuard_PacketGuard(packet_guard);
}

function add_equiment_socket(equipment_type) {//0代表开孔失败 成功返回标识
	/*
	武器10
	称号11
	上衣12
	头肩13
	下衣14
	鞋子15
	腰带16
	项链17
	手镯18
	戒指19
	辅助装备20
	魔法石21
	*/

	/*
	红色:'010000000000010000000000000000000000000000000000000000000000'	A
	黄色:'020000000000020000000000000000000000000000000000000000000000'	B
	绿色:'040000000000040000000000000000000000000000000000000000000000'	C
	蓝色:'080000000000080000000000000000000000000000000000000000000000'	D
	白金:'100000000000100000000000000000000000000000000000000000000000'
	*/
	var DB_JewelsocketData = '';
	switch (equipment_type) {
		case 10://武器10	SS
			DB_JewelsocketData = '100000000000000000000000000000000000000000000000000000000000'
			break;
		case 11://称号11	SS
			DB_JewelsocketData = '100000000000000000000000000000000000000000000000000000000000'
			break;
		case 12://上衣12 	C
			DB_JewelsocketData = '040000000000040000000000000000000000000000000000000000000000'
			break;
		case 13://头肩13	B
			DB_JewelsocketData = '020000000000020000000000000000000000000000000000000000000000'
			break;
		case 14://下衣14	C
			DB_JewelsocketData = '040000000000040000000000000000000000000000000000000000000000'
			break;
		case 15://鞋子15	D
			DB_JewelsocketData = '080000000000080000000000000000000000000000000000000000000000'
			break;
		case 16://腰带16	A
			DB_JewelsocketData = '010000000000010000000000000000000000000000000000000000000000'
			break;
		case 17://项链17	B
			DB_JewelsocketData = '020000000000020000000000000000000000000000000000000000000000'
			break;
		case 18://手镯18	D
			DB_JewelsocketData = '080000000000080000000000000000000000000000000000000000000000'
			break;
		case 19://戒指19	A
			DB_JewelsocketData = '010000000000010000000000000000000000000000000000000000000000'
			break;
		case 20://辅助装备20	S
			DB_JewelsocketData = '100000000000000000000000000000000000000000000000000000000000'
			break;
		case 21://魔法石21		S
			DB_JewelsocketData = '100000000000000000000000000000000000000000000000000000000000'
			break;
		default:
			DB_JewelsocketData = '000000000000000000000000000000000000000000000000000000000000'
			break;
	}
	var date = get_timestamp();
	if (api_MySQL_exec(mysql_frida, 'INSERT INTO data (index_flag,jewel_data,date) VALUES(1,0x' + DB_JewelsocketData + ',\'' + date + '\');') == 1) {
		api_MySQL_exec(mysql_frida, 'SELECT equ_id FROM data where date = \'' + date + '\';')
		if (MySQL_get_n_rows(mysql_frida) == 1) {
			if (MySQL_fetch(mysql_frida)) {
				return api_MySQL_get_int(mysql_frida, 0);
			}
		}
	}
	return 0;
}
function api_set_JewelSocketData(jewelSocketData, slot, emblem_item_id) {//fr自带的时装徽章保存函数
	if (!jewelSocketData.isNull()) {
		//每个槽数据长6个字节: 2字节槽类型+4字节徽章item_id
		//镶嵌不改变槽类型, 这里只修改徽章id
		jewelSocketData.add(slot * 6 + 2).writeInt(emblem_item_id);
	}

	return;
}
function CUser_SendUpdateItemList_DB(CUser, Slot, DB_JewelSocketData) {//防装备刷新函数,带镶嵌数据的刷新函数
	var v10 = api_PacketGuard_PacketGuard();
	InterfacePacketBuf_put_header(v10, 0, 14);
	InterfacePacketBuf_put_byte(v10, 0);
	InterfacePacketBuf_put_short(v10, 1);
	var v4 = CUserCharacInfo_getCurCharacInvenW(CUser);
	CInventory_MakeItemPacket(v4, 1, Slot, v10);
	InterfacePacketBuf_put_binary(v10, DB_JewelSocketData, 30);
	InterfacePacketBuf_finalize(v10, 1);
	CUser_Send(CUser, v10);
	Destroy_PacketGuard_PacketGuard(v10);
}
//xq
var CAccountCargo_CheckValidSlot = new NativeFunction(ptr(0x0828A554), 'int', ['pointer', 'int'], { "abi": "sysv" });
var CAccountCargo_ResetSlot = new NativeFunction(ptr(0x082898C0), 'int', ['pointer', 'int'], { "abi": "sysv" });
var ARAD_Singleton_ServiceRestrictManager_Get = new NativeFunction(ptr(0x081625E6), 'pointer', [], { "abi": "sysv" });
var ServiceRestrictManager_isRestricted = new NativeFunction(ptr(0x0816E6B8), 'uint8', ['int', 'pointer', 'int', 'int'], { "abi": "sysv" });
var CUser_SendCmdErrorPacket = new NativeFunction(ptr(0x0867BF42), 'int', ['pointer', 'int', 'uint8'], { "abi": "sysv" });
var CSecu_ProtectionField_Check = new NativeFunction(ptr(0x08288A02), 'int', ['pointer', 'pointer', 'int'], { "abi": "sysv" });
var CUserCharacInfo_getCurCharacMoney = new NativeFunction(ptr(0x0817A188), 'int', ['pointer'], { "abi": "sysv" });
var CAccountCargo_CheckMoneyLimit = new NativeFunction(ptr(0x0828A4CA), 'int', ['pointer', 'uint'], { "abi": "sysv" });
//设置幸运点数
var CUserCharacInfo_SetCurCharacLuckPoint = new NativeFunction(ptr(0x0864670A), 'int', ['pointer', 'int'], { "abi": "sysv" });
//获取角色当前幸运点
var CUserCharacInfo_GetCurCharacLuckPoint = new NativeFunction(ptr(0x822F828), 'int', ['pointer'], { "abi": "sysv" });
//设置角色属性改变脏标记(角色上线时把所有属性从数据库缓存到内存中, 只有设置了脏标记, 角色下线时才能正确存档到数据库, 否则变动的属性下线后可能会回档)
var CUserCharacInfo_enableSaveCharacStat = new NativeFunction(ptr(0x819A870), 'int', ['pointer'], { "abi": "sysv" });
//获取角色状态
var CUser_get_state = new NativeFunction(ptr(0x80DA38C), 'int', ['pointer'], { "abi": "sysv" });
//获取角色账号id
var CUser_get_acc_id = new NativeFunction(ptr(0x80DA36E), 'int', ['pointer'], { "abi": "sysv" });
var Stream_operator_p = new NativeFunction(ptr(0x0861C796), 'int', ['pointer', 'int'], { "abi": "sysv" });
var NumberToString = new NativeFunction(ptr(0x0810904B), 'uint', ['uint', 'int'], { "abi": "sysv" });
var Stream_GetOutBuffer_SIG_ACCOUNT_CARGO_DATA = new NativeFunction(ptr(0x08453A26), 'int', ['pointer'], { "abi": "sysv" });
var CAccountCargo_GetMoney = new NativeFunction(ptr(0x0822F020), 'int', ['pointer'], { "abi": "sysv" });
//获取当前角色id
var CUserCharacInfo_getCurCharacNo = new NativeFunction(ptr(0x80CBC4E), 'int', ['pointer'], { "abi": "sysv" });
//执行debug命令
var DoUserDefineCommand = new NativeFunction(ptr(0x0820BA90), 'int', ['pointer', 'int', 'pointer'], { "abi": "sysv" });
//获取角色等级
var CUserCharacInfo_get_charac_level = new NativeFunction(ptr(0x80DA2B8), 'int', ['pointer'], { "abi": "sysv" });
//获取角色名字
var CUserCharacInfo_getCurCharacName = new NativeFunction(ptr(0x8101028), 'pointer', ['pointer'], { "abi": "sysv" });
//获取角色当前等级升级所需经验
var CUserCharacInfo_get_level_up_exp = new NativeFunction(ptr(0x0864E3BA), 'int', ['pointer', 'int'], { "abi": "sysv" });
// 获取账号金库
var CUser_getAccountCargo = new NativeFunction(ptr(0x822fc22), 'pointer', ['pointer'], { "abi": "sysv" });
// 获取账号金库一个空的格子
var CAccountCargo_getEmptySlot = new NativeFunction(ptr(0x828a580), 'int', ['pointer'], { "abi": "sysv" });
// 将已经物品移动到某个格子 第一个账号金库，第二个移入的物品，第三个格子位置
var CAccountCargo_InsertItem = new NativeFunction(ptr(0x8289c82), 'int', ['pointer', 'pointer', 'int'], { "abi": "sysv" });
// 向客户端发送账号金库列表
var CAccountCargo_SendItemList = new NativeFunction(ptr(0x828a88a), 'int', ['pointer'], { "abi": "sysv" });
//通知客户端QuestPiece更新
var GET_USER = new NativeFunction(ptr(0x084bb9cf), 'int', ['pointer'], { "abi": "sysv" });
//删除背包槽中的道具
var Inven_Item_reset = new NativeFunction(ptr(0x080CB7D8), 'int', ['pointer'], { "abi": "sysv" });
// 分解机 参数 角色 位置 背包类型  239  角色（谁的） 0xFFFF
var DisPatcher_DisJointItem_disjoint = new NativeFunction(ptr(0x81f92ca), 'int', ['pointer', 'int', 'int', 'int', 'pointer', 'int'], { "abi": "sysv" });
// 价差分解机用户的状态 参数 用户  239 背包类型 位置
var CUserCharacInfo_getCurCharacExpertJob = new NativeFunction(ptr(0x822f8d4), 'int', ['pointer'], { "abi": "sysv" });
//获取角色背包
var CUserCharacInfo_getCurCharacInvenW = new NativeFunction(ptr(0x80DA28E), 'pointer', ['pointer'], { "abi": "sysv" });
//获取副本id
var CDungeon_get_index = new NativeFunction(ptr(0x080FDCF0), 'int', ['pointer'], { "abi": "sysv" });
//获取背包槽中的道具
var CInventory_GetInvenRef = new NativeFunction(ptr(0x84FC1DE), 'pointer', ['pointer', 'int', 'int'], { "abi": "sysv" });
//道具是否是装备
var Inven_Item_isEquipableItemType = new NativeFunction(ptr(0x08150812), 'int', ['pointer'], { "abi": "sysv" });
//是否魔法封印装备
var CEquipItem_IsRandomOption = new NativeFunction(ptr(0x8514E5E), 'int', ['pointer'], { "abi": "sysv" });
//解封魔法封印
var random_option_CRandomOptionItemHandle_give_option = new NativeFunction(ptr(0x85F2CC6), 'int', ['pointer', 'int', 'int', 'int', 'int', 'int', 'pointer'], { "abi": "sysv" });
//获取装备品级
var CItem_get_rarity = new NativeFunction(ptr(0x080F12D6), 'int', ['pointer'], { "abi": "sysv" });
//获取装备可穿戴等级
var CItem_getUsableLevel = new NativeFunction(ptr(0x80F12EE), 'int', ['pointer'], { "abi": "sysv" });
//获取装备[item group name]
var CItem_getItemGroupName = new NativeFunction(ptr(0x80F1312), 'int', ['pointer'], { "abi": "sysv" });
//获取装备魔法封印等级
var CEquipItem_GetRandomOptionGrade = new NativeFunction(ptr(0x8514E6E), 'int', ['pointer'], { "abi": "sysv" });
//检查背包中道具是否为空
var Inven_Item_isEmpty = new NativeFunction(ptr(0x811ED66), 'int', ['pointer'], { "abi": "sysv" });
//获取背包中道具item_id
var Inven_Item_getKey = new NativeFunction(ptr(0x850D14E), 'int', ['pointer'], { "abi": "sysv" });
//获取道具附加信息
var Inven_Item_get_add_info = new NativeFunction(ptr(0x80F783A), 'int', ['pointer'], { "abi": "sysv" });
//获取时装插槽数据
var WongWork_CAvatarItemMgr_getJewelSocketData = new NativeFunction(ptr(0x82F98F8), 'pointer', ['pointer', 'int'], { "abi": "sysv" });
//获取GameWorld实例
var G_GameWorld = new NativeFunction(ptr(0x80DA3A7), 'pointer', [], { "abi": "sysv" });
//获取DataManager实例
var G_CDataManager = new NativeFunction(ptr(0x80CC19B), 'pointer', [], { "abi": "sysv" });
//获取时装管理器
var CInventory_GetAvatarItemMgrR = new NativeFunction(ptr(0x80DD576), 'pointer', ['pointer'], { "abi": "sysv" });
//获取装备pvf数据
var CDataManager_find_item = new NativeFunction(ptr(0x835FA32), 'pointer', ['pointer', 'int'], { "abi": "sysv" });
var CDataManager_get_level_exp = new NativeFunction(ptr(0x08360442), 'int', ['pointer', 'int'], { "abi": "sysv" });
var CDataManager_getDailyTrainingQuest = new NativeFunction(ptr(0x083640fe), 'pointer', ['pointer', 'int'], { "abi": "sysv" });
var CDataManager_getSpAtLevelUp = new NativeFunction(ptr(0x08360cb8), 'int', ['pointer', 'int'], { "abi": "sysv" });
var CDataManager_get_event_script_mng = new NativeFunction(ptr(0x08110b62), 'pointer', ['pointer'], { "abi": "sysv" });
var CDataManager_getExpertJobScript = new NativeFunction(ptr(0x0822b5f2), 'pointer', ['pointer', 'int'], { "abi": "sysv" });
var CDataManager_get_dimensionInout = new NativeFunction(ptr(0x0822b612), 'int', ['pointer', 'int'], { "abi": "sysv" });
//从pvf中获取任务数据
var CDataManager_find_quest = new NativeFunction(ptr(0x835FDC6), 'pointer', ['pointer', 'int'], { "abi": "sysv" });
//获取消耗品类型
var CStackableItem_GetItemType = new NativeFunction(ptr(0x8514A84), 'int', ['pointer'], { "abi": "sysv" });
//获取徽章支持的镶嵌槽类型
var CStackableItem_getJewelTargetSocket = new NativeFunction(ptr(0x0822CA28), 'int', ['pointer'], { "abi": "sysv" });
//背包道具
var Inven_Item_Inven_Item = new NativeFunction(ptr(0x80CB854), 'pointer', ['pointer'], { "abi": "sysv" });
//获取角色点券余额
var CUser_GetCera = new NativeFunction(ptr(0x080FDF7A), 'int', ['pointer'], { "abi": "sysv" });
//获取玩家任务信息
var CUser_getCurCharacQuestW = new NativeFunction(ptr(0x814AA5E), 'pointer', ['pointer'], { "abi": "sysv" });
//获取系统时间
var CSystemTime_getCurSec = new NativeFunction(ptr(0x80CBC9E), 'int', ['pointer'], { "abi": "sysv" });
var GlobalData_s_systemTime_ = ptr(0x941F714);
//本次登录时间
var CUserCharacInfo_GetLoginTick = new NativeFunction(ptr(0x822F692), 'int', ['pointer'], { "abi": "sysv" });
//道具是否被锁
var CUser_CheckItemLock = new NativeFunction(ptr(0x8646942), 'int', ['pointer', 'int', 'int'], { "abi": "sysv" });
//道具是否为消耗品
var CItem_is_stackable = new NativeFunction(ptr(0x80F12FA), 'int', ['pointer'], { "abi": "sysv" });
// 设置用户最大等级 int为等级
var CUser_SetUserMaxLevel = new NativeFunction(ptr(0x0868fec8), 'pointer', ['pointer', 'int'], { "abi": "sysv" });
var CUser_CalcurateUserMaxLevel = new NativeFunction(ptr(0x0868ff04), 'pointer', ['pointer'], { "abi": "sysv" });
var CItem_getIndex = new NativeFunction(ptr(0x8110c48), 'int', ['pointer'], { "abi": "sysv" });
var CItem_getGrade = new NativeFunction(ptr(0x8110c54), 'int', ['pointer'], { "abi": "sysv" });
var CItem_getItemName = new NativeFunction(ptr(0x811ed82), 'int', ['pointer'], { "abi": "sysv" });
var CItem_getPrice = new NativeFunction(ptr(0x822c84a), 'int', ['pointer'], { "abi": "sysv" });
var CItem_getGenRate = new NativeFunction(ptr(0x822c84a), 'int', ['pointer'], { "abi": "sysv" });
var CItem_getNeedLevel = new NativeFunction(ptr(0x8545fda), 'int', ['pointer'], { "abi": "sysv" });
var CItem_getSellPrice = new NativeFunction(ptr(0x08473612), 'int', ['pointer'], { "abi": "sysv" });
//获取装备可穿戴等级
var CItem_getUsableLevel = new NativeFunction(ptr(0x80F12EE), 'int', ['pointer'], { "abi": "sysv" });
var CItem_getRarity = new NativeFunction(ptr(0x80f12d6), 'int', ['pointer'], { "abi": "sysv" });
var CItem_getAttachType = new NativeFunction(ptr(0x80f12e2), 'int', ['pointer'], { "abi": "sysv" });
//获取装备[item group name]

var CItem_getUpSkillType = new NativeFunction(ptr(0x8545fcc), 'int', ['pointer'], { "abi": "sysv" });
var CItem_getGetExpertJobCompoundMaterialVariation = new NativeFunction(ptr(0x850d292), 'int', ['pointer'], { "abi": "sysv" });
var CItem_getExpertJobCompoundRateVariation = new NativeFunction(ptr(0x850d2aa), 'int', ['pointer'], { "abi": "sysv" });
var CItem_getExpertJobCompoundResultVariation = new NativeFunction(ptr(0x850d2c2), 'int', ['pointer'], { "abi": "sysv" });
var CItem_getExpertJobSelfDisjointBigWinRate = new NativeFunction(ptr(0x850d2de), 'int', ['pointer'], { "abi": "sysv" });
var CItem_getExpertJobSelfDisjointResultVariation = new NativeFunction(ptr(0x850d2f6), 'int', ['pointer'], { "abi": "sysv" });
var CItem_getExpertJobAdditionalExp = new NativeFunction(ptr(0x850d30e), 'int', ['pointer'], { "abi": "sysv" });
//任务是否已完成
var WongWork_CQuestClear_isClearedQuest = new NativeFunction(ptr(0x808BAE0), 'int', ['pointer', 'int'], { "abi": "sysv" });
//根据账号查找已登录角色
var GameWorld_find_user_from_world_byaccid = new NativeFunction(ptr(0x86C4D40), 'pointer', ['pointer', 'int'], { "abi": "sysv" });
//任务相关操作(第二个参数为协议编号: 33=接受任务, 34=放弃任务, 35=任务完成条件已满足, 36=提交任务领取奖励)
var CUser_quest_action = new NativeFunction(ptr(0x0866DA8A), 'int', ['pointer', 'int', 'int', 'int', 'int'], { "abi": "sysv" });
//设置GM完成任务模式(无条件完成任务)
var CUser_setGmQuestFlag = new NativeFunction(ptr(0x822FC8E), 'int', ['pointer', 'int'], { "abi": "sysv" });
//删除背包槽中的道具
var Inven_Item_reset = new NativeFunction(ptr(0x080CB7D8), 'int', ['pointer'], { "abi": "sysv" });
//减少金币
var CInventory_use_money = new NativeFunction(ptr(0x84FF54C), 'int', ['pointer', 'int', 'int', 'int'], { "abi": "sysv" });
var CInventory_gain_money = new NativeFunction(ptr(0x084ff29C), 'pointer', ['pointer', 'int', 'int', 'int', 'int'], { "abi": "sysv" });
var CAccountCargo_AddMoney = new NativeFunction(ptr(0x0828A742), 'pointer', ['pointer', 'uint'], { "abi": "sysv" });
var CAccountCargo_SendNotifyMoney = new NativeFunction(ptr(0x0828A7DC), 'pointer', ['int', 'int'], { "abi": "sysv" });
var CUser_CheckMoney = new NativeFunction(ptr(0x0866AF1C), 'int', ['pointer', 'int'], { "abi": "sysv" });
var CAccountCargo_SubMoney = new NativeFunction(ptr(0x0828A764), 'pointer', ['pointer', 'uint'], { "abi": "sysv" });
//背包中删除道具(背包指针, 背包类型, 槽, 数量, 删除原因, 记录删除日志)
var CInventory_delete_item = new NativeFunction(ptr(0x850400C), 'int', ['pointer', 'int', 'int', 'int', 'int', 'int'], { "abi": "sysv" });
//角色增加经验
var CUser_gain_exp_sp = new NativeFunction(ptr(0x866A3FE), 'int', ['pointer', 'int', 'pointer', 'pointer', 'int', 'int', 'int'], { "abi": "sysv" });
//时装镶嵌数据存盘
var DB_UpdateAvatarJewelSlot_makeRequest = new NativeFunction(ptr(0x843081C), 'pointer', ['int', 'int', 'pointer'], { "abi": "sysv" });
//发包给客户端
var CUser_Send = new NativeFunction(ptr(0x86485BA), 'int', ['pointer', 'pointer'], { "abi": "sysv" });
//给角色发消息
var CUser_SendNotiPacketMessage = new NativeFunction(ptr(0x86886CE), 'int', ['pointer', 'pointer', 'int'], { "abi": "sysv" });
//将协议发给所有在线玩家(慎用! 广播类接口必须限制调用频率, 防止CC攻击)
//除非必须使用, 否则改用对象更加明确的CParty::send_to_party/GameWorld::send_to_area
var GameWorld_send_all = new NativeFunction(ptr(0x86C8C14), 'int', ['pointer', 'pointer'], { "abi": "sysv" });
var GameWorld_send_all_with_state = new NativeFunction(ptr(0x86C9184), 'int', ['pointer', 'pointer', 'int'], { "abi": "sysv" });


//通知客户端QuestPiece更新
var GET_USER = new NativeFunction(ptr(0x084bb9cf), 'int', ['pointer'], { "abi": "sysv" });

//发送道具
var CUser_AddItem = new NativeFunction(ptr(0x867B6D4), 'int', ['pointer', 'int', 'int', 'int', 'pointer', 'int'], { "abi": "sysv" });


//通知客户端道具更新(客户端指针, 通知方式[仅客户端=1, 世界广播=0, 小队=2, war room=3], itemSpace[装备=0, 时装=1], 道具所在的背包槽)
var CUser_SendUpdateItemList = new NativeFunction(ptr(0x867C65A), 'int', ['pointer', 'int', 'int', 'int'], { "abi": "sysv" });
//通知客户端更新已完成任务列表
var CUser_send_clear_quest_list = new NativeFunction(ptr(0x868B044), 'int', ['pointer'], { "abi": "sysv" });
//通知客户端更新角色任务列表
var UserQuest_get_quest_info = new NativeFunction(ptr(0x86ABBA8), 'int', ['pointer', 'pointer'], { "abi": "sysv" });
//获取在线玩家数量
var GameWorld_get_UserCount_InWorld = new NativeFunction(ptr(0x86C4550), 'int', ['pointer'], { "abi": "sysv" });
//在线玩家列表(用于std::map遍历)
var gameworld_user_map_begin = new NativeFunction(ptr(0x80F78A6), 'int', ['pointer', 'pointer'], { "abi": "sysv" });
var gameworld_user_map_end = new NativeFunction(ptr(0x80F78CC), 'int', ['pointer', 'pointer'], { "abi": "sysv" });
var gameworld_user_map_not_equal = new NativeFunction(ptr(0x80F78F2), 'bool', ['pointer', 'pointer'], { "abi": "sysv" });
var gameworld_user_map_get = new NativeFunction(ptr(0x80F7944), 'pointer', ['pointer'], { "abi": "sysv" });
var gameworld_user_map_next = new NativeFunction(ptr(0x80F7906), 'pointer', ['pointer', 'pointer'], { "abi": "sysv" });
//发系统邮件(多道具)
var WongWork_CMailBoxHelper_ReqDBSendNewSystemMultiMail = new NativeFunction(ptr(0x8556B68), 'int', ['pointer', 'pointer', 'int', 'int', 'int', 'pointer', 'int', 'int', 'int', 'int'], { "abi": "sysv" });
var WongWork_CMailBoxHelper_MakeSystemMultiMailPostal = new NativeFunction(ptr(0x8556A14), 'int', ['pointer', 'pointer', 'int'], { "abi": "sysv" });
//发系统邮件(时装)(仅支持在线角色发信)
var WongWork_CMailBoxHelper_ReqDBSendNewAvatarMail = new NativeFunction(ptr(0x85561B0), 'pointer', ['pointer', 'int', 'int', 'int', 'int', 'int', 'int', 'pointer', 'int'], { "abi": "sysv" });
//vector相关操作
var std_vector_std_pair_int_int_vector = new NativeFunction(ptr(0x81349D6), 'pointer', ['pointer'], { "abi": "sysv" });
var std_vector_std_pair_int_int_clear = new NativeFunction(ptr(0x817A342), 'pointer', ['pointer'], { "abi": "sysv" });
var std_make_pair_int_int = new NativeFunction(ptr(0x81B8D41), 'pointer', ['pointer', 'pointer', 'pointer'], { "abi": "sysv" });
var std_vector_std_pair_int_int_push_back = new NativeFunction(ptr(0x80DD606), 'pointer', ['pointer', 'pointer'], { "abi": "sysv" });
//点券充值
var WongWork_IPG_CIPGHelper_IPGInput = new NativeFunction(ptr(0x80FFCA4), 'int', ['pointer', 'pointer', 'int', 'int', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer'], { "abi": "sysv" });
//同步点券数据库
var WongWork_IPG_CIPGHelper_IPGQuery = new NativeFunction(ptr(0x8100790), 'int', ['pointer', 'pointer'], { "abi": "sysv" });
//代币充值
var WongWork_IPG_CIPGHelper_IPGInputPoint = new NativeFunction(ptr(0x80FFFC0), 'int', ['pointer', 'pointer', 'int', 'int', 'pointer', 'pointer'], { "abi": "sysv" });
//从客户端封包中读取数据
var PacketBuf_get_byte = new NativeFunction(ptr(0x858CF22), 'int', ['pointer', 'pointer'], { "abi": "sysv" });
var PacketBuf_get_short = new NativeFunction(ptr(0x858CFC0), 'int', ['pointer', 'pointer'], { "abi": "sysv" });
var PacketBuf_get_int = new NativeFunction(ptr(0x858D27E), 'int', ['pointer', 'pointer'], { "abi": "sysv" });
var PacketBuf_get_binary = new NativeFunction(ptr(0x858D3B2), 'int', ['pointer', 'pointer', 'int'], { "abi": "sysv" });
//服务器组包
var PacketGuard_PacketGuard = new NativeFunction(ptr(0x858DD4C), 'int', ['pointer'], { "abi": "sysv" });
var InterfacePacketBuf_put_header = new NativeFunction(ptr(0x80CB8FC), 'int', ['pointer', 'int', 'int'], { "abi": "sysv" });
var InterfacePacketBuf_put_byte = new NativeFunction(ptr(0x80CB920), 'int', ['pointer', 'uint8'], { "abi": "sysv" });
var InterfacePacketBuf_put_short = new NativeFunction(ptr(0x80D9EA4), 'int', ['pointer', 'uint16'], { "abi": "sysv" });
var InterfacePacketBuf_put_int = new NativeFunction(ptr(0x80CB93C), 'int', ['pointer', 'int'], { "abi": "sysv" });
var InterfacePacketBuf_put_binary = new NativeFunction(ptr(0x811DF08), 'int', ['pointer', 'pointer', 'int'], { "abi": "sysv" });
var InterfacePacketBuf_finalize = new NativeFunction(ptr(0x80CB958), 'int', ['pointer', 'int'], { "abi": "sysv" });
var Destroy_PacketGuard_PacketGuard = new NativeFunction(ptr(0x858DE80), 'int', ['pointer'], { "abi": "sysv" });
var InterfacePacketBuf_clear = new NativeFunction(ptr(0x080CB8E6), 'int', ['pointer'], { "abi": "sysv" });
var InterfacePacketBuf_put_packet = new NativeFunction(ptr(0x0815098E), 'int', ['pointer', 'pointer'], { "abi": "sysv" });
var CAccountCargo_GetItemCount = new NativeFunction(ptr(0x0828A794), 'int', ['pointer'], { "abi": "sysv" });
var GetIntegratedPvPItemAttr = new NativeFunction(ptr(0x084FC5FF), 'int', ['pointer'], { "abi": "sysv" });
var G_GameWorld = new NativeFunction(ptr(0x080DA3A7), 'pointer', [], { "abi": "sysv" });
var GameWorld_IsEnchantRevisionChannel = new NativeFunction(ptr(0x082343FC), 'int', ['pointer'], { "abi": "sysv" });
var stAmplifyOption_t_getAbilityType = new NativeFunction(ptr(0x08150732), 'uint8', ['pointer'], { "abi": "sysv" });
var stAmplifyOption_t_getAbilityValue = new NativeFunction(ptr(0x08150772), 'uint16', ['pointer'], { "abi": "sysv" });
//linux读本地文件
var fopen = new NativeFunction(Module.getExportByName(null, 'fopen'), 'int', ['pointer', 'pointer'], { "abi": "sysv" });
var fread = new NativeFunction(Module.getExportByName(null, 'fread'), 'int', ['pointer', 'int', 'int', 'int'], { "abi": "sysv" });
var fclose = new NativeFunction(Module.getExportByName(null, 'fclose'), 'int', ['int'], { "abi": "sysv" });
//MYSQL操作
//游戏中已打开的数据库索引(游戏数据库非线程安全 谨慎操作)
var TAIWAN_CAIN = 2;
var DBMgr_GetDBHandle = new NativeFunction(ptr(0x83F523E), 'pointer', ['pointer', 'int', 'int'], { "abi": "sysv" });
var MySQL_MySQL = new NativeFunction(ptr(0x83F3AC8), 'pointer', ['pointer'], { "abi": "sysv" });
var MySQL_init = new NativeFunction(ptr(0x83F3CE4), 'int', ['pointer'], { "abi": "sysv" });
var MySQL_open = new NativeFunction(ptr(0x83F4024), 'int', ['pointer', 'pointer', 'int', 'pointer', 'pointer', 'pointer'], { "abi": "sysv" });
var MySQL_close = new NativeFunction(ptr(0x83F3E74), 'int', ['pointer'], { "abi": "sysv" });
var MySQL_set_query_2 = new NativeFunction(ptr(0x83F41C0), 'int', ['pointer', 'pointer'], { "abi": "sysv" });

var MySQL_set_query_3 = new NativeFunction(ptr(0x83F41C0), 'int', ['pointer', 'pointer', 'pointer'], { "abi": "sysv" });
var MySQL_set_query_4 = new NativeFunction(ptr(0x83F41C0), 'int', ['pointer', 'pointer', 'int', 'int'], { "abi": "sysv" });
var MySQL_set_query_5 = new NativeFunction(ptr(0x83F41C0), 'int', ['pointer', 'pointer', 'int', 'int', 'int'], { "abi": "sysv" });
var MySQL_set_query_6 = new NativeFunction(ptr(0x83F41C0), 'int', ['pointer', 'pointer', 'int', 'int', 'int', 'int'], { "abi": "sysv" });
var MySQL_exec = new NativeFunction(ptr(0x83F4326), 'int', ['pointer', 'int'], { "abi": "sysv" });
var MySQL_exec_query = new NativeFunction(ptr(0x083F5348), 'int', ['pointer'], { "abi": "sysv" });
var MySQL_get_n_rows = new NativeFunction(ptr(0x80E236C), 'int', ['pointer'], { "abi": "sysv" });
var MySQL_fetch = new NativeFunction(ptr(0x83F44BC), 'int', ['pointer'], { "abi": "sysv" });
var MySQL_get_int = new NativeFunction(ptr(0x811692C), 'int', ['pointer', 'int', 'pointer'], { "abi": "sysv" });
var MySQL_get_short = new NativeFunction(ptr(0x0814201C), 'int', ['pointer', 'int', 'pointer'], { "abi": "sysv" });
var MySQL_get_uint = new NativeFunction(ptr(0x80E22F2), 'int', ['pointer', 'int', 'pointer'], { "abi": "sysv" });
var MySQL_get_ulonglong = new NativeFunction(ptr(0x81754C8), 'int', ['pointer', 'int', 'pointer'], { "abi": "sysv" });
var MySQL_get_ushort = new NativeFunction(ptr(0x8116990), 'int', ['pointer'], { "abi": "sysv" });
var MySQL_get_float = new NativeFunction(ptr(0x844D6D0), 'int', ['pointer', 'int', 'pointer'], { "abi": "sysv" });
var MySQL_get_binary = new NativeFunction(ptr(0x812531A), 'int', ['pointer', 'int', 'pointer', 'int'], { "abi": "sysv" });
var MySQL_get_binary_length = new NativeFunction(ptr(0x81253DE), 'int', ['pointer', 'int'], { "abi": "sysv" });
var MySQL_get_str = new NativeFunction(ptr(0x80ECDEA), 'int', ['pointer', 'int', 'pointer', 'int'], { "abi": "sysv" });
var MySQL_blob_to_str = new NativeFunction(ptr(0x83F452A), 'pointer', ['pointer', 'int', 'pointer', 'int'], { "abi": "sysv" });
var compress_zip = new NativeFunction(ptr(0x86B201F), 'int', ['pointer', 'pointer', 'pointer', 'int'], { "abi": "sysv" });
var uncompress_zip = new NativeFunction(ptr(0x86B2102), 'int', ['pointer', 'pointer', 'pointer', 'int'], { "abi": "sysv" });
var StreamPool_Acquire = new NativeFunction(ptr(0x0828FA86), 'pointer', ['pointer', 'pointer', 'int'], { "abi": "sysv" });
var CStreamGuard_CStreamGuard = new NativeFunction(ptr(0x080C8C26), 'void', ['pointer', 'pointer', 'int'], { "abi": "sysv" });
var CStreamGuard_operator = new NativeFunction(ptr(0x080C8C46), 'int', ['int'], { "abi": "sysv" });
var CStreamGuard_operator_int = new NativeFunction(ptr(0x080C8C56), 'int', ['pointer', 'int'], { "abi": "sysv" });
var CStreamGuard_operator_p = new NativeFunction(ptr(0x080C8C4E), 'int', ['int'], { "abi": "sysv" });
var CStreamGuard_GetInBuffer_SIG_ACCOUNT_CARGO_DATA = new NativeFunction(ptr(0x08453A10), 'pointer', ['pointer'], { "abi": "sysv" });
var MsgQueueMgr_put = new NativeFunction(ptr(0x08570FDE), 'int', ['int', 'int', 'pointer'], { "abi": "sysv" });
var CAccountCargo_SetStable = new NativeFunction(ptr(0x0844DC16), 'pointer', ['pointer'], { "abi": "sysv" });
var Destroy_CStreamGuard_CStreamGuard = new NativeFunction(ptr(0x0861C8D2), 'void', ['pointer'], { "abi": "sysv" });
var AccountCargoScript_GetCurrUpgradeInfo = new NativeFunction(ptr(0x088C80BA), 'int', ['pointer', 'int'], { "abi": "sysv" });
var CStackableItem_getStackableLimit = new NativeFunction(ptr(0x0822C9FC), 'int', ['pointer'], { "abi": "sysv" });
var CItem_isPackagable = new NativeFunction(ptr(0x0828B5B4), 'int', ['pointer'], { "abi": "sysv" });
var stAmplifyOption_t_GetLock = new NativeFunction(ptr(0x0828B5A8), 'int', ['pointer'], { "abi": "sysv" });
var CUser_GetCharacExpandDataR = new NativeFunction(ptr(0x0828B5DE), 'int', ['int', 'int'], { "abi": "sysv" });
var item_lock_CItemLock_CheckItemLock = new NativeFunction(ptr(0x08541A96), 'int', ['int', 'int'], { "abi": "sysv" });
var CItem_GetAttachType = new NativeFunction(ptr(0x80F12E2), 'int', ['pointer'], { "abi": "sysv" });
var UpgradeSeparateInfo_IsTradeRestriction = new NativeFunction(ptr(0x08110B0A), 'int', ['pointer'], { "abi": "sysv" });
var CUser_isGMUser = new NativeFunction(ptr(0x0814589C), 'int', ['pointer'], { "abi": "sysv" });
var CItem_getUsablePeriod = new NativeFunction(ptr(0x08110C60), 'int', ['pointer'], { "abi": "sysv" });
var CItem_getExpirationDate = new NativeFunction(ptr(0x080F1306), 'int', ['pointer'], { "abi": "sysv" });
//线程安全锁
var Guard_Mutex_Guard = new NativeFunction(ptr(0x810544C), 'int', ['pointer', 'pointer'], { "abi": "sysv" });
var Destroy_Guard_Mutex_Guard = new NativeFunction(ptr(0x8105468), 'int', ['pointer'], { "abi": "sysv" });

var CUserCharacInfo_get_charac_job = new NativeFunction(ptr(0x80FDF20), 'int', ['pointer'],
	{
		"abi": "sysv"
	});
var CUserCharacInfo_getCurCharacGrowType = new NativeFunction(ptr(0x815741C), 'int', ['pointer'],
	{
		"abi": "sysv"
	});
var CUserCharacInfo_get_charac_guildkey = new NativeFunction(ptr(0x822F46C), 'int', ['pointer'],
	{
		"abi": "sysv"
	});
var CUser_GetGuildName = new NativeFunction(ptr(0x869742A), 'pointer', ['pointer'],
	{
		"abi": "sysv"
	});
//服务器内置定时器队列
var G_TimerQueue = new NativeFunction(ptr(0x80F647C), 'pointer', [], { "abi": "sysv" });
//需要在dispatcher线程执行的任务队列(热加载后会被清空)

var CEquipItem_GetSubType = new NativeFunction(ptr(0x833eecc), 'int', ['pointer'], { "abi": "sysv" });
var CItem_GetRarity = new NativeFunction(ptr(0x80f12d6), 'int', ['pointer'], { "abi": "sysv" });
var CItem_GetUsableLevel = new NativeFunction(ptr(0x80f12ee), 'int', ['pointer'], { "abi": "sysv" });

var timer_dispatcher_list = [];
//获取背包槽中的道具
var INVENTORY_TYPE_BODY = 0;            //身上穿的装备(0-26)
var INVENTORY_TYPE_ITEM = 1;            //物品栏(0-311)
var INVENTORY_TYPE_AVARTAR = 2;         //时装栏(0-104)
var INVENTORY_TYPE_CREATURE = 3;        //宠物装备(0-241)
//通知客户端更新背包栏
var ENUM_ITEMSPACE_INVENTORY = 0;       //物品栏
var ENUM_ITEMSPACE_AVATAR = 1;          //时装栏
var ENUM_ITEMSPACE_CARGO = 2;           //仓库
var ENUM_ITEMSPACE_CREATURE = 7;        //宠物栏
var ENUM_ITEMSPACE_ACCOUNT_CARGO = 12;  //账号仓库
//完成角色当前可接的所有任务(仅发送金币/经验/QP等基础奖励 无道具奖励)
var QUEST_gRADE_COMMON_UNIQUE = 5;                  //任务脚本中[grade]字段对应的常量定义 可以在importQuestScript函数中找到
var QUEST_gRADE_NORMALY_REPEAT = 4;                 //可重复提交的重复任务
var QUEST_gRADE_DAILY = 3;                          //每日任务
var QUEST_gRADE_EPIC = 0;                           //史诗任务
var QUEST_gRADE_ACHIEVEMENT = 2;                           //史诗任务

//已打开的数据库句柄
var mysql_taiwan_cain = null;
var mysql_taiwan_cain_2nd = null;
var mysql_taiwan_billing = null;
var mysql_frida = null;
var mysql_frida = null;
var mysql_taiwan_login = null;
var mysql_d_taiwan = null;
var mysql_personal_production = null;
var mysql_Prohibition_of_Cheating = null;
//怪物攻城活动当前状态
const VILLAGEATTACK_STATE_P1 = 0; //一阶段
const VILLAGEATTACK_STATE_P2 = 1; //二阶段
const VILLAGEATTACK_STATE_P3 = 2; //三阶段
const VILLAGEATTACK_STATE_END = 3; //活动已结束

const TAU_CAPTAIN_MONSTER_ID = 50071; //牛头统帅id(P1阶段击杀该怪物可提升活动难度等级)
const GBL_POPE_MONSTER_ID = 262; //GBL教主教(P2/P3阶段城镇存在该怪物 持续减少PT点数)
const TAU_META_COW_MONSTER_ID = 17; //机械牛(P3阶段世界BOSS)

const EVENT_VILLAGEATTACK_START_HOUR = 12; //每日北京时间20点开启活动
const EVENT_VILLAGEATTACK_TARGET_SCORE = [100, 200, 300]; //各阶段目标PT
const EVENT_VILLAGEATTACK_TOTAL_TIME = 3600; //活动总时长(秒)

//怪物攻城活动数据
var villageAttackEventInfo =
{
	'state': VILLAGEATTACK_STATE_END, //活动当前状态
	'score': 0, //当前阶段频道内总PT
	'start_time': 0, //活动开始时间(UTC)
	'difficult': 0, //活动难度(0-4)
	'next_village_monster_id': 0, //下次刷新的攻城怪物id
	'last_killed_monster_id': 0, //上次击杀的攻城怪物id
	'p2_last_killed_monster_time': 0, //P2阶段上次击杀攻城怪物时间
	'p2_kill_combo': 0, //P2阶段连续击杀相同攻城怪物数量
	'gbl_cnt': 0, //城镇中存活的GBL主教数量
	'defend_success': 0, //怪物攻城活动防守成功
	'user_pt_info': {}, //角色个人pt数据
}

//获取角色所在队伍
const CUser_GetParty = new NativeFunction(ptr(0x0865514C), 'pointer', ['pointer'], { "abi": "sysv" });
//获取队伍中玩家
const CParty_get_user = new NativeFunction(ptr(0x08145764), 'pointer', ['pointer', 'int'], { "abi": "sysv" });
//获取角色扩展数据
const CUser_GetCharacExpandData = new NativeFunction(ptr(0x080DD584), 'pointer', ['pointer', 'int'], { "abi": "sysv" });
//绝望之塔层数
const TOD_Layer_TOD_Layer = new NativeFunction(ptr(0x085FE7B4), 'pointer', ['pointer', 'int'], { "abi": "sysv" });
//设置绝望之塔层数
const TOD_UserState_setEnterLayer = new NativeFunction(ptr(0x086438FC), 'pointer', ['pointer', 'pointer'], { "abi": "sysv" });
//获取角色当前持有金币数量
var CInventory_get_money = new NativeFunction(ptr(0x81347D6), 'int', ['pointer'], { "abi": "sysv" });
//通知客户端更新角色身上装备
const CUser_SendNotiPacket = new NativeFunction(ptr(0x0867BA5C), 'int', ['pointer', 'int', 'int', 'int'], { "abi": "sysv" });
//开启怪物攻城
const Inter_VillageAttackedStart_dispatch_sig = new NativeFunction(ptr(0x84DF47A), 'pointer', ['pointer', 'pointer', 'pointer'], { "abi": "sysv" });
//结束怪物攻城
const village_attacked_CVillageMonsterMgr_OnDestroyVillageMonster = new NativeFunction(ptr(0x086B43D4), 'pointer', ['pointer', 'int'], { "abi": "sysv" });
const GlobalData_s_villageMonsterMgr = ptr(0x941F77C);
const nullptr = Memory.alloc(4);
var Inven_Item = new NativeFunction(ptr(0x080CB854), 'void', ['pointer'], { "abi": "sysv" });
var GetItem_index = new NativeFunction(ptr(0x08110C48), 'int', ['pointer'], { "abi": "sysv" });
var GetCurCharacNo = new NativeFunction(ptr(0x80CBC4E), 'int', ['pointer'], { "abi": "sysv" });
var GetServerGroup = new NativeFunction(ptr(0x080CBC90), 'int', ['pointer'], { "abi": "sysv" });
var GetCurVAttackCount = new NativeFunction(ptr(0x084EC216), 'int', ['pointer'], { "abi": "sysv" });
var ReqDBSendNewSystemMail = new NativeFunction(ptr(0x085555E8), 'int', ['pointer', 'pointer', 'int', 'int', 'pointer', 'int', 'int', 'int', 'char', 'char'], { "abi": "sysv" });

//测试系统API
var strlen = new NativeFunction(ptr(0x0807E3B0), 'int', ['pointer'], { "abi": "sysv" }); //获取字符串长度
var strlen = new NativeFunction(Module.getExportByName(null, 'strlen'), 'int', ['pointer'], { "abi": "sysv" });
var global_config = {};

//获取道具名
var CItem_GetItemName = new NativeFunction(ptr(0x811ED82), 'pointer', ['pointer'], { "abi": "sysv" });



var G_GameWorld = new NativeFunction(ptr(0x080DA3A7), 'pointer', [], { "abi": "sysv" });
var gameworld_user_map_begin = new NativeFunction(ptr(0x80F78A6), 'int', ['pointer', 'pointer'], { "abi": "sysv" });
var gameworld_user_map_end = new NativeFunction(ptr(0x80F78CC), 'int', ['pointer', 'pointer'], { "abi": "sysv" });
var gameworld_user_map_not_equal = new NativeFunction(ptr(0x80F78F2), 'bool', ['pointer', 'pointer'], { "abi": "sysv" });
var gameworld_user_map_get = new NativeFunction(ptr(0x80F7944), 'pointer', ['pointer'], { "abi": "sysv" });
var CUser_get_state = new NativeFunction(ptr(0x80DA38C), 'int', ['pointer'], { "abi": "sysv" });
var CUserCharacInfo_getCurCharacNo = new NativeFunction(ptr(0x80CBC4E), 'int', ['pointer'], { "abi": "sysv" });
var gameworld_user_map_next = new NativeFunction(ptr(0x80F7906), 'pointer', ['pointer', 'pointer'], { "abi": "sysv" });
var Inven_Item_Inven_Item = new NativeFunction(ptr(0x80CB854), 'pointer', ['pointer'], { "abi": "sysv" });
var std_vector_std_pair_int_int_push_back = new NativeFunction(ptr(0x80DD606), 'pointer', ['pointer', 'pointer'], { "abi": "sysv" });
var std_make_pair_int_int = new NativeFunction(ptr(0x81B8D41), 'pointer', ['pointer', 'pointer', 'pointer'], { "abi": "sysv" });
var std_vector_std_pair_int_int_vector = new NativeFunction(ptr(0x81349D6), 'pointer', ['pointer'], { "abi": "sysv" });
var std_vector_std_pair_int_int_clear = new NativeFunction(ptr(0x817A342), 'pointer', ['pointer'], { "abi": "sysv" });

var WongWork_CMailBoxHelper_ReqDBSendNewSystemMultiMail = new NativeFunction(ptr(0x8556B68), 'int', ['pointer', 'pointer', 'int', 'int', 'int', 'pointer', 'int', 'int', 'int', 'int'], { "abi": "sysv" });
var WongWork_CMailBoxHelper_MakeSystemMultiMailPostal = new NativeFunction(ptr(0x8556A14), 'int', ['pointer', 'pointer', 'int'], { "abi": "sysv" });


//获取道具名字
function api_CItem_GetItemName(item_id) {
	var citem = CDataManager_find_item(G_CDataManager(), item_id);
	if (!citem.isNull()) {
		return CItem_GetItemName(citem).readUtf8String(-1);
	}

	return item_id.toString();
}

//获取随机数
function get_random_int(min, max) {
	return Math.floor(Math.random() * (max - min)) + min;
}

//读取文件
function api_read_file(path, mode, len) {
	var path_ptr = Memory.allocUtf8String(path);
	var mode_ptr = Memory.allocUtf8String(mode);
	var f = fopen(path_ptr, mode_ptr);
	if (f == 0)
		return null;
	var data = Memory.alloc(len);
	var fread_ret = fread(data, 1, len, f);
	fclose(f);
	//返回字符串
	if (mode == 'r')
		return data.readUtf8String(fread_ret);
	//返回二进制buff指针
	return data;
}

//加载本地配置文件(json格式)
function load_config(path) {
	var data = api_read_file(path, 'r', 10 * 1024 * 1024);
	global_config = JSON.parse(data);
}

//获取系统UTC时间(秒)
function api_CSystemTime_getCurSec() {
	return GlobalData_s_systemTime_.readInt();
}

//获取道具数据
function find_item(item_id) {
	return CDataManager_find_item(G_CDataManager(), item_id);
}

//邮件函数封装
function CMailBoxHelperReqDBSendNewSystemMail(User, item_id, item_count) {
	var retitem = find_item(item_id);
	if (retitem) {
		var Inven_ItemPr = Memory.alloc(100);
		Inven_Item(Inven_ItemPr); //清空道具
		var itemid = GetItem_index(retitem);
		var itemtype = retitem.add(8).readU8();
		Inven_ItemPr.writeU8(itemtype);
		Inven_ItemPr.add(2).writeInt(itemid);
		Inven_ItemPr.add(7).writeInt(item_count);
		// set_add_info(Inven_ItemPr, item_count);
		var GoldValue = 0;
		var TitlePr = Memory.allocUtf8String('怪物攻城奖励');
		var TxtValue = '击退奖励：';
		var UserID = GetCurCharacNo(User);
		var TxtValuePr = Memory.allocUtf8String(TxtValue);
		var TxtValueLength = toString(TxtValue).length;
		var ServerGroup = GetServerGroup(User);
		var MailDate = 30;
		ReqDBSendNewSystemMail(TitlePr, Inven_ItemPr, GoldValue, UserID, TxtValuePr, TxtValueLength, MailDate, ServerGroup, 0, 0);
	}
}

//获取角色名字
function api_CUserCharacInfo_getCurCharacName(user) {
	var p = CUserCharacInfo_getCurCharacName(user);
	if (p.isNull()) {
		return '';
	}
	return p.readUtf8String(-1);
}

//点券充值 (禁止直接修改billing库所有表字段, 点券相关操作务必调用数据库存储过程!)
function api_recharge_cash_cera(user, amount) {
	//充值
	WongWork_IPG_CIPGHelper_IPGInput(ptr(0x941F734).readPointer(), user, 5, amount, ptr(0x8C7FA20), ptr(0x8C7FA20),
		Memory.allocUtf8String('GM'), ptr(0), ptr(0), ptr(0));
	//通知客户端充值结果
	WongWork_IPG_CIPGHelper_IPGQuery(ptr(0x941F734).readPointer(), user);
}

//代币充值 (禁止直接修改billing库所有表字段, 点券相关操作务必调用数据库存储过程!)
function api_recharge_cash_cera_point(user, amount) {
	//充值
	WongWork_IPG_CIPGHelper_IPGInputPoint(ptr(0x941F734).readPointer(), user, amount, 4, ptr(0), ptr(0));
	//通知客户端充值结果
	WongWork_IPG_CIPGHelper_IPGQuery(ptr(0x941F734).readPointer(), user);
}

//抽取幸运在线玩家活动
function on_event_lucky_online_user() {
	//在线玩家数量
	var online_player_cnt = GameWorld_get_UserCount_InWorld(G_GameWorld());

	//没有在线玩家时跳过本轮活动
	if (online_player_cnt > 0) {
		//幸运在线玩家
		var lucky_user = null;

		//遍历在线玩家列表
		var it = api_gameworld_user_map_begin();
		var end = api_gameworld_user_map_end();

		//随机抽取一名在线玩家
		var user_index = get_random_int(0, online_player_cnt);

		while (user_index >= 0) {
			user_index--;

			//判断在线玩家列表遍历是否已结束
			if (gameworld_user_map_not_equal(it, end)) {
				//当前被遍历到的玩家
				lucky_user = api_gameworld_user_map_get(it);

				//state > 2 的玩家才有资格参加抽奖
				if (CUser_get_state(lucky_user) < 3) {
					lucky_user = null;
				}

				//继续遍历下一个玩家
				api_gameworld_user_map_next(it);
			}
			else {
				break;
			}
		}

		//给幸运玩家发奖
		if (lucky_user) {
			//获取该活动配置文件
			var config = global_config["lucky_online_user_event"];

			//道具奖励
			var reward_msg = '';
			for (var i = 0; i < config["reward_items_list"].length; ++i) {
				var item_id = config["reward_items_list"][i][0];
				var item_cnt = config["reward_items_list"][i][1];

				api_CUser_AddItem(lucky_user, item_id, item_cnt);

				reward_msg += api_CItem_GetItemName(item_id) + '*' + item_cnt + '\n';
			}

			//点券奖励
			api_recharge_cash_cera(lucky_user, config["reward_cash_cera"]);
			reward_msg += config["reward_cash_cera"] + ' 点券';

			//世界广播本轮幸运在线玩家
			api_GameWorld_SendNotiPacketMessage('<幸运在线玩家活动>开奖:\n恭喜 [' + api_CUserCharacInfo_getCurCharacName(lucky_user) + '] 成为本轮活动幸运玩家, 已发送奖励:\n' + reward_msg, 0);

		}
	}

	//定时开启下一次活动
	start_event_lucky_online_user();
}

//每小时开启抽取幸运在线玩家活动
function start_event_lucky_online_user() {
	//获取当前系统时间
	var cur_time = api_CSystemTime_getCurSec();

	//计算距离下次抽取幸运玩家时间(每小时执行一次)
	var delay_time = 3600 - (cur_time % 3600) + 3;

	//log('距离下次抽取幸运在线玩家还有:' + delay_time/60 + '分钟');

	//定时开启活动
	api_scheduleOnMainThread_delay(on_event_lucky_online_user, null, delay_time * 1000);
}

var MySQL_set_query_3_ptr = new NativeFunction(ptr(0x83F41C0), 'int', ['pointer', 'pointer', 'pointer'], { "abi": "sysv" });
// 获取账号金库一个空的格子
var CAccountCargo_GetEmptySlot_NEW;
// 将已经物品移动到某个格子 第一个账号金库，第二个移入的物品，第三个格子位置
var CAccountCargo_InsertItem_NEW;
// 向客户端发送账号金库列表
var CAccountCargo_SendItemList_NEW;
// 存放所有用户的账号金库数据
var accountCargfo = {};
var initMaxSolt = 0;
function setMaxCAccountCargoSolt(maxSolt) {
	// console.log(1);
	initMaxSolt = maxSolt;
	GetMoney(maxSolt);
	CAccountCargo(maxSolt);
	GetCapacity(maxSolt);
	SetDBData(maxSolt);
	Clear(maxSolt);
	InsertItem(maxSolt);
	DeleteItem(maxSolt);
	MoveItem(maxSolt);
	DepositMoney(maxSolt);
	WithdrawMoney(maxSolt);
	CheckMoneyLimit(maxSolt);
	CheckValidSlot(maxSolt);
	GetEmptySlot(maxSolt);
	GetSpecificItemSlot(maxSolt);
	AddMoney(maxSolt);
	SubMoney(maxSolt);
	GetItemCount(maxSolt);
	SendNotifyMoney(maxSolt);
	SendItemList(maxSolt);
	IsAlter(maxSolt);
	SetCapacity(maxSolt);
	SetStable(maxSolt);
	DB_SaveAccountCargo_makeRequest(maxSolt);
	GetAccountCargo();
	MakeItemPacket(maxSolt);
	CheckStackLimit(maxSolt);
	CheckSlotEmpty(maxSolt);
	// CheckInsertCondition(maxSolt);
	GetSlotRef(maxSolt);
	GetSlot(maxSolt);
	ResetSlot(maxSolt);
	DB_LoadAccountCargo_dispatch(maxSolt);
	DB_SaveAccountCargo_dispatch(maxSolt);
	IsExistAccountCargo();
	// userLogout();
	console.log(12);
}

function IsExistAccountCargo() {
	Interceptor.attach(ptr(0x0822fc30), {

		onEnter: function (args) {
			// console.log('IsExistAccountCargo start:'+args[0])
		},
		onLeave: function (retval) {
			// console.log('IsExistAccountCargo end:'+retval)
		}
	});
}

function DB_SaveAccountCargo_dispatch(maxSolt) {
	Interceptor.replace(ptr(0x0843b7c2), new NativeCallback(function (dbcargoRef, a2, a3, a4) {
		// console.log("DB_SaveAccountCargo_dispatch -------------:")
		var v14 = Memory.alloc(4);
		v14.writeU32(0);
		Stream_operator_p(a4, v14.toInt32());
		var v4 = NumberToString(v14.readU32(), 0);
		// console.log("mid:"+ptr(v4).readUtf8String(-1));

		var out = Stream_GetOutBuffer_SIG_ACCOUNT_CARGO_DATA(a4);
		var outPtr = ptr(out);
		var v17Addr = Memory.alloc(4);
		v17Addr.writeInt(61 * maxSolt);
		var readBuff = Memory.alloc(61 * maxSolt);
		if (compress_zip(readBuff, v17Addr, outPtr.add(8), 61 * maxSolt) != 1) {
			return 0;
		}
		var dbHandelAddr = DBMgr_GetDBHandle(ptr(ptr(0x0940BDAC).readU32()), 2, 0);
		var dbHandel = ptr(dbHandelAddr);
		var blobPtr = MySQL_blob_to_str(dbHandel, 0, readBuff, v17Addr.readU32());
		// console.log('blob: '+blobPtr +' '+outPtr.readU32()+' '+outPtr.add(4).readU32()+'  ');
		MySQL_set_query_6(dbHandel, Memory.allocUtf8String("upDate account_cargo set capacity=%u, money=%u, cargo='%s' where m_id = %s")
			, outPtr.readU32(), outPtr.add(4).readU32(), blobPtr.toInt32(), ptr(v4).toInt32());
		return MySQL_exec(dbHandel, 1) == 1 ? 1 : 0;
	}, 'int', ['pointer', 'int', 'int', 'pointer']));
}

function DB_LoadAccountCargo_dispatch(maxSolt) {
	Interceptor.replace(ptr(0x0843b3b6), new NativeCallback(function (dbcargoRef, a2, a3, a4) {
		console.log('DB_LoadAccountCargo_dispatch:::' + dbcargoRef + ',' + a2 + ',' + a3 + ',' + a4);

		var v19 = Memory.alloc(4);
		v19.writeU32(0);
		Stream_operator_p(a4, v19.toInt32());
		var v4 = NumberToString(v19.readU32(), 0);
		// console.log("mid:"+ptr(v4).readUtf8String(-1))

		var dbHandelAddr = DBMgr_GetDBHandle(ptr(ptr(0x0940BDAC).readU32()), 2, 0);
		var dbHandel = ptr(dbHandelAddr);
		// console.log('dbHandel:'+dbHandel);

		MySQL_set_query_3_ptr(dbHandel, Memory.allocUtf8String('seLect capacity, money, cargo from account_cargo where m_id = %s'), ptr(v4));
		if (MySQL_exec(dbHandel, 1) != 1) {
			// console.log("exec fail :")
			return 0;
		}
		if (MySQL_get_n_rows(dbHandel) == 0) {
			// console.log("get rows  = 0 ")
			return 1;
		}
		if (MySQL_fetch(dbHandel) != 1) {
			// console.log("fetch fial  = 0 ")
			return 0;
		}
		var v18 = Memory.alloc(8);
		var v6 = StreamPool_Acquire(ptr(ptr(0x0940BD6C).readU32()), Memory.allocUtf8String('DBThread.cpp'), 35923);
		CStreamGuard_CStreamGuard(v18, v6, 1);
		var v7 = CStreamGuard_operator(v18.toInt32());
		CStreamGuard_operator_int(ptr(v7), a2);
		var v8 = CStreamGuard_operator(v18.toInt32());
		CStreamGuard_operator_int(ptr(v8), a3);
		var v9 = CStreamGuard_operator_p(v18.toInt32());
		var v21 = CStreamGuard_GetInBuffer_SIG_ACCOUNT_CARGO_DATA(ptr(v9));
		v21.writeU32(0);
		v21.add(4).writeU32(0);
		var cargoRefAdd = v21.add(8);
		for (var i = 0; i < maxSolt; i++) {
			cargoRefAdd.writeU32(0);
			cargoRefAdd = cargoRefAdd.add(61);
		}
		v21.add(8 + 61 * maxSolt).writeU32(0);
		v21.add(8 + 61 * maxSolt).writeU32(0);
		var res = 0;
		if (MySQL_get_uint(dbHandel, 0, v21) != 1) {
			// console.log('uint capacity get error')
			res = 0;
		} else if (MySQL_get_uint(dbHandel, 1, v21.add(4)) != 1) {
			// console.log('uint money get error')
			res = 0;
		} else {
			var v10 = Memory.alloc(61 * maxSolt * 4);
			for (var i = 0; i < 61 * maxSolt; i++) {
				v10.add(i * 4).writeU32(0);
			}
			var binaryLength = MySQL_get_binary_length(dbHandel, 2);
			if (MySQL_get_binary(dbHandel, 2, v10, binaryLength) != 1) {
				// console.log('read val length 0');
				// 解决创建账号金库后什么也不操作 然后保存字节为0 导致创建的打不开
				for (var i = 0; i < maxSolt; i++) {
					v21.add(8 + i * 61).writeU32(0);
				}
				var msgName = ptr(ptr(0x0940BD68).readU32());
				MsgQueueMgr_put(msgName.toInt32(), 1, v18);
				res = 1;
			} else {
				binaryLength = MySQL_get_binary_length(dbHandel, 2);
				var v17Addr = Memory.alloc(4);
				v17Addr.writeInt(61 * maxSolt)
				if (uncompress_zip(v21.add(8), v17Addr, v10, binaryLength) != 1) {
					// console.log("uncompress_zip error  !!!")
					res = 0;
				} else if (v17Addr.readU32() != 0 && v17Addr.readU32() % (61 * maxSolt) != 0) {
					res = 0;
				} else {
					var msgName = ptr(ptr(0x0940BD68).readU32());
					MsgQueueMgr_put(msgName.toInt32(), 1, v18);
					res = 1;

				}
				// console.log("v17 length:"+v17Addr.readU32());
			}
		}
		// console.log('money or capacity:'+v21.readU32()+','+v21.add(4).readU32()+','+v21.add(8).readU32()+' ,'+res)
		Destroy_CStreamGuard_CStreamGuard(v18);
		return res;
	}, 'int', ['pointer', 'int', 'int', 'pointer']));
}

function ResetSlot(maxSolt) {
	Interceptor.replace(ptr(0x082898C0), new NativeCallback(function (cargoRef, solt) {
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		// console.log('ResetSlot------------------------------------'+cargoRef)
		if (CAccountCargo_CheckValidSlot(cargoRef, solt) == 0) {
			return 0;
		}
		cargoRef = getCargoRef(accId, cargoRef);
		return Inven_Item_reset(cargoRef.add(61 * solt + 4));
	}, 'int', ['pointer', 'int']));
}

function GetSlot(maxSolt) {
	Interceptor.replace(ptr(0x082898F8), new NativeCallback(function (buff, cargo, solt) {
		var cargoRef = ptr(cargo);
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return buff;
		}
		// console.log('GetSlot------------------------------------'+cargoRef)
		cargoRef = getCargoRef(accId, cargoRef);
		if (CAccountCargo_CheckValidSlot(cargoRef, solt) == 0) {
			buff.writeU32(cargoRef.add(61 * solt + 4).readU32());
			buff.add(1 * 4).writeU32(0);
			buff.add(2 * 4).writeU32(0);
			buff.add(3 * 4).writeU32(0);
			buff.add(4 * 4).writeU32(0);
			buff.add(5 * 4).writeU32(0);
			buff.add(6 * 4).writeU32(0);
			buff.add(7 * 4).writeU32(0);
			buff.add(8 * 4).writeU32(0);
			buff.add(9 * 4).writeU32(0);
			buff.add(10 * 4).writeU32(0);
			buff.add(11 * 4).writeU32(0);
			buff.add(12 * 4).writeU32(0);
			buff.add(13 * 4).writeU32(0);
			buff.add(14 * 4).writeU32(0);
			buff.add(60).writeU8(0);
		} else {
			buff.writeU32(cargoRef.add(61 * solt + 4).readU32());
			buff.add(1 * 4).writeU32(cargoRef.add(61 * solt + 8).readU32());
			buff.add(2 * 4).writeU32(cargoRef.add(61 * solt + 12).readU32());
			buff.add(3 * 4).writeU32(cargoRef.add(61 * solt + 16).readU32());
			buff.add(4 * 4).writeU32(cargoRef.add(61 * solt + 20).readU32());
			buff.add(5 * 4).writeU32(cargoRef.add(61 * solt + 24).readU32());
			buff.add(6 * 4).writeU32(cargoRef.add(61 * solt + 28).readU32());
			buff.add(7 * 4).writeU32(cargoRef.add(61 * solt + 32).readU32());
			buff.add(8 * 4).writeU32(cargoRef.add(61 * solt + 36).readU32());
			buff.add(9 * 4).writeU32(cargoRef.add(61 * solt + 40).readU32());
			buff.add(10 * 4).writeU32(cargoRef.add(61 * solt + 44).readU32());
			buff.add(11 * 4).writeU32(cargoRef.add(61 * solt + 48).readU32());
			buff.add(12 * 4).writeU32(cargoRef.add(61 * solt + 52).readU32());
			buff.add(13 * 4).writeU32(cargoRef.add(61 * solt + 56).readU32());
			buff.add(14 * 4).writeU32(cargoRef.add(61 * solt + 60).readU32());
			buff.add(60).writeU8(cargoRef.add(61 * solt + 64).readU8());
		}
		return buff;
	}, 'pointer', ['pointer', 'int', 'int']));
}

function GetSlotRef(maxSolt) {
	Interceptor.replace(ptr(0x08289A0C), new NativeCallback(function (cargoRef, solt) {
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		// console.log("GetSlotRef ------------------------"+cargoRef)
		if (CAccountCargo_CheckValidSlot(cargoRef, solt) == 0) {
			return 0;
		}
		cargoRef.add(12 + 61 * 56).writeU8(1); // 标志
		cargoRef = getCargoRef(accId, cargoRef);
		cargoRef.add(12 + 61 * maxSolt).writeU8(1); // 标志
		return cargoRef.add(61 * solt + 4);
	}, 'pointer', ['pointer', 'int']));
}

// todo 没有写替换
function CheckInsertCondition(maxSolt) {
	Interceptor.replace(ptr(0x08289A4A), new NativeCallback(function (cargoRef, itemInven) {
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		// console.log('CheckInsertCondition------------------------------------'+cargoRef)
		var itemId = itemInven.add(2).readU32();
		var item = CDataManager_find_item(G_CDataManager(), itemId);
		if (item == 0) {
			return 0;
		}
		if (CItem_isPackagable(item) != 1) {
			return 0;
		}
		var lock = stAmplifyOption_t_GetLock(itemInven.add(17));
		if (lock != 0) {
			var characExpandDataR = CUser_GetCharacExpandDataR(cargoRef.readU32(), 2);
			if (item_lock_CItemLock_CheckItemLock(characExpandDataR, lock) != 0) {
				return 0;
			}
		}
		var typeVal = itemInven.add(1).readU8();
		if (typeVal == 4 || typeVal == 5 || typeVal == 6 || typeVal == 7 || typeVal == 8) {
			return 0;
		}
		if (itemId > 0x1963 && itemId <= 0x1B57) {
			return 0;
		}
		var attachType = CItem_GetAttachType(item);
		if (attachType == 1 || attachType == 2) {
			return 0;
		}
		if (attachType == 3 && itemInven.readU8() != 1) {
			return 0;
		}
		if (UpgradeSeparateInfo_IsTradeRestriction(itemInven.add(51)) != 0) {
			return 0;
		}
		var tempMethod = new NativeFunction(ptr(item.add(16 * 4).readU32()), 'int', ['pointer'], { "abi": "sysv" });
		// ||tempMethod(item)==1
		var isGMUser = CUser_isGMUser(ptr(cargoRef.readU32()));
		if (isGMUser == 1) {
			return 1;
		}
		if (CItem_getUsablePeriod(item) == 0 && CItem_getExpirationDate(item) == 0) {
			return 1;
		}
		if (CItem_getUsablePeriod(item) == 0 && CItem_getExpirationDate(item) == 0) {
			return 0;
		}
		var expDate = 86400 * itemInven.add(11).readU16() + 1151683200;
		return expDate > CSystemTime_getCurSec(ptr(0x0941F714)) ? 1 : 0;
	}, 'int', ['pointer', 'pointer']));
}

function CheckSlotEmpty(maxSolt) {
	Interceptor.replace(ptr(0x0828A5D4), new NativeCallback(function (cargoRef, solt) {
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		// console.log('CheckSlotEmpty------------------------------------'+cargoRef)
		var buffCargoRef = getCargoRef(accId, cargoRef);
		// console.log("CheckSlotEmpty accId:"+accId)
		return (CAccountCargo_CheckValidSlot(cargoRef, solt) != 0 && buffCargoRef.add(61 * solt + 6).readU32() != 0) ? 1 : 0;
	}, 'int', ['pointer', 'int']));
}

function CheckStackLimit(maxSolt) {
	Interceptor.replace(ptr(0x0828A670), new NativeCallback(function (cargoRef, solt, itemId, size) {
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		// console.log('CheckStackLimit------------------------------------'+cargoRef)
		if (CAccountCargo_CheckValidSlot(cargoRef, solt) == 0) {
			return 0;
		}
		cargoRef = getCargoRef(accId, cargoRef);;
		if (cargoRef.add(61 * solt + 6).readU32() != itemId) {
			return 0;
		}
		var item = CDataManager_find_item(G_CDataManager(), itemId);
		if (item == 0) {
			return 0;
		}
		if (CItem_is_stackable(item) != 1) {
			return 0;
		}
		var allSize = size + cargoRef.add(61 * solt + 11).readU32();
		var limit = CStackableItem_getStackableLimit(item);
		return limit < allSize || allSize < 0 ? 0 : 1;
	}, 'int', ['pointer', 'int', 'int', 'int']));
}

function MakeItemPacket(maxSolt) {
	Interceptor.replace(ptr(0x0828AB1C), new NativeCallback(function (cargoRef, buff, solt) {
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		// console.log('MakeItemPacket------------------------------------'+cargoRef)
		cargoRef = getCargoRef(accId, cargoRef);
		// console.log("MakeItemPacket accId:"+accId)
		InterfacePacketBuf_put_short(buff, solt);
		if (cargoRef.add(61 * solt + 6).readU32() != 0) {
			InterfacePacketBuf_put_int(buff, cargoRef.add(61 * solt + 6).readU32());
			InterfacePacketBuf_put_int(buff, cargoRef.add(61 * solt + 11).readU32());
			var integratedPvPItemAttr = GetIntegratedPvPItemAttr(cargoRef.add(61 * solt + 4));
			InterfacePacketBuf_put_byte(buff, integratedPvPItemAttr);
			InterfacePacketBuf_put_short(buff, cargoRef.add(61 * solt + 15).readU16());
			InterfacePacketBuf_put_byte(buff, cargoRef.add(61 * solt + 4).readU8());
			if (GameWorld_IsEnchantRevisionChannel(G_GameWorld()) != 0) {
				InterfacePacketBuf_put_int(buff, 0);
			} else {
				InterfacePacketBuf_put_int(buff, cargoRef.add(61 * solt + 17).readU32());
			}
			var abilityType = stAmplifyOption_t_getAbilityType(cargoRef.add(61 * solt + 21));
			InterfacePacketBuf_put_byte(buff, abilityType);
			var abilityValue = stAmplifyOption_t_getAbilityValue(cargoRef.add(61 * solt + 21));
			InterfacePacketBuf_put_short(buff, abilityValue);
			InterfacePacketBuf_put_byte(buff, 0);
			return InterfacePacketBuf_put_packet(buff, cargoRef.add(61 * solt + 4));
		} else {
			InterfacePacketBuf_put_int(buff, -1);
			InterfacePacketBuf_put_int(buff, 0);
			InterfacePacketBuf_put_byte(buff, 0);
			InterfacePacketBuf_put_short(buff, 0);
			InterfacePacketBuf_put_byte(buff, 0);
			InterfacePacketBuf_put_int(buff, 0);
			InterfacePacketBuf_put_byte(buff, 0);
			InterfacePacketBuf_put_short(buff, 0);
			InterfacePacketBuf_put_byte(buff, 0);
			return InterfacePacketBuf_put_packet(buff, ptr(0x0943DDC0).readPointer());
		}
	}, 'int', ['pointer', 'pointer', 'int']));
}

function GetAccountCargo() {
	Interceptor.replace(ptr(0x0822fc22), new NativeCallback(function (cargoRef) {
		// var accId =  CUser_get_acc_id(cargoRef);
		// if(accId == -1){
		//     return 0;
		// }
		console.log('GetAccountCargo------------------------------------' + cargoRef)
		// if(accountCargfo[accId]){
		//     return  accountCargfo[accId];
		// }
		// 返回原来的地址
		return cargoRef.add(454652);
	}, 'pointer', ['pointer']));
}

function DB_SaveAccountCargo_makeRequest(maxSolt) {
	Interceptor.replace(ptr(0x0843B946), new NativeCallback(function (a1, a2, cargo) {
		console.log("DB_SaveAccountCargo_makeRequest---------" + ptr(cargo) + ',' + a1 + ',,,' + a2);
		var cargoRef = ptr(cargo);
		var accId = getUserAccId(cargoRef);
		// console.log('makeRequest------accId-----'+accId);
		cargoRef = getCargoRef(accId, cargoRef);
		var v8 = Memory.alloc(61 * maxSolt + 9);
		var v3 = StreamPool_Acquire(ptr(ptr(0x0940BD6C).readU32()), Memory.allocUtf8String('DBThread.cpp'), 35999);
		CStreamGuard_CStreamGuard(v8, v3, 1);
		var v4 = CStreamGuard_operator(v8.toInt32());
		CStreamGuard_operator_int(ptr(v4), 497);
		var v5 = CStreamGuard_operator(v8.toInt32());
		CStreamGuard_operator_int(ptr(v5), a1.toInt32());
		var v6 = CStreamGuard_operator(v8.toInt32());
		CStreamGuard_operator_int(ptr(v6), a2);
		var v7 = CStreamGuard_operator_p(v8.toInt32());
		var v9 = CStreamGuard_GetInBuffer_SIG_ACCOUNT_CARGO_DATA(ptr(v7));
		v9.writeU32(0);
		var cargoRefAdd = v9.add(4);
		for (var i = 0; i < maxSolt; i++) {
			cargoRefAdd.writeU32(0);
			cargoRefAdd = cargoRefAdd.add(61);
		}
		var money = cargoRef.add(4 + 61 * maxSolt).readU32();
		var capacity = cargoRef.add(8 + 61 * maxSolt).readU32();
		// console.log('money or capacity:'+money+','+capacity)
		v9.writeU32(capacity); // 钱
		v9.add(4).writeU32(money); // 容量
		Memory.copy(v9.add(8), cargoRef.add(4), maxSolt * 61);
		MsgQueueMgr_put(ptr(ptr(0x0940BD68).readU32()).toInt32(), 2, v8);
		CAccountCargo_SetStable(cargoRef);
		Destroy_CStreamGuard_CStreamGuard(v8);
		// console.log("makeRequest success")
	}, 'void', ['pointer', 'int', 'uint']));
}

function SetStable(maxSolt) {
	Interceptor.replace(ptr(0x0844DC16), new NativeCallback(function (cargoRef) {
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		// console.log("SetStable ---------------------"+cargoRef)
		var buffCargoRef = getCargoRef(accId, cargoRef);;
		buffCargoRef.add(12 + 61 * maxSolt).writeU8(0); // 标志
		return cargoRef;
	}, 'pointer', ['pointer']));
}

function SetCapacity(maxSolt) {
	Interceptor.replace(ptr(0x084EBE46), new NativeCallback(function (cargoRef, capacity) {
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		// console.log("SetCapacity--------------------"+cargoRef)
		var buffCargoRef = getCargoRef(accId, cargoRef);
		buffCargoRef.add(8 + 61 * maxSolt).writeU32(capacity); // 容量
		return cargoRef;
	}, 'pointer', ['pointer', 'uint']));
}

function IsAlter(maxSolt) {
	Interceptor.replace(ptr(0x08695A0C), new NativeCallback(function (cargoRef) {
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		// console.log('IsAlter------------------------------------'+cargoRef)
		cargoRef = getCargoRef(accId, cargoRef);;
		return cargoRef.add(12 + 61 * maxSolt).readU8(); // 标志
	}, 'int', ['pointer']));
}

function SendItemList(maxSolt) {
	var tempFunc = new NativeCallback(function (cargoRef) {
		// console.log("SendItemList-------------"+cargoRef)
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		var buffCargoRef = getCargoRef(accId, cargoRef);;
		var buff = Memory.alloc(61 * maxSolt + 9);
		PacketGuard_PacketGuard(buff);
		InterfacePacketBuf_put_header(buff, 0, 13);
		InterfacePacketBuf_put_byte(buff, 12);
		InterfacePacketBuf_put_short(buff, buffCargoRef.add(8 + 61 * maxSolt).readU32());
		InterfacePacketBuf_put_int(buff, buffCargoRef.add(4 + 61 * maxSolt).readU32());
		var itemCount = CAccountCargo_GetItemCount(cargoRef);
		InterfacePacketBuf_put_short(buff, itemCount);
		for (var i = 0; buffCargoRef.add(8 + 61 * maxSolt).readU32() > i; ++i) {
			if (buffCargoRef.add(61 * i + 6).readU32() != 0) {
				InterfacePacketBuf_put_short(buff, i);
				InterfacePacketBuf_put_int(buff, buffCargoRef.add(61 * i + 6).readU32());
				InterfacePacketBuf_put_int(buff, buffCargoRef.add(61 * i + 11).readU32());
				var integratedPvPItemAttr = GetIntegratedPvPItemAttr(buffCargoRef.add(61 * i + 4));
				InterfacePacketBuf_put_byte(buff, integratedPvPItemAttr);
				InterfacePacketBuf_put_short(buff, buffCargoRef.add(61 * i + 15).readU16());
				InterfacePacketBuf_put_byte(buff, buffCargoRef.add(61 * i + 4).readU8());
				if (GameWorld_IsEnchantRevisionChannel(G_GameWorld()) != 0) {
					InterfacePacketBuf_put_int(buff, 0);
				} else {
					InterfacePacketBuf_put_int(buff, buffCargoRef.add(61 * i + 17).readU32());
				}
				var abilityType = stAmplifyOption_t_getAbilityType(buffCargoRef.add(61 * i + 21));
				InterfacePacketBuf_put_byte(buff, abilityType);
				var abilityValue = stAmplifyOption_t_getAbilityValue(buffCargoRef.add(61 * i + 21));
				InterfacePacketBuf_put_short(buff, abilityValue);
				InterfacePacketBuf_put_byte(buff, 0);
				InterfacePacketBuf_put_packet(buff, buffCargoRef.add(61 * i + 4));
			}
		}
		InterfacePacketBuf_finalize(buff, 1);
		var v6 = CUser_Send(ptr(cargoRef.readU32()), buff);
		Destroy_PacketGuard_PacketGuard(buff);
		return v6;
	}, 'int', ['pointer']);
	CAccountCargo_SendItemList_NEW = new NativeFunction(tempFunc, 'int', ['pointer'], { "abi": "sysv" });
	Interceptor.replace(ptr(0x0828a88a), tempFunc);
}

function SendNotifyMoney(maxSolt) {
	Interceptor.replace(ptr(0x0828A7DC), new NativeCallback(function (cargo, a2) {
		// console.log("SendNotifyMoney------------"+ptr(cargo))
		var cargoRef = ptr(cargo);
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return;
		}
		var buffCargoRef = getCargoRef(accId, cargoRef);;
		var buff = Memory.alloc(20);
		PacketGuard_PacketGuard(buff);
		InterfacePacketBuf_put_header(buff, 1, a2);
		InterfacePacketBuf_put_byte(buff, 1);
		InterfacePacketBuf_put_int(buff, buffCargoRef.add(4 + 61 * maxSolt).readU32());
		InterfacePacketBuf_finalize(buff, 1);
		CUser_Send(ptr(cargoRef.readU32()), buff);
		Destroy_PacketGuard_PacketGuard(buff);
	}, 'void', ['int', 'int']));
}

function GetItemCount(maxSolt) {
	Interceptor.replace(ptr(0x0828A794), new NativeCallback(function (cargoRef) {
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		// console.log('GetItemCount------------------------------------'+cargoRef)
		cargoRef = getCargoRef(accId, cargoRef);
		var cap = cargoRef.add(8 + 61 * maxSolt).readU32();
		var index = 0;
		for (var i = 0; i < cap; i++) {
			if (cargoRef.add(61 * i + 6).readU32() != 0) {
				index++;
			}
		}
		// console.log("GetItemCount  val:"+index)
		return index;
	}, 'int', ['pointer']));
}

function SubMoney(maxSolt) {
	Interceptor.replace(ptr(0x0828A764), new NativeCallback(function (cargoRef, money) {
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		// console.log('SubMoney------------------------------------')
		var buffCargoRef = getCargoRef(accId, cargoRef);
		var res;
		if (money != 0) {
			res = cargoRef;
			var add = buffCargoRef.add(4 + 61 * maxSolt).readU32();
			if (add >= money) {
				buffCargoRef.add(4 + 61 * maxSolt).writeU32(add - money);
			}
		}
		return res;
	}, 'pointer', ['pointer', 'uint']));
}

function AddMoney(maxSolt) {
	Interceptor.replace(ptr(0x0828A742), new NativeCallback(function (cargoRef, money) {
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		// console.log('AddMoney------------------------------------')
		var buffCargoRef = getCargoRef(accId, cargoRef);
		var res;
		if (money != 0) {
			res = cargoRef;
			var add = buffCargoRef.add(4 + 61 * maxSolt).readU32();
			buffCargoRef.add(4 + 61 * maxSolt).writeU32(add + money);
		}
		return res;
	}, 'pointer', ['pointer', 'uint']));
}

function GetSpecificItemSlot(maxSolt) {
	Interceptor.replace(ptr(0x0828A61A), new NativeCallback(function (cargoRef, itemId) {
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		// console.log('GetSpecificItemSlot------------------------------------'+cargoRef)
		cargoRef = getCargoRef(accId, cargoRef);
		var cap = cargoRef.add(8 + 61 * maxSolt).readU32();
		if (cap > maxSolt) {
			cap = maxSolt;
		}
		for (var i = 0; i < cap; i++) {
			if (cargoRef.add(61 * i + 6).readU32() == itemId) {
				return i;
			}
		}
		return -1;
	}, 'int', ['pointer', 'int']));
}

function GetEmptySlot(maxSolt) {
	var tempFunc = new NativeCallback(function (cargoRef) {
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		console.log('GetEmptySlot------------------------------------' + cargoRef)
		cargoRef = getCargoRef(accId, cargoRef);
		console.log("GetEmptySlot accId:" + accId + ' ' + cargoRef)
		var cap = cargoRef.add(8 + 61 * maxSolt).readU32();
		if (cap > maxSolt) {
			cap = maxSolt;
		}
		for (var i = 0; i < cap; i++) {
			if (cargoRef.add(61 * i + 6).readU32() == 0) {
				return i;
			}
		}
		return -1;
	}, 'int', ['pointer']);
	CAccountCargo_GetEmptySlot_NEW = new NativeFunction(tempFunc, 'int', ['pointer'], { "abi": "sysv" });
	Interceptor.replace(ptr(0x0828a580), tempFunc);
}

function CheckValidSlot(maxSolt) {
	Interceptor.replace(ptr(0x0828A554), new NativeCallback(function (cargoRef, solt) {
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		// console.log('CheckValidSlot------------------------------------'+cargoRef)
		cargoRef = getCargoRef(accId, cargoRef);
		var cap = cargoRef.add(8 + 61 * maxSolt).readU32();
		return (solt >= 0 && solt <= maxSolt && cap > solt) ? 1 : 0;
	}, 'int', ['pointer', 'int']));
}

function CheckMoneyLimit(maxSolt) {
	Interceptor.replace(ptr(0x0828A4CA), new NativeCallback(function (cargoRef, money) {
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		// console.log('CheckMoneyLimit------------------------------------'+cargoRef)
		cargoRef = getCargoRef(accId, cargoRef);
		var cap = cargoRef.add(8 + 61 * maxSolt).readU32();
		var nowMoney = cargoRef.add(4 + 61 * maxSolt).readU32()
		var manager = G_CDataManager();
		var currUpfradeIfo = AccountCargoScript_GetCurrUpgradeInfo(manager.add(42976), cap);
		return (currUpfradeIfo != 0 && ptr(currUpfradeIfo).add(4).readU32() >= (money + nowMoney)) ? 1 : 0;
	}, 'int', ['pointer', 'uint32']));
}

function WithdrawMoney(maxSolt) {
	Interceptor.replace(ptr(0x0828A2F6), new NativeCallback(function (cargoRef, money) {
		// console.log("WithdrawMoney------------"+cargoRef)
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		var buffCargoRef = getCargoRef(accId, cargoRef);
		var manage = ARAD_Singleton_ServiceRestrictManager_Get();
		var isRestricted = ServiceRestrictManager_isRestricted(manage.toInt32(), cargoRef, 1, 26);
		if (isRestricted != 0) {
			CUser_SendCmdErrorPacket(cargoRef, 309, 0xD1);
			return 0;
		}
		var check = CSecu_ProtectionField_Check(ptr(ptr(0x0941F7CC).readU32()), cargoRef, 3);
		if (check != 0) {
			CUser_SendCmdErrorPacket(cargoRef, 309, check);
			return 0;
		}
		// console.log("WithdrawMoney now money:"+money)
		if (money > CAccountCargo_GetMoney(cargoRef) || (money & 0x80000000) != 0) {
			CUser_SendCmdErrorPacket(cargoRef, 309, 0xA);
			return 0;
		}
		if (CUser_CheckMoney(ptr(cargoRef.readU32()), money) == 0) {
			// console.log('CUser_CheckMoney ---')
			CUser_SendCmdErrorPacket(cargoRef, 308, 0x5e);
			return 0;
		} else {
			CAccountCargo_SubMoney(cargoRef, money);
			var curCharacInvenW = CUserCharacInfo_getCurCharacInvenW(ptr(cargoRef.readU32()));
			if (CInventory_gain_money(curCharacInvenW, money, 27, 1, 0) == 0) {
				CUser_SendCmdErrorPacket(cargoRef, 309, 0xA);
				return 0;
			}
		}
		CAccountCargo_SendNotifyMoney(cargoRef.toInt32(), 309);
		buffCargoRef.add(12 + 61 * maxSolt).writeU8(1);
		cargoRef.add(12 + 61 * 56).writeU8(1);
		// console.log("WithdrawMoney success")
		return 1;
	}, 'int', ['pointer', 'uint32']));
}

function DepositMoney(maxSolt) {
	Interceptor.replace(ptr(0x0828A12A), new NativeCallback(function (cargoRef, money) {
		// console.log("DepositMoney------------"+cargoRef)
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		var buffCargoRef = getCargoRef(accId, cargoRef);
		var manage = ARAD_Singleton_ServiceRestrictManager_Get();
		var isRestricted = ServiceRestrictManager_isRestricted(manage.toInt32(), cargoRef, 1, 26);
		if (isRestricted != 0) {
			CUser_SendCmdErrorPacket(cargoRef, 308, 0xD1);
			return 0;
		}
		var check = CSecu_ProtectionField_Check(ptr(ptr(0x0941F7CC).readU32()), cargoRef, 2);
		if (check != 0) {
			CUser_SendCmdErrorPacket(cargoRef, 308, check);
			return 0;
		}
		// console.log("DepositMoney now money:"+money+','+CUserCharacInfo_getCurCharacMoney(ptr(cargoRef.readU32()))+','+((money & 0x80000000) !=0))
		if (money > CUserCharacInfo_getCurCharacMoney(ptr(cargoRef.readU32())) || (money & 0x80000000) != 0) {
			CUser_SendCmdErrorPacket(cargoRef, 308, 0xA);
			return 0;
		}
		// console.log("DepositMoney 2 now money:"+money)
		if (CAccountCargo_CheckMoneyLimit(cargoRef, money) == 0) {
			// console.log('CAccountCargo_CheckMoneyLimit error')
			CUser_SendCmdErrorPacket(cargoRef, 308, 0x5f);
			return 0;
		} else {
			// console.log("DepositMoney 3 now money:"+money)
			var curCharacInvenW = CUserCharacInfo_getCurCharacInvenW(ptr(cargoRef.readU32()));
			if (CInventory_use_money(curCharacInvenW, money, 40, 1) != 1) {
				CUser_SendCmdErrorPacket(cargoRef, 308, 0xA);
				return 0;
			}
		}
		// console.log("DepositMoney 4 now money:"+money)
		// 有addMoney方法修改 改这里不重要
		CAccountCargo_AddMoney(cargoRef, money);
		CAccountCargo_SendNotifyMoney(cargoRef.toInt32(), 308);
		buffCargoRef.add(12 + 61 * maxSolt).writeU8(1);
		cargoRef.add(12 + 61 * 56).writeU8(1);
		// console.log("DepositMoney success")
		return 1;
	}, 'int', ['pointer', 'uint32']));
}

function MoveItem(maxSolt) {
	Interceptor.replace(ptr(0x08289F26), new NativeCallback(function (cargoRef, slot1, slot2) {
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		console.log('MoveItem------------------------------------' + cargoRef)

		if (CAccountCargo_CheckValidSlot(cargoRef, slot1) == 0 || CAccountCargo_CheckValidSlot(cargoRef, slot2) == 0 || slot1 == slot2) {
			return 0;
		}
		cargoRef.add(12 + 61 * 56).writeU8(1);
		cargoRef = getCargoRef(accId, cargoRef);
		var temp = Memory.alloc(61);
		Memory.copy(temp, cargoRef.add(61 * slot1 + 4), 61 - 4);
		Memory.copy(cargoRef.add(61 * slot1 + 4), cargoRef.add(61 * slot2 + 4), 61 - 4);
		Memory.copy(cargoRef.add(61 * slot2 + 4), temp, 61 - 4);
		cargoRef.add(12 + 61 * maxSolt).writeU8(1);
		return 1;
	}, 'int', ['pointer', 'int', 'int']));
}

function DeleteItem(maxSolt) {
	Interceptor.replace(ptr(0x08289E3C), new NativeCallback(function (cargoRef, slot, number) {
		console.log('DeleteItem---' + cargoRef)
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		var buffCargoRef = getCargoRef(accId, cargoRef);
		if (CAccountCargo_CheckValidSlot(cargoRef, slot) == 0) {
			return 0;
		}
		if (buffCargoRef.add(61 * slot + 6).readU32() == 0 || number <= 0) {
			return 0;
		}
		if (Inven_Item_isEquipableItemType(buffCargoRef.add(61 * slot + 4)) != 0) {
			CAccountCargo_ResetSlot(cargoRef, slot);
			buffCargoRef.add(12 + 61 * maxSolt).writeU8(1);
			cargoRef.add(12 + 61 * 56).writeU8(1);
			return 1;
		}
		if (buffCargoRef.add(61 * slot + 11).readU32() < number) {
			return 0;
		}
		if (buffCargoRef.add(61 * slot + 11).readU32() <= number) {
			CAccountCargo_ResetSlot(cargoRef, slot);
		} else {
			var num = buffCargoRef.add(61 * slot + 11).readU32();
			buffCargoRef.add(61 * slot + 11).writeU32(num - number);
		}
		buffCargoRef.add(12 + 61 * maxSolt).writeU8(1);
		cargoRef.add(12 + 61 * 56).writeU8(1);
		return 1;
	}, 'int', ['pointer', 'int', 'int']));
}

function InsertItem(maxSolt) {

	var tempFunc = new NativeCallback(function (cargoRef, item, slot) {
		console.log('InsertItem-------------------' + cargoRef + ' ' + slot)
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		var buffCargoRef = getCargoRef(accId, cargoRef);
		if (CAccountCargo_CheckValidSlot(cargoRef, slot) == 0) {
			// console.log("slot error")
			return -1;
		}
		// console.log("slot success!!!")
		var res = -1;
		if (Inven_Item_isEquipableItemType(item) != 0) {
			console.log("Inven_Item_isEquipableItemType  success：" + cargoRef.add(61 * slot + 6).readU32())
			if (buffCargoRef.add(61 * slot + 6).readU32() == 0) {
				var v4 = 61 * slot;
				buffCargoRef.add(v4 + 4).writeU32(item.readU32());
				buffCargoRef.add(v4 + 8).writeU32(item.add(1 * 4).readU32());
				buffCargoRef.add(v4 + 12).writeU32(item.add(2 * 4).readU32());
				buffCargoRef.add(v4 + 16).writeU32(item.add(3 * 4).readU32());
				buffCargoRef.add(v4 + 20).writeU32(item.add(4 * 4).readU32());
				buffCargoRef.add(v4 + 24).writeU32(item.add(5 * 4).readU32());
				buffCargoRef.add(v4 + 28).writeU32(item.add(6 * 4).readU32());
				buffCargoRef.add(v4 + 32).writeU32(item.add(7 * 4).readU32());
				buffCargoRef.add(v4 + 36).writeU32(item.add(8 * 4).readU32());
				buffCargoRef.add(v4 + 40).writeU32(item.add(9 * 4).readU32());
				buffCargoRef.add(v4 + 44).writeU32(item.add(10 * 4).readU32());
				buffCargoRef.add(v4 + 48).writeU32(item.add(11 * 4).readU32());
				buffCargoRef.add(v4 + 52).writeU32(item.add(12 * 4).readU32());
				buffCargoRef.add(v4 + 56).writeU32(item.add(13 * 4).readU32());
				buffCargoRef.add(v4 + 60).writeU32(item.add(14 * 4).readU32());
				buffCargoRef.add(v4 + 64).writeU8(item.add(60).readU8());
				res = slot;
			}
		} else {
			console.log("Inven_Item_isEquipableItemType  fail：" + cargoRef.add(61 * slot + 6).readU32())
			if (item.add(2).readU32() == buffCargoRef.add(61 * slot + 6).readU32()) {
				var size = buffCargoRef.add(61 * slot + 11).readU32();
				buffCargoRef.add(61 * slot + 11).writeU32(size + item.add(7).readU32());
			} else {
				var v4 = 61 * slot;
				buffCargoRef.add(v4 + 4).writeU32(item.readU32());
				buffCargoRef.add(v4 + 8).writeU32(item.add(1 * 4).readU32());
				buffCargoRef.add(v4 + 12).writeU32(item.add(2 * 4).readU32());
				buffCargoRef.add(v4 + 16).writeU32(item.add(3 * 4).readU32());
				buffCargoRef.add(v4 + 20).writeU32(item.add(4 * 4).readU32());
				buffCargoRef.add(v4 + 24).writeU32(item.add(5 * 4).readU32());
				buffCargoRef.add(v4 + 28).writeU32(item.add(6 * 4).readU32());
				buffCargoRef.add(v4 + 32).writeU32(item.add(7 * 4).readU32());
				buffCargoRef.add(v4 + 36).writeU32(item.add(8 * 4).readU32());
				buffCargoRef.add(v4 + 40).writeU32(item.add(9 * 4).readU32());
				buffCargoRef.add(v4 + 44).writeU32(item.add(10 * 4).readU32());
				buffCargoRef.add(v4 + 48).writeU32(item.add(11 * 4).readU32());
				buffCargoRef.add(v4 + 52).writeU32(item.add(12 * 4).readU32());
				buffCargoRef.add(v4 + 56).writeU32(item.add(13 * 4).readU32());
				buffCargoRef.add(v4 + 60).writeU32(item.add(14 * 4).readU32());
				buffCargoRef.add(v4 + 64).writeU8(item.add(60).readU8());
			}
			res = slot;
		}
		buffCargoRef.add(12 + 61 * maxSolt).writeU8(1);
		cargoRef.add(12 + 61 * 56).writeU8(1);
		// console.log("InsertItem:"+res);
		return res;
	}, 'int', ['pointer', 'pointer', 'int']);
	CAccountCargo_InsertItem_NEW = new NativeFunction(tempFunc, 'int', ['pointer', 'pointer', 'int'], { "abi": "sysv" });
	Interceptor.replace(ptr(0x08289C82), tempFunc);
}
function Clear(maxSolt) {
	Interceptor.replace(ptr(0x0828986C), new NativeCallback(function (cargoRef) {
		// // console.log('Clear:'+cargoRef)
		// 离线是清零
		cargoRef.writeU32(0);
		var cargoRefAdd = cargoRef.add(4);
		for (var i = 0; i < maxSolt; i++) {
			Inven_Item_Inven_Item(cargoRefAdd);
			cargoRefAdd.writeU32(0);
			cargoRefAdd = cargoRefAdd.add(61);
		}
		cargoRef.add(4 + 61 * maxSolt).writeU32(0); // 钱
		cargoRef.add(8 + 61 * maxSolt).writeU32(0); // 容量
		cargoRef.add(12 + 61 * maxSolt).writeU8(0); // 标志
		return cargoRef;
	}, 'pointer', ['pointer']));
}

function SetDBData(maxSolt) {
	Interceptor.replace(ptr(0x08289816), new NativeCallback(function (cargoRef, user, item, money, copacity) {
		console.log('SetDBData-------------------' + cargoRef + ' ' + user + ' ,' + item + ',' + money + '  ' + copacity)
		var accId = CUser_get_acc_id(user);
		// 再设置是 将 重新申请账号金库空间  61*maxSolt是格子 4个字节的钱  4个字节的容量 1个字节的标志
		accountCargfo[accId] = Memory.alloc(61 * maxSolt + 4 + 4 + 1 + 30);
		var buffCargoRef = cargoRef;
		if (accountCargfo[accId]) {
			// 给原来的设置一些默认值，防止获取不到金库
			cargoRef.writePointer(user);
			cargoRef.add(4 + 61 * 56).writeU32(money);
			cargoRef.add(8 + 61 * 56).writeU32(copacity);
			cargoRef.add(12 + 61 * 56).writeU8(0);
			buffCargoRef = accountCargfo[accId];
			// 初始化数据
			for (var i = 0; i < maxSolt; i++) {
				buffCargoRef.add(4 + i * 61).writeU32(0);
			}
		}
		buffCargoRef.writePointer(user);
		buffCargoRef.add(4 + 61 * maxSolt).writeU32(money);
		buffCargoRef.add(8 + 61 * maxSolt).writeU32(copacity);
		buffCargoRef.add(12 + 61 * maxSolt).writeU8(0);
		if (item != 0) {
			Memory.copy(cargoRef.add(4), item, 56 * 61);
			Memory.copy(buffCargoRef.add(4), item, maxSolt * 61);
		}
		return cargoRef;
	}, 'pointer', ['pointer', 'pointer', 'pointer', 'uint32', 'uint32']));
}

function CAccountCargo(maxSolt) {
	Interceptor.replace(ptr(0x08289794), new NativeCallback(function (cargoRef) {
		cargoRef.writeU32(0);
		var cargoRefAdd = cargoRef.add(4);
		for (var i = 0; i < 56; i++) {
			Inven_Item_Inven_Item(cargoRefAdd);
			cargoRefAdd.writeU32(0);
			cargoRefAdd = cargoRefAdd.add(61);
		}
		cargoRef.add(4 + 61 * 56).writeU32(0); // 钱
		cargoRef.add(8 + 61 * 56).writeU32(0); // 容量
		cargoRef.add(12 + 61 * 56).writeU8(0); // 标志
	}, 'void', ['pointer']));
}

function GetMoney(maxSolt) {
	Interceptor.replace(ptr(0x0822F020), new NativeCallback(function (cargoRef) {
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		// console.log('GetMoney------------------------------------'+cargoRef)
		cargoRef = getCargoRef(accId, cargoRef);
		// console.log("GetMoney accId:"+accId)
		return cargoRef.add(4 + 61 * maxSolt).readU32();
	}, 'int', ['pointer']));
}

function GetCapacity(maxSolt) {
	Interceptor.replace(ptr(0x0822F012), new NativeCallback(function (cargoRef) {
		var accId = getUserAccId(cargoRef);
		if (accId == -1) {
			return 0;
		}
		// console.log('GetCapacity------------------------------------'+cargoRef)
		cargoRef = getCargoRef(accId, cargoRef);
		return cargoRef.add(8 + 61 * maxSolt).readU32();
	}, 'int', ['pointer']));
}


function getCargoRef(accId, cargoRef) {
	if (accountCargfo[accId]) {
		cargoRef = accountCargfo[accId];
	} else {
		// 解决 判断文件中是否有缓存的配置 如果有就加载
		if (initCharacAccountCargoDbData(accId, cargoRef)) {
			cargoRef = accountCargfo[accId];
		}
	}
	return cargoRef;
}

function initCharacAccountCargoDbData(accId, cargoRef) {
	console.log("initCharacAccountCargoDbData:" + accId)
	var dbHandelAddr = DBMgr_GetDBHandle(ptr(ptr(0x0940BDAC).readU32()), 2, 0);
	var dbHandel = ptr(dbHandelAddr);
	var mId = Memory.allocUtf8String(accId + '');
	MySQL_set_query_3_ptr(dbHandel, Memory.allocUtf8String('seLect capacity, money, cargo from account_cargo where m_id = %s'), mId);
	if (MySQL_exec(dbHandel, 1) != 1) {
		console.log("pre one 111")
		return false;
	}
	if (MySQL_get_n_rows(dbHandel) == 0) {
		console.log("pre one 222")
		return false;
	}
	if (MySQL_fetch(dbHandel) != 1) {
		console.log("pre one 333")
		return false;
	}
	var maxSolt = initMaxSolt;
	accountCargfo[accId] = Memory.alloc(61 * maxSolt + 4 + 4 + 1 + 30);
	var buffCargoRef = accountCargfo[accId];
	// 初始化数据
	for (var i = 0; i < maxSolt; i++) {
		buffCargoRef.add(4 + i * 61).writeU32(0);
	}
	buffCargoRef.writePointer(ptr(cargoRef).readPointer());
	buffCargoRef.add(12 + 61 * maxSolt).writeU8(0);
	var res = false;
	if (MySQL_get_uint(dbHandel, 0, buffCargoRef.add(8 + 61 * maxSolt)) != 1) {
		// console.log('uint capacity get error')
		console.log("pre one 444")
		res = false;
	} else if (MySQL_get_uint(dbHandel, 1, buffCargoRef.add(4 + 61 * maxSolt)) != 1) {
		console.log('uint money get error')
		res = false;
	} else {
		var v10 = Memory.alloc(61 * maxSolt * 4);
		for (var i = 0; i < 61 * maxSolt; i++) {
			v10.add(i * 4).writeU32(0);
		}
		var binaryLength = MySQL_get_binary_length(dbHandel, 2);
		if (MySQL_get_binary(dbHandel, 2, v10, binaryLength) != 1) {
			res = true;
		} else {
			binaryLength = MySQL_get_binary_length(dbHandel, 2);
			var maxLength = 61 * maxSolt;
			var v17Addr = Memory.alloc(4);
			v17Addr.writeInt(maxLength)
			if (uncompress_zip(buffCargoRef.add(4), v17Addr, v10, binaryLength) != 1) {
				// console.log("uncompress_zip error  !!!")
				res = false;
			} else if (v17Addr.readU32() != 0 && v17Addr.readU32() % (61 * maxSolt) != 0) {
				res = false;
			} else {
				res = true;
			}
		}
	}
	if (!res) {
		delete accountCargfo[accId]
	}
	return res;
}

function getUserAccId(cargoRef) {
	if (cargoRef == 0) {
		return -1;
	}
	var userAddr = ptr(cargoRef.readU32());
	if (userAddr == 0) {
		return -1;
	}
	return CUser_get_acc_id(userAddr);
}

function setMaxUpGrade(maxLevel) {
	if (maxLevel) {
		console.log("1")
		calcurateUserMaxLevel(maxLevel);
		setUserMaxLevel(maxLevel);
		isThereDailyTrainingQuestList(maxLevel);
		calLevelUpItemCheck(maxLevel);
		getLevelSectionExp();
		getSpAtLevelUp(maxLevel);
		setLevelExp(maxLevel);
		setRewardSp(maxLevel);
		checkLevelUp(maxLevel);
		gainExpSp(maxLevel);
		onLevelUp(maxLevel);
		increaseStatus(maxLevel);
		getReturnUserLevelKey(maxLevel)
		console.log("13");

	}
}


function getReturnUserLevelKey(maxLevel) {
	Interceptor.replace(ptr(0x0869230a), new NativeCallback(function (stNotifyIngameADInfo, a2, a3) {
		console.log('getReturnUserLevelKey ' + stNotifyIngameADInfo + ' ' + a2 + ' ' + a3);
		if (a3 != 0) {
			if (a2 <= 19) {
				return 15;
			}
		} else {
			if (a2 <= 9) {
				return 5;
			}
			if (a2 <= 14) {
				return 10;
			}
			if (a2 <= 19) {
				return 15;
			}
		}
		if (a2 <= 29) {
			return 20;
		}
		if (a2 <= 39) {
			return 30;
		}
		if (a2 <= 49) {
			return 40;
		}
		if (a2 <= 59) {
			return 50;
		}
		if (a2 <= 69) {
			return 60;
		}
		if (a2 <= 79) {
			return 70;
		}
		if (a2 <= 86) {
			return 80;
		}
		return 60;
	}, 'int', ['pointer', 'int', 'int']));
}

//在线奖励
function enable_online_reward() {
	//在线每5min发一次奖, 在线时间越长, 奖励越高
	//CUser::WorkPerFiveMin
	Interceptor.attach(ptr(0x8652F0C),
		{
			onEnter: function (args) {
				var user = args[0];
				//当前系统时间
				var cur_time = api_CSystemTime_getCurSec();
				//本次登录时间
				var login_tick = CUserCharacInfo_GetLoginTick(user);
				if (login_tick > 0) {
					//在线时长(分钟)
					var diff_time = Math.floor((cur_time - login_tick) / 60);
					//在线10min后开始计算
					if (diff_time < 5)
						return;
					//在线奖励最多发送1天
					if (diff_time > 1 * 24 * 60)
						return;
					//奖励: 每分钟1点券
					var REWARD_CASH_CERA_PER_MIN = 1;
					//计算奖励
					var reward_cash_cera = 200;
					//发点券item_cnt
					api_recharge_cash_cera(user, reward_cash_cera);
					//发消息通知客户端奖励已发送
					api_CUser_SendNotiPacketMessage(user, '[' + get_timestamp() + '] 在线奖励已发送(当前阶段点券奖励:' + reward_cash_cera + ')', 6);
				}
			},
			onLeave: function (retval) {
			}
		});
}

//给角色发经验
function api_CUser_gain_exp_sp(user, exp) {
	var a2 = Memory.alloc(4);
	var a3 = Memory.alloc(4);
	CUser_gain_exp_sp(user, exp, a2, a3, 0, 0, 0);
}
//给角色发道具
function api_CUser_AddItem(user, item_id, item_cnt) {
	var item_space = Memory.alloc(4);
	var slot = CUser_AddItem(user, item_id, item_cnt, 6, item_space, 0);

	if (slot >= 0) {
		//通知客户端有游戏道具更新
		CUser_SendUpdateItemList(user, 1, item_space.readInt(), slot);
	}

	return;
}
//获取在线玩家列表表头
function api_gameworld_user_map_begin() {
	var begin = Memory.alloc(4);
	gameworld_user_map_begin(begin, G_GameWorld().add(308));
	return begin;
}

//获取在线玩家列表表尾
function api_gameworld_user_map_end() {
	var end = Memory.alloc(4);
	gameworld_user_map_end(end, G_GameWorld().add(308));
	return end;
}

//获取当前正在遍历的玩家
function api_gameworld_user_map_get(it) {
	return gameworld_user_map_get(it).add(4).readPointer();
}

//遍历在线玩家列表
function api_gameworld_user_map_next(it) {
	var next = Memory.alloc(4);
	gameworld_user_map_next(next, it);
	return next;
}

//对全服在线玩家执行回调函数
function api_gameworld_foreach(f, args) {
	//遍历在线玩家列表
	var it = api_gameworld_user_map_begin();
	var end = api_gameworld_user_map_end();

	//判断在线玩家列表遍历是否已结束
	while (gameworld_user_map_not_equal(it, end)) {
		//当前被遍历到的玩家
		var user = api_gameworld_user_map_get(it);

		//只处理已登录角色
		if (CUser_get_state(user) >= 3) {
			//执行回调函数
			f(user, args);
		}
		//继续遍历下一个玩家
		api_gameworld_user_map_next(it);
	}
}

//设置角色当前绝望之塔层数
function api_TOD_UserState_setEnterLayer(user, layer) {
	var tod_layer = Memory.alloc(100);
	TOD_Layer_TOD_Layer(tod_layer, layer);
	var expand_data = CUser_GetCharacExpandData(user, 13);
	TOD_UserState_setEnterLayer(expand_data, tod_layer);
}

//根据角色id查询角色名
function api_get_charac_name_by_charac_no(charac_no) {
	//从数据库中查询角色名
	if (api_MySQL_exec(mysql_taiwan_cain, "select charac_name from charac_info where charac_no=" + charac_no + ";")) {
		if (MySQL_get_n_rows(mysql_taiwan_cain) == 1) {
			if (MySQL_fetch(mysql_taiwan_cain)) {
				var charac_name = api_MySQL_get_str(mysql_taiwan_cain, 0);
				return charac_name;
			}
		}
	}
	return charac_no.toString();
}



//服务器组包
function api_PacketGuard_PacketGuard() {
	var packet_guard = Memory.alloc(0x20000);
	PacketGuard_PacketGuard(packet_guard);
	return packet_guard;
}

//从客户端封包中读取数据(失败会抛异常, 调用方必须做异常处理)
function api_PacketBuf_get_byte(packet_buf) {
	var data = Memory.alloc(1);
	if (PacketBuf_get_byte(packet_buf, data)) {
		return data.readU8();
	}
	throw new Error('PacketBuf_get_byte Fail!');
}

function api_PacketBuf_get_short(packet_buf) {
	var data = Memory.alloc(2);

	if (PacketBuf_get_short(packet_buf, data)) {
		return data.readShort();
	}
	throw new Error('PacketBuf_get_short Fail!');
}

function api_PacketBuf_get_int(packet_buf) {
	var data = Memory.alloc(4);

	if (PacketBuf_get_int(packet_buf, data)) {
		return data.readInt();
	}
	throw new Error('PacketBuf_get_int Fail!');
}

function api_PacketBuf_get_binary(packet_buf, len) {
	var data = Memory.alloc(len);

	if (PacketBuf_get_binary(packet_buf, data, len)) {
		return data.readByteArray(len);
	}
	throw new Error('PacketBuf_get_binary Fail!');
}




//hookCUser::DisConnSig
function CUser_is_ConnSig() {

	Interceptor.attach(ptr(0x86489F4),
		{

			onEnter: function (args) {
				console.log("CUserisConnSig--------------------------state:" + args[0], args[1], args[2], args[3]);
				var cu = args[0]
			},
			onLeave: function (retval) {
			}
		});
}

//调用Encrypt解密函数
var decrypt = new NativeFunction(ptr(0x848DB5E), 'pointer', ['pointer', 'pointer', 'pointer'], { "abi": "sysv" });

//拦截Encryption::Encrypt
function hook_encrypt() {
	Interceptor.attach(ptr(0x848DA70),
		{

			onEnter: function (args) {
				console.log("Encrypt:" + args[0], args[1], args[2]);
			},
			onLeave: function (retval) {
			}
		});
}

//拦截Encryption::decrypt
function hookdecrypt() {
	Interceptor.attach(ptr(0x848DB5E),
		{

			onEnter: function (args) {
				console.log("decrypt:" + args[0], args[1], args[2]);
			},
			onLeave: function (retval) {
			}
		});
}

//拦截encrypt_packet
function hookencrypt_packet() {
	Interceptor.attach(ptr(0x858D86A),
		{

			onEnter: function (args) {
				console.log("encrypt_packet:" + args[0]);
			},
			onLeave: function (retval) {
			}
		});
}

//拦截DisPatcher_Login
function DisPatcher_Login() {

	Interceptor.attach(ptr(0x81E8C78),
		{
			onEnter: function (args) {
				console.log('DisPatcher_Login:' + args[0], args[1], args[2], args[3], args[4]);
			},
			onLeave: function (retval) {
			}
		});
}

//拦截DisPatcher_ResPeer::dispatch_sig
function DisPatcher_ResPeer_dispatch_sig() {

	Interceptor.attach(ptr(0x81F088E),
		{
			onEnter: function (args) {
				console.log('DisPatcher_ResPeer_dispatch_sig:' + args[0], args[1], args[2], args[3]);
			},
			onLeave: function (retval) {
			}
		});
}

//拦截PacketDispatcher::doDispatch
function PacketDispatcher_doDispatch() {

	Interceptor.attach(ptr(0x8594922),
		{

			onEnter: function (args) {
				console.log('PacketDispatcher_doDispatch:' + args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
				var a1 = args[0].readInt();
				console.log(a1);
				var a2 = args[1].readInt();
				console.log(a2);
				var a5 = args[4].readUtf16String(-1);
				console.log(a5);
			},
			onLeave: function (retval) {
			}
		});
}

//拦截PacketDispatcher::PacketDispatcher
function PacketDispatcher_PacketDispatcher() {
	Interceptor.attach(ptr(0x8590A2E),
		{
			onEnter: function (args) {
				console.log('PacketDispatcher_PacketDispatcher:' + args[0]);
				var a1 = args[0].readInt();
			},
			onLeave: function (retval) {
			}
		});
}

//拦截CUser::SendCmdOkPacket
function CUser_SendCmdOkPacket() {
	Interceptor.attach(ptr(0x867BEA0),
		{
			onEnter: function (args) {
				console.log('CUser_SendCmdOkPacket:' + args[0] + args[1]);
				var a2 = args[0].readInt();
				console.log("CUser_SendCmdOkPacket:" + a2);
			},
			onLeave: function (retval) {
			}
		});
}


//获取原始封包数据
function api_PacketBuf_get_buf(packet_buf) {
	return packet_buf.add(20).readPointer().add(13);
}

//给角色发消息
function api_CUser_SendNotiPacketMessage(user, msg, msg_type) {
	var p = Memory.allocUtf8String(msg);
	CUser_SendNotiPacketMessage(user, p, msg_type);
	return;
}

//发送字符串给客户端
function api_InterfacePacketBuf_put_string(packet_guard, s) {
	var p = Memory.allocUtf8String(s);
	var len = strlen(p);
	InterfacePacketBuf_put_int(packet_guard, len);
	InterfacePacketBuf_put_binary(packet_guard, p, len);
	return;
}

//世界广播(频道内公告)
function api_GameWorld_SendNotiPacketMessage(msg, msg_type) {
	var packet_guard = api_PacketGuard_PacketGuard();
	InterfacePacketBuf_put_header(packet_guard, 0, 12);
	InterfacePacketBuf_put_byte(packet_guard, msg_type);
	InterfacePacketBuf_put_short(packet_guard, 0);
	InterfacePacketBuf_put_byte(packet_guard, 0);
	api_InterfacePacketBuf_put_string(packet_guard, msg);
	InterfacePacketBuf_finalize(packet_guard, 1);
	GameWorld_send_all_with_state(G_GameWorld(), packet_guard, 3); //只给state >= 3 的玩家发公告
	Destroy_PacketGuard_PacketGuard(packet_guard);
}

//打开数据库
function api_MYSQL_open(db_name, db_ip, db_port, db_account, db_password) {
	//mysql初始化
	var mysql = Memory.alloc(0x80000);
	MySQL_MySQL(mysql);
	MySQL_init(mysql);
	//连接数据库
	var db_ip_ptr = Memory.allocUtf8String(db_ip);
	var db_port = db_port;
	var db_name_ptr = Memory.allocUtf8String(db_name);
	var db_account_ptr = Memory.allocUtf8String(db_account);
	var db_password_ptr = Memory.allocUtf8String(db_password);
	var ret = MySQL_open(mysql, db_ip_ptr, db_port, db_name_ptr, db_account_ptr, db_password_ptr);
	if (ret) {
		//log('Connect MYSQL DB <' + db_name + '> SUCCESS!');
		return mysql;
	}
	return null;
}


//mysql查询(返回mysql句柄)(注意线程安全)
function api_MySQL_exec(mysql, sql) {
	var sql_ptr = Memory.allocUtf8String(sql);

	MySQL_set_query_2(mysql, sql_ptr);

	return MySQL_exec(mysql, 1);
}

//查询sql结果
//使用前务必保证api_MySQL_exec返回0
//并且MySQL_get_n_rows与预期一致
function api_MySQL_get_int(mysql, field_index) {
	var v = Memory.alloc(4);
	if (1 == MySQL_get_int(mysql, field_index, v))
		return v.readInt();
	//log('api_MySQL_get_int Fail!!!');
	return null;
}

function api_MySQL_get_uint(mysql, field_index) {
	var v = Memory.alloc(4);
	if (1 == MySQL_get_uint(mysql, field_index, v))
		return v.readUInt();
	//log('api_MySQL_get_uint Fail!!!');
	return null;
}

function api_MySQL_get_short(mysql, field_index) {
	var v = Memory.alloc(4);
	if (1 == MySQL_get_short(mysql, field_index, v))
		return v.readShort();
	//log('MySQL_get_short Fail!!!');
	return null;
}

function api_MySQL_get_float(mysql, field_index) {
	var v = Memory.alloc(4);
	if (1 == MySQL_get_float(mysql, field_index, v))
		return v.readFloat();
	//log('MySQL_get_float Fail!!!');
	return null;
}

function api_MySQL_get_str(mysql, field_index) {
	var binary_length = MySQL_get_binary_length(mysql, field_index);
	if (binary_length > 0) {
		var v = Memory.alloc(binary_length);
		if (1 == MySQL_get_binary(mysql, field_index, v, binary_length))
			return v.readUtf8String(binary_length);
	}
	//log('MySQL_get_str Fail!!!');
	return null;
}

function api_MySQL_get_binary(mysql, field_index) {
	var binary_length = MySQL_get_binary_length(mysql, field_index);
	if (binary_length > 0) {
		var v = Memory.alloc(binary_length);
		if (1 == MySQL_get_binary(mysql, field_index, v, binary_length))
			return v.readByteArray(binary_length);
	}
	//log('api_MySQL_get_binary Fail!!!');
	return null;
}

//初始化数据库(打开数据库/建库建表/数据库字段扩展)
function init_db() {
	//配置文件
	var config = global_config['db_config'];
	//打开数据库连接
	if (mysql_taiwan_cain == null) {
		mysql_taiwan_cain = api_MYSQL_open('taiwan_cain', '127.0.0.1', 3306, config['account'], config['password']);
	}
	api_MySQL_exec(mysql_taiwan_cain, 'create database if not exists myequ_jewel default charset utf8;');
	if (mysql_taiwan_cain_2nd == null) {
		mysql_taiwan_cain_2nd = api_MYSQL_open('taiwan_cain_2nd', '127.0.0.1', 3306, config['account'], config['password']);
	}
	if (mysql_taiwan_billing == null) {
		mysql_taiwan_billing = api_MYSQL_open('taiwan_billing', '127.0.0.1', 3306, config['account'], config['password']);
	}

	if (mysql_d_taiwan == null) {
		mysql_d_taiwan = api_MYSQL_open('d_taiwan', '127.0.0.1', 3306, config['account'], config['password']);
	}

	api_MySQL_exec(mysql_taiwan_cain, 'create database if not exists frida default charset utf8;');
	if (mysql_frida == null) {
		mysql_frida = api_MYSQL_open('frida', '127.0.0.1', 3306, config['account'], config['password']);
	}

	if (mysql_taiwan_login == null) {
		mysql_taiwan_login = api_MYSQL_open('taiwan_login', '127.0.0.1', 3306, config['account'], config['password']);
	}

	// 镶嵌建表
	api_MySQL_exec(mysql_frida, 'CREATE TABLE data (\        equ_id int(11) AUTO_INCREMENT, jewel_data blob NOT NULL,index_flag int(11),date datetime,\        PRIMARY KEY  (equ_id)\    ) ENGINE=InnoDB DEFAULT CHARSET=utf8,AUTO_INCREMENT = 150;');//创建数据库，排序从150开始，也可以从大一点的数值开始

	//建表 init_sp_tp
	api_MySQL_exec(mysql_frida, 'CREATE TABLE `frida`.`init_sp_tp`  (\`id` int NOT NULL AUTO_INCREMENT,\`charac_no` varchar(255) NULL,\`sp_item` text NULL,\`tp_item` text NULL,\PRIMARY KEY (`id`)\) ENGINE=InnoDB DEFAULT CHARSET=utf8;');
	//建表frida.game_event
	api_MySQL_exec(mysql_frida, 'CREATE TABLE game_event (\event_id varchar(30) NOT NULL, event_info mediumtext NULL,\PRIMARY KEY  (event_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8;');

	//创建personal_production数据库
	api_MySQL_exec(mysql_taiwan_cain, 'create database if not exists personal_production default charset utf8;');
	//初始化personal_production数据库
	if (mysql_personal_production == null) {
		mysql_personal_production = api_MYSQL_open('personal_production', '127.0.0.1', 3306, config['account'], config['password']);
	}

	api_MySQL_exec(mysql_personal_production, 'CREATE TABLE joyclub_vip (\charac_no int(11) NOT NULL, quest int(255) NULL, vip varchar(255) NULL, \PRIMARY KEY (charac_no)\) ENGINE=InnoDB DEFAULT CHARSET=utf8;');

	//创建personal_production数据库
	api_MySQL_exec(mysql_taiwan_cain, 'create database if not exists personal_production default charset utf8;');
	//初始化personal_production数据库
	if (mysql_personal_production == null) {
		mysql_personal_production = api_MYSQL_open('personal_production', '127.0.0.1', 3306, config['account'], config['password']);
	}
	//创建外挂数据库
	api_MySQL_exec(mysql_taiwan_cain, 'create database if not exists Prohibition_of_Cheating default charset utf8;');
	//初始化外挂数据库
	if (mysql_Prohibition_of_Cheating == null) {
		mysql_Prohibition_of_Cheating = api_MYSQL_open('Prohibition_of_Cheating', '127.0.0.1', 3306, config['account'], config['password']);
	}
	//建表
	api_MySQL_exec(mysql_Prohibition_of_Cheating, 'CREATE TABLE reward_event (event_id int NOT NULL AUTO_INCREMENT, event_info text NULL, PRIMARY KEY (event_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8;');

	//载入活动数据
	event_villageattack_load_from_db();






	//建表frida.chouj_limit_acc
	api_MySQL_exec(mysql_frida, 'CREATE TABLE IF NOT EXISTS chouj_limit_acc (\
        uid int(10), limit_type int(10), luck_points int(10)\
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;');

	//建表frida.account_reward
	api_MySQL_exec(mysql_frida, 'CREATE TABLE IF NOT EXISTS account_reward (\
		user_no int(11),\
		msg varchar(255)\
	) ENGINE = InnoDB DEFAULT CHARSET=utf8;');
	event_rankinfo_load_from_db();

	/**
		CREATE TABLE IF NOT EXISTS obtain_equips (
		id int(11) NOT NULL AUTO_INCREMENT,\
		equ_id int(11) NOT NULL,\
		PRIMARY KEY (`id`)\
		) ENGINE=InnoDB DEFAULT CHARSET=utf8;
	 */
	//建表frida.first_obtain   首爆
	api_MySQL_exec(mysql_frida, 'CREATE TABLE IF NOT EXISTS first_obtain  (\
		equ_id int(11) NULL DEFAULT NULL,\
		char_no int(11) NULL DEFAULT NULL,\
		cur_date varchar(15) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,\
		char_name varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL\
	) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Compact;');

	//建表frida.obtain_equips   装备 
	api_MySQL_exec(mysql_frida, 'CREATE TABLE IF NOT EXISTS obtain_equips (\
		id int(11) NOT NULL AUTO_INCREMENT,\
		equ_id int(11) NOT NULL,\
		PRIMARY KEY (`id`)\
	) ENGINE=InnoDB DEFAULT CHARSET=utf8;');

	//建表frida.epic_rask 史诗大比拼
	api_MySQL_exec(mysql_frida, 'CREATE TABLE IF NOT EXISTS epic_rask (\
		`char_no` int(10),\
		`char_name` varchar(255),\
		`epic_num` int(10)\
	) ENGINE = InnoDB DEFAULT CHARSET=utf8;');
	//进入指定副本参与抽奖-表格
	api_MySQL_exec(mysql_frida, 'CREATE TABLE `frida`.`dungeon_lucks`  (\
		`id` int NOT NULL AUTO_INCREMENT,\
		`charac_no` int NOT NULL,\
		`luck_date` varchar(255) NOT NULL,\
		PRIMARY KEY (`id`)\
	) ENGINE=InnoDB DEFAULT CHARSET=utf8;');

	/*首爆表格*/
	var mysql_t = "select equ_id from obtain_equips;";
	if (api_MySQL_exec(mysql_frida, mysql_t)) {
		var n = MySQL_get_n_rows(mysql_frida);
		if (n == 0) {
			var equs = [190108101, 190108301, 190108401, 190108501, 20191127, 160929141, 160927006, 160929116, 160929136, 160929166, 20191117, 160929101, 160929106, 160929126, 20191122, 160929156, 160927026, 160927031, 160929151, 190118601, 190118701, 210483, 160929146, 160929121, 160929131, 160929161, 20191132, 190108102, 190108302, 190108402, 190108502, 20191128, 160929142, 160927007, 160929117, 160929137, 160929167, 20191118, 160929102, 160929107, 160929127, 160929157, 20191123, 160927027, 160927032, 160929152, 190118602, 190118702, 210482, 160929147, 160929122, 160929132, 160929162, 20191133, 190108103, 190108303, 190108403, 190108503, 20191129, 160929143, 160927008, 160929118, 160929138, 160929168, 20191119, 160929103, 160929108, 160929128, 160929158, 20191124, 160927028, 160927033, 160929153, 190118603, 190118703, 160929148, 210486, 160929123, 160929133, 160929163, 20191134, 190108104, 190108304, 190108404, 190108504, 20191130, 160929144, 160927009, 160929119, 160929139, 160929169, 20191120, 160929104, 160929109, 160929129, 160929159, 20191125, 160927029, 160927034, 160929154, 190118604, 190118704, 160929149, 210484, 160929124, 160929134, 160929164, 20191135, 190108105, 190108305, 190108405, 190108505, 20191131, 160929145, 160927010, 160929120, 160929140, 160929170, 20191121, 160929105, 160929110, 160929130, 20191126, 160929160, 160927030, 160927035, 160929155, 190118605, 190118705, 210485, 160929150, 160929125, 160929135, 160929165, 20191136];
			for (var i = 0; i < equs.length; i++) {
				var e = equs[i];
				var sql_t = "insert into obtain_equips(equ_id) values (" + e + ");";
				api_MySQL_exec(mysql_frida, sql_t);

			}
		}
	}
	//建表 frida.RestrictNpcShopBuy
	api_MySQL_exec(mysql_frida, "CREATE TABLE `frida`.`restrict_npc_shop_buy`  (\
		`id` int NOT NULL AUTO_INCREMENT,\
		`charac_no` int NULL,\
		`item_id` int NULL,\
		`buy_count` int NULL,\
		`item_shop` int NULL,\
		`refresh_time` varchar(255) NULL,\
		PRIMARY KEY (`id`)\
	  ) ENGINE=InnoDB DEFAULT CHARSET=utf8;");



}

//关闭数据库（卸载插件前调用）
function uninit_db() {
	//活动数据存档
	event_villageattack_save_to_db();
	//关闭数据库连接
	if (mysql_taiwan_cain) {
		MySQL_close(mysql_taiwan_cain);
		mysql_taiwan_cain = null;
	}
	if (mysql_taiwan_cain_2nd) {
		MySQL_close(mysql_taiwan_cain_2nd);
		mysql_taiwan_cain_2nd = null;
	}
	if (mysql_taiwan_billing) {
		MySQL_close(mysql_taiwan_billing);
		mysql_taiwan_billing = null;
	}
	if (mysql_frida) {
		MySQL_close(mysql_frida);
		mysql_frida = null;
	}

	if (mysql_frida) {
		MySQL_close(mysql_frida);
		mysql_frida = null;
	}

	if (mysql_d_taiwan) {
		MySQL_close(mysql_d_taiwan);
		mysql_d_taiwan = null;
	}
	if (mysql_taiwan_login) {
		MySQL_close(mysql_taiwan_login);
		mysql_taiwan_login = null;
	}


	if (mysql_personal_production) {
		MySQL_close(mysql_personal_production);
		mysql_personal_production = null;
	}
	if (mysql_Prohibition_of_Cheating) {
		MySQL_close(mysql_Prohibition_of_Cheating);
		mysql_Prohibition_of_Cheating = null;
	}

}

//怪物攻城活动数据存档
function event_villageattack_save_to_db() {
	api_MySQL_exec(mysql_frida, "replace into game_event (event_id, event_info) values ('villageattack', '" + JSON.stringify(villageAttackEventInfo) + "');");
}

//从数据库载入怪物攻城活动数据
function event_villageattack_load_from_db() {
	if (api_MySQL_exec(mysql_frida, "select event_info from game_event where event_id = 'villageattack';")) {
		if (MySQL_get_n_rows(mysql_frida) == 1) {
			MySQL_fetch(mysql_frida);
			var info = api_MySQL_get_str(mysql_frida, 0);
			villageAttackEventInfo = JSON.parse(info);
		}
	}
}

//处理到期的自定义定时器
function do_timer_dispatch() {
	//当前待处理的定时器任务列表
	var task_list = [];

	//线程安全
	var guard = api_Guard_Mutex_Guard();
	//依次取出队列中的任务
	while (timer_dispatcher_list.length > 0) {
		//先入先出
		var task = timer_dispatcher_list.shift();
		task_list.push(task);
	}
	Destroy_Guard_Mutex_Guard(guard);
	//执行任务
	for (var i = 0; i < task_list.length; ++i) {
		var task = task_list[i];

		var f = task[0];
		var args = task[1];
		f.apply(null, args);
	}
}

//申请锁(申请后务必手动释放!!!)
function api_Guard_Mutex_Guard() {
	var a1 = Memory.alloc(100);
	Guard_Mutex_Guard(a1, G_TimerQueue().add(16));

	return a1;
}

//挂接消息分发线程 确保代码线程安全
function hook_TimerDispatcher_dispatch() {
	//hook TimerDispatcher::dispatch
	//服务器内置定时器 每秒至少执行一次
	Interceptor.attach(ptr(0x8632A18),
		{
			onEnter: function (args) { },
			onLeave: function (retval) {
				//清空等待执行的任务队列
				do_timer_dispatch();
			}
		});
}

//在dispatcher线程执行(args为函数f的参数组成的数组, 若f无参数args可为null)
function api_scheduleOnMainThread(f, args) {
	//线程安全
	var guard = api_Guard_Mutex_Guard();
	timer_dispatcher_list.push([f, args]);
	Destroy_Guard_Mutex_Guard(guard);
	return;
}

function api_CUser_GetGuildName(user) {
	var p = CUser_GetGuildName(user);
	if (p.isNull()) {
		return '';
	}
	return p.readUtf8String(-1);
}
//设置定时器 到期后在dispatcher线程执行
function api_scheduleOnMainThread_delay(f, args, delay) {
	setTimeout(api_scheduleOnMainThread, delay, f, args);
}

//重置活动数据
function reset_villageattack_info() {
	villageAttackEventInfo.state = VILLAGEATTACK_STATE_P1;
	villageAttackEventInfo.score = 0;
	villageAttackEventInfo.difficult = 0;
	villageAttackEventInfo.next_village_monster_id = TAU_CAPTAIN_MONSTER_ID;
	villageAttackEventInfo.last_killed_monster_id = 0;
	villageAttackEventInfo.p2_kill_combo = 0;
	villageAttackEventInfo.user_pt_info = {};
	set_villageattack_dungeon_difficult(villageAttackEventInfo.difficult);
	villageAttackEventInfo.start_time = api_CSystemTime_getCurSec();
}

//怪物攻城活动计时器(每5秒触发一次)
function event_villageattack_timer() {
	if (villageAttackEventInfo.state == VILLAGEATTACK_STATE_END)
		return;
	//活动结束检测
	var remain_time = event_villageattack_get_remain_time();
	if (remain_time <= 0) {
		//活动结束
		on_end_event_villageattack();
		return;
	}
	//当前应扣除的PT
	var damage = 0;
	//P2/P3阶段GBL主教扣PT
	if ((villageAttackEventInfo.state == VILLAGEATTACK_STATE_P2) || (villageAttackEventInfo.state == VILLAGEATTACK_STATE_P3)) {
		for (var i = 0; i < villageAttackEventInfo.gbl_cnt; ++i) {
			if (get_random_int(0, 100) < (4 + villageAttackEventInfo.difficult)) {
				damage += 1;
			}
		}
	}
	//P3阶段世界BOSS自身回血
	if (villageAttackEventInfo.state == VILLAGEATTACK_STATE_P3) {
		if (get_random_int(0, 100) < (6 + villageAttackEventInfo.difficult)) {
			damage += 1;
		}
	}
	//扣除PT
	if (damage > 0) {
		villageAttackEventInfo.score -= damage;
		if (villageAttackEventInfo.score < EVENT_VILLAGEATTACK_TARGET_SCORE[villageAttackEventInfo.state - 1]) {
			villageAttackEventInfo.score = EVENT_VILLAGEATTACK_TARGET_SCORE[villageAttackEventInfo.state - 1]
		}
		//更新PT
		gameworld_update_villageattack_score();
	}
	//重复触发计时器
	if (villageAttackEventInfo.state != VILLAGEATTACK_STATE_END) {
		api_scheduleOnMainThread_delay(event_villageattack_timer, null, 5000);
	}
}

//开启怪物攻城活动
function start_villageattack() {
	console.log('start_villageattack-------------');
	var a3 = Memory.alloc(100);
	a3.add(10).writeInt(EVENT_VILLAGEATTACK_TOTAL_TIME); //活动剩余时间
	a3.add(14).writeInt(villageAttackEventInfo.score); //当前频道PT点数
	a3.add(18).writeInt(EVENT_VILLAGEATTACK_TARGET_SCORE[2]); //成功防守所需点数
	Inter_VillageAttackedStart_dispatch_sig(ptr(0), ptr(0), a3);
}

//开始怪物攻城活动
function on_start_event_villageattack() {
	//重置活动数据
	reset_villageattack_info();
	//通知全服玩家活动开始 并刷新城镇怪物
	start_villageattack();
	//开启活动计时器
	api_scheduleOnMainThread_delay(event_villageattack_timer, null, 5000);
	//公告通知当前活动进度
	event_villageattack_broadcast_diffcult();
}

//开启怪物攻城活动定时器
function start_event_villageattack_timer() {
	//获取当前系统时间
	var cur_time = api_CSystemTime_getCurSec();
	//计算距离下次开启怪物攻城活动的时间
	var delay_time = (3600 * EVENT_VILLAGEATTACK_START_HOUR) - (cur_time % (3600 * 24));
	if (delay_time <= 0)
		delay_time += 3600 * 24;
	//delay_time = 10;
	console.log('<>:' + delay_time);
	//log('距离下次开启<怪物攻城活动>还有:' + delay_time / 3600 + '小时');
	//log('距离下次开启<怪物攻城活动>还有:' + delay_time * 1000);
	//定时开启活动
	api_scheduleOnMainThread_delay(on_start_event_villageattack, null, delay_time * 1000);
}

//开启怪物攻城活动
function start_event_villageattack() {
	//patch相关函数, 修复活动流程
	hook_VillageAttack();
	console.log('-------------------- start_event_villageattack-----------------');
	if (villageAttackEventInfo.state == VILLAGEATTACK_STATE_END) {
		//开启怪物攻城活动定时器
		start_event_villageattack_timer();
	}
	else {
		//开启活动计时器
		api_scheduleOnMainThread_delay(event_villageattack_timer, null, 5000);
	}
}

//设置怪物攻城副本难度(0-4: 普通-英雄)
function set_villageattack_dungeon_difficult(difficult) {
	Memory.protect(ptr(0x085B9605), 4, 'rwx'); //修改内存保护属性为可写
	ptr(0x085B9605).writeInt(difficult);
}

//世界广播怪物攻城活动当前进度/难度
function event_villageattack_broadcast_diffcult() {
	if (villageAttackEventInfo.state != VILLAGEATTACK_STATE_END) {
		api_GameWorld_SendNotiPacketMessage('<怪物攻城活动> 当前阶段:' + (villageAttackEventInfo.state + 1) + ', 当前难度等级: ' + villageAttackEventInfo.difficult, 14);
	}
}

//计算活动剩余时间
function event_villageattack_get_remain_time() {
	var cur_time = api_CSystemTime_getCurSec();
	var event_end_time = villageAttackEventInfo.start_time + EVENT_VILLAGEATTACK_TOTAL_TIME;
	var remain_time = event_end_time - cur_time;
	return remain_time;
}

//更新怪物攻城当前进度(广播给频道内在线玩家)
function gameworld_update_villageattack_score() {
	//计算活动剩余时间
	var remain_time = event_villageattack_get_remain_time();
	if ((remain_time <= 0) || (villageAttackEventInfo.state == VILLAGEATTACK_STATE_END))
		return;
	var packet_guard = api_PacketGuard_PacketGuard();
	InterfacePacketBuf_put_header(packet_guard, 0, 247); //协议: ENUM_NOTIPACKET_UPDATE_VILLAGE_ATTACKED
	InterfacePacketBuf_put_int(packet_guard, remain_time); //活动剩余时间
	InterfacePacketBuf_put_int(packet_guard, villageAttackEventInfo.score); //当前频道PT点数
	InterfacePacketBuf_put_int(packet_guard, EVENT_VILLAGEATTACK_TARGET_SCORE[2]); //成功防守所需点数
	InterfacePacketBuf_finalize(packet_guard, 1);
	GameWorld_send_all(G_GameWorld(), packet_guard);
	Destroy_PacketGuard_PacketGuard(packet_guard);
}

//通知玩家怪物攻城进度
function notify_villageattack_score(user) {
	//玩家当前PT点
	var charac_no = CUserCharacInfo_getCurCharacNo(user).toString();
	var villageattack_pt = 0;
	if (charac_no in villageAttackEventInfo.user_pt_info)
		villageattack_pt = villageAttackEventInfo.user_pt_info[charac_no][1];
	//计算活动剩余时间
	var remain_time = event_villageattack_get_remain_time();
	//log("remain_time=" + remain_time);
	if ((remain_time <= 0) || (villageAttackEventInfo.state == VILLAGEATTACK_STATE_END))
		return;
	//发包通知角色打开怪物攻城UI并更新当前进度
	var packet_guard = api_PacketGuard_PacketGuard();
	InterfacePacketBuf_put_header(packet_guard, 0, 248); //协议: ENUM_NOTIPACKET_STARTED_VILLAGE_ATTACKED
	InterfacePacketBuf_put_int(packet_guard, remain_time); //活动剩余时间
	InterfacePacketBuf_put_int(packet_guard, villageAttackEventInfo.score); //当前频道PT点数
	InterfacePacketBuf_put_int(packet_guard, EVENT_VILLAGEATTACK_TARGET_SCORE[2]); //成功防守所需点数
	InterfacePacketBuf_put_int(packet_guard, villageattack_pt); //个人PT点数
	InterfacePacketBuf_finalize(packet_guard, 1);
	CUser_Send(user, packet_guard);
	Destroy_PacketGuard_PacketGuard(packet_guard);
}

//怪物攻城活动相关patch
function hook_VillageAttack() {
	//怪物攻城副本回调
	Interceptor.attach(ptr(0x086B34A0),
		{
			onEnter: function (args) {
				//保存函数参数
				//var CVillageMonster = args[0];
				this.user = args[1];
			},
			onLeave: function (retval) {
				if (retval == 0 && this.user.isNull() == false) {
					VillageAttackedRewardSendReward(this.user);
				}
			}
		});
	//hook挑战攻城怪物副本结束事件, 更新怪物攻城活动各阶段状态
	//village_attacked::CVillageMonster::SendVillageMonsterFightResult
	Interceptor.attach(ptr(0x086B330A),
		{
			onEnter: function (args) {
				this.village_monster = args[0]; //当前挑战的攻城怪物
				this.user = args[1]; //当前挑战的角色
				this.result = args[2].toInt32(); //挑战结果: 1==成功
			},
			onLeave: function (retval) {
				//玩家杀死了攻城怪物
				if (this.result == 1) {
					if (villageAttackEventInfo.state == VILLAGEATTACK_STATE_END) //攻城活动已结束
						return;
					//当前杀死的攻城怪物id
					var village_monster_id = this.village_monster.add(2).readUShort();
					//当前阶段杀死每只攻城怪物PT点数奖励: (1, 2, 4, 8, 16)
					var bonus_pt = 2 ** villageAttackEventInfo.difficult;
					//玩家所在队伍
					var party = CUser_GetParty(this.user);
					if (party.isNull())
						return;
					//更新队伍中的所有玩家PT点数
					for (var i = 0; i < 4; ++i) {
						var user = CParty_get_user(party, i);
						if (!user.isNull()) {
							//角色当前PT点数(游戏中的原始PT数据记录在village_attack_dungeon表中)
							var charac_no = CUserCharacInfo_getCurCharacNo(user).toString();
							if (!(charac_no in villageAttackEventInfo.user_pt_info))
								villageAttackEventInfo.user_pt_info[charac_no] = [CUser_get_acc_id(user), 0]; //记录角色accid, 方便离线充值
							//更新角色当前PT点数
							villageAttackEventInfo.user_pt_info[charac_no][1] += bonus_pt;

							//击杀世界BOSS, 额外获得PT奖励
							if ((village_monster_id == TAU_META_COW_MONSTER_ID) && (villageAttackEventInfo.state == VILLAGEATTACK_STATE_P3)) {
								villageAttackEventInfo.user_pt_info[charac_no][1] += 1000 * (1 + villageAttackEventInfo.difficult);
							}
						}
					}
					if (villageAttackEventInfo.state == VILLAGEATTACK_STATE_P1) //怪物攻城一阶段
					{
						//更新频道内总PT
						villageAttackEventInfo.score += bonus_pt;

						//P1阶段未完成
						if (villageAttackEventInfo.score < EVENT_VILLAGEATTACK_TARGET_SCORE[0]) {
							//若杀死了牛头统帅, 则攻城难度+1
							if (village_monster_id == TAU_CAPTAIN_MONSTER_ID) {
								if (villageAttackEventInfo.difficult < 4) {
									villageAttackEventInfo.difficult += 1;
									//怪物攻城副本难度
									set_villageattack_dungeon_difficult(villageAttackEventInfo.difficult);
									//下次刷新出的攻城怪物为: 牛头统帅
									villageAttackEventInfo.next_village_monster_id = TAU_CAPTAIN_MONSTER_ID;
									//公告通知客户端活动进度
									event_villageattack_broadcast_diffcult();
								}
							}
						} else {
							//P1阶段已结束, 进入P2
							villageAttackEventInfo.state = VILLAGEATTACK_STATE_P2;
							villageAttackEventInfo.score = EVENT_VILLAGEATTACK_TARGET_SCORE[0];
							villageAttackEventInfo.p2_last_killed_monster_time = 0;
							villageAttackEventInfo.last_killed_monster_id = 0;
							villageAttackEventInfo.p2_kill_combo = 0;
							//公告通知客户端活动进度
							event_villageattack_broadcast_diffcult();
						}
					} else if (villageAttackEventInfo.state == VILLAGEATTACK_STATE_P2) //怪物攻城二阶段
					{
						//计算连杀时间
						var cur_time = api_CSystemTime_getCurSec();
						var diff_time = cur_time - villageAttackEventInfo.p2_last_killed_monster_time;

						//1分钟内连续击杀相同攻城怪物
						if ((diff_time < 60) && (village_monster_id == villageAttackEventInfo.last_killed_monster_id)) {
							//连杀点数+1
							villageAttackEventInfo.p2_kill_combo += 1;
							if (villageAttackEventInfo.p2_kill_combo >= 3) {
								//三连杀增加当前阶段总PT
								villageAttackEventInfo.score += 33;
								//重新计算连杀
								villageAttackEventInfo.last_killed_monster_id = 0;
								villageAttackEventInfo.p2_kill_combo = 0;
							}
						} else {
							//重新计算连杀
							villageAttackEventInfo.last_killed_monster_id = village_monster_id;
							villageAttackEventInfo.p2_kill_combo = 1;
						}
						//保存本次击杀时间
						villageAttackEventInfo.p2_last_killed_monster_time = cur_time;
						//P2阶段已结束, 进入P3
						if (villageAttackEventInfo.score >= EVENT_VILLAGEATTACK_TARGET_SCORE[1]) {
							//P2阶段已结束, 进入P3
							villageAttackEventInfo.state = VILLAGEATTACK_STATE_P3;
							villageAttackEventInfo.score = EVENT_VILLAGEATTACK_TARGET_SCORE[1];
							villageAttackEventInfo.next_village_monster_id = TAU_META_COW_MONSTER_ID;
							//公告通知客户端活动进度
							event_villageattack_broadcast_diffcult();
						}
					} else if (villageAttackEventInfo.state == VILLAGEATTACK_STATE_P3) //怪物攻城三阶段
					{
						//击杀世界boss
						if (village_monster_id == TAU_META_COW_MONSTER_ID) {
							//更新世界BOSS血量(PT)
							villageAttackEventInfo.score += 25;
							//继续刷新世界BOSS
							villageAttackEventInfo.next_village_monster_id = TAU_META_COW_MONSTER_ID;

							//世界广播
							api_GameWorld_SendNotiPacketMessage('<怪物攻城活动> 世界BOSS已被[' + api_CUserCharacInfo_getCurCharacName(this.user) + ']击杀!', 14);

							//P3阶段已结束
							if (villageAttackEventInfo.score >= EVENT_VILLAGEATTACK_TARGET_SCORE[2]) {
								//怪物攻城活动防守成功, 立即结束活动
								villageAttackEventInfo.defend_success = 1;
								api_scheduleOnMainThread(on_end_event_villageattack, null);
								return;
							}
						}
					}
					//世界广播当前活动进度
					gameworld_update_villageattack_score();
					//通知队伍中的所有玩家更新PT点数
					for (var i = 0; i < 4; ++i) {
						var user = CParty_get_user(party, i);
						if (!user.isNull()) {
							notify_villageattack_score(user);
						}
					}
					//更新存活GBL主教数量
					if (village_monster_id == GBL_POPE_MONSTER_ID) {
						if (villageAttackEventInfo.gbl_cnt > 0) {
							villageAttackEventInfo.gbl_cnt -= 1;
						}
					}
				}
			}
		});
	//hook 刷新攻城怪物函数, 控制下一只刷新的攻城怪物id
	//village_attacked::CVillageMonsterArea::GetAttackedMonster
	Interceptor.attach(ptr(0x086B3AEA),
		{
			onEnter: function (args) { },
			onLeave: function (retval) {
				//返回值为下一次刷新的攻城怪物
				if (retval != 0) {
					//下一只刷新的攻城怪物
					var next_village_monster = ptr(retval);
					var next_village_monster_id = next_village_monster.readUShort();

					//当前刷新的怪物为机制怪物
					if ((next_village_monster_id == TAU_META_COW_MONSTER_ID) || (next_village_monster_id == TAU_CAPTAIN_MONSTER_ID)) {
						//替换为随机怪物
						next_village_monster.writeUShort(get_random_int(1, 17));
					}
					//如果需要刷新指定怪物
					if (villageAttackEventInfo.next_village_monster_id) {
						if ((villageAttackEventInfo.state == VILLAGEATTACK_STATE_P1) || (villageAttackEventInfo.state == VILLAGEATTACK_STATE_P2)) {
							//P1 P2阶段立即刷新怪物
							next_village_monster.writeUShort(villageAttackEventInfo.next_village_monster_id);
							villageAttackEventInfo.next_village_monster_id = 0;
						} else if (villageAttackEventInfo.state == VILLAGEATTACK_STATE_P3) {
							//P3阶段 几率刷新出世界BOSS
							if (get_random_int(0, 100) < 44) {
								next_village_monster.writeUShort(villageAttackEventInfo.next_village_monster_id);
								villageAttackEventInfo.next_village_monster_id = 0;
								//世界广播
								api_GameWorld_SendNotiPacketMessage('<怪物攻城活动> 世界BOSS已刷新, 请勇士们前往挑战!', 14);
							}
						}
					}
					//统计存活GBL主教数量
					if (next_village_monster.readUShort() == GBL_POPE_MONSTER_ID) {
						villageAttackEventInfo.gbl_cnt += 1;
					}
				}
			}
		});
	//当前正在处理挑战的攻城怪物请求
	var state_on_fighting = false;
	//当前正在被挑战的怪物id
	var on_fighting_village_monster_id = 0;
	//hook 挑战攻城怪物函数 控制副本刷怪流程
	//CParty::OnFightVillageMonster
	Interceptor.attach(ptr(0x085B9596),
		{
			onEnter: function (args) {
				state_on_fighting = true;
				on_fighting_village_monster_id = 0;
			},
			onLeave: function (retval) {
				on_fighting_village_monster_id = 0;
				state_on_fighting = false;
			}
		});
	//village_attacked::CVillageMonster::OnFightVillageMonster
	Interceptor.attach(ptr(0x086B3240),
		{
			onEnter: function (args) {
				if (state_on_fighting) {
					var village_monster = args[0];

					//记录当前正在挑战的攻城怪物id
					on_fighting_village_monster_id = village_monster.add(2).readU16();
				}
			},
			onLeave: function (retval) { }
		});
	//hook 副本刷怪函数 控制副本内怪物的数量和属性
	//MapInfo::Add_Mob
	var read_f = new NativeFunction(ptr(0x08151612), 'int', ['pointer', 'pointer'], { "abi": "sysv" });
	Interceptor.replace(ptr(0x08151612), new NativeCallback(function (map_info, monster) {
		//当前刷怪的副本id
		//var map_id = map_info.add(4).readUInt();
		//怪物攻城副本
		//if((map_id >= 40001) && (map_id <= 40095))
		if (state_on_fighting) {
			//怪物攻城活动未结束
			if (villageAttackEventInfo != VILLAGEATTACK_STATE_END) {
				//正在挑战世界BOSS
				if (on_fighting_village_monster_id == TAU_META_COW_MONSTER_ID) {
					//P3阶段
					if (villageAttackEventInfo.state == VILLAGEATTACK_STATE_P3) {
						//副本中有几率刷新出世界BOSS, 当前PT点数越高, 活动难度越大, 刷新出世界BOSS概率越大
						if (get_random_int(0, 100) < ((villageAttackEventInfo.score - EVENT_VILLAGEATTACK_TARGET_SCORE[1]) + (6 * villageAttackEventInfo.difficult))) {
							monster.add(0xc).writeUInt(TAU_META_COW_MONSTER_ID);
						}
					}
				}
				if (villageAttackEventInfo.difficult == 0) {
					//难度0: 无变化
					return read_f(map_info, monster);
				} else if (villageAttackEventInfo.difficult == 1) {
					//难度1: 怪物等级提升至100级
					monster.add(16).writeU8(100);
					return read_f(map_info, monster);
				} else if (villageAttackEventInfo.difficult == 2) {
					//难度2: 怪物等级提升至110级; 随机刷新紫名怪
					monster.add(16).writeU8(110);
					//非BOSS怪
					if (monster.add(8).readU8() != 3) {
						if (get_random_int(0, 100) < 50) {
							monster.add(8).writeU8(1); //怪物类型: 0-3
						}
					}
					return read_f(map_info, monster);
				} else if (villageAttackEventInfo.difficult == 3) {
					//难度3: 怪物等级提升至120级; 随机刷新不灭粉名怪; 怪物数量*2
					monster.add(16).writeU8(120);
					//非BOSS怪
					if (monster.add(8).readU8() != 3) {
						if (get_random_int(0, 100) < 75) {
							monster.add(8).writeU8(2); //怪物类型: 0-3
						}
					}
					//执行原始刷怪流程
					read_f(map_info, monster);
					//刷新额外的怪物(同一张地图内, 怪物index和怪物uid必须唯一, 这里为怪物分配新的index和uid)
					//额外刷新怪物数量
					var cnt = 1;
					//新的怪物uid偏移
					var uid_offset = 1000;
					//返回值
					var ret = 0;
					while (cnt > 0) {
						--cnt;
						//新增怪物index
						monster.writeUInt(monster.readUInt() + uid_offset);
						//新增怪物uid
						monster.add(4).writeUInt(monster.add(4).readUInt() + uid_offset);

						//为当前地图刷新额外的怪物
						ret = read_f(map_info, monster);
					}
					return ret;
				} else if (villageAttackEventInfo.difficult == 4) {
					//难度4: 怪物等级提升至127级; 随机刷新橙名怪; 怪物数量*4
					monster.add(16).writeU8(127);
					//非BOSS怪
					if (monster.add(8).readU8() != 3) {
						//英雄级副本精英怪类型等于2的怪为橙名怪
						monster.add(8).writeU8(get_random_int(1, 3)); //怪物类型: 0-3
					}
					//执行原始刷怪流程
					read_f(map_info, monster);
					//刷新额外的怪物(同一张地图内, 怪物index和怪物uid必须唯一, 这里为怪物分配新的index和uid)
					//额外刷新怪物数量
					var cnt = 3;
					//新的怪物uid偏移
					var uid_offset = 1000;
					//返回值
					var ret = 0;
					while (cnt > 0) {
						--cnt;
						//新增怪物index
						monster.writeUInt(monster.readUInt() + uid_offset);
						//新增怪物uid
						monster.add(4).writeUInt(monster.add(4).readUInt() + uid_offset);

						//为当前地图刷新额外的怪物
						ret = read_f(map_info, monster);
					}
					return ret;
				}
			}
		}
		//执行原始刷怪流程
		return read_f(map_info, monster);
	}, 'int', ['pointer', 'pointer']));
	//每次通关额外获取当前等级升级所需经验的0%-0.1%
	//village_attacked::CVillageMonsterMgr::OnKillVillageMonster
	Interceptor.attach(ptr(0x086B4866),
		{
			onEnter: function (args) {
				this.user = args[1];
				this.result = args[2].toInt32();
			},
			onLeave: function (retval) {
				if (retval == 0) {
					//挑战成功
					if (this.result) {
						//玩家所在队伍
						var party = CUser_GetParty(this.user);
						//怪物攻城挑战成功, 给队伍中所有成员发送额外通关发经验
						for (var i = 0; i < 4; ++i) {
							var user = CParty_get_user(party, i);
							if (!user.isNull()) {
								//随机经验奖励
								var cur_level = CUserCharacInfo_get_charac_level(user);
								var reward_exp = Math.floor(CUserCharacInfo_get_level_up_exp(user, cur_level) * get_random_int(0, 1000) / 1000000);
								//发经验
								api_CUser_gain_exp_sp(user, reward_exp);
								//通知玩家获取额外奖励
								api_CUser_SendNotiPacketMessage(user, '怪物攻城挑战成功, 获取额外经验奖励' + reward_exp, 0);
							}
						}
					}
				}
			}
		});
}

//结束怪物攻城活动(立即销毁攻城怪物, 不开启逆袭之谷, 不发送活动奖励)
function end_villageattack() {
	village_attacked_CVillageMonsterMgr_OnDestroyVillageMonster(GlobalData_s_villageMonsterMgr.readPointer(), 2);
}

//结束怪物攻城活动
function on_end_event_villageattack() {
	if (villageAttackEventInfo.state == VILLAGEATTACK_STATE_END)
		return;
	//设置活动状态
	villageAttackEventInfo.state = VILLAGEATTACK_STATE_END;
	//立即结束怪物攻城活动
	end_villageattack();
	//防守成功
	if (villageAttackEventInfo.defend_success) {
		//频道内在线玩家发奖
		//发信奖励: 金币+道具
		var reward_gold = 1000000 * (1 + villageAttackEventInfo.difficult); //金币
		var reward_item_list =
			[
				[7745, 5 * (1 + villageAttackEventInfo.difficult)], //士气冲天
				[2600028, 5 * (1 + villageAttackEventInfo.difficult)], //天堂痊愈
				[42, 5 * (1 + villageAttackEventInfo.difficult)], //复活币
				[3314, 1 + villageAttackEventInfo.difficult], //绝望之塔通关奖章
			];
		api_gameworld_send_mail('<怪物攻城活动>', '恭喜勇士!', reward_gold, reward_item_list);

		//特殊奖励
		api_gameworld_foreach(function (user, args) {
			//设置绝望之塔当前层数为100层
			api_TOD_UserState_setEnterLayer(user, 99);
			//随机选择一件穿戴中的装备
			var inven = CUserCharacInfo_getCurCharacInvenW(user);
			var slot = get_random_int(10, 21); //12件装备slot范围10-21
			var equ = CInventory_GetInvenRef(inven, INVENTORY_TYPE_BODY, slot);
			if (Inven_Item_getKey(equ)) {
				//读取装备强化等级
				var upgrade_level = equ.add(6).readU8();
				if (upgrade_level < 31) {
					//提升装备的强化/增幅等级
					var bonus_level = get_random_int(1, 1 + villageAttackEventInfo.difficult);
					upgrade_level += bonus_level;
					if (upgrade_level >= 31)
						upgrade_level = 31;
					//提升强化/增幅等级
					equ.add(6).writeU8(upgrade_level);
					//通知客户端更新装备
					CUser_SendUpdateItemList(user, 1, 3, slot);
				}
			}
		}, null);
		//榜一大哥
		var rank_first_charac_no = 0;
		var rank_first_account_id = 0;
		var max_pt = 0;
		//论功行赏
		for (var charac_no in villageAttackEventInfo.user_pt_info) {
			//发点券
			var account_id = villageAttackEventInfo.user_pt_info[charac_no][0];
			var pt = villageAttackEventInfo.user_pt_info[charac_no][1];
			var reward_cera = pt * 10; //点券奖励 = 个人PT * 10
			var user_pr = GameWorld_find_user_from_world_byaccid(G_GameWorld(), account_id);
			api_recharge_cash_cera(user_pr, reward_cera);
			//找出榜一大哥
			if (pt > max_pt) {
				rank_first_charac_no = charac_no;
				rank_first_account_id = account_id;
				max_pt = pt;
			}
		}
		//频道内公告活动已结束
		api_GameWorld_SendNotiPacketMessage('<怪物攻城活动> 防守成功, 奖励已发送!', 14);
		if (rank_first_charac_no) {
			//个人积分排行榜第一名 额外获得10倍点券奖励
			var user_pr = GameWorld_find_user_from_world_byaccid(G_GameWorld(), rank_first_account_id);
			api_recharge_cash_cera(user_pr, max_pt * 10);

			//频道内广播本轮活动排行榜第一名玩家名字
			var rank_first_charac_name = api_get_charac_name_by_charac_no(rank_first_charac_no);
			api_GameWorld_SendNotiPacketMessage('<怪物攻城活动> 恭喜勇士 [' + rank_first_charac_name + '] 成为个人积分排行榜第一名(' + max_pt + 'pt)!', 14);
		}
	} else {
		//防守失败
		api_gameworld_foreach(function (user, args) {
			//获取角色背包
			var inven = CUserCharacInfo_getCurCharacInvenW(user);
			//在线玩家被攻城怪物随机掠夺一件穿戴中的装备
			if (get_random_int(0, 100) < 7) {
				//随机删除一件穿戴中的装备
				var slot = get_random_int(10, 21); //12件装备slot范围10-21
				var equ = CInventory_GetInvenRef(inven, INVENTORY_TYPE_BODY, slot);

				if (Inven_Item_getKey(equ)) {
					Inven_Item_reset(equ);
					//通知客户端更新装备
					CUser_SendNotiPacket(user, 1, 2, 3);
				}
			}
			//在线玩家被攻城怪物随机掠夺1%-10%所持金币
			var rate = get_random_int(1, 11);
			var cur_gold = CInventory_get_money(inven);
			var tax = Math.floor((rate / 100) * cur_gold);
			CInventory_use_money(inven, tax, 0, 0);
			//通知客户端更新金币数量
			CUser_SendUpdateItemList(user, 1, 0, 0);
		}, null);
		//频道内公告活动已结束
		api_GameWorld_SendNotiPacketMessage('<怪物攻城活动> 防守失败, 请勇士们再接再厉!', 14);
	}
	//释放空间
	villageAttackEventInfo.user_pt_info = {};
	//存档
	event_villageattack_save_to_db();
	//开启怪物攻城活动定时器
	start_event_villageattack_timer();
}

//无条件完成指定任务并领取奖励
function api_force_clear_quest(user, quest_id) {
	//设置GM完成任务模式(无条件完成任务)
	CUser_setGmQuestFlag(user, 1);
	//接受任务
	CUser_quest_action(user, 33, quest_id, 0, 0);
	//完成任务
	CUser_quest_action(user, 35, quest_id, 0, 0);
	//领取任务奖励(倒数第二个参数表示领取奖励的编号, -1=领取不需要选择的奖励; 0=领取可选奖励中的第1个奖励; 1=领取可选奖励中的第二个奖励)
	CUser_quest_action(user, 36, quest_id, -1, 1);

	//服务端有反作弊机制: 任务完成时间间隔不能小于1秒.  这里将上次任务完成时间清零 可以连续提交任务
	user.add(0x79644).writeInt(0);

	//关闭GM完成任务模式(不需要材料直接完成)
	CUser_setGmQuestFlag(user, 0);
	return;
}

//完成指定任务并领取奖励
function clear_doing_questEx(user, quest_id) { //完成指定任务并领取奖励1
	//玩家任务信息
	var user_quest = CUser_getCurCharacQuestW(user);
	//玩家已完成任务信息
	var WongWork_CQuestClear = user_quest.add(4);
	//pvf数据
	var data_manager = G_CDataManager();
	//跳过已完成的任务
	if (!WongWork_CQuestClear_isClearedQuest(WongWork_CQuestClear, quest_id)) {
		//获取pvf任务数据
		var quest = CDataManager_find_quest(data_manager, quest_id);
		if (!quest.isNull()) {
			//无条件完成指定任务并领取奖励
			api_force_clear_quest(user, quest_id);
			//通知客户端更新已完成任务列表
			CUser_send_clear_quest_list(user);
			//通知客户端更新任务列表
			var packet_guard = api_PacketGuard_PacketGuard();
			UserQuest_get_quest_info(user_quest, packet_guard);
			CUser_Send(user, packet_guard);
			Destroy_PacketGuard_PacketGuard(packet_guard);
		}
	} else {
		//公告通知客户端本次自动完成任务数据
		api_CUser_SendNotiPacketMessage(user, '当前任务已完成: ', 14);
	}
}

//修复绝望之塔 skip_user_apc: 为true时, 跳过每10层的UserAPC
function fix_TOD(skip_user_apc) {

	//每日进入次数限制
	//TOD_UserState::getEnterCount
	Interceptor.attach(ptr(0x08643872), {

		onEnter: function (args) {
			//今日已进入次数强制清零
			args[0].add(0x10).writeInt(0);
		},
		onLeave: function (retval) {
		}
	});


	//每10层挑战玩家APC 服务器内角色不足10个无法进入
	if (skip_user_apc) {
		//跳过10/20/.../90层
		//TOD_UserState::getTodayEnterLayer
		Interceptor.attach(ptr(0x0864383E),
			{
				onEnter: function (args) {
					//绝望之塔当前层数
					var today_enter_layer = args[1].add(0x14).readShort();

					if (((today_enter_layer % 10) == 9) && (today_enter_layer > 0) && (today_enter_layer < 100)) {
						//当前层数为10的倍数时  直接进入下一层
						args[1].add(0x14).writeShort(today_enter_layer + 1);
					}
				},
				onLeave: function (retval) {
				}
			});
	}


	//修复金币异常
	//CParty::UseAncientDungeonItems
	var CParty_UseAncientDungeonItems_ptr = ptr(0x859EAC2);
	var CParty_UseAncientDungeonItems = new NativeFunction(CParty_UseAncientDungeonItems_ptr, 'int', ['pointer', 'pointer', 'pointer', 'pointer'], { "abi": "sysv" });
	Interceptor.replace(CParty_UseAncientDungeonItems_ptr, new NativeCallback(function (party, dungeon, inven_item, a4) {
		//当前进入的地下城id
		var dungeon_index = CDungeon_get_index(dungeon);
		//根据地下城id判断是否为绝望之塔
		if ((dungeon_index >= 11008) && (dungeon_index <= 11107)) {
			//绝望之塔 不再扣除金币
			return 1;
		}
		//其他副本执行原始扣除道具逻辑
		return CParty_UseAncientDungeonItems(party, dungeon, inven_item, a4);
	}, 'int', ['pointer', 'pointer', 'pointer', 'pointer']));
}

//获取时装在数据库中的uid
function api_get_avartar_ui_id(avartar) {
	return avartar.add(7).readInt();
}

//设置时装插槽数据(时装插槽数据指针, 插槽, 徽章id)
// jewel_type: 红=0x1, 黄=0x2, 绿=0x4, 蓝=0x8, 白金=0x10
function api_set_JewelSocketData(jewelSocketData, slot, emblem_item_id) {
	if (!jewelSocketData.isNull()) {
		//每个槽数据长6个字节: 2字节槽类型+4字节徽章item_id
		//镶嵌不改变槽类型, 这里只修改徽章id
		jewelSocketData.add(slot * 6 + 2).writeInt(emblem_item_id);
	}
	return;
}

//修复时装镶嵌
function fix_use_emblem() {
	//Dispatcher_UseJewel::dispatch_sig
	Interceptor.attach(ptr(0x8217BD6),
		{
			onEnter: function (args) {
				try {
					var user = args[1];
					var packet_buf = args[2];
					//校验角色状态是否允许镶嵌
					var state = CUser_get_state(user);
					if (state != 3) {
						return;
					}
					//解析packet_buf
					//时装所在的背包槽
					var avartar_inven_slot = api_PacketBuf_get_short(packet_buf);
					//时装item_id
					var avartar_item_id = api_PacketBuf_get_int(packet_buf);
					//本次镶嵌徽章数量
					var emblem_cnt = api_PacketBuf_get_byte(packet_buf);
					//获取时装道具
					var inven = CUserCharacInfo_getCurCharacInvenW(user);
					var avartar = CInventory_GetInvenRef(inven, INVENTORY_TYPE_AVARTAR, avartar_inven_slot);
					//校验时装 数据是否合法
					if (Inven_Item_isEmpty(avartar) || (Inven_Item_getKey(avartar) != avartar_item_id) || CUser_CheckItemLock(user, 2, avartar_inven_slot)) {
						return;
					}
					//获取时装插槽数据
					var avartar_add_info = Inven_Item_get_add_info(avartar);
					var inven_avartar_mgr = CInventory_GetAvatarItemMgrR(inven);
					var jewel_socket_data = WongWork_CAvatarItemMgr_getJewelSocketData(inven_avartar_mgr, avartar_add_info);

					if (jewel_socket_data.isNull()) {
						return;
					}
					//最多只支持3个插槽
					if (emblem_cnt <= 3) {
						var emblems = {};
						for (var i = 0; i < emblem_cnt; i++) {
							//徽章所在的背包槽
							var emblem_inven_slot = api_PacketBuf_get_short(packet_buf);
							//徽章item_id
							var emblem_item_id = api_PacketBuf_get_int(packet_buf);
							//该徽章镶嵌的时装插槽id
							var avartar_socket_slot = api_PacketBuf_get_byte(packet_buf);
							//log('emblem_inven_slot=' + emblem_inven_slot + ', emblem_item_id=' + emblem_item_id + ', avartar_socket_slot=' + avartar_socket_slot);
							//获取徽章道具
							var emblem = CInventory_GetInvenRef(inven, INVENTORY_TYPE_ITEM, emblem_inven_slot);
							//校验徽章及插槽数据是否合法
							if (Inven_Item_isEmpty(emblem) || (Inven_Item_getKey(emblem) != emblem_item_id) || (avartar_socket_slot >= 3)) {
								return;
							}
							//校验徽章是否满足时装插槽颜色要求
							//获取徽章pvf数据
							var citem = CDataManager_find_item(G_CDataManager(), emblem_item_id);
							if (citem.isNull()) {
								return;
							}
							//校验徽章类型
							if (!CItem_is_stackable(citem) || (CStackableItem_GetItemType(citem) != 20)) {
								return;
							}
							//获取徽章支持的插槽
							var emblem_socket_type = CStackableItem_getJewelTargetSocket(citem);
							//获取要镶嵌的时装插槽类型
							var avartar_socket_type = jewel_socket_data.add(avartar_socket_slot * 6).readShort()
							if (!(emblem_socket_type & avartar_socket_type)) {
								//插槽类型不匹配
								//log('socket type not match!');
								return;
							}
							emblems[avartar_socket_slot] = [emblem_inven_slot, emblem_item_id];
						}
						//开始镶嵌
						for (var avartar_socket_slot in emblems) {
							//删除徽章
							var emblem_inven_slot = emblems[avartar_socket_slot][0];
							CInventory_delete_item(inven, 1, emblem_inven_slot, 1, 8, 1);
							//设置时装插槽数据
							var emblem_item_id = emblems[avartar_socket_slot][1];
							api_set_JewelSocketData(jewel_socket_data, avartar_socket_slot, emblem_item_id);
							//log('徽章item_id=' + emblem_item_id + '已成功镶嵌进avartar_socket_slot=' + avartar_socket_slot + '的槽内!');
						}
						//时装插槽数据存档
						DB_UpdateAvatarJewelSlot_makeRequest(CUserCharacInfo_getCurCharacNo(user), api_get_avartar_ui_id(avartar), jewel_socket_data);
						//通知客户端时装数据已更新
						CUser_SendUpdateItemList(user, 1, 1, avartar_inven_slot);
						//回包给客户端
						var packet_guard = api_PacketGuard_PacketGuard();
						InterfacePacketBuf_put_header(packet_guard, 1, 204);
						InterfacePacketBuf_put_int(packet_guard, 1);
						InterfacePacketBuf_finalize(packet_guard, 1);
						CUser_Send(user, packet_guard);
						Destroy_PacketGuard_PacketGuard(packet_guard);
						//log('镶嵌请求已处理完成!');
					}
				} catch (error) {
					console.log('fix_use_emblem throw Exception:' + error);
				}
			},
			onLeave: function (retval) {
				//返回值改为0  不再踢线
				retval.replace(0);
			}
		});
}
var dungeonNameStorage;
var firstSecondsValueStorage = null;
var First_kill = null;
var dungeonTimeRecords = {};
var seconds;
function saveFirstSecondsValue(charac_no, seconds) {
	firstSecondsValueStorage = seconds;
}
function clearSavedFirstSecondsValue(charac_no) {
	firstSecondsValueStorage = null;
}
function getSavedFirstSecondsValue(charac_no) {
	return firstSecondsValueStorage;
}
function recordDungeonName(dungeonName, charac_no) //记录副本名
{
	dungeonNameStorage = dungeonName;
}

function getStoredDungeonName(charac_no) //调用副本名
{
	return dungeonNameStorage;
}

function clearStoredDungeonName(charac_no) //清除记录
{
	dungeonNameStorage = null;
}



//所有副本开王图
function unlock_all_dungeon_difficulty(user) {
	var a3 = Memory.allocUtf8String('3');
	DoUserDefineCommand(user, 120, a3);
}

//踢人
function api_gameWorld_Kill_The_game(user) {
	var packet_guard = api_PacketGuard_PacketGuard();
	InterfacePacketBuf_clear(packet_guard);
	InterfacePacketBuf_put_header(packet_guard, 1, 3);
	InterfacePacketBuf_put_byte(packet_guard, 1);
	InterfacePacketBuf_finalize(packet_guard, 1);
	CUser_Send(user, packet_guard);
	Destroy_PacketGuard_PacketGuard(packet_guard);
}

//返回选择角色界面
var CUser_ReturnToSelectCharacList = new NativeFunction(ptr(0x8686FEE), 'int', ['pointer', 'int'], { "abi": "sysv" });

//返回选择角色界面CUser_ReturnToSelectCharacList
function api_CUser_ReturnToSelectCharacList(user) {
	api_scheduleOnMainThread(CUser_ReturnToSelectCharacList, [user, 1]);
}

var CUser_getCurCharacQuestR = new NativeFunction(ptr(0x0819a8a6), 'pointer', ['pointer'], { "abi": "sysv" });
var WongWork_CQuestClear_isClearedQuest = new NativeFunction(ptr(0x808BAE0), 'int', ['pointer', 'int'], { "abi": "sysv" });

var CUserCharacInfo_setDemensionInoutValue = new NativeFunction(ptr(0x0822f184), 'int', ['pointer', 'int', 'int'], { "abi": "sysv" });

function resetResetDimensionInout(user, index) {
	var dimensionInout = CDataManager_get_dimensionInout(G_CDataManager(), index);
	CUserCharacInfo_setDemensionInoutValue(user, index, dimensionInout);
}

var CInventory_SendItemLockListInven = new NativeFunction(ptr(0x84FAF8E), 'void', ['pointer'], { "abi": "sysv" });

var CUserCharacInfo_get_charac_job = new NativeFunction(ptr(0x080fdf20), 'int', ['pointer'], { "abi": "sysv" });//职业id
var CUserCharacInfo_get_pvp_grade = new NativeFunction(ptr(0x0819ee4a), 'int', ['pointer'], { "abi": "sysv" });//pk等级
var CUserCharacInfo_setCurCharacFatigue = new NativeFunction(ptr(0x0822f2ce), 'int', ['pointer', 'int'], { "abi": "sysv" });
var CUserCharacInfo_getCurCharacFatigue = new NativeFunction(ptr(0x0822f2ae), 'int', ['pointer'], { "abi": "sysv" });
var CUser_getCurCharacTotalFatigue = new NativeFunction(ptr(0x08657766), 'int', ['pointer'], { "abi": "sysv" });

var CUser_RecoverFatigue = new NativeFunction(ptr(0x08657ada), 'int', ['pointer', 'int'], { "abi": "sysv" });
var CUser_SendFatigue = new NativeFunction(ptr(0x08656540), 'void', ['pointer'], { "abi": "sysv" });

var CUserCharacInfo_getCurCharacSkillR = new NativeFunction(ptr(0x0822f130), 'pointer', ['pointer'], { "abi": "sysv" });
var CUser_send_skill_info = new NativeFunction(ptr(0x0866C46A), 'void', ['pointer'], { "abi": "sysv" });

//强制退出副本
var CParty_ReturnToVillage = new NativeFunction(ptr(0X85ACA60), 'void', ['int', 'pointer'], { "abi": "sysv" });

//检查背包中是否存在item
var CInventory_check_item_exist = new NativeFunction(ptr(0x08505172), 'int', ['pointer', 'int'], { "abi": "sysv" });

var CInventory_getInvenData = new NativeFunction(ptr(0x084fbf2c), 'int', ['pointer', 'int', 'pointer'], { "abi": "sysv" });

var CItem_getPrice = new NativeFunction(ptr(0x822c84a), 'int', ['pointer'], { "abi": "sysv" });


//返回选择角色界面
var CUser_ReturnToSelectCharacList = new NativeFunction(ptr(0x8686FEE), 'int', ['pointer', 'int'], { "abi": "sysv" });

//返回选择角色界面CUser_ReturnToSelectCharacList
function api_CUser_ReturnToSelectCharacList(user) {
	api_scheduleOnMainThread(CUser_ReturnToSelectCharacList, [user, 1]);
}

var CUserCharacInfo_setDemensionInoutValue = new NativeFunction(ptr(0x0822f184), 'int', ['pointer', 'int', 'int'], { "abi": "sysv" });


function resetResetDimensionInout(user, index) {
	var dimensionInout = CDataManager_get_dimensionInout(G_CDataManager(), index);
	CUserCharacInfo_setDemensionInoutValue(user, index, dimensionInout);
}

//获取pvf数据
var CDataManager_find_dungeon = new NativeFunction(ptr(0x835F9F8), 'pointer', ['pointer', 'int'], { "abi": "sysv" });
//获取副本名称
var CDungeon_getDungeonName = new NativeFunction(ptr(0x81455A6), 'pointer', ['pointer'], { "abi": "sysv" });
//读取副本id
var getDungeonIdxAfterClear = new NativeFunction(ptr(0x0867CB90), 'int', ['pointer'], { "abi": "sysv" });


//减少胜点
var useWinPoint = new NativeFunction(ptr(0x0864FCC6), 'int', ['pointer', 'int', 'int'], { "abi": "sysv" });
//增加胜点
var gainWinPoint = new NativeFunction(ptr(0x0864FD2C), 'pointer', ['pointer', 'int', 'int'], { "abi": "sysv" });
//通知客户端更新背包栏
var CUser_send_itemspace = new NativeFunction(ptr(0x865DB6C), 'int', ['pointer', 'int'], { "abi": "sysv" });

//增加x点胜点
function api_up_charac_WinPoint(user, value) {
	var oldpoint = api_get_charac_WinPoint(user);
	var newpoint = oldpoint + value;
	var charac_no = CUserCharacInfo_getCurCharacNo(user);
	gainWinPoint(user, value, 0);
	api_MySQL_exec(mysql_taiwan_cain, 'update pvp_result set win_point=' + newpoint + ' where charac_no=' + charac_no + ';');
	CUser_send_itemspace(user, ENUM_ITEMSPACE_INVENTORY);
}

//减少x点胜点
function api_down_charac_WinPoint(user, value) {
	var oldpoint = api_get_charac_WinPoint(user);
	var newpoint = oldpoint - value;
	var charac_no = CUserCharacInfo_getCurCharacNo(user);
	useWinPoint(user, value, 0);
	api_MySQL_exec(mysql_taiwan_cain, 'update pvp_result set win_point=' + newpoint + ' where charac_no=' + charac_no + ';');
	CUser_send_itemspace(user, ENUM_ITEMSPACE_INVENTORY);
}

function api_get_charac_WinPoint(user) {
	var value = null;
	var M_id = CUser_get_acc_id(user);
	var charac_no = CUserCharacInfo_getCurCharacNo(user);
	if (api_MySQL_exec(mysql_taiwan_cain, "select win_point from pvp_result where charac_no=" + charac_no + ";")) {
		if (MySQL_get_n_rows(mysql_taiwan_cain) == 1) {
			if (MySQL_fetch(mysql_taiwan_cain)) {
				value = api_MySQL_get_int(mysql_taiwan_cain, 0);
			}
		}
	}
	return value;
}


var dungeonTimeRecords = {};
var ss_reward = 0;
var dj_reward = 0;
var number = 0;
var identification = '玩家[';
var dgnname = {};
var dgndifficulty = {};
//捕获玩家游戏事件
function hook_history_log() {
	//cHistoryTrace::operator()
	Interceptor.attach(ptr(0x854F990),
		{
			onEnter: function (args) {
				//解析日志内容: "18000008",18000008,D,145636,"nickname",1,72,8,0,192.168.200.1,192.168.200.1,50963,11, DungeonLeave,"龍人之塔",0,0,"aabb","aabb","N/A","N/A","N/A"
				var history_log = args[1].readUtf8String(-1);
				var group = history_log.split(',');
				var rewardAmount = 1;
				var account_id = parseInt(group[1]);
				var time_hh_mm_ss = group[3];
				var charac_name = group[4];
				var charac_no = group[5];
				var charac_level = group[6];
				var charac_job = group[7];
				var charac_growtype = group[8];
				var user_web_address = group[9];
				var user_peer_ip2 = group[10];
				var user_port = group[11];
				var channel_index = group[12];
				var game_event = group[13].slice(1);
				var Dungeon_nameget = group[14];
				var item_id = parseInt(group[15]);
				var reason = parseInt(group[18]);
				var mob_boss = group[22];
				var mob_id = group[14];
				var Dungeon_name = Dungeon_nameget;
				var Item_Total_number = group[16];
				var Item_number = group[17];
				var Item_mode = group[18];
				var mail_number = group[19];
				var user = GameWorld_find_user_from_world_byaccid(G_GameWorld(), account_id);

				//道具减少:  Item-,1,10000113,63,1,3,63,0,0,0,0,0,0000000000000000000000000000,0,0,00000000000000000000
				if (game_event == 'Item-') {
					var item_id = parseInt(group[15]); //本次操作道具id
					var item_cnt = parseInt(group[17]); //本次操作道具数量
					var reason = parseInt(group[18]); //本次操作原因
					//log('玩家[' + charac_name + ']道具减少, 原因:' + reason + '(道具id=' + item_id + ', 使用数量=' + item_cnt);
					if (5 == reason) {
						//丢弃道具
					} else if (3 == reason) {
						//使用道具
						UserUseItemEvent(user, item_id); //角色使用道具触发事件

						if ((item_id >= 10300052) && (item_id <= 10300387)) {
							send_reward_all(user, item_id);//口令红包
						}

						if ((item_id >= 202404753) && (item_id <= 202404756)) {
							rechargeCeraBasedOnItemId(user, item_id);//点券充值额外赠送
						}
						if (item_id == 10000113) {
							unlock_all_dungeon_difficulty(user);
							api_CUser_SendNotiPacketMessage(user, '已解锁所有副本难度，请当前角色小退刷新。', 1);
						}
						if (item_id == 123001) {
							crossover(user, item_id, excludedItemIds)//跨界石
						}
						if (item_id == 123007) {
							equInherit(user, item_id)// 装备继承
						}
						if (item_id == 2024042001) {
							var item_list = rewaditem(user, item_id); //十连魔盒
							SendCreateDnf(user, item_list);
						}
						if (item_id == 8087) {
							KuoZ(user, item_id)//扩展角色创建+1
						}
						if (item_id === 8066) {
							itemunLock(user, item_id); // 清除装备锁
						}

						//-----------------------------下方为装备镶嵌，不想要就删除整段-------------------------------------------------------------------------------------------------------
						//UseItemEventHandler(user, item_id);//角色使用道具触发装备镶嵌
						//-----------------------------下方为装备镶嵌，不想要就删除整段-------------------------------------------------------------------------------------------------------
						//这里并未改变道具原始效果 原始效果成功执行后触发下面的代码
					} else if (9 == reason) {
						//分解道具
					} else if (10 == reason) {
						//使用属性石头
					}
				}
				//道具增加:  Item-,

				if (game_event == 'Item+') {
					var item_id = parseInt(group[15]);
					var group_18 = parseInt(group[18]);
					var itemData = CDataManager_find_item(G_CDataManager(), item_id);
					var inEquRarity = CItem_GetRarity(itemData); // 稀有度
					if (group_18 == 4) {

						Prompt_to_drop(user, item_id)    //获得史诗奖励道具，彩色公告

						if (inEquRarity == 4)//要求品级为史诗
						{
							//-----------------------------下方为单个史诗播报，不想要就删除整段--------------------------------------------------------------------------------------------------------------------------------------------							
							//api_GameWorld_SendNotiPacketMessage('玩家[' + api_CUserCharacInfo_getCurCharacName(user) + ']' + ']在地下城中获得了[' + api_CItem_GetItemName(item_id) + '] x1', 14);
							//-----------------------------上方为单个史诗播报，不想要就删除整段--------------------------------------------------------------------------------------------------------------------------------------------	
							//countQuality4EquipsInCurrentInstance(user, charac_no);//多黄判定，不需要则删除这行
						}
						//if (item_id == 3037) //测试
						//processing_data(item_id, user, 3257, 2500, get_random_int(50, 888));
					}



					//var item_cnt = parseInt(group[17]);

					//gift_pack_return_award(user, account_id, item_id, item_cnt);		//商城商店多买多送			

				}


				if (game_event == 'KillMob') //杀死怪物
				{
					//魔法封印装备词条升级
					//boost_random_option_equ(user);
					if (mob_id == 1) //代码可以自定义，怪物首杀奖励
					{
						if (First_kill == null) //如果这个怪物还未其他人被击杀过
						{
							ss_reward = 3171 //碳
							number = 1 //1个
							//api_GameWorld_SendNotiPacketMessage('首杀!', 1)
							//sendRewardsByWindow(user, [ss_reward, number]);//发放道具奖励1个
							//First_kill = {}//置空，证明该怪物已被首杀//每次保存此脚本会还原成未被击杀状态
						}
					}
					if (mob_boss == 3) {
						seconds = timeToSeconds(time_hh_mm_ss) - dungeonTimeRecords[charac_no];
						saveFirstSecondsValue(charac_no, seconds); // 保存通关时间
					}


					var Mob_id = group[14];                //账号uid
					var dgn_id = getDungeonIdxAfterClear(user);                //副本id
					var charac_no = CUserCharacInfo_getCurCharacNo(user);//角色id
					var CharacName = api_CUserCharacInfo_getCurCharacName(user);//角色名字

					if (group[24] == 0 && group[25] == 0 && group[26] == 0 && group[27] == 0) {
						if (group[15] == 0 && group[16] == 0 || group[17] != ' (0:0)' && group[18] == 0) {
							if (group[20] == 0 && group[21] == 0 && group[22] == 0) {
								api_CUser_SendNotiPacketMessage(user, '检测到数据异常进行踢线处理', 37);
								api_CUser_SendNotiPacketMessage(user, '请自觉关闭外挂', 37);
								//api_CUser_ReturnToSelectCharacList(user);
								api_gameWorld_Kill_The_game(user);
							}
						}
					}
					if (group[24] == 0 && group[27] == 0 && group[29] == 0) {
						if (group[15] == 0 && group[16] == 0 || group[17] != ' (0:0)' && group[18] == 0) {
							if (group[20] == 0 && group[21] == 0 && group[22] == 0) {
								api_CUser_SendNotiPacketMessage(user, '检测到数据异常进行踢线处理', 37);
								api_CUser_SendNotiPacketMessage(user, '请自觉关闭外挂', 37);
								//api_CUser_ReturnToSelectCharacList(user);
								api_gameWorld_Kill_The_game(user);
							}
						}
					}



				}
				if (game_event == "CP") {
					return_sp_tp(user);
				}

				if (game_event == "SkillInit") {
					return_sp_tp(user);
				}

				if (game_event == "Level+") {
					//level_reward(user);   //升级邮件
				}
				if (game_event == 'Enchant+')//使用宝珠
				{
					var equ_id = parseInt(group[14]);
					var old_monster_card_id = parseInt(group[15]);
					var monster_card_id = parseInt(group[16]);
					random_monster_card(user, equ_id, monster_card_id, old_monster_card_id);
				}

				if (game_event == 'QuestComplete')  //心悦任务 
				{

					var qst_id = parseInt(group[14]); //本次操作道具id
					var charac_no = CUserCharacInfo_getCurCharacNo(user);

					if (qst_id == 9813) {
						maxCreatureChange(user); // 顶阶宠物置换
					}

					if (qst_id == 9814) {
						maxAuraChange(user); // 顶阶光环置换
					}

					if (qst_id == 9815) {
						maxTitleChange(user); // 顶阶称号置换
					}

					if ((qst_id >= 20117) && (qst_id <= 20118)) {
						api_MySQL_exec(mysql_personal_production, 'update joyclub_vip set vip=vip+1 where charac_no=' + charac_no + ';');

					}
					if (qst_id == 20117) {
						api_GameWorld_SendNotiPacketMessage('恭喜玩家[' + api_CUserCharacInfo_getCurCharacName(user) + ']成为尊贵的心悦vip1', 0);

					}
					if (qst_id == 20118) {
						api_GameWorld_SendNotiPacketMessage('恭喜玩家[' + api_CUserCharacInfo_getCurCharacName(user) + ']成为尊贵的心悦vip2', 0);
					}
					if (qst_id == 20119) {
						api_GameWorld_SendNotiPacketMessage('恭喜玩家[' + api_CUserCharacInfo_getCurCharacName(user) + ']成为尊贵的心悦vip3', 0);
					}


				}

				if (game_event == 'Money+') {
					var cur_money = parseInt(group[14]); //当前持有的金币数量
					var add_money = parseInt(group[15]); //本次获得金币数量
					var reason = parseInt(group[16]); //本次获得金币原因
					//log('玩家[' + charac_name + ']获取金币, 原因:' + reason + '(当前持有金币=' + cur_money + ', 本次获得金币数量=' + add_money);
					if (4 == reason) {
						//副本拾取
					} else if (5 == reason) {
						//副本通关翻牌获取金币
					}
				}
				//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------				
				if (game_event == 'DungeonClearInfo') //副本信息清除
				{

					Prompt_end_of_dungeon(user)
					Clear_all_records(user)



					var savedFirstSecondsValue = getSavedFirstSecondsValue(charac_no);
					var seconds = timeToSeconds(time_hh_mm_ss) - dungeonTimeRecords[charac_no];
					if (savedFirstSecondsValue > 0) //如果通关时间判定大于0
					{
						if (savedFirstSecondsValue < 1000) //如果副本通关时间小于1000秒通关则播报
						{
							if (dgndifficulty[charac_no] == 0) //如果难度标识=0则为普通级
							{
								api_GameWorld_SendNotiPacketMessage(identification + api_CUserCharacInfo_getCurCharacName(user) + ']' + '通关' + dgnname[charac_no] + '(普通级) \n用时 ' + parseInt((savedFirstSecondsValue / 60)) + '分' + (savedFirstSecondsValue % 60) + '秒', 0);
								console.log(identification + api_CUserCharacInfo_getCurCharacName(user) + ']' + '通关' + dgnname[charac_no] + '(普通级) 用时 ' + parseInt((savedFirstSecondsValue / 60)) + ' 分 ' + (savedFirstSecondsValue % 60) + ' 秒');
								clearSavedFirstSecondsValue(charac_no);
							}
							else if (dgndifficulty[charac_no] == 1) //如果难度标识=1则为冒险级
							{
								api_GameWorld_SendNotiPacketMessage(identification + api_CUserCharacInfo_getCurCharacName(user) + ']' + '通关' + dgnname[charac_no] + '(冒险级) \n用时 ' + parseInt((savedFirstSecondsValue / 60)) + '分' + (savedFirstSecondsValue % 60) + '秒', 0);
								console.log(identification + api_CUserCharacInfo_getCurCharacName(user) + ']' + '通关' + dgnname[charac_no] + '(冒险级) 用时 ' + parseInt((savedFirstSecondsValue / 60)) + ' 分 ' + (savedFirstSecondsValue % 60) + ' 秒');
								clearSavedFirstSecondsValue(charac_no);
							}
							else if (dgndifficulty[charac_no] == 2) //如果难度标识=2则为王者级
							{
								api_GameWorld_SendNotiPacketMessage(identification + api_CUserCharacInfo_getCurCharacName(user) + ']' + '通关' + dgnname[charac_no] + '(王者级) \n用时 ' + parseInt((savedFirstSecondsValue / 60)) + '分' + (savedFirstSecondsValue % 60) + '秒', 0);
								console.log(identification + api_CUserCharacInfo_getCurCharacName(user) + ']' + '通关' + dgnname[charac_no] + '(王者级) 用时 ' + parseInt((savedFirstSecondsValue / 60)) + ' 分 ' + (savedFirstSecondsValue % 60) + ' 秒');
								clearSavedFirstSecondsValue(charac_no);
							}
							else if (dgndifficulty[charac_no] == 3) //如果难度标识=3则为地狱级
							{
								api_GameWorld_SendNotiPacketMessage(identification + api_CUserCharacInfo_getCurCharacName(user) + ']' + '通关' + dgnname[charac_no] + '(地狱级) \n用时 ' + parseInt((savedFirstSecondsValue / 60)) + '分' + (savedFirstSecondsValue % 60) + '秒', 0);
								console.log(identification + api_CUserCharacInfo_getCurCharacName(user) + ']' + '通关' + dgnname[charac_no] + '(地狱级) 用时 ' + parseInt((savedFirstSecondsValue / 60)) + ' 分 ' + (savedFirstSecondsValue % 60) + ' 秒');
								clearSavedFirstSecondsValue(charac_no);
							}
						}
						else if (savedFirstSecondsValue < 2) //如果副本通关时间小于5秒则踢出游戏
						{
							api_CUser_SendNotiPacketMessage(user, '\n    检测到数据异常\n    请自觉关闭外挂', 37);
							console.log(identification + api_CUserCharacInfo_getCurCharacName(user) + ']刷图数据异常');
							api_CUser_ReturnToSelectCharacList(user);
						}
					}
					else {
						if (seconds < 300) //如果进副本时间小于300秒退出则播报
						{
							if (dgndifficulty[charac_no] == 0) //如果难度标识=0则为普通级
							{
								api_GameWorld_SendNotiPacketMessage(identification + api_CUserCharacInfo_getCurCharacName(user) + ']' + '未通关' + dgnname[charac_no] + '(普通级) 并离开副本\n用时 ' + parseInt((seconds / 60)) + '分' + (seconds % 60) + '秒', 0);
								console.log(identification + api_CUserCharacInfo_getCurCharacName(user) + ']' + '未通关' + dgnname[charac_no] + '并离开副本，用时 ' + parseInt((seconds / 60)) + ' 分 ' + (seconds % 60) + ' 秒');
							}
							else if (dgndifficulty[charac_no] == 1) //如果难度标识=1则为冒险级
							{
								api_GameWorld_SendNotiPacketMessage(identification + api_CUserCharacInfo_getCurCharacName(user) + ']' + '未通关' + dgnname[charac_no] + '(冒险级) 并离开副本\n用时 ' + parseInt((seconds / 60)) + '分' + (seconds % 60) + '秒', 0);
								console.log(identification + api_CUserCharacInfo_getCurCharacName(user) + ']' + '未通关' + dgnname[charac_no] + '并离开副本，用时 ' + parseInt((seconds / 60)) + ' 分 ' + (seconds % 60) + ' 秒');
							}
							else if (dgndifficulty[charac_no] == 2) //如果难度标识=2则为王者级
							{
								api_GameWorld_SendNotiPacketMessage(identification + api_CUserCharacInfo_getCurCharacName(user) + ']' + '未通关' + dgnname[charac_no] + '(王者级) 并离开副本\n用时 ' + parseInt((seconds / 60)) + '分' + (seconds % 60) + '秒', 0);
								console.log(identification + api_CUserCharacInfo_getCurCharacName(user) + ']' + '未通关' + dgnname[charac_no] + '并离开副本，用时 ' + parseInt((seconds / 60)) + ' 分 ' + (seconds % 60) + ' 秒');
							}
							else if (dgndifficulty[charac_no] == 3) //如果难度标识=3则为地狱级
							{
								api_GameWorld_SendNotiPacketMessage(identification + api_CUserCharacInfo_getCurCharacName(user) + ']' + '未通关' + dgnname[charac_no] + '(地狱级) 并离开副本\n用时 ' + parseInt((seconds / 60)) + '分' + (seconds % 60) + '秒', 0);
								console.log(identification + api_CUserCharacInfo_getCurCharacName(user) + ']' + '未通关' + dgnname[charac_no] + '并离开副本，用时 ' + parseInt((seconds / 60)) + ' 分 ' + (seconds % 60) + ' 秒');
							}
						}
					}
					//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
					/*
					if (userCounters[charac_no] == 3) //如果个人在副本中获得史诗装备3件
							{
							api_CUser_Add_Item_list(user, [[3037, 1],[3037, 2]]);//多物品示例，奖励无色1个和无色2个,公告内容也需要手动更改
							rewardAmount = rewardAmount * 3 //点券奖励3点	
							api_GameWorld_SendNotiPacketMessage('--------------鸿运当头--------------\n恭喜玩家[' + api_CUserCharacInfo_getCurCharacName(user) + ']在' + dgnname[charac_no] + '爆出3黄\n☆奖励☆[点券+' + rewardAmount + ']\n☆奖励☆[' + api_CItem_GetItemName(3037)+ 'x1]\n☆奖励☆[' + api_CItem_GetItemName(3037)+ 'x2]', 14);
							api_recharge_cash_cera(user, rewardAmount);//发放点券奖励
							}
					 else if (userCounters[charac_no] == 4)  //如果个人在副本中获得史诗装备4件
							{
							 ss_reward = 3037 //奖励无色
							number = 4 //4个
							rewardAmount = rewardAmount * 4 //点券奖励4点	
							api_GameWorld_SendNotiPacketMessage('--------------吉星高照--------------\n恭喜玩家[' + api_CUserCharacInfo_getCurCharacName(user) + ']在' + dgnname[charac_no] + '爆出4黄\n☆奖励☆[点券+' + rewardAmount + ']\n☆奖励☆[' + api_CItem_GetItemName( ss_reward)+ 'x' + number + ']', 14);
							sendRewardsByWindow(user, [ ss_reward, number]);//发放道具奖励
							api_recharge_cash_cera(user, rewardAmount);//发放点券奖励
							}
					 else if (userCounters[charac_no] == 5) //如果个人在副本中获得史诗装备5件
							{
							 ss_reward = 3037 //奖励无色
							number = 5 //5个
							rewardAmount = rewardAmount * 5 //点券奖励5点	
							api_GameWorld_SendNotiPacketMessage('--------------五福临门--------------\n恭喜玩家[' + api_CUserCharacInfo_getCurCharacName(user) + ']在' + dgnname[charac_no] + '爆出5黄\n☆奖励☆[点券+' + rewardAmount + ']\n☆奖励☆[' + api_CItem_GetItemName( ss_reward)+ 'x' + number + ']', 14);
							sendRewardsByWindow(user, [ ss_reward, number]);//发放道具奖励
							api_recharge_cash_cera(user, rewardAmount);//发放点券奖励
							}
					 else if (userCounters[charac_no] == 6) //如果个人在副本中获得史诗装备6件
							{
							 ss_reward = 3037 //奖励无色
							number = 6 //6个
							rewardAmount = rewardAmount * 6 //点券奖励6点	
							api_GameWorld_SendNotiPacketMessage('--------------好运连连--------------\n恭喜玩家[' + api_CUserCharacInfo_getCurCharacName(user) + ']在' + dgnname[charac_no] + '爆出6黄\n☆奖励☆[点券+' + rewardAmount + ']\n☆奖励☆[' + api_CItem_GetItemName( ss_reward)+ 'x' + number + ']', 14);
							sendRewardsByWindow(user, [ ss_reward, number]);//发放道具奖励
							api_recharge_cash_cera(user, rewardAmount);//发放点券奖励
							}
					 else if (userCounters[charac_no] == 7) //如果个人在副本中获得史诗装备7件
							{
							 ss_reward = 3037 //奖励无色
							number = 7 //7个
							rewardAmount = rewardAmount * 7 //点券奖励7点	
							api_GameWorld_SendNotiPacketMessage('--------------喜从天降--------------\n恭喜玩家[' + api_CUserCharacInfo_getCurCharacName(user) + ']在' + dgnname[charac_no] + '爆出7黄\n☆奖励☆[点券+' + rewardAmount + ']\n☆奖励☆[' + api_CItem_GetItemName( ss_reward)+ 'x' + number + ']', 14);
							sendRewardsByWindow(user, [ ss_reward, number]);//发放道具奖励
							api_recharge_cash_cera(user, rewardAmount);//发放点券奖励
							}
					 else if (userCounters[charac_no] == 8) //如果个人在副本中获得史诗装备8件
							{
							 ss_reward = 3037 //奖励无色
							number = 8 //8个
							rewardAmount = rewardAmount * 8 //点券奖励9点	
							api_GameWorld_SendNotiPacketMessage('--------------千载难逢--------------\n恭喜玩家[' + api_CUserCharacInfo_getCurCharacName(user) + ']在' + dgnname[charac_no] + '爆出8黄\n☆奖励☆[点券+' + rewardAmount + ']\n☆奖励☆[' + api_CItem_GetItemName( ss_reward)+ 'x' + number + ']', 14);
							sendRewardsByWindow(user, [ ss_reward, number]);//发放道具奖励
							api_recharge_cash_cera(user, rewardAmount);//发放点券奖励
							}
					 else if (userCounters[charac_no] == 9) //如果个人在副本中获得史诗装备9件
							{
							 ss_reward = 3037 //奖励无色
							number = 9 //9个
							rewardAmount = rewardAmount * 9 //点券奖励9点	
							api_GameWorld_SendNotiPacketMessage('--------------万中无一--------------\n恭喜玩家[' + api_CUserCharacInfo_getCurCharacName(user) + ']在' + dgnname[charac_no] + '爆出9黄\n☆奖励☆[点券+' + rewardAmount + ']\n☆奖励☆[' + api_CItem_GetItemName( ss_reward)+ 'x' + number + ']', 14);
							sendRewardsByWindow(user, [ ss_reward, number]);//发放道具奖励
							api_recharge_cash_cera(user, rewardAmount);//发放点券奖励
							}
					 else if (userCounters[charac_no] == 10) //如果个人在副本中获得史诗装备10件
							{
							 ss_reward = 3037 //奖励无色
							number = 10 //10个
							rewardAmount = rewardAmount * 10 //点券奖励10点
							api_GameWorld_SendNotiPacketMessage('--------------披靡众生--------------\n恭喜玩家[' + api_CUserCharacInfo_getCurCharacName(user) + ']在' + dgnname[charac_no] + '爆出10黄\n☆奖励☆[点券+' + rewardAmount + ']\n☆奖励☆[' + api_CItem_GetItemName( ss_reward)+ 'x' + number + ']', 14);
							sendRewardsByWindow(user, [ ss_reward, number]);//发放道具奖励
							api_recharge_cash_cera(user, rewardAmount);//发放点券奖励
							}
							
						if (userCounters[charac_no] == undefined)
							{
							userCounters[charac_no]=0
							}
							else
							{
							console.log(identification + api_CUserCharacInfo_getCurCharacName(user) + ']退出副本[' + dgnname[charac_no] + ']多黄判定次数:[' + userCounters[charac_no] + ']次，归零!');//添加日志
							userCounters[charac_no] = 0;//退出副本时清空当前角色的多黄判定次数
							}
					*/
				}

				if (game_event == 'DungeonEnter') {


					dungeonTimeRecords[charac_no] = timeToSeconds(time_hh_mm_ss); // 记录角色进入副本时间
					var charac_no = CUserCharacInfo_getCurCharacNo(user);
					dgnname[charac_no] = group[14];//记录进入副本名字
					dgndifficulty[charac_no] = group[15];



					var charac_no = CUserCharacInfo_getCurCharacNo(user);
					DGN_ID[charac_no] = getDungeonIdxAfterClear(user);
					Clear_all_records(user)

					/* var dgn_id = getDungeonIdxAfterClear(user);
					if (dgn_id <= 88 && dgn_id >= 82) {
						Add_lucky_draw(user, dgn_id);
					} */

				}

				//离开副本
				if (game_event == 'DungeonLeave') {
					//刷完副本后, 重置异界+极限祭坛次数
					// CUser_DimensionInoutUpdate(user, 1, 1);

					// 自动修理
					repair_equ(user);
				}


			},
			onLeave: function (retval) {
			}
		});
}

//回城自动修理
var CEquipItem_get_endurance = new NativeFunction(ptr(0x0811ED98), 'int', ['pointer'], { 'abi': 'sysv' });
function repair_equ(user) {
	//遍历身上的装备
	var inven = CUserCharacInfo_getCurCharacInvenW(user);
	for (var slot = 10; slot <= 21; slot++) {
		var item = CInventory_GetInvenRef(inven, INVENTORY_TYPE_BODY, slot);
		var item_id = Inven_Item_getKey(item);
		if (item_id) {
			var item_data = CDataManager_find_item(G_CDataManager(), item_id);
			var durability_max = CEquipItem_get_endurance(item_data);
			item.add(11).writeU16(durability_max);
			CUser_SendUpdateItemList(user, 1, 3, slot)
		}
	}
	for (var slot = 3; slot <= 8; slot++) {
		var item = CInventory_GetInvenRef(inven, INVENTORY_TYPE_ITEM, slot);
		var item_id = Inven_Item_getKey(item);
		if (item_id) {
			var item_data = CDataManager_find_item(G_CDataManager(), item_id);
			var durability_max = CEquipItem_get_endurance(item_data);
			item.add(11).writeU16(durability_max);
		}
	}
	api_CUser_SendNotiPacketMessage(user, '通知 ： 装备已经修复', 6);
	CUser_send_itemspace(user, ENUM_ITEMSPACE_INVENTORY);
}

//播报
function Prompt_end_of_dungeon(user) {
	var charac_no = CUserCharacInfo_getCurCharacNo(user); // 获取当前角色编号
	var hasAcquiredItems = globalData.acquiredItems[charac_no] && Object.keys(globalData.acquiredItems[charac_no]).length > 0;
	var totalEpicCount = 0;
	if (globalData.epicItems[charac_no]) {
		for (var epicItemName in globalData.epicItems[charac_no]) {
			if (globalData.epicItems[charac_no].hasOwnProperty(epicItemName)) {
				totalEpicCount += globalData.epicItems[charac_no][epicItemName];
			}
		}
	}
	var hasEpicItems = totalEpicCount >= 1;

	if (hasAcquiredItems || hasEpicItems) {
		api_SendHyperLinkChatMsg_emoji(user,
			[
				['str', '玩家 ： ', [255, 255, 0, 255]],
				['str', '[' + api_CUserCharacInfo_getCurCharacName(user) + ']', [255, 0, 255, 255]],
				['str', ' 在 ', [255, 255, 0, 255]],
				['str', '[' + api_CDungeon_getDungeonName(DGN_ID[charac_no]) + ']', [255, 0, 128, 255]],
			], 14, 0, 0);
		if (hasAcquiredItems) {
			var firstItem = true;

			for (var item_id in globalData.acquiredItems[charac_no]) {
				if (globalData.acquiredItems[charac_no].hasOwnProperty(item_id)) {
					if (firstItem) {
						api_SendHyperLinkChatMsg_emoji(user,
							[
								['str', '爆出 ： ', [255, 255, 0, 255]],
								['item', parseInt(item_id), [255, 170, 0, 255]],
								['str', ' x' + globalData.acquiredItems[charac_no][item_id] + '', [255, 255, 0, 255]]
							], 14, 0, 0);
						firstItem = false;
					}
					else {
						api_SendHyperLinkChatMsg_emoji(user,
							[
								['str', '     - ', [255, 255, 0, 255]],
								['item', parseInt(item_id), [255, 170, 0, 255]],
								['str', ' x' + globalData.acquiredItems[charac_no][item_id] + '', [255, 255, 0, 255]]
							], 14, 0, 0);
					}
				}
			}
		}
		if (hasEpicItems) {
			if (totalEpicCount == 2) //SS数量
			{
				/* api_SendHyperLinkChatMsg_emoji(user, 
				[
					['str', '奖励', [255, 255, 0, 255]],
					['str', '' + (totalEpicCount * 250) + '', [255, 255, 255, 255]],
					['str', '点卷', [255, 255, 0, 255]]
				], 14, 0, 0);
				api_recharge_cash_cera(user, (totalEpicCount * 250))//点卷数量

				//奖励道具
				api_CUser_Rarity_Item(user,'获得',3330,5);
				*/
				totalEpicCount = 0;
			}
			if (totalEpicCount == 3) {
				/* api_SendHyperLinkChatMsg_emoji(user, 
				[
					['str', '       奖励', [255, 255, 0, 255]],
					['str', '' + (totalEpicCount * 250) + '', [255, 255, 255, 255]],
					['str', '点卷', [255, 255, 0, 255]]
				], 14, 0, 0);
				api_recharge_cash_cera(user, (totalEpicCount * 250))

				api_CUser_Rarity_Item(user,'获得',3330,5); */

				totalEpicCount = 0;
			}
			if (totalEpicCount == 4) {
				/* api_SendHyperLinkChatMsg_emoji(user, 
				[
					['str', '       奖励', [255, 255, 0, 255]],
					['str', '' + (totalEpicCount * 250) + '', [255, 255, 255, 255]],
					['str', '点卷', [255, 255, 0, 255]]
				], 14, 0, 0);
				api_recharge_cash_cera(user, (totalEpicCount * 250))

				api_CUser_Rarity_Item(user,'获得',3330,5); */

				totalEpicCount = 0;
			}
			if (totalEpicCount >= 5) {
				/* api_SendHyperLinkChatMsg_emoji(user, 
				[
					['str', '       奖励', [255, 255, 0, 255]],
					['str', '' + (totalEpicCount * 0) + '', [255, 255, 255, 255]],
					['str', '点卷', [255, 255, 0, 255]]
				], 14, 0, 0);
				api_recharge_cash_cera(user, (totalEpicCount * 0))

				api_CUser_Rarity_Item(user,'获得',3330,5); */

				totalEpicCount = 0;
			}
		}
	}
}

function Clear_all_records(user) {
	var charac_no = CUserCharacInfo_getCurCharacNo(user); // 获取当前角色编号
	// 清理记录的道具数据
	if (globalData.acquiredItems[charac_no]) {
		delete globalData.acquiredItems[charac_no];
	}
	if (globalData.epicItems[charac_no]) {
		delete globalData.epicItems[charac_no];
	}
}

function api_CUser_SendNotiPacketMessage_quest(user, quest, msg, msg_type) {
	var user_quest = CUser_getCurCharacQuestW(user);
	var WongWork_CQuestClear = user_quest.add(4);
	var quest_id = WongWork_CQuestClear_isClearedQuest(WongWork_CQuestClear, quest);
	if (quest_id) {
		api_GameWorld_SendNotiPacketMessage(msg, msg_type);
	}
}

function api_Event_data_quest(user) {
	var value = null;
	var charac_no = CUserCharacInfo_getCurCharacNo(user); //角色id
	if (api_MySQL_exec(mysql_personal_production, "select quest from joyclub_vip where charac_no=" + charac_no + ";")) {
		if (MySQL_get_n_rows(mysql_personal_production) == 1) {
			if (MySQL_fetch(mysql_personal_production)) {
				value = api_MySQL_get_int(mysql_personal_production, 0);
			}
		}
	}
	return value;
}


var level_reward_items =
{
	//等级：[金币,[[物品,数量],[物品,数量]]]
	60: [0, [[3037, 1], [3038, 1], [3039, 1]]],
	70: [0, [[3037, 1], [3038, 1], [3039, 1]]]
}

/**升级邮件奖励 */
function level_reward(user) {
	//角色编号
	var charac_no = CUserCharacInfo_getCurCharacNo(user);
	//角色等级
	var level = CUserCharacInfo_get_charac_level(user);
	if (level_reward_items.hasOwnProperty(level)) {
		var items = level_reward_items[level];
		api_WongWork_CMailBoxHelper_ReqDBSendNewSystemMultiMail(charac_no, '系统', '恭喜您达到Lv.' + level + '，这是您当前阶段的奖励，感谢您的支持与厚爱。', items[0], items[1]);
	}
}


// 发放奖励
function sendRewardsByWindow(user, reward) {
	api_CUser_Add_Item_list(user, [[ss_reward, number]]);
}

/*添加道具到背包(数组)*/
function api_CUser_Add_Item_list(user, item_list) {
	for (var i in item_list) {
		api_CUser_AddItem(user, item_list[i][0], item_list[i][1]) //背包增加道具
	}
	SendItemWindowNotification(user, item_list);
}
/*获取道具时使用ui显示*/
function SendItemWindowNotification(user, item_list) {
	var packet_guard = api_PacketGuard_PacketGuard();
	InterfacePacketBuf_put_header(packet_guard, 1, 163); //协议 ENUM_NOTIPACKET_POWER_WAR_PROLONG
	InterfacePacketBuf_put_byte(packet_guard, 1); //默认1
	InterfacePacketBuf_put_short(packet_guard, 0); //槽位id 填入0即可
	InterfacePacketBuf_put_int(packet_guard, 0); //未知 0以上即可
	InterfacePacketBuf_put_short(packet_guard, item_list.length); //道具组数
	//写入道具代码和道具数量
	for (var i = 0; i < item_list.length; i++) {
		InterfacePacketBuf_put_int(packet_guard, item_list[i][0]); //道具代码
		InterfacePacketBuf_put_int(packet_guard, item_list[i][1]); //道具数量 装备/时装时 任意均可
	}
	InterfacePacketBuf_finalize(packet_guard, 1); //确定发包内容
	CUser_Send(user, packet_guard); //发包
	Destroy_PacketGuard_PacketGuard(packet_guard); //清空buff区
}

var userCounters = {}; // 在函数外部定义
function countQuality4EquipsInCurrentInstance(user, charac_no) {

	if (!userCounters[charac_no]) {
		userCounters[charac_no] = 0;
	}

	userCounters[charac_no]++;
	console.log('Cid[' + charac_no + ']', userCounters[charac_no]);

	return userCounters[charac_no];
}




function timeToSeconds(timeString) {
	// 将时间字符串拆分为小时、分钟和秒
	var hours = parseInt(timeString.substring(0, 2));
	var minutes = parseInt(timeString.substring(2, 4));
	var seconds = parseInt(timeString.substring(4, 6));
	// 将时间转换为秒数
	var totalSeconds = hours * 3600 + minutes * 60 + seconds;
	return totalSeconds;
}



//地下城拾取物品播报

// * @param item_id 物品ID

// * @param user 用户

// * @param award_item_id 奖励物品ID

// * @param award_item_count 奖励物品数量

// * @param count 点卷数量

function processing_data(item_id, user, award_item_id, award_item_count, count) {

	//获取在线玩家数量

	var online_player_cnt = GameWorld_get_UserCount_InWorld(G_GameWorld());

	//在线玩家数量大于0

	if (online_player_cnt > 0) {

		var o_user = null;

		var it = api_gameworld_user_map_begin();

		var end = api_gameworld_user_map_end();

		while (gameworld_user_map_not_equal(it, end)) {//遍历所有玩家

			//判断在线玩家列表遍历是否已结束

			if (CUser_get_state(user) >= 3) {

				//当前被遍历到的玩家

				o_user = api_gameworld_user_map_get(it);

				const itemName = api_CItem_GetItemName(item_id);

				if (award_item_id != 0 && count != 0) {

					api_CUser_SendNotiPacketMessage(o_user, "恭喜玩家<" + "" + api_CUserCharacInfo_getCurCharacName(user) + "" + ">在地下城中获得了[" + itemName + "]，奖励：☆" + api_CItem_GetItemName(award_item_id) + "☆，奖励D点：" + count, 14);

					api_CUser_AddItem(user, award_item_id, award_item_count);

					api_recharge_cash_cera(user, count);

				}

				CUser_send_itemspace(user, INVENTORY_TYPE_ITEM);

				//继续遍历下一个玩家

				api_gameworld_user_map_next(it);

			}

		}

	}

}




/*
function processing_data(item_id, user, award_item_id, award_item_count, count) {

	const itemName = api_CItem_GetItemName(item_id);
	if (award_item_id == 0 && count != 0) {
	
	api_GameWorld_SendNotiPacketMessage("恭喜玩家<" +
	"" + api_CUserCharacInfo_getCurCharacName(user) + "" +
	">在地下城中获得了[" + itemName + "]，奖励点券：☆" + count + "☆", 14);
	
	api_recharge_cash_cera(user, count);
	}
	
	if (award_item_id != 0 && count == 0) {
	
	api_GameWorld_SendNotiPacketMessage("恭喜玩家<" +
	"" + api_CUserCharacInfo_getCurCharacName(user) + "" +
	">在地下城中获得了[" + itemName + "]，奖励：☆" + api_CItem_GetItemName(award_item_id) + award_item_count+"个☆", 14);
	
	api_CUser_AddItem(user, award_item_id, award_item_count);
	}
	
	if (award_item_id != 0 && count != 0) {
	
	api_GameWorld_SendNotiPacketMessage("恭喜玩家<" +
	"" + api_CUserCharacInfo_getCurCharacName(user) + "" +
	">在地下城中获得了[" + itemName + "]，奖励：☆" + api_CItem_GetItemName(award_item_id) + "☆，奖励点券：" + count, 14);
	
	api_CUser_AddItem(user, award_item_id, award_item_count);
	
	api_recharge_cash_cera(user, count);
	//api_recharge_cash_cera_point(user, count);
	}
	
	
	CUser_send_itemspace(user, INVENTORY_TYPE_ITEM);
	
	}
	
	*/



//--------此为旧版，非彩色播报----------------------------------------------------------------------
/*
function vip_Login() {
	Interceptor.attach(ptr(0x86C4E50), {
		onEnter: function (args) {
			this.user = args[1];
		},
		onLeave: function (retval) {
			var user = this.user;
			var quest_ids1 = getQuestIds1();
			var quest_ids2 = getQuestIds2();
			var quest_ids3 = getQuestIds3();
			var quest_ids4 = getQuestIds4();
			var quest_ids5 = getQuestIds5();
			var completedQuests1 = Inspection_tasks(user, quest_ids1);
			var completedQuests2 = Inspection_tasks(user, quest_ids2);
			var completedQuests3 = Inspection_tasks(user, quest_ids3);
			var completedQuests4 = Inspection_tasks(user, quest_ids4);
			var completedQuests5 = Inspection_tasks(user, quest_ids5);
			if ( completedQuests5 > 0 ) //判断任务代码5是否是完成的状态，如果是则播报且跳过后续判定
				{
				api_GameWorld_SendNotiPacketMessage('尊贵的心悦Vip5玩家[' + api_CUserCharacInfo_getCurCharacName(this.user) + ']上线了！！！', 14);
				}
			else if ( completedQuests4 > 0 ) //判断任务代码4是否是完成的状态，如果是则播报且跳过后续判定
				{
				api_GameWorld_SendNotiPacketMessage('尊贵的心悦Vip4玩家[' + api_CUserCharacInfo_getCurCharacName(this.user) + ']上线了！！！', 14);
				}
			else if ( completedQuests3 > 0 ) //判断任务代码3是否是完成的状态，如果是则播报且跳过后续判定
				{
				api_GameWorld_SendNotiPacketMessage('尊贵的心悦Vip3玩家[' + api_CUserCharacInfo_getCurCharacName(this.user) + ']上线了！！！', 14);
				}
			else if ( completedQuests2 > 0 ) //判断任务代码2是否是完成的状态，如果是则播报且跳过后续判定
				{
				api_GameWorld_SendNotiPacketMessage('尊贵的心悦Vip2玩家[' + api_CUserCharacInfo_getCurCharacName(this.user) + ']上线了！！！', 14);
				}
			else if ( completedQuests1 > 0 ) //判断任务代码1是否是完成的状态，如果是则播报
				{
				api_GameWorld_SendNotiPacketMessage('尊贵的心悦Vip1玩家[' + api_CUserCharacInfo_getCurCharacName(this.user) + ']上线了！！！', 14);
				}
		}
	});
}

function getQuestIds1() {//任务代码1
	return [4414];
}
function getQuestIds2() {//任务代码2
	return [4415];
}
function getQuestIds3() {//任务代码3
	return [4416];
}
function getQuestIds4() {//任务代码4
	return [4417];
}
function getQuestIds5() {//任务代码5
	return [4418];
}

function Inspection_tasks(user, quest_ids) {
	var WongWork_CQuestClear = CUser_getCurCharacQuestW(user).add(4);
	var completedQuests = [];
    
	for (var i = 0; i < quest_ids.length; i++) {
		var quest_id = quest_ids[i];
		if (WongWork_CQuestClear_isClearedQuest(WongWork_CQuestClear, quest_id)) {
			completedQuests.push(quest_id);
		}
	}
    
	return completedQuests;
}
*/
//------------------------------------------------------------------------------------------------


function GetHighestRankZLZ() {
	var highestZLZ = -1;
	var selectQuery = "SELECT ZLZ FROM d_starsky.zhanli";
	if (api_MySQL_exec(mysql_taiwan_cain, selectQuery)) {
		var numRows = MySQL_get_n_rows(mysql_taiwan_cain);
		for (var i = 0; i < numRows; i++) {
			MySQL_fetch(mysql_taiwan_cain);
			var zlz = parseInt(api_MySQL_get_str(mysql_taiwan_cain, 0));
			if (zlz > highestZLZ) {
				highestZLZ = zlz;
			}
		}
	}
	return highestZLZ;
}

function GetTopThreeZLZ() {
	var topThreeZLZ = [-1, -1, -1];
	var selectQuery = "SELECT ZLZ FROM d_starsky.zhanli ORDER BY ZLZ DESC LIMIT 3";
	if (api_MySQL_exec(mysql_taiwan_cain, selectQuery)) {
		var numRows = MySQL_get_n_rows(mysql_taiwan_cain);
		for (var i = 0; i < numRows && i < 3; i++) {
			MySQL_fetch(mysql_taiwan_cain);
			var zlz = parseInt(api_MySQL_get_str(mysql_taiwan_cain, 0));
			topThreeZLZ[i] = zlz;
		}
	}
	return topThreeZLZ;
}


//角色登入登出处理
function hook_user_inout_game_world() {
	//选择角色处理函数 Hook GameWorld::reach_game_world
	Interceptor.attach(ptr(0x86C4E50),
		{
			//函数入口, 拿到函数参数args
			onEnter: function (args) {
				//保存函数参数
				this.user = args[1];
				//console.log('[GameWorld::reach_game_world] this.user=' + this.user);
			},
			//原函数执行完毕, 这里可以得到并修改返回值retval
			onLeave: function (retval) {
				//use_ftcoin_change_luck_point(this.user); //开启幸运点
				console.log('hook_user_inout_game_world——villageAttackEventInfo.state=' + villageAttackEventInfo.state);
				/*			
								//怪物攻城活动更新进度
								if (villageAttackEventInfo.state != VILLAGEATTACK_STATE_END) {
									//通知客户端打开活动UI
									notify_villageattack_score(this.user);
									//公告通知客户端活动进度
									event_villageattack_broadcast_diffcult();
								}
				*/
				//给角色发消息问候
				//api_CUser_SendNotiPacketMessage(this.user, 'Hi,Boy ' + api_CUserCharacInfo_getCurCharacName(this.user), 2);

				//全服播报玩家上线
				api_GameWorld_SendNotiPacketMessage('玩家[' + api_CUserCharacInfo_getCurCharacName(this.user) + ']上线了！！！', 12);
				/*
//指定角色进入游戏后全服播报---------------------------------------------------------------------------				
				if (api_CUserCharacInfo_getCurCharacName(this.user) == '测试1') //如果角色名称=测试1
				{
				api_GameWorld_SendNotiPacketMessage('尊贵的战力排行榜-榜一大佬[' + api_CUserCharacInfo_getCurCharacName(this.user) + ']上线了！！！', 12);//全服播报
				} 
				else if (api_CUserCharacInfo_getCurCharacName(this.user) == '测试2') //如果角色名称=测试2
				{
				api_GameWorld_SendNotiPacketMessage('尊贵的战力排行榜-榜二大佬[' + api_CUserCharacInfo_getCurCharacName(this.user) + ']上线了！！！', 12);//全服播报
				} 
				else if (api_CUserCharacInfo_getCurCharacName(this.user) == '测试3') //如果角色名称=测试2
				{
				api_GameWorld_SendNotiPacketMessage('尊贵的战力排行榜-榜三大佬[' + api_CUserCharacInfo_getCurCharacName(this.user) + ']上线了！！！', 12);//全服播报
				} 
//指定角色进入游戏后全服播报---------------------------------------------------------------------------		*/

				//榜一榜二进入游戏后全服播报（包含携带武器）---------------------------------------------------------------------------	
				var inven = CUserCharacInfo_getCurCharacInvenW(this.user);
				var equ = CInventory_GetInvenRef(inven, INVENTORY_TYPE_BODY, 10);
				var itemId = Inven_Item_getKey(equ)
				var inItemData = CDataManager_find_item(G_CDataManager(), itemId);
				var inEqu_type = inItemData.add(141 * 4).readU32();
				var inEquRarity = CItem_GetRarity(inItemData);
				var inNeedLevel = CItem_GetUsableLevel(inItemData);
				var upgrade_level = equ.add(6).readU8();
				var wuqiming = api_CItem_GetItemName(itemId);
				var charac_no = CUserCharacInfo_getCurCharacNo(this.user);
				var myzhanli = GetRankNumber(charac_no);
				var highzhanli = GetHighestRankZLZ();
				var diyiming = GetTopThreeZLZ()[0];
				var dierming = GetTopThreeZLZ()[1];
				var disanming = GetTopThreeZLZ()[2];

				if (highzhanli == myzhanli) {
					var charac_no = CUserCharacInfo_getCurCharacNo(this.user);
					var charac_name = api_CUserCharacInfo_getCurCharacName(this.user);
					api_SendHyperLinkChatMsg_emoji(this.user, [
						['str', '本服最高战力玩家  ', [230, 200, 156, 255]],
						['str', '[ ' + charac_name + ' ]', [88, 92, 129, 255]],
						['str', ' 携带 ', [230, 200, 156, 255]],
						['str', '[ +' + upgrade_level + ' ' + wuqiming + ' ]', [88, 92, 129, 255]],
						['str', '  上线了！', [230, 200, 156, 255]],
					], 14, 0, 0);
				}

				if (dierming == myzhanli) {
					var charac_no = CUserCharacInfo_getCurCharacNo(this.user);
					var charac_name = api_CUserCharacInfo_getCurCharacName(this.user);
					api_SendHyperLinkChatMsg_emoji(this.user, [
						['str', '榜二玩家', [230, 200, 156, 255]],
						['str', '[' + charac_name + ']', [88, 92, 129, 255]],
						['str', '携带', [230, 200, 156, 255]],
						['str', '[+' + upgrade_level + ' ' + wuqiming + ']', [88, 92, 129, 255]],
						['str', '上线了', [230, 200, 156, 255]],
					], 14, 0, 35);
				}
				//榜一榜二进入游戏后全服播报（包含携带武器）---------------------------------------------------------------------------	


				var charac_no = CUserCharacInfo_getCurCharacNo(this.user);

				if (api_joyclub_vip(this.user) == 1) {
					api_SendHyperLinkChatMsg_emoji(this.user,
						[
							['str', '欢迎尊贵的', [255, 255, 0, 255]],
							['str', '[心悦' + api_joyclub_vip(this.user) + ']', [158, 247, 69, 255]],
							['str', '玩家', [255, 255, 0, 255]],
							['str', '[' + api_CUserCharacInfo_getCurCharacName(this.user) + ']', [158, 247, 69, 255]],
						], 14, 0, 36);
				}
				if (api_joyclub_vip(this.user) == 2) {
					api_SendHyperLinkChatMsg_emoji(this.user,
						[
							['str', '欢迎尊贵的', [255, 255, 0, 255]],
							['str', '[心悦' + api_joyclub_vip(this.user) + ']', [65, 118, 251, 255]],
							['str', '玩家', [255, 255, 0, 255]],
							['str', '[' + api_CUserCharacInfo_getCurCharacName(this.user) + ']', [65, 118, 251, 255]],
						], 14, 0, 37);
				}
				if (api_joyclub_vip(this.user) == 3) {
					api_SendHyperLinkChatMsg_emoji(this.user,
						[
							['str', '欢迎尊贵的', [255, 255, 0, 255]],
							['str', '[心悦' + api_joyclub_vip(this.user) + ']', [250, 89, 0, 255]],
							['str', '玩家', [255, 255, 0, 255]],
							['str', '[' + api_CUserCharacInfo_getCurCharacName(this.user) + ']', [250, 89, 0, 255]],
						], 14, 0, 38);
				}

				api_scheduleOnMainThread(SendRankLits, [this.user, true]); //战力榜相关
			}
		});
	//角色退出时处理函数 Hook GameWorld::leave_game_world
	Interceptor.attach(ptr(0x86C5288),
		{
			onEnter: function (args) {
				var user = args[1];
				SetRanking(user); //战力榜相关

			},
			onLeave: function (retval) { }
		});

	/*		
	   //角色退出时处理函数 Hook CGameManager::user_exit  金库扩容这里要开启
	   Interceptor.attach(ptr(0x082985a8), {
	
		onEnter: function (args) {
	
			var user = args[1];
			this.user = user;
			console.log('[CGameManager::user_exit] user=' + user);
		},
		onLeave: function (retval) {
			var accId = CUser_get_acc_id(this.user);
			// 清除账号仓库 释放空间
			if(accountCargfo[accId]){
				delete accountCargfo[accId];
				// console.log('clean accountCargfo accId:'+accId)
			}
		}
	});
	
	*/


}

//怪物攻城副本回调奖励处理函数
function VillageAttackedRewardSendReward(user) {
	var VAttackCount = GetCurVAttackCount(user);
	switch (VAttackCount) {
		case 1:
			CMailBoxHelperReqDBSendNewSystemMail(user, 3037, 5);
			break;
		case 2:
			CMailBoxHelperReqDBSendNewSystemMail(user, 3037, 5);
			break;
		case 3:
			CMailBoxHelperReqDBSendNewSystemMail(user, 3037, 10);
			break;
		case 4:
			CMailBoxHelperReqDBSendNewSystemMail(user, 1085, 2);
			break;
		case 5:
			CMailBoxHelperReqDBSendNewSystemMail(user, 1085, 5);
			break;
		case 6:
			CMailBoxHelperReqDBSendNewSystemMail(user, 1085, 2);
			break;
		case 7:
			CMailBoxHelperReqDBSendNewSystemMail(user, 8, 2);
			break;
		case 8:
			CMailBoxHelperReqDBSendNewSystemMail(user, 8, 5);
			break;
		case 9:
			CMailBoxHelperReqDBSendNewSystemMail(user, 8, 2);
			break;
		case 10:
			CMailBoxHelperReqDBSendNewSystemMail(user, 36, 1);
			break;
		case 11:
			CMailBoxHelperReqDBSendNewSystemMail(user, 36, 1);
			break;
		case 12:
			CMailBoxHelperReqDBSendNewSystemMail(user, 15, 1);
			break;
		case 13:
			CMailBoxHelperReqDBSendNewSystemMail(user, 15, 1);
			break;
		case 14:
			CMailBoxHelperReqDBSendNewSystemMail(user, 1031, 1);
			break;
		case 15:
			CMailBoxHelperReqDBSendNewSystemMail(user, 3262, 2);
			break;
		case 16:
			CMailBoxHelperReqDBSendNewSystemMail(user, 3262, 3);
			break;
		case 17:
			CMailBoxHelperReqDBSendNewSystemMail(user, 2600261, 1);
			break;
		case 18:
			CMailBoxHelperReqDBSendNewSystemMail(user, 2600261, 1);
			break;
		case 19:
			CMailBoxHelperReqDBSendNewSystemMail(user, 3037, 5);
			break;
		case 20:
			CMailBoxHelperReqDBSendNewSystemMail(user, 1085, 2);
			break;
		case 21:
			CMailBoxHelperReqDBSendNewSystemMail(user, 8, 2);
			break;
		case 22:
			CMailBoxHelperReqDBSendNewSystemMail(user, 1085, 2);
			break;
		case 23:
			CMailBoxHelperReqDBSendNewSystemMail(user, 8, 5);
			break;
		case 24:
			CMailBoxHelperReqDBSendNewSystemMail(user, 15, 1);
			break;
		case 25:
			CMailBoxHelperReqDBSendNewSystemMail(user, 15, 2);
			break;
		case 26:
			CMailBoxHelperReqDBSendNewSystemMail(user, 3262, 5);
			break;
		case 27:
			CMailBoxHelperReqDBSendNewSystemMail(user, 3262, 2);
			break;
		case 28:
			CMailBoxHelperReqDBSendNewSystemMail(user, 10000160, 1);
			break;
		case 29:
			CMailBoxHelperReqDBSendNewSystemMail(user, 1085, 2);
			break;
		case 30:
			CMailBoxHelperReqDBSendNewSystemMail(user, 8, 2);
			break;
		case 31:
			CMailBoxHelperReqDBSendNewSystemMail(user, 3037, 5);
			break;
		case 32:
			CMailBoxHelperReqDBSendNewSystemMail(user, 3037, 5);
			break;
		case 33:
			CMailBoxHelperReqDBSendNewSystemMail(user, 8, 2);
			break;
		case 34:
			CMailBoxHelperReqDBSendNewSystemMail(user, 1085, 2);
			break;
		case 35:
			CMailBoxHelperReqDBSendNewSystemMail(user, 2600261, 1);
			break;
		case 36:
			CMailBoxHelperReqDBSendNewSystemMail(user, 10000161, 1);
			break;
		default:
			CMailBoxHelperReqDBSendNewSystemMail(user, 3037, 5);
	}
}

//增加魔法封印装备的魔法封印等级
function _boost_random_option_equ(inven_item) {
	//空装备
	if (Inven_Item_isEmpty(inven_item))
		return false;
	//获取装备当前魔法封印属性
	var random_option = inven_item.add(37);
	//随机选取一个词条槽
	var random_option_slot = get_random_int(0, 3);
	//若词条槽已有魔法封印
	if (random_option.add(3 * random_option_slot).readU8()) {
		//每个词条有2个属性值
		var value_slot = get_random_int(1, 3);
		//当前词条等级
		var random_option_level = random_option.add(3 * random_option_slot + value_slot).readU8();
		if (random_option_level < 0xFF) {
			//1%概率词条等级+1
			if (get_random_int(random_option_level, 100000) < 1000) {
				random_option.add(3 * random_option_slot + value_slot).writeU8(random_option_level + 1);
				return true;
			}
		}
	}
	return false;
}

//穿戴中的魔法封印装备词条升级
function boost_random_option_equ(user) {
	//遍历身上的装备 为拥有魔法封印属性的装备提升魔法封印等级
	var inven = CUserCharacInfo_getCurCharacInvenW(user);
	for (var slot = 10; slot <= 21; slot++) {
		var inven_item = CInventory_GetInvenRef(inven, INVENTORY_TYPE_BODY, slot);
		if (_boost_random_option_equ(inven_item)) {
			//通知客户端更新
			CUser_SendUpdateItemList(user, 1, 3, slot);
		}
	}
}

//魔法封印属性转换时可以继承
function change_random_option_inherit() {
	//random_option::CRandomOptionItemHandle::change_option
	Interceptor.attach(ptr(0x85F3340),
		{
			onEnter: function (args) {
				//保存原始魔法封印属性
				this.random_option = args[7];
				//本次变换的属性编号
				this.change_random_option_index = args[6].toInt32();
				//记录原始属性
				this.random_optio_type = this.random_option.add(3 * this.change_random_option_index).readU8();
				this.random_optio_value_1 = this.random_option.add(3 * this.change_random_option_index + 1).readU8();
				this.random_optio_value_2 = this.random_option.add(3 * this.change_random_option_index + 2).readU8();
			},
			onLeave: function (retval) {
				//魔法封印转换成功
				if (retval == 1) {
					//获取未被附魔的魔法封印槽
					var index = -1;
					if (this.random_option.add(0).readU8() == 0)
						index = 0;
					else if (this.random_option.add(3).readU8() == 0)
						index = 1;
					else if (this.random_option.add(6).readU8() == 0)
						index = 2;

					//当魔法封印词条不足3个时, 若变换出等级极低的属性, 可直接附魔到装备空的魔法封印槽内
					if (index >= 0) {
						if ((this.random_option.add(11).readU8() <= 5) && (this.random_option.add(12).readU8() <= 5)) {
							//魔法封印附魔
							this.random_option.add(3 * index).writeU8(this.random_option.add(10).readU8());
							this.random_option.add(3 * index + 1).writeU8(this.random_option.add(11).readU8());
							this.random_option.add(3 * index + 2).writeU8(this.random_option.add(12).readU8());

							//清空本次变换的属性(可以继续选择其他词条变换)
							this.random_option.add(10).writeInt(0);

							return;
						}
					}
					//用变换后的词条覆盖原始魔法封印词条
					this.random_option.add(3 * this.change_random_option_index).writeU8(this.random_option.add(10).readU8());
					//若变换后的属性低于原来的值 则继承原有属性值 否则使用变换后的属性
					if (this.random_option.add(11).readU8() > this.random_optio_value_1)
						this.random_option.add(3 * this.change_random_option_index + 1).writeU8(this.random_option.add(11).readU8());
					if (this.random_option.add(12).readU8() > this.random_optio_value_2)
						this.random_option.add(3 * this.change_random_option_index + 2).writeU8(this.random_option.add(12).readU8());
					//清空本次变换的属性(可以继续选择其他词条变换)
					this.random_option.add(10).writeInt(0);
				}
			}
		});
}

//魔法封印自动解封
function auto_unseal_random_option_equipment(user) {
	//CInventory::insertItemIntoInventory
	Interceptor.attach(ptr(0x8502D86),
		{
			onEnter: function (args) {
				this.user = args[0].readPointer();
			},
			onLeave: function (retval) {
				//物品栏新增物品的位置
				var slot = retval.toInt32();
				if (slot > 0) {
					//获取道具的角色
					var user = this.user;
					//角色背包
					var inven = CUserCharacInfo_getCurCharacInvenW(user);
					//背包中新增的道具
					var inven_item = CInventory_GetInvenRef(inven, INVENTORY_TYPE_ITEM, slot);
					//过滤道具类型
					if (!Inven_Item_isEquipableItemType(inven_item))
						return;
					//装备id
					var item_id = Inven_Item_getKey(inven_item);
					//pvf中获取装备数据
					var citem = CDataManager_find_item(G_CDataManager(), item_id);
					//检查装备是否为魔法封印类型
					if (!CEquipItem_IsRandomOption(citem))
						return;
					//是否已被解除魔法封印（魔法封印前10个字节是否为0）
					var random_option = inven_item.add(37);
					if (random_option.readU32() || random_option.add(4).readU32() || random_option.add(8).readShort()) {
						return;
					}
					//尝试解除魔法封印
					var ret = random_option_CRandomOptionItemHandle_give_option(ptr(0x941F820).readPointer(), item_id, CItem_get_rarity(citem), CItem_getUsableLevel(citem), CItem_getItemGroupName(citem), CEquipItem_GetRandomOptionGrade(citem), inven_item.add(37));
					if (ret) {
						//通知客户端有装备更新
						CUser_SendUpdateItemList(user, 1, 0, slot);
					}
				}
			}
		});
}

//幸运点上下限
var MAX_LUCK_POINT = 99999;
var MIN_LUCK_POINT = 1;

//设置角色幸运点
function api_CUserCharacInfo_SetCurCharacLuckPoint(user, new_luck_point) {
	if (new_luck_point > MAX_LUCK_POINT)
		new_luck_point = MAX_LUCK_POINT;
	else if (new_luck_point < MIN_LUCK_POINT)
		new_luck_point = MIN_LUCK_POINT;
	CUserCharacInfo_enableSaveCharacStat(user);
	CUserCharacInfo_SetCurCharacLuckPoint(user, new_luck_point);
	return new_luck_point;
}

//使用命运硬币后, 可以改变自身幸运点
//查询角色当前幸运点GM命令: //show lp
//当前角色幸运点拉满GM命令: //max lp
function use_ftcoin_change_luck_point(user) {
	//抛命运硬币
	var rand = get_random_int(0, 100);

	//当前幸运点数
	var new_luck_point = null;

	if (rand == 0) {
		//1%几率将玩家幸运点充满(最大值10W)
		new_luck_point = MAX_LUCK_POINT;
	}
	else if (rand == 1) {
		//1%几率将玩家幸运点耗尽
		new_luck_point = MIN_LUCK_POINT;
	}
	else if (rand < 51) {
		//49%几率当前幸运点增加20%
		new_luck_point = Math.floor(CUserCharacInfo_GetCurCharacLuckPoint(user) * 1.2);
	}
	else {
		//49%几率当前幸运点降低20%
		new_luck_point = Math.floor(CUserCharacInfo_GetCurCharacLuckPoint(user) * 0.8);
	}
	//修改角色幸运点
	new_luck_point = api_CUserCharacInfo_SetCurCharacLuckPoint(user, new_luck_point);
	//通知客户端当前角色幸运点已改变
	api_CUser_SendNotiPacketMessage(user, '命运已被改变, 当前幸运点数: ' + new_luck_point, 0);
}

//使用角色幸运值加成装备爆率
function enable_drop_use_luck_piont() {
	//由于roll点爆装函数拿不到user, 在杀怪和翻牌函数入口保存当前正在处理的user
	var cur_luck_user = null;
	//DisPatcher_DieMob::dispatch_sig
	Interceptor.attach(ptr(0x81EB0C4),
		{
			onEnter: function (args) {
				cur_luck_user = args[1];
			},
			onLeave: function (retval) {
				cur_luck_user = null;
			}
		});

	//CParty::SetPlayResult
	Interceptor.attach(ptr(0x85B2412),
		{
			onEnter: function (args) {
				cur_luck_user = args[1];
			},
			onLeave: function (retval) {
				cur_luck_user = null;
			}
		});

	//修改决定出货品质(rarity)的函数 使出货率享受角色幸运值加成
	//CLuckPoint::GetItemRarity
	var CLuckPoint_GetItemRarity_ptr = ptr(0x8550BE4);
	var CLuckPoint_GetItemRarity = new NativeFunction(CLuckPoint_GetItemRarity_ptr, 'int', ['pointer', 'pointer', 'int', 'int'], { "abi": "sysv" });
	Interceptor.replace(CLuckPoint_GetItemRarity_ptr, new NativeCallback(function (a1, a2, roll, a4) {
		//使用角色幸运值roll点代替纯随机roll点
		if (cur_luck_user) {
			//获取当前角色幸运值
			var luck_point = CUserCharacInfo_GetCurCharacLuckPoint(cur_luck_user);

			//roll点范围1-100W, roll点越大, 出货率越高
			//角色幸运值范围1-10W
			//使用角色 [当前幸运值*10] 作为roll点下限, 幸运值越高, roll点越大
			roll = get_random_int(luck_point * 10, 1000000);
		}
		//执行原始计算爆装品质函数
		var rarity = CLuckPoint_GetItemRarity(a1, a2, roll, a4);
		//调整角色幸运值
		if (cur_luck_user) {
			var rate = 1.0;

			//出货粉装以上, 降低角色幸运值
			if (rarity >= 3) {
				//出货品质越高, 幸运值下降约快
				rate = 1 - (rarity * 0.01);
			}
			else {
				//未出货时, 提升幸运值
				rate = 1.01;
			}
			//设置新的幸运值
			var new_luck_point = Math.floor(CUserCharacInfo_GetCurCharacLuckPoint(cur_luck_user) * rate);
			api_CUserCharacInfo_SetCurCharacLuckPoint(cur_luck_user, new_luck_point);
		}
		return rarity;
	}, 'int', ['pointer', 'pointer', 'int', 'int']));
}

//取消新账号送成长契约
function InterSelectMobileAuthReward() {
	//还原 InterSelectMobileAuthReward::dispatch_sig 函数
	var Defptr = ptr(0x08161384);
	var value = Defptr.readU8()
	if (value != 0x0F) {
		Memory.protect(Defptr, 10, 'rwx');
		Defptr.writeShort(0x840F);
	}
	//重写InterSelectMobileAuthReward::dispatch_sig 函数
	var Inter_DispatchPr = ptr(0x0816132A);
	var Inter_Dispatch = new NativeFunction(Inter_DispatchPr, 'int', ['pointer', 'pointer', 'pointer'], { "abi": "sysv" });
	Interceptor.replace(Inter_DispatchPr, new NativeCallback(function (InterSelectMobileAuthReward, CUser, a3) {
		//var Inter_DispatchOpen = true;
		var Inter_DispatchOpen = false;
		if (Inter_DispatchOpen) {
			a3.add(4).writeInt(0);
			return Inter_Dispatch(InterSelectMobileAuthReward, CUser, a3); //执行原函数发送成长契约
		}
		return 0; //取消新账号送成长契约    返回0表示正常返回
	}, 'int', ['pointer', 'pointer', 'pointer']));
}

//解除每日创建角色数量限制
function disable_check_create_character_limit() {
	//DB_CreateCharac::CheckLimitCreateNewCharac
	Interceptor.attach(ptr(0x8401922),
		{
			onEnter: function (args) {
			},
			onLeave: function (retval) {
				//强制返回允许创建
				retval.replace(1);
			}
		});
}


//角色使用道具触发事件


function UserUseItemEvent(user, item_id) {

	//代码自定义	
	if ('0' == item_id) {

		// 随机强化  装备栏第一格装备 
		randomIncrease(user)
	}


	if ('123012' == item_id) {
		// 装备回收兑换道具
		recoverEqu(user)
	}



}




//获取道具类型
var CInventory_GetItemType = new NativeFunction(ptr(0x085018D2), 'int', ['pointer', 'int'], { "abi": "sysv" });
var CInventory_check_empty_count = new NativeFunction(ptr(0x08504F64), 'int', ['pointer', 'int', 'int'], { "abi": "sysv" });
var CInventory_check_empty_count = new NativeFunction(ptr(0x08504F64), 'int', ['pointer', 'int', 'int'], { "abi": "sysv" });

var CEquipItem_getSubType = new NativeFunction(ptr(0x833eecc), 'int', ['pointer'], { "abi": "sysv" });
var CUserCharacInfo_getCurCharacInvenR = new NativeFunction(ptr(0x80DA27E), 'pointer', ['pointer'], { "abi": "sysv" });
/**---------------------------------------装备回收-----------------------------------------------------**/
var EquMap = {
	27564: [3037, 1], // 回收的道具[奖励道具ID, 数量]奖励的道具如果是装备，数量只能是1
	190108101: [100000069, 1],
	190108102: [100000070, 1],
	160929158: [100000057, 1],
	160929160: [100000128, 1],

}

function recoverEqu(user, item_id) {
	var slot = 3;//快捷栏第一格
	var inven = CUserCharacInfo_getCurCharacInvenR(user);
	var equ = CInventory_GetInvenRef(inven, INVENTORY_TYPE_ITEM, slot);
	var Item_Id = Inven_Item_getKey(equ);
	var charac_no = CUserCharacInfo_getCurCharacNo(user);
	const reward_item_lists = [];

	if (!Item_Id || CUser_CheckItemLock(user, INVENTORY_TYPE_ITEM, slot)) {
		api_CUser_SendNotiPacketMessage(user, "装备兑换失败，快捷栏第一格没有可兑换的装备或装备已上锁！", 1);
		api_scheduleOnMainThread_delay(api_CUser_AddItem, [user, item_id, 1], 1);
		return;
	}

	var reward = EquMap[Item_Id];

	if (!reward) {
		api_CUser_SendNotiPacketMessage(user, "装备兑换失败，快捷栏第一格没有可兑换的装备！", 1);
		api_scheduleOnMainThread_delay(api_CUser_AddItem, [user, item_id, 1], 1);
		return;
	}

	Inven_Item_reset(equ);
	CUser_SendUpdateItemList(user, 1, 0, slot);

	var reward_id = reward[0];
	var reward_q = reward[1];
	reward_item_lists.push([reward_id, reward_q]);

	var type = CInventory_GetItemType(inven, reward_id);
	var cnt = CInventory_check_empty_count(inven, type, 1);

	if (cnt >= 1) {
		api_CUser_AddItem(user, reward_id, reward_q);
		api_CUser_SendNotiPacketMessage(user, "       装备兑换成功 \n获得[" + api_CItem_GetItemName(reward_id) + "]", 1);
	} else {
		api_WongWork_CMailBoxHelper_ReqDBSendNewSystemMultiMail(charac_no, "<装备兑换>", "兑换成功，但您的背包已满，这是你通过邮件获得的道具。", 0, reward_item_lists);
		api_CUser_SendNotiPacketMessage(user, "空间不足！奖励已通过邮件发送！", 1);
	}
}




//强化等级和概率
function randomNumber() {
	var nums = [11, 12, 13, 14, 15, 16, 17, 18];
	var weights = [1, 0.9, 0.6, 0.3, 0.01, 0.01, 0.005, 0.001];

	var totalWeight = weights.reduce(function (a, b) {

		return a + b;

	}, 0);

	var rnd = Math.random() * totalWeight;

	var sum = 0;

	var result = null;

	for (var i = 0; i < nums.length; i++) {
		sum += weights[i];
		if (rnd < sum) {
			result = nums[i];
			break;
		}
	}
	return result;
}

function randomIncrease(user) {

	var inven = CUserCharacInfo_getCurCharacInvenW(user);
	var equ = CInventory_GetInvenRef(inven, INVENTORY_TYPE_ITEM, 9);
	var itemId = Inven_Item_getKey(equ);
	var inUpgrade_level = equ.add(6).readU8();
	var append = equ.add(17).readU16();
	var characName = api_CUserCharacInfo_getCurCharacName(user);
	var equipmentName = api_CItem_GetItemName(itemId);


	var inItemData = CDataManager_find_item(G_CDataManager(), itemId);
	var inEqu_type = inItemData.add(141 * 4).readU32();

	if (Inven_Item_getKey(equ)) {


		if (inEqu_type != 11) {
			if (equ != null) {
				if (append != null && append != 0) {
					api_CUser_SendNotiPacketMessage(user, "使用失败：此装备有异界气息！", 1);
					api_CUser_AddItem(user, 0, 1);
				} else {


					if (inUpgrade_level < 31) {
						var now = randomNumber();
						equ.add(6).writeU8(now);
						CUser_SendUpdateItemList(user, 1, 0, 9);
						api_CUser_SendNotiPacketMessage(user, "[" + [characName] + "] 强化 +" + now + " " + [equipmentName] + "成功", 0);
					} else {
						api_CUser_SendNotiPacketMessage(user, "使用失败：当前装备强化等级，已到最大限制！", 1);
						api_CUser_AddItem(user, 0, 1);
					}
				}
			}

		}

		else {
			api_CUser_SendNotiPacketMessage(user, "称号无法强化！", 1);
			api_CUser_AddItem(user, 0, 1);
		}



	}
	else {
		api_CUser_SendNotiPacketMessage(user, "装备栏无装备！", 1);
		api_CUser_AddItem(user, 0, 1);
	}
}



/**
 * 发系统邮件(多道具)
 *
 * @param target_charac_no 角色charac_no
 * @param title 邮件标题
 * @param text 邮件正文
 * @param gold 金币数量
 * @param item_list 道具列表
 */
function api_WongWork_CMailBoxHelper_ReqDBSendNewSystemMultiMail(target_charac_no, title, text, gold, item_list) {

	var vector = Memory.alloc(100);
	std_vector_std_pair_int_int_vector(vector);
	std_vector_std_pair_int_int_clear(vector);

	for (var i = 0; i < item_list.length; ++i) {
		var item_id = Memory.alloc(4);
		var item_cnt = Memory.alloc(4);
		item_id.writeInt(item_list[i][0]);
		item_cnt.writeInt(item_list[i][1]);
		var pair = Memory.alloc(100);
		std_make_pair_int_int(pair, item_id, item_cnt);
		std_vector_std_pair_int_int_push_back(vector, pair);
	}

	var addition_slots = Memory.alloc(1000);
	for (var i = 0; i < 10; ++i) {
		Inven_Item_Inven_Item(addition_slots.add(i * 61));
	}
	WongWork_CMailBoxHelper_MakeSystemMultiMailPostal(vector, addition_slots, 10);
	var title_ptr = Memory.allocUtf8String(title);
	var text_ptr = Memory.allocUtf8String(text);
	var text_len = strlen(text_ptr);
	//发邮件给角色
	WongWork_CMailBoxHelper_ReqDBSendNewSystemMultiMail(title_ptr, addition_slots, item_list.length, gold, target_charac_no, text_ptr, text_len, 0, 99, 1);
}

/**
 * 遍历在线玩家列表
 *
 * @param it 参数
 * @returns {*}
 */
function api_gameworld_user_map_next(it) {
	var next = Memory.alloc(4);
	gameworld_user_map_next(next, it);
	return next;
}

/**
 * 获取当前正在遍历的玩家
 * @param it 参数
 * @returns {*}
 */
function api_gameworld_user_map_get(it) {
	return gameworld_user_map_get(it).add(4).readPointer();
}

/**
 * 获取在线玩家列表表头
 *
 * @returns {*}
 */
function api_gameworld_user_map_begin() {
	var begin = Memory.alloc(4);
	gameworld_user_map_begin(begin, G_GameWorld().add(308));
	return begin;
}

/**
 * //获取在线玩家列表表尾
 *
 * @returns {*}
 */
function api_gameworld_user_map_end() {
	var end = Memory.alloc(4);
	gameworld_user_map_end(end, G_GameWorld().add(308));
	return end;
}

/**
 * 全服在线玩家发信
 *
 * @param title 标题
 * @param text 内容
 * @param gold 金币
 * @param item_list 道具数组
 */
function api_gameworld_send_mail(title, text, gold, item_list) {
	//遍历在线玩家列表
	var it = api_gameworld_user_map_begin();
	var end = api_gameworld_user_map_end();

	//判断在线玩家列表遍历是否已结束
	while (gameworld_user_map_not_equal(it, end)) {
		//当前被遍历到的玩家
		var user = api_gameworld_user_map_get(it);

		//只处理已登录角色
		if (CUser_get_state(user) >= 3) {
			//角色uid
			var charac_no = CUserCharacInfo_getCurCharacNo(user);
			//给角色发信
			api_WongWork_CMailBoxHelper_ReqDBSendNewSystemMultiMail(charac_no, title, text, gold, item_list);
		}
		//继续遍历下一个玩家
		api_gameworld_user_map_next(it);
	}
}


/**
 * 定时发送邮件
 *
 * @param hour 小时
 * @param minute 分钟
 * @param second 秒
 * @param gold 金币数量
 * @param item_list 道具 二维数组
 * @param task 表示需要执行的任务，通常是一个函数对象，将在设定的时间点触发执行。
 */
function executeAtTime(hour, minute, second, gold, item_list, task) {

	var now = new Date();

	var target = new Date(now.getFullYear(), now.getMonth(), now.getDate(), hour, minute, second);

	if (now.getTime() > target.getTime()) {
		target.setDate(target.getDate() + 1);
	}

	var diff = target.getTime() - now.getTime();

	setTimeout(function () {
		// 下方为定时邮件，需要就把前面的//去掉

		// api_gameworld_send_mail("GM台服官方邮件", "DNF台服运营商不会已任何形式索要你的用户名密码请你不要邮寄关于您账号密码的任何信息!", gold, item_list);
		// task(); 
		// 上方为定时邮件，需要就把前面的//去掉
		executeAtTime(hour, minute, second, task);
	}, diff);
}

/**
 * 第一次发送道具，代表发了两个道具 蓝色小晶块(3036) -> 20个，复活币（1）-> 20个
 *
 * @type {number[][]}
 */
var item_list_one = [
	[3036, 20],
	[1, 20]
];

// 当天的21点10分0秒，0 ->代表发多少个金币，item_list_one ->发送的道具最多10个道具！
executeAtTime(21, 10, 0, 0, item_list_one, function () {

});

/**
 * 第二次发送道具，代表发了两个道具 蓝色小晶块(3036) -> 20个，蓝色小晶块（3036）-> 20个
 *
 * @type {number[][]}
 */
var item_list_two = [
	[3036, 20],
	[3036, 20]
];

// 当天的22点10分0秒，0 ->代表发多少个金币，item_list_one ->发送的道具最多10个道具！
executeAtTime(22, 10, 0, 0, item_list_two, function () {
});


/**
 * 第三次发送道具，(以此类推)
 *
 * @type {number[][]}
 */
var item_list_two = [
	[3036, 20],
	[3036, 20]
];

executeAtTime(23, 10, 0, 0, item_list_two, function () {
});



//允许赛利亚房间的人互相可见
function share_seria_room() {
	//Hook Area::insert_user
	Interceptor.attach(ptr(0x86C25A6), {

		onEnter: function (args) {
			//修改标志位, 让服务器广播赛利亚旅馆消息
			args[0].add(0x68).writeInt(0);
		},
		onLeave: function (retval) {
		}
	});
}

// 史诗免确认
function cancel_epic_ok() {
	Memory.patchCode(ptr(0x085A56CE).add(2), 1, function (code) {
		var cw = new X86Writer(code, { pc: ptr(0x085A56CE).add(2) });
		cw.putU8(9);
		cw.flush();
	});
	Interceptor.attach(ptr(0x08150f18), {
		onLeave: function (retval) {
			retval.replace(0);
		}
	});
}


function startHellParty() {
	Interceptor.attach(ptr(0x085a0954),
		{
			onEnter: function (args) {
				if (heffPartyTag) {
					args[3] = ptr(1);
				}
			}
		});
}

function startEquNew() {
	Interceptor.attach(ptr(0x080FC850),
		{
			onEnter: function (args) {
				this.equiPos = args[2].add(27).readU16();
				this.user = args[1];
			},
			onLeave: function (retval) {
				CUser_SendUpdateItemList(this.user, 1, 0, this.equiPos);
			}
		});
}


var heffPartyTag = false;
//处理GM信息
function hook_gm_command() {
	//HOOK Dispatcher_New_Gmdebug_Command::dispatch_sig
	Interceptor.attach(ptr(0x820BBDE), {

		onEnter: function (args) {

			//获取原始封包数据
			var raw_packet_buf = api_PacketBuf_get_buf(args[2]);

			//解析GM DEBUG命令
			var msg_len = raw_packet_buf.readInt();
			var msg = raw_packet_buf.add(4).readUtf8String(msg_len);

			var user = args[1];


			console.log('收到GM_DEBUG消息: [' + api_CUserCharacInfo_getCurCharacName(user) + '] ' + msg);

			//去除命令开头的 '//'
			msg = msg.slice(2);
			switch (msg) {
				case 'zt':
					if (enhance_dungeon) {
						api_CUser_SendNotiPacketMessage(user, '-------------------', 1);
						api_CUser_SendNotiPacketMessage(user, '增强副本模式 : ' + enhance_dungeon, 1);
						api_CUser_SendNotiPacketMessage(user, '强制随机装备属性 : ' + enhanced_equip, 1);
						api_CUser_SendNotiPacketMessage(user, '复制怪物数量 : ' + copy_monster, 1);
						api_CUser_SendNotiPacketMessage(user, '额外增加怪物等级 : ' + add_monster_level, 1);
						api_CUser_SendNotiPacketMessage(user, '随机怪物模式 : ' + random_monster, 1);
					} else {
						api_CUser_SendNotiPacketMessage(user, '-------------------', 1);
						api_CUser_SendNotiPacketMessage(user, '增强副本模式 : ' + enhance_dungeon, 1);
						api_CUser_SendNotiPacketMessage(user, '强制随机装备属性 : ' + enhanced_equip, 1);
					}
					return;
				case 'zq':
					if (enhance_dungeon) {
						enhance_dungeon = false;
						api_CUser_SendNotiPacketMessage(user, '关闭增强副本', 1);
					} else {
						enhance_dungeon = true;
						api_CUser_SendNotiPacketMessage(user, '开启增强副本', 1);
					}
					return;
				case 'sj':
					if (random_monster) {
						random_monster = false;
						api_CUser_SendNotiPacketMessage(user, '关闭随机刷怪', 1);
					} else {
						random_monster = true;
						api_CUser_SendNotiPacketMessage(user, '开启随机刷怪, 部分怪物无法生成, 请手动去除编号', 1);
					}
					return;
				case 'zb':
					if (enhanced_equip) {
						enhanced_equip = false;
						api_CUser_SendNotiPacketMessage(user, '关闭强制随机装备属性', 1);
					} else {
						enhanced_equip = true;
						api_CUser_SendNotiPacketMessage(user, '开启强制随机装备属性', 1);
					}
					return;
			}
			if (msg == 'test') {
				//向客户端发送消息
				api_CUser_SendNotiPacketMessage(user, '这是一条测试命令', 1);

				//执行一些测试代码

				return;
			}
			else if (msg.indexOf('move ') == 0) {
				//城镇瞬移
				var msg_group = msg.split(' ');
				if (msg_group.length == 5) {
					var village = parseInt(msg_group[1]);
					var area = parseInt(msg_group[2]);
					var pos_x = parseInt(msg_group[3]);
					var pos_y = parseInt(msg_group[4]);
					GameWorld_move_area(G_GameWorld(), user, village, area, pos_x, pos_y, 0, 0, 0, 0, 0);
				}
				else {
					api_CUser_SendNotiPacketMessage(user, '格式错误. 使用示例: //move 2 1 100 100', 2);
				}
			} else if (msg.indexOf('item ') == 0) {
				//获得物品
				var msg_group = msg.split(' ');
				if (msg_group.length == 3) {
					var item_id = parseInt(msg_group[1]);
					var item_cnt = parseInt(msg_group[2]);
					//发送道具到玩家背包
					api_CUser_AddItem(user, item_id, item_cnt);
					api_CUser_SendNotiPacketMessage(user, 'GM命令完成', 1);
				}
				else {
					api_CUser_SendNotiPacketMessage(user, '格式错误. item: //item 1 1', 2);
				}
			} else if (msg == 'attackstart') {	//GM模式开启怪物攻城
				on_start_event_villageattack()
			}
			else if (msg == 'attackend') {	//GM模式关闭怪物攻城
				on_end_event_villageattack();
			} else if (msg == 'onhell') {
				heffPartyTag = true;
				api_CUser_SendNotiPacketMessage(user, '开启深渊模式', 1);
			} else if (msg == 'offhell') {
				heffPartyTag = false;
				api_CUser_SendNotiPacketMessage(user, '关闭深渊模式', 1);
			}
		},
		onLeave: function (retval) {
		}
	});
}


function HookDsSwordman_SkillSlot() {
	Interceptor.attach(ptr(0x08608D58), {
		//SkillSlot::checkMoveComboSkillSlot 返回1
		onEnter: function (args) {
		},
		onLeave: function (retval) {
			retval.replace(1)
		}
	});
	Interceptor.attach(ptr(0x08608C98), {
		//SkillSlot::checkMoveComboSkillSlot 返回1
		onEnter: function (args) {
		},
		onLeave: function (retval) {
			retval.replace(1)
		}
	});
}


var decryptPasswork = [
	4545, 2244, 9972, 6445, 7812,
	5235, 7445, 5489, 4130, 4141,
	4487, 7899, 8236, 8711, 9546,
	4449, 4747, 4415, 6542, 5448
];

function decryptValue(encryptData, Num, Var) {
	for (var i = Num - 1; i >= 0; --i) {
		encryptData = (encryptData >>> decryptPasswork[Var]) | (encryptData << (32 - decryptPasswork[Var]));
		encryptData = (encryptData ^ decryptPasswork[Var]) - decryptPasswork[Var];
	}
	return encryptData;
}
//魔法封印装备开孔
function fy1(user, item_id, slot, flag) {
	//log('fy==>>'+item_id+" " + flag)
	var inven = CUserCharacInfo_getCurCharacInvenW(user);
	var equ = CInventory_GetInvenRef(inven, INVENTORY_TYPE_ITEM, slot);

	var Item_Id = Inven_Item_getKey(equ)
	//pvf中获取装备数据
	var inItemData = CDataManager_find_item(G_CDataManager(), Item_Id); //获取pvf数据
	var inEqu_type = inItemData.add(141 * 4).readU32(); // 装备类型
	var i0 = equ.add(37).add(0).readU8()
	var i1 = equ.add(37).add(1).readU8()
	var i2 = equ.add(37).add(2).readU8()
	var i3 = equ.add(37).add(3).readU8()
	var i4 = equ.add(37).add(4).readU8()
	var i5 = equ.add(37).add(5).readU8()
	var i6 = equ.add(37).add(6).readU8()
	var i7 = equ.add(37).add(7).readU8()
	var i8 = equ.add(37).add(8).readU8()

	if (!Item_Id && flag) {
		api_CUser_SendNotiPacketMessage(user, "注意： 镶嵌开孔失败, 你的物品栏第一格是空的！", 0);

		api_scheduleOnMainThread_delay(api_CUser_AddItem, [user, item_id, 1], 1);//道具返还间隔

		return
	}

	if (inEqu_type == 10 || inEqu_type == 20 || inEqu_type == 21 && flag) {
		if (i0 >= 6) {
			equ.add(37).add(0).writeU8(6);
			equ.add(37).add(3).writeU8(0)
			api_CUser_SendNotiPacketMessage(user, "注意： 镶嵌徽章已成功清除1！", 0);
			return;
		}
		equ.add(37).add(0).writeU8(6);
		CUser_SendUpdateItemList(user, 1, 0, slot);
		api_CUser_SendNotiPacketMessage(user, '第一格装备镶嵌孔已成功开启1。', 0);
		return
	}


	if (i0 + i1 + i2 + i3 + i4 + i5 + i6 + i7 + i8 <= 0 && flag) {
		api_CUser_SendNotiPacketMessage(user, "注意： 此装备不能开孔！", 0);

		api_scheduleOnMainThread_delay(api_CUser_AddItem, [user, item_id, 1], 1);//道具返还间隔

		return;
	}



	if (i1 + i2 + i3 + i4 + i5 + i6 + i7 + i8 > 0 && flag) {

		api_CUser_SendNotiPacketMessage(user, "注意： 镶嵌徽章已成功清除2！", 0);
		equ.add(37).add(0).writeU8(6);
		equ.add(37).add(3).writeU8(6);
		CUser_SendUpdateItemList(user, 1, 0, slot);
		//api_scheduleOnMainThread_delay(api_CUser_AddItem,[user,item_id,1],1);//道具返还间隔

		return slot;
	}


	equ.add(37).add(0).writeU8(6);
	equ.add(37).add(3).writeU8(6);
	//equ.add(37).add(3).writeU8(random_option_level);

	//通知客户端有装备更新
	if (flag) {
		CUser_SendUpdateItemList(user, 1, 0, slot);
		api_CUser_SendNotiPacketMessage(user, '第一格装备镶嵌孔已成功开启2。', 0);
	} else {
		api_scheduleOnMainThread_delay(CUser_SendUpdateItemList, [user, 1, 0, slot], 1)
	}
	return slot;
}
//魔法封印装备开孔（白金开双孔）
function fy2222(user, item_id, slot, flag) {
	//log('fy==>>'+item_id+" " + flag)
	var inven = CUserCharacInfo_getCurCharacInvenW(user);
	var equ = CInventory_GetInvenRef(inven, INVENTORY_TYPE_ITEM, slot);

	var Item_Id = Inven_Item_getKey(equ)
	//pvf中获取装备数据
	var citem = CDataManager_find_item(G_CDataManager(), item_id);
	var inEqu_type = citem.add(141 * 4).readU32(); // 装备类型
	if (!Item_Id && flag) {
		api_CUser_SendNotiPacketMessage(user, "注意： 镶嵌开孔失败, 你的物品栏第一格是空的！", 0);

		api_scheduleOnMainThread_delay(api_CUser_AddItem, [user, item_id, 1], 1);//道具返还间隔

		return
	}

	if ((inEqu_type == 10 || inEqu_type == 20 || inEqu_type == 21) && flag) {
		equ.add(37).add(0).writeU8(6);
		CUser_SendUpdateItemList(user, 1, 0, slot);
		api_CUser_SendNotiPacketMessage(user, '第一格装备镶嵌孔已成功开启。', 0);
	}
	var i0 = equ.add(37).add(0).readU8()
	var i1 = equ.add(37).add(1).readU8()
	var i2 = equ.add(37).add(2).readU8()
	var i3 = equ.add(37).add(3).readU8()
	var i4 = equ.add(37).add(4).readU8()
	var i5 = equ.add(37).add(5).readU8()
	var i6 = equ.add(37).add(6).readU8()
	var i7 = equ.add(37).add(7).readU8()
	var i8 = equ.add(37).add(8).readU8()

	if (i0 + i1 + i2 + i3 + i4 + i5 + i6 + i7 + i8 <= 0 && flag) {
		api_CUser_SendNotiPacketMessage(user, "注意： 此装备不能开孔！", 0);

		api_scheduleOnMainThread_delay(api_CUser_AddItem, [user, item_id, 1], 1);//道具返还间隔

		return;
	}

	var inItemData = CDataManager_find_item(G_CDataManager(), Item_Id); //获取pvf数据
	var inEqu_type = inItemData.add(141 * 4).readU32(); // 装备类型



	if (i1 + i2 + i3 + i4 + i5 + i6 + i7 + i8 > 0 && flag) {
		api_CUser_SendNotiPacketMessage(user, "注意： 镶嵌徽章已成功清除！", 0);
		equ.add(37).add(0).writeU8(6);
		equ.add(37).add(3).writeU8(6);
		CUser_SendUpdateItemList(user, 1, 0, slot);
		//api_scheduleOnMainThread_delay(api_CUser_AddItem,[user,item_id,1],1);//道具返还间隔

		return slot;
	}
	equ.add(37).add(0).writeU8(6);
	equ.add(37).add(3).writeU8(6);
	//equ.add(37).add(3).writeU8(random_option_level);

	//通知客户端有装备更新
	if (flag) {
		CUser_SendUpdateItemList(user, 1, 0, slot);
		api_CUser_SendNotiPacketMessage(user, '第一格装备镶嵌孔已成功开启。', 0);
	} else {
		api_scheduleOnMainThread_delay(CUser_SendUpdateItemList, [user, 1, 0, slot], 1)
	}
	return slot;
}
function fun(param, value) {
	var len = param.length;
	for (var i = 0; i < len; i++) {
		if (param[i] == value)
			return true;
	}
	return false;
}
//装备赋予魔法封印
function fy(user, item_id, slot, flag, c1) {
	//log('fy==>>'+item_id+" " + flag)
	var inven = CUserCharacInfo_getCurCharacInvenW(user);
	var equ = CInventory_GetInvenRef(inven, INVENTORY_TYPE_ITEM, slot);

	var Item_Id = Inven_Item_getKey(equ)
	if (!Item_Id && flag) {
		api_CUser_SendNotiPacketMessage(user, "注意： 镶嵌镶嵌失败, 你的物品栏第一格是空的！", 0);

		// api_CUser_AddItem(user, item_id, 1);
		api_scheduleOnMainThread_delay(api_CUser_AddItem, [user, item_id, 1], 1);//道具返还间隔



		return
	}
	var inItemData = CDataManager_find_item(G_CDataManager(), Item_Id); //获取pvf数据
	var inEqu_type = inItemData.add(141 * 4).readU32(); // 装备类型
	var blue = [2530055, 2530064, 2530067, 2530058, 2530061, 2530000, 2530003, 2530004, 2530002, 2530035, 2530036, 2530037, 2530044, 2530045, 2530046, 2530047, 2530038, 2530041, 2530020, 2530029, 2530032, 2530023, 2530026, 2530027]
	var gree = [2520048, 2520049, 2520038, 2520041, 2520042, 2520044, 2520035, 2520037, 2520033, 2520034, 2520023, 2520024, 2520026, 2520027, 2520029]
	var red = [2500017, 2500010, 2500016, 2500013, 2500007, 2500043, 2500035, 2500041, 2500037, 2500032, 2500022, 2500023, 2500029, 2500026, 2500020]
	var yellow = [2510003, 2510000, 2510001, 2510002, 2510004, 2510044, 2510035, 2510038, 2510041, 2510047, 2510029, 2510020, 2510023, 2510026, 2510032]
	var caise = [2550101, 2550098, 2550107, 2550104, 2550113, 2550110, 2550095, 2550080, 2550089, 2550083, 2550092, 2550074, 2550077, 2550086, 2550059, 2550056, 2550065, 2550062, 2550071, 2550068, 2550053, 2550038, 2550047, 2550041, 2550050, 2550032, 2550035, 2550044]
	var baijin = [2540102, 2540104, 2540105, 2540106]

	var i0 = equ.add(37).add(0).readU8()
	var i1 = equ.add(37).add(1).readU8()
	var i2 = equ.add(37).add(2).readU8()
	var i3 = equ.add(37).add(3).readU8()
	var i4 = equ.add(37).add(4).readU8()
	var i5 = equ.add(37).add(5).readU8()
	var i6 = equ.add(37).add(6).readU8()
	var i7 = equ.add(37).add(7).readU8()
	var i8 = equ.add(37).add(8).readU8()
	//api_CUser_SendNotiPacketMessage(user, '输出' + i0 + '。', 0);

	if (fun(blue, item_id) && (inEqu_type == 10 || inEqu_type == 11 || inEqu_type == 12 || inEqu_type == 13 || inEqu_type == 14 || inEqu_type == 16 || inEqu_type == 17 || inEqu_type == 19 || inEqu_type == 20 || inEqu_type == 21)) {
		api_CUser_SendNotiPacketMessage(user, "蓝色徽章只能镶嵌鞋子和手镯部位！", 0);

		api_scheduleOnMainThread_delay(api_CUser_AddItem, [user, item_id, 1], 1);//道具返还间隔
		return

	}
	if (fun(gree, item_id) && (inEqu_type == 10 || inEqu_type == 11 || inEqu_type == 13 || inEqu_type == 15 || inEqu_type == 16 || inEqu_type == 17 || inEqu_type == 18 || inEqu_type == 19 || inEqu_type == 20 || inEqu_type == 21)) {
		api_CUser_SendNotiPacketMessage(user, "绿色徽章只能镶嵌上衣和下衣部位！", 0);

		api_scheduleOnMainThread_delay(api_CUser_AddItem, [user, item_id, 1], 1);//道具返还间隔
		return

	}
	if (fun(red, item_id) && (inEqu_type == 10 || inEqu_type == 11 || inEqu_type == 13 || inEqu_type == 15 || inEqu_type == 14 || inEqu_type == 17 || inEqu_type == 18 || inEqu_type == 12 || inEqu_type == 20 || inEqu_type == 21)) {
		api_CUser_SendNotiPacketMessage(user, "红色色徽章只能镶嵌腰带和戒指部位！", 0);

		api_scheduleOnMainThread_delay(api_CUser_AddItem, [user, item_id, 1], 1);//道具返还间隔
		return

	}
	if (fun(yellow, item_id) && (inEqu_type == 10 || inEqu_type == 11 || inEqu_type == 12 || inEqu_type == 14 || inEqu_type == 15 || inEqu_type == 16 || inEqu_type == 18 || inEqu_type == 19 || inEqu_type == 20 || inEqu_type == 21)) {
		api_CUser_SendNotiPacketMessage(user, "黄色徽章只能镶嵌武肩和项链部位！", 0);

		api_scheduleOnMainThread_delay(api_CUser_AddItem, [user, item_id, 1], 1);//道具返还间隔
		return

	}
	if (fun(caise, item_id) && (inEqu_type == 10 || inEqu_type == 20 || inEqu_type == 21)) {
		api_CUser_SendNotiPacketMessage(user, "彩色徽章不能镶嵌白金槽！", 0);

		api_scheduleOnMainThread_delay(api_CUser_AddItem, [user, item_id, 1], 1);//道具返还间隔
		return

	}
	if (fun(baijin, item_id) && (inEqu_type == 11 || inEqu_type == 12 || inEqu_type == 14 || inEqu_type == 15 || inEqu_type == 16 || inEqu_type == 18 || inEqu_type == 19 || inEqu_type == 13 || inEqu_type == 17)) {
		api_CUser_SendNotiPacketMessage(user, "白金徽章只能镶嵌武器和左右槽部位！", 0);

		api_scheduleOnMainThread_delay(api_CUser_AddItem, [user, item_id, 1], 1);//道具返还间隔
		return

	}

	if (i1 + i2 + i3 + i4 + i5 + i6 + i7 + i8 <= 0 && flag) {

		if (i0 + i1 == 6) {
			equ.add(37).add(0).writeU8(c1);
			CUser_SendUpdateItemList(user, 1, 0, slot);
			api_CUser_SendNotiPacketMessage(user, '孔1镶嵌成功。', 0);

			return
		}
		if (i0 > 6) {
			equ.add(37).add(0).writeU8(c1);
			CUser_SendUpdateItemList(user, 1, 0, slot);
			api_CUser_SendNotiPacketMessage(user, '孔1镶嵌成功。', 0);

			return
		}

		api_CUser_SendNotiPacketMessage(user, "注意： 徽章镶嵌失败, 你的装备没有开孔！", 0);



		api_scheduleOnMainThread_delay(api_CUser_AddItem, [user, item_id, 1], 1);//道具返还间隔

		return slot;
	}
	if (i0 == 6) {
		equ.add(37).add(0).writeU8(c1);
		CUser_SendUpdateItemList(user, 1, 0, slot);
		api_CUser_SendNotiPacketMessage(user, '孔1镶嵌成功。', 0);
		return slot;

	}

	else if (i0 > 6 && flag) {


		if (inEqu_type == 10 || inEqu_type == 20 || inEqu_type == 21) {
			equ.add(37).add(0).writeU8(c1);
			api_CUser_SendNotiPacketMessage(user, '孔1镶嵌成功。', 0);

			return slot;
		}
		equ.add(37).add(3).writeU8(c1);
	}

	//equ.add(37).add(3).writeU8(random_option_level);

	//通知客户端有装备更新
	if (flag) {
		CUser_SendUpdateItemList(user, 1, 0, slot);
		api_CUser_SendNotiPacketMessage(user, '孔2镶嵌成功。', 0);
	} else {
		api_scheduleOnMainThread_delay(CUser_SendUpdateItemList, [user, 1, 0, slot], 1)
	}
	return slot;
}
//史诗魔法封印变换券
function qc(user) {
	var inven = CUserCharacInfo_getCurCharacInvenW(user);
	//遍历装备
	for (var i = 9; i <= 16; i++) {
		//获取物品栏第一排的装备
		var equIn = CInventory_GetInvenRef(inven, INVENTORY_TYPE_ITEM, i); //遍历类型为物品栏
		var inItemId = Inven_Item_getKey(equIn) //道具id
		var inItemData = CDataManager_find_item(G_CDataManager(), inItemId); //获取pvf数据
		var equRarity = CItem_getRarity(inItemData); // 稀有度  >=3  粉色以上
		if (equRarity == 4) {
			var inEqu_type = inItemData.add(141 * 4).readU32(); // 装备类型10武器 11称号	       
			//清空所有魔法封印字节
			if (inEqu_type != 11) {
				equIn.add(37).writeU8(0);
				equIn.add(38).writeU8(0);
				equIn.add(39).writeU8(0);
				equIn.add(40).writeU8(0);
				equIn.add(41).writeU8(0);
				equIn.add(42).writeU8(0);
				equIn.add(43).writeU8(0);
				equIn.add(44).writeU8(0);
				equIn.add(45).writeU8(0);
				equIn.add(46).writeU8(0);
				equIn.add(47).writeU8(0);
				equIn.add(48).writeU8(0);
				equIn.add(49).writeU8(0);
				equIn.add(50).writeU8(0);
				//尝试解除魔法封印
				var ret = random_option_CRandomOptionItemHandle_give_option(ptr(0x941F820).readPointer(), inItemId, CItem_getRarity(inItemData), CItem_getUsableLevel(inItemData)
					, CItem_getItemGroupName(inItemData), CEquipItem_getRandomOptionGrade(inItemData), equIn.add(37));
				if (ret) {
					//通知客户端有装备更新
					CUser_SendUpdateItemList(user, 1, 0, i);
				}
			}
		}
	}
}


function UseItemEventHandler(user, item_id) {
	//log('item_id : ' + item_id);
	if (item_id == 690017018) { fy1(user, item_id, 9, true) }//开孔器

	if (item_id == 1230) { qc(user) }//随机 魔法封印属性
	///////////////////////////////////蓝色徽章//////////////////////////////////////////////////
	if (item_id == 2530055) { fy(user, item_id, 9, true, 16) }//闪耀的蓝色徽章 [物理攻击力]
	if (item_id == 2530064) { fy(user, item_id, 9, true, 17) }//闪耀的蓝色徽章 [魔法攻击力]
	if (item_id == 2530067) { fy(user, item_id, 9, true, 18) } //闪耀的蓝色徽章 [独立攻击力]
	if (item_id == 2530058) { fy(user, item_id, 9, true, 19) } //闪耀的蓝色徽章 [魔法防御]
	if (item_id == 2530061) { fy(user, item_id, 9, true, 20) } //闪耀的蓝色徽章 [物理防御]
	if (item_id == 2530000) { fy(user, item_id, 9, true, 21) }//闪耀的蓝色徽章 [移动速度]
	if (item_id == 2530003) { fy(user, item_id, 9, true, 22) }//闪耀的蓝色徽章 [命中率]
	if (item_id == 2530004) { fy(user, item_id, 9, true, 23) } //闪耀的蓝色徽章 [跳跃力]
	/////////////////////////////////////////////////////////////////////////////////////
	if (item_id == 2530002) { fy(user, item_id, 9, true, 24) } //华丽的蓝色徽章 [物理攻击力]
	if (item_id == 2530035) { fy(user, item_id, 9, true, 25) } //华丽的蓝色徽章 [魔法攻击力]
	if (item_id == 2530036) { fy(user, item_id, 9, true, 26) }//华丽的蓝色徽章 [独立攻击力]
	if (item_id == 2530037) { fy(user, item_id, 9, true, 27) }//华丽的蓝色徽章 [魔法防御]
	if (item_id == 2530044) { fy(user, item_id, 9, true, 28) } //华丽的蓝色徽章 [物理防御]
	if (item_id == 2530045) { fy(user, item_id, 9, true, 29) } //华丽的蓝色徽章 [移动速度]
	if (item_id == 2530046) { fy(user, item_id, 9, true, 30) } //华丽的蓝色徽章 [命中率]
	if (item_id == 2530047) { fy(user, item_id, 9, true, 31) }//华丽的蓝色徽章 [跳跃力]
	/////////////////////////////////////////////////////////////////////////////////////
	if (item_id == 2530038) { fy(user, item_id, 9, true, 32) }//灿烂的蓝色徽章 [物理攻击力]
	if (item_id == 2530041) { fy(user, item_id, 9, true, 33) } //灿烂的蓝色徽章 [魔法攻击力]
	if (item_id == 2530020) { fy(user, item_id, 9, true, 34) } //灿烂的蓝色徽章 [独立攻击力]
	if (item_id == 2530029) { fy(user, item_id, 9, true, 35) } //灿烂的蓝色徽章 [魔法防御]
	if (item_id == 2530032) { fy(user, item_id, 9, true, 36) } //灿烂的蓝色徽章 [物理防御]
	if (item_id == 2530023) { fy(user, item_id, 9, true, 37) } //灿烂的蓝色徽章 [移动速度]
	if (item_id == 2530026) { fy(user, item_id, 9, true, 38) } //灿烂的蓝色徽章 [命中率]
	if (item_id == 2530027) { fy(user, item_id, 9, true, 39) } //灿烂的蓝色徽章 [跳跃力]
	/////////////////////////////////////////////////////////////////////////////////////

	///////////////////////////////////绿色徽章//////////////////////////////////////////////////
	if (item_id == 2520048) { fy(user, item_id, 9, true, 40) }//闪耀的绿色徽章 [物理暴击]
	if (item_id == 2520049) { fy(user, item_id, 9, true, 41) } //闪耀的绿色徽章 [魔法暴击]
	if (item_id == 2520038) { fy(user, item_id, 9, true, 42) }  //闪耀的绿色徽章 [HP最大值]
	if (item_id == 2520041) { fy(user, item_id, 9, true, 43) }//闪耀的绿色徽章 [MP最大值]
	if (item_id == 2520042) { fy(user, item_id, 9, true, 44) }  //闪耀的绿色徽章 [回避率]
	/////////////////////////////////////////////////////////////////////////////////////
	if (item_id == 2520044) { fy(user, item_id, 9, true, 45) }  //华丽的绿色徽章 [物理暴击]
	if (item_id == 2520035) { fy(user, item_id, 9, true, 46) } //华丽的绿色徽章 [魔法暴击]
	if (item_id == 2520037) { fy(user, item_id, 9, true, 47) } //华丽的绿色徽章 [HP最大值]
	if (item_id == 2520033) { fy(user, item_id, 9, true, 48) }  //华丽的绿色徽章 [MP最大值]
	if (item_id == 2520034) { fy(user, item_id, 9, true, 49) }//华丽的绿色徽章 [回避率]
	/////////////////////////////////////////////////////////////////////////////////////
	if (item_id == 2520023) { fy(user, item_id, 9, true, 50) }//灿烂的绿色徽章 [物理暴击]
	if (item_id == 2520024) { fy(user, item_id, 9, true, 51) } //灿烂的绿色徽章 [魔法暴击]
	if (item_id == 2520026) { fy(user, item_id, 9, true, 52) } //灿烂的绿色徽章 [HP最大值]
	if (item_id == 2520027) { fy(user, item_id, 9, true, 53) }//灿烂的绿色徽章 [MP最大值]
	if (item_id == 2520029) { fy(user, item_id, 9, true, 54) }//灿烂的绿色徽章 [回避率]
	/////////////////////////////////////////////////////////////////////////////////////




	///////////////////////////////////红色徽章//////////////////////////////////////////////////
	if (item_id == 2500017) { fy(user, item_id, 9, true, 5) }//闪耀的红色徽章 [所有属性]
	if (item_id == 2500010) { fy(user, item_id, 9, true, 2) }//闪耀的红色徽章 [智力]
	if (item_id == 2500016) { fy(user, item_id, 9, true, 4) }//闪耀的红色徽章 [精神]
	if (item_id == 2500013) { fy(user, item_id, 9, true, 3) }//闪耀的红色徽章 [体力]
	if (item_id == 2500007) { fy(user, item_id, 9, true, 98) }//闪耀的红色徽章 [力量]
	/////////////////////////////////////////////////////////////////////////////////////
	if (item_id == 2500043) { fy(user, item_id, 9, true, 15) }//灿烂的红色徽章 [所有属性]
	if (item_id == 2500035) { fy(user, item_id, 9, true, 12) }//灿烂的红色徽章 [智力]
	if (item_id == 2500041) { fy(user, item_id, 9, true, 14) }//灿烂的红色徽章 [精神]
	if (item_id == 2500037) { fy(user, item_id, 9, true, 13) }//灿烂的红色徽章 [体力]
	if (item_id == 2500032) { fy(user, item_id, 9, true, 11) }//灿烂的红色徽章 [力量]
	/////////////////////////////////////////////////////////////////////////////////////
	if (item_id == 2500022) { fy(user, item_id, 9, true, 10) }//华丽的红色徽章 [所有属性]
	if (item_id == 2500023) { fy(user, item_id, 9, true, 7) }//华丽的红色徽章 [智力]
	if (item_id == 2500029) { fy(user, item_id, 9, true, 9) }//华丽的红色徽章 [精神]
	if (item_id == 2500026) { fy(user, item_id, 9, true, 8) }//华丽的红色徽章 [体力]
	if (item_id == 2500020) { fy(user, item_id, 9, true, 99) }//华丽的红色徽章 [力量]
	/////////////////////////////////////////////////////////////////////////////////////



	///////////////////////////////////黄色徽章//////////////////////////////////////////////////
	if (item_id == 2510003) { fy(user, item_id, 9, true, 57) }//闪耀的黄色徽章 [攻击速度]
	if (item_id == 2510000) { fy(user, item_id, 9, true, 58) } //闪耀的黄色徽章 [施放速度]
	if (item_id == 2510001) { fy(user, item_id, 9, true, 59) }//闪耀的黄色徽章 [硬直]
	if (item_id == 2510002) { fy(user, item_id, 9, true, 55) } //闪耀的黄色徽章 [HP恢复]
	if (item_id == 2510004) { fy(user, item_id, 9, true, 56) } //闪耀的黄色徽章 [MP恢复]
	/////////////////////////////////////////////////////////////////////////////////////
	if (item_id == 2510044) { fy(user, item_id, 9, true, 62) } //华丽的黄色徽章 [攻击速度]
	if (item_id == 2510035) { fy(user, item_id, 9, true, 63) } //华丽的黄色徽章 [施放速度]
	if (item_id == 2510038) { fy(user, item_id, 9, true, 64) }//华丽的黄色徽章 [硬直]
	if (item_id == 2510041) { fy(user, item_id, 9, true, 60) } //华丽的黄色徽章 [HP恢复]
	if (item_id == 2510047) { fy(user, item_id, 9, true, 61) } //华丽的黄色徽章 [MP恢复]
	/////////////////////////////////////////////////////////////////////////////////////
	if (item_id == 2510029) { fy(user, item_id, 9, true, 67) } //灿烂的黄色徽章 [攻击速度]
	if (item_id == 2510020) { fy(user, item_id, 9, true, 68) } //灿烂的黄色徽章 [施放速度]
	if (item_id == 2510023) { fy(user, item_id, 9, true, 69) }//灿烂的黄色徽章 [硬直]
	if (item_id == 2510026) { fy(user, item_id, 9, true, 65) } //灿烂的黄色徽章 [HP恢复]
	if (item_id == 2510032) { fy(user, item_id, 9, true, 66) } //灿烂的黄色徽章 [MP恢复]
	/////////////////////////////////////////////////////////////////////////////////////



	///////////////////////////////////白金徽章//////////////////////////////////////////////////
	if (item_id == 2540102) { fy(user, item_id, 9, true, 103) }//冒险家的白金徽章
	if (item_id == 2540104) { fy(user, item_id, 9, true, 102) }//冒险家的白金徽章
	if (item_id == 2540105) { fy(user, item_id, 9, true, 101) }//冒险家的白金徽章
	if (item_id == 2540106) { fy(user, item_id, 9, true, 100) }//冒险家的白金徽章
	/////////////////////////////////////////////////////////////////////////////////////




	///////////////////////////////////彩色徽章//////////////////////////////////////////////////
	if (item_id == 2550059) { fy(user, item_id, 9, true, 71) }//华丽的双重徽章 [攻击速度 + 命中率]
	if (item_id == 2550056) { fy(user, item_id, 9, true, 70) }//华丽的双重徽章 [攻击速度 + 移动速度]
	if (item_id == 2550065) { fy(user, item_id, 9, true, 77) }//华丽的双重徽章 [施放速度 + 命中率]
	if (item_id == 2550062) { fy(user, item_id, 9, true, 76) }//华丽的双重徽章 [施放速度 + 移动速度]
	if (item_id == 2550071) { fy(user, item_id, 9, true, 83) }//华丽的双重徽章 [硬直 + 命中率]
	if (item_id == 2550068) { fy(user, item_id, 9, true, 82) }//华丽的双重徽章 [硬直 + 移动速度]
	if (item_id == 2550053) { fy(user, item_id, 9, true, 75) }//华丽的双重徽章 [智力 + 回避率]
	if (item_id == 2550038) { fy(user, item_id, 9, true, 72) }//华丽的双重徽章 [智力 + HP最大值]
	if (item_id == 2550047) { fy(user, item_id, 9, true, 74) }//华丽的双重徽章 [智力 + 魔法暴击]
	if (item_id == 2550041) { fy(user, item_id, 9, true, 73) }//华丽的双重徽章 [智力 + MP最大值]
	if (item_id == 2550050) { fy(user, item_id, 9, true, 81) }//华丽的双重徽章 [力量 + 回避率]
	if (item_id == 2550032) { fy(user, item_id, 9, true, 78) }//华丽的双重徽章 [力量 + HP最大值]
	if (item_id == 2550035) { fy(user, item_id, 9, true, 79) }//华丽的双重徽章 [力量 + MP最大值]
	if (item_id == 2550044) { fy(user, item_id, 9, true, 80) }//华丽的双重徽章 [力量 + 物理暴击]
	/////////////////////////////////////////////////////////////////////////////////////
	if (item_id == 2550101) { fy(user, item_id, 9, true, 85) }//灿烂的双重徽章 [攻击速度 + 命中率]
	if (item_id == 2550098) { fy(user, item_id, 9, true, 84) }//灿烂的双重徽章 [攻击速度 + 移动速度]
	if (item_id == 2550107) { fy(user, item_id, 9, true, 91) }//灿烂的双重徽章 [施放速度 + 命中率]
	if (item_id == 2550104) { fy(user, item_id, 9, true, 90) }//灿烂的双重徽章 [施放速度 + 移动速度]
	if (item_id == 2550113) { fy(user, item_id, 9, true, 97) }//灿烂的双重徽章 [硬直 + 命中率]
	if (item_id == 2550110) { fy(user, item_id, 9, true, 96) }//灿烂的双重徽章 [硬直 + 移动速度]
	if (item_id == 2550095) { fy(user, item_id, 9, true, 89) }//灿烂的双重徽章 [智力 + 回避率]
	if (item_id == 2550080) { fy(user, item_id, 9, true, 86) }//灿烂的双重徽章 [智力 + HP最大值]
	if (item_id == 2550089) { fy(user, item_id, 9, true, 88) }//灿烂的双重徽章 [智力 + 魔法暴击]
	if (item_id == 2550083) { fy(user, item_id, 9, true, 87) }//灿烂的双重徽章 [智力 + MP最大值]
	if (item_id == 2550092) { fy(user, item_id, 9, true, 95) }//灿烂的双重徽章 [力量 + 回避率]
	if (item_id == 2550074) { fy(user, item_id, 9, true, 92) }//灿烂的双重徽章 [力量 + HP最大值]
	if (item_id == 2550077) { fy(user, item_id, 9, true, 93) }//灿烂的双重徽章 [力量 + MP最大值]
	if (item_id == 2550086) { fy(user, item_id, 9, true, 94) }//灿烂的双重徽章 [力量 + 物理暴击]
	/////////////////////////////////////////////////////////////////////////////////////


}



function zhen14() {
	Memory.protect(ptr(0x08608D7B), 3, 'rwx');
	ptr(0x08608D7B).writeByteArray([0x83, 0xF8, 0x0B]);
	Memory.protect(ptr(0x08604B1E), 4, 'rwx');
	ptr(0x08604B1E).writeByteArray([0x83, 0x7D, 0xEC, 0x07]);
	Memory.protect(ptr(0x08604B8C), 7, 'rwx');
	ptr(0x08604B8C).writeByteArray([0xC7, 0x45, 0xE4, 0x08, 0x00, 0x00, 0x00]);
	Memory.protect(ptr(0x08604A09), 4, 'rwx');
	ptr(0x08604A09).writeByteArray([0x83, 0x7D, 0x0C, 0x07]);
	Memory.protect(ptr(0x086050b1), 7, 'rwx');
	ptr(0x086050b1).writeByteArray([0xC7, 0x45, 0xEC, 0x08, 0x00, 0x00, 0x00]);
	Memory.protect(ptr(0x0860511c), 7, 'rwx');
	ptr(0x0860511c).writeByteArray([0xC7, 0x45, 0xE8, 0x08, 0x00, 0x00, 0x00]);
}

//xq
function andonglishanbai_Equipment_inlay() {//装备镶嵌
	var CTitleBook_putItemData = new NativeFunction(ptr(0x08641A6A), 'int', ['pointer', 'pointer', 'int', 'pointer'], { "abi": "sysv" });	//称号回包
	Interceptor.replace(ptr(0x08641A6A), new NativeCallback(function (CTitleBook, PacketGuard, a3, Inven_Item) {
		var JewelSocketData = Memory.alloc(30);
		var ret = CTitleBook_putItemData(CTitleBook, PacketGuard, a3, Inven_Item);
		JewelSocketData = api_get_jewel_socket_data(mysql_frida, Inven_Item.add(25).readU32())
		if (JewelSocketData.add(0).readU8() != 0) {
			InterfacePacketBuf_put_binary(PacketGuard, JewelSocketData, 30);
			return ret;
		}
		return ret
	}, 'int', ['pointer', 'pointer', 'int', 'pointer']));

	var CUser_copyItemOption = new NativeFunction(ptr(0x08671EB2), 'int', ['pointer', 'pointer', 'pointer'], { "abi": "sysv" });//设计图继承
	Interceptor.replace(ptr(0x08671EB2), new NativeCallback(function (CUser, Inven_Item1, Inven_Item2) {
		var jewelSocketID = Inven_Item2.add(25).readU32()
		Inven_Item1.add(25).writeU32(jewelSocketID)
		return CUser_copyItemOption(CUser, Inven_Item1, Inven_Item2);
	}, 'int', ['pointer', 'pointer', 'pointer']));


	var Dispatcher_AddSocketToAvatar_dispatch_sig = new NativeFunction(ptr(0x0821A412), 'int', ['pointer', 'pointer', 'pointer'], { "abi": "sysv" });
	Interceptor.replace(ptr(0x0821A412), new NativeCallback(function (Dispatcher_AddSocketToAvatar, CUser, PacketBuf) {//装备开孔
		var pack = Memory.alloc(0x20000)
		Memory.copy(pack, PacketBuf, 1000)
		var ret = 0;
		try {
			var equ_slot = api_PacketBuf_get_short(pack);//装备所在位置
			var equitem_id = api_PacketBuf_get_int(pack);//装备代码
			var sta_slot = api_PacketBuf_get_short(pack);//道具所在位置
			var CurCharacInvenW = CUserCharacInfo_getCurCharacInvenW(CUser);//获取人物背包
			var inven_item = CInventory_GetInvenRef(CurCharacInvenW, 1, equ_slot);//获取背包对应槽位的装备物品对象
			//var is_equ = inven_item.add(1).readU8()//是否为装备物品
			if (equ_slot > 56) {//修改后：大于56则是时装装备   原：如果不是装备文件就调用原逻辑
				equ_slot = equ_slot - 57;
				var C_PacketBuf = api_PacketBuf_get_buf(PacketBuf)//获取原始封包数据
				C_PacketBuf.add(0).writeShort(equ_slot)//修改掉装备位置信息 时装类镶嵌从57开始。
				return Dispatcher_AddSocketToAvatar_dispatch_sig(Dispatcher_AddSocketToAvatar, CUser, PacketBuf);

			}
			var equ_id = inven_item.add(25).readU32()
			if (api_exitjeweldata(equ_id) == 1) {//判断是否存在数据槽位
				CUser_SendCmdErrorPacket(CUser, 209, 19);
				return 0;
			}

			var item = CDataManager_find_item(G_CDataManager(), equitem_id);//取出pvf文件
			var ItemType = CEquipItem_GetItemType(item)	//这个地方是获取标识的 10是武器 11是称号
			// if(ItemType == 10){
			// send_windows_pack_233(CUser,'武器类型的装备暂不支持打孔。');
			// CUser_SendCmdErrorPacket(CUser, 209, 0);//回包防假死
			// return 0;
			//}else if(ItemType == 11){
			//send_windows_pack_233(CUser,'称号类型的装备暂不支持打孔。');
			//CUser_SendCmdErrorPacket(CUser, 209, 0);//回包防假死，注意称号不要关闭，不然扔到称号铺炸数据！
			//return 0;	

			//}
			var id = add_equiment_socket(ItemType)//生成槽位
			CInventory_delete_item(CurCharacInvenW, 1, sta_slot, 1, 8, 1);//删除打孔道具
			inven_item.add(25).writeU32(id)//写入槽位标识
			CUser_SendUpdateItemList(CUser, 1, 0, equ_slot);
			var packet_guard = api_PacketGuard_PacketGuard();
			InterfacePacketBuf_put_header(packet_guard, 1, 209);
			InterfacePacketBuf_put_byte(packet_guard, 1);
			InterfacePacketBuf_put_short(packet_guard, equ_slot + 104);//装备槽位 从104开始返回给本地处理显示正确的装备
			InterfacePacketBuf_put_short(packet_guard, sta_slot);//道具槽位
			InterfacePacketBuf_finalize(packet_guard, 1);
			CUser_Send(CUser, packet_guard);
			Destroy_PacketGuard_PacketGuard(packet_guard);
		} catch (error) {
			console.log(error)
		}
		return 0;
	}, 'int', ['pointer', 'pointer', 'pointer']));
	Interceptor.attach(ptr(0x8217BD6), {//装备镶嵌和时装镶嵌
		onEnter: function (args) {

			try {
				var user = args[1];
				var packet_buf = args[2];
				var state = CUser_get_state(user);
				if (state != 3) {
					return;
				}
				var avartar_inven_slot = api_PacketBuf_get_short(packet_buf);
				var avartar_item_id = api_PacketBuf_get_int(packet_buf);
				var emblem_cnt = api_PacketBuf_get_byte(packet_buf);

				//下面是参照原时装镶嵌的思路写的。个别点标记出来。
				if (avartar_inven_slot > 104) {//为了不与时装镶嵌冲突,用孔位来判断,小于104是时装装备

					var equipment_inven_slot = avartar_inven_slot - 104;//取出真实装备所在背包位置值
					var inven = CUserCharacInfo_getCurCharacInvenW(user);
					var equipment = CInventory_GetInvenRef(inven, 1, equipment_inven_slot);
					if (Inven_Item_isEmpty(equipment) || (Inven_Item_getKey(equipment) != avartar_item_id) || CUser_CheckItemLock(user, 1, equipment_inven_slot)) {
						return;
					}

					var id = equipment.add(25).readU32();
					var JewelSocketData = Memory.alloc(30);//空字节数据
					JewelSocketData = api_get_jewel_socket_data(mysql_frida, id)//取出原有的孔位以及徽章数据
					if (JewelSocketData.isNull()) {//为空则不进行镶嵌
						return;
					}

					if (emblem_cnt <= 3) {
						var emblems = {};
						for (var i = 0; i < emblem_cnt; i++) {
							var emblem_inven_slot = api_PacketBuf_get_short(packet_buf);
							var emblem_item_id = api_PacketBuf_get_int(packet_buf);
							var equipment_socket_slot = api_PacketBuf_get_byte(packet_buf);
							var emblem = CInventory_GetInvenRef(inven, 1, emblem_inven_slot);
							if (Inven_Item_isEmpty(emblem) || (Inven_Item_getKey(emblem) != emblem_item_id) || (equipment_socket_slot >= 3)) {
								return;
							}

							var citem = CDataManager_find_item(G_CDataManager(), emblem_item_id);
							if (citem.isNull()) {
								return;
							}

							if (!CItem_is_stackable(citem) || (CStackableItem_GetItemType(citem) != 20)) {
								return;
							}

							var emblem_socket_type = CStackableItem_getJewelTargetSocket(citem);
							var avartar_socket_type = JewelSocketData.add(equipment_socket_slot * 6).readU16();

							if (!(emblem_socket_type & avartar_socket_type)) {
								return;
							}

							emblems[equipment_socket_slot] = [emblem_inven_slot, emblem_item_id];
						}
					}

					for (var equipment_socket_slot in emblems) {
						var emblem_inven_slot = emblems[equipment_socket_slot][0];
						CInventory_delete_item(inven, 1, emblem_inven_slot, 1, 8, 1);
						var emblem_item_id = emblems[equipment_socket_slot][1];
						JewelSocketData.add(2 + 6 * equipment_socket_slot).writeU32(emblem_item_id)
					}
					var DB_JewelSocketData = '';//用于生成镶嵌后的数据
					for (var i = 0; i <= 4; i++) {
						DB_JewelSocketData = lengthCutting(JewelSocketData.add(i * 6).readU16().toString(16), DB_JewelSocketData, 2, 4)
						DB_JewelSocketData = lengthCutting(JewelSocketData.add(2 + i * 6).readU32().toString(16), DB_JewelSocketData, 2, 8)
					}
					var a = save_equiment_socket(DB_JewelSocketData, id)//保存数据,向数据库中写入数据
					if (a == 0) {//0为失败
						return;
					}
					CUser_SendUpdateItemList_DB(user, equipment_inven_slot, JewelSocketData);//用于更新镶嵌后的装备显示,这里用的是带镶嵌数据的更新背包函数,并非CUser_SendUpdateItemList
					var packet_guard = api_PacketGuard_PacketGuard();
					InterfacePacketBuf_put_header(packet_guard, 1, 209);//呼出弹窗
					InterfacePacketBuf_put_byte(packet_guard, 1);
					InterfacePacketBuf_put_short(packet_guard, equipment_inven_slot + 104);//装备槽位+104发送回本地让本地处理正确的数据 
					InterfacePacketBuf_finalize(packet_guard, 1);
					CUser_Send(user, packet_guard);
					return;
				}
				//以下是fr自带的嵌入逻辑
				//获取时装道具
				var inven = CUserCharacInfo_getCurCharacInvenW(user);
				var avartar = CInventory_GetInvenRef(inven, 2, avartar_inven_slot);

				//校验时装 数据是否合法
				if (Inven_Item_isEmpty(avartar) || (Inven_Item_getKey(avartar) != avartar_item_id) || CUser_CheckItemLock(user, 2, avartar_inven_slot)) {
					return;
				}

				//获取时装插槽数据
				var avartar_add_info = avartar.add(7).readInt();
				var inven_avartar_mgr = CInventory_GetAvatarItemMgrR(inven);
				var jewel_socket_data = WongWork_CAvatarItemMgr_getJewelSocketData(inven_avartar_mgr, avartar_add_info);
				//log('jewel_socket_data=' + jewel_socket_data + ':' + bin2hex(jewel_socket_data, 30));

				if (jewel_socket_data.isNull()) {
					return;
				}

				//最多只支持3个插槽
				if (emblem_cnt <= 3) {
					var emblems = {};

					for (var i = 0; i < emblem_cnt; i++) {
						//徽章所在的背包槽
						var emblem_inven_slot = api_PacketBuf_get_short(packet_buf);
						//徽章item_id
						var emblem_item_id = api_PacketBuf_get_int(packet_buf);
						//该徽章镶嵌的时装插槽id
						var avartar_socket_slot = api_PacketBuf_get_byte(packet_buf);

						//log('emblem_inven_slot=' + emblem_inven_slot + ', emblem_item_id=' + emblem_item_id + ', avartar_socket_slot=' + avartar_socket_slot);

						//获取徽章道具
						var emblem = CInventory_GetInvenRef(inven, 1, emblem_inven_slot);

						//校验徽章及插槽数据是否合法
						if (Inven_Item_isEmpty(emblem) || (Inven_Item_getKey(emblem) != emblem_item_id) || (avartar_socket_slot >= 3)) {
							return;
						}

						//校验徽章是否满足时装插槽颜色要求

						//获取徽章pvf数据
						var citem = CDataManager_find_item(G_CDataManager(), emblem_item_id);
						if (citem.isNull()) {
							return;
						}

						//校验徽章类型
						if (!CItem_is_stackable(citem) || (CStackableItem_GetItemType(citem) != 20)) {
							return;
						}

						//获取徽章支持的插槽
						var emblem_socket_type = CStackableItem_getJewelTargetSocket(citem);

						//获取要镶嵌的时装插槽类型
						var avartar_socket_type = jewel_socket_data.add(avartar_socket_slot * 6).readShort();

						if (!(emblem_socket_type & avartar_socket_type)) {
							//插槽类型不匹配
							//log('socket type not match!');
							return;
						}

						emblems[avartar_socket_slot] = [emblem_inven_slot, emblem_item_id];
					}



					//开始镶嵌
					for (var avartar_socket_slot in emblems) {
						//删除徽章
						var emblem_inven_slot = emblems[avartar_socket_slot][0];
						CInventory_delete_item(inven, 1, emblem_inven_slot, 1, 8, 1);

						//设置时装插槽数据
						var emblem_item_id = emblems[avartar_socket_slot][1];
						api_set_JewelSocketData(jewel_socket_data, avartar_socket_slot, emblem_item_id);

						//log('徽章item_id=' + emblem_item_id + '已成功镶嵌进avartar_socket_slot=' + avartar_socket_slot + '的槽内!');
					}

					//时装插槽数据存档
					DB_UpdateAvatarJewelSlot_makeRequest(CUserCharacInfo_getCurCharacNo(user), avartar.add(7).readInt(), jewel_socket_data);

					//通知客户端时装数据已更新
					CUser_SendUpdateItemList(user, 1, 1, avartar_inven_slot);

					//回包给客户端
					var packet_guard = api_PacketGuard_PacketGuard();
					InterfacePacketBuf_put_header(packet_guard, 1, 204);
					InterfacePacketBuf_put_int(packet_guard, 1);
					InterfacePacketBuf_finalize(packet_guard, 1);
					CUser_Send(user, packet_guard);
					Destroy_PacketGuard_PacketGuard(packet_guard);

					//log('镶嵌请求已处理完成!');
				}


			} catch (error) {
				console.log('fix_use_emblem throw Exception:' + error);
			}


		},
		onLeave: function (retval) {
			//返回值改为0  不再踢线
			retval.replace(0);
		}
	});
	var InterfacePacketBuf_put_packet = new NativeFunction(ptr(0x0815098e), 'int', ['pointer', 'pointer'], { "abi": "sysv" });
	Interceptor.replace(ptr(0x0815098e), new NativeCallback(function (PacketBuf, Inven_Item) {//额外数据包,发送装备镶嵌数据给本地处理
		var ret = InterfacePacketBuf_put_packet(PacketBuf, Inven_Item);
		if (Inven_Item.add(1).readU8() == 1) {
			var JewelSocketData = Memory.alloc(30);
			JewelSocketData = api_get_jewel_socket_data(mysql_frida, Inven_Item.add(25).readU32())
			if (JewelSocketData.add(0).readU8() != 0) {
				InterfacePacketBuf_put_binary(PacketBuf, JewelSocketData, 30);
				return ret;
			}
		}
		return ret;
	}, 'int', ['pointer', 'pointer']));
	var Inter_AuctionResultMyRegistedItems_dispatch_sig = new NativeFunction(ptr(0x084D7758), 'int', ['pointer', 'pointer', 'pointer', 'int'], { "abi": "sysv" });
	Interceptor.replace(ptr(0x084D7758), new NativeCallback(function (Inter_AuctionResultMyRegistedItems, CUser, src, a4) {//上架显示
		//每个物品占117字节 所以每个物品的偏移量是117
		var JewelSocketData = Memory.alloc(30)
		var count = src.add(5).readU8()//获取上架物品数量
		for (var i = 0; i < count; i++) {//遍历写入数据
			var item_id = src.add(37 + 117 * i).readU32();
			var item = CDataManager_find_item(G_CDataManager(), item_id);
			var item_groupname = CItem_getItemGroupName(item)
			if (item_groupname > 0 && item_groupname < 59) {//1-58是装备
				JewelSocketData = api_get_jewel_socket_data(mysql_frida, src.add(59 + i * 117).readU32())
				Memory.copy(src.add(89 + i * 117), JewelSocketData, 30);
			}
		}
		var ret = Inter_AuctionResultMyRegistedItems_dispatch_sig(Inter_AuctionResultMyRegistedItems, CUser, src, a4)
		return ret;
	}, 'int', ['pointer', 'pointer', 'pointer', 'int']));
	var Inter_AuctionResultItemList_dispatch_sig = new NativeFunction(ptr(0x084D75BC), 'int', ['pointer', 'pointer', 'pointer', 'int'], { "abi": "sysv" });
	Interceptor.replace(ptr(0x084D75BC), new NativeCallback(function (Inter_AuctionResultMyRegistedItems, CUser, src, a4) {//搜索显示
		//每个物品占137字节 所以每个物品的偏移量是137
		var JewelSocketData = Memory.alloc(30)
		var count = src.add(5).readU8()//获取上架物品数量
		for (var i = 0; i < count; i++) {//遍历写入数据
			var item_id = src.add(54 + 137 * i).readU32();
			var item = CDataManager_find_item(G_CDataManager(), item_id);
			var item_groupname = CItem_getItemGroupName(item)
			if (item_groupname > 0 && item_groupname < 59) {//1-58是装备
				JewelSocketData = api_get_jewel_socket_data(mysql_frida, src.add(76 + i * 137).readU32())
				Memory.copy(src.add(106 + i * 137), JewelSocketData, 30);
			}
		}
		var ret = Inter_AuctionResultItemList_dispatch_sig(Inter_AuctionResultMyRegistedItems, CUser, src, a4)
		return ret;
	}, 'int', ['pointer', 'pointer', 'pointer', 'int']));
	var Inter_AuctionResultMyBidding_dispatch_sig = new NativeFunction(ptr(0x084D78F4), 'int', ['pointer', 'pointer', 'pointer', 'int'], { "abi": "sysv" });
	Interceptor.replace(ptr(0x084D78F4), new NativeCallback(function (Inter_AuctionResultMyRegistedItems, CUser, src, a4) {//竞拍显示
		//每个物品占125字节 所以每个物品的偏移量是125
		var JewelSocketData = Memory.alloc(30)
		var count = src.add(5).readU8()//获取上架物品数量
		for (var i = 0; i < count; i++) {//遍历写入数据
			var item_id = src.add(46 + 125 * i).readU32();
			var item = CDataManager_find_item(G_CDataManager(), item_id);
			var item_groupname = CItem_getItemGroupName(item)
			if (item_groupname > 0 && item_groupname < 59) {//1-58是装备
				JewelSocketData = api_get_jewel_socket_data(mysql_frida, src.add(68 + i * 125).readU32())
				Memory.copy(src.add(98 + i * 125), JewelSocketData, 30);
			}
		}
		var ret = Inter_AuctionResultMyBidding_dispatch_sig(Inter_AuctionResultMyRegistedItems, CUser, src, a4)
		return ret;
	}, 'int', ['pointer', 'pointer', 'pointer', 'int']));
	Interceptor.replace(ptr(0x0814A62E), new NativeCallback(function (Inven_Item, CInven_Item) {//装备全字节复制
		Memory.copy(Inven_Item, CInven_Item, 61)
		return Inven_Item;
	}, 'pointer', ['pointer', 'pointer']));
	Interceptor.replace(ptr(0x080CB7D8), new NativeCallback(function (Inven_Item) {//装备全字节删除
		var MReset = Memory.alloc(61)
		Memory.copy(Inven_Item, MReset, 61)
		return Inven_Item;
	}, 'pointer', ['pointer']));
	Memory.patchCode(ptr(0x085A6563), 72, function (code) {//装备掉落全字节保存
		var cw = new X86Writer(code, { pc: ptr(0x085A6563) });
		cw.putLeaRegRegOffset('eax', 'ebp', -392);//lea eax, [ebp-188h]
		cw.putLeaRegRegOffset('ebx', 'ebp', -213);//lea ebx, [ebp-0D5h]
		cw.putMovRegOffsetPtrU32('esp', 8, 61)
		cw.putMovRegOffsetPtrReg('esp', 4, 'eax')
		cw.putMovRegOffsetPtrReg('esp', 0, 'ebx')
		cw.putCallAddress(ptr(0x0807d880))
		cw.putLeaRegRegOffset('eax', 'ebp', -392);//lea eax, [ebp-188h]
		cw.putLeaRegRegOffset('ebx', 'ebp', -300);//
		cw.putAddRegImm('ebx', 0x10)//add ebx,0x10
		cw.putMovRegOffsetPtrU32('esp', 8, 61)//mov [esp+8],61
		cw.putMovRegOffsetPtrReg('esp', 4, 'eax')
		cw.putMovRegOffsetPtrReg('esp', 0, 'ebx')
		cw.putCallAddress(ptr(0x0807d880))
		cw.putNop()
		cw.putNop()
		cw.putNop()
		cw.putNop()
		cw.putNop()
		cw.flush();
	});
	//	Memory.patchCode(ptr(0x0820154E), 12, function (code) {//装备调整箱强制最上级,我用的功能,你不用可以删除掉
	//       var cw = new X86Writer(code, { pc: ptr(0x0820154E)});
	//        cw.putMovRegU32('eax',0x5);
	//		cw.putNop()
	//		cw.putNop()
	//		cw.putMovRegU32('eax',0x5);
	//        cw.flush();
	//    });
}
//xq

var get_rand_int = new NativeFunction(ptr(0x086B1B87), 'int', ['int'], { "abi": "sysv" });

//额外怪物等级
var add_monster_level = 0;
//随机怪物模式
var random_monster = false;
//额外怪物数量
var copy_monster = 0
//当前副本难度
var dungeon_difficult = 0;
//强制随机装备模式
var enhanced_equip = false;
//增强副本模式
var enhance_dungeon = false;
// 所有卡片数组, 提取序号填入下面即可
// pvf路径stackable\monstercard下一般全为卡片
// 下面列表提取至版本日期20130613的pvf
// 宝珠的类型必须跟装备类型一致,属性才会生效
// var all_monster_card2 = [];
var all_monster_card2 = [3600, 3601, 3602, 3603, 3604, 3605, 3606, 3607, 3608, 3609, 3610, 3611, 3612, 3613, 3614, 3615, 3616, 3617, 3618, 3619, 3620, 3621, 3622, 3623, 3624, 3625, 3626, 3627, 3628, 3629, 3630, 3631, 3632, 3633, 3634, 3635, 3636, 3637, 3638, 3639, 3640, 3641, 3642, 3643, 3644, 3645, 3646, 3647, 3648, 3649, 3650, 3651, 3652, 3653, 3654, 3655, 3656, 3657, 3658, 3659, 3660, 3661, 3662, 3663, 3664, 3665, 3666, 3667, 3668, 3669, 3670, 3671, 3672, 3673, 3674, 3675, 3676, 3677, 3678, 3679, 3680, 3681, 3682, 3683, 3684, 3685, 3686, 3687, 3688, 3689, 3690, 3691, 3692, 3693, 3694, 3695, 3696, 3697, 3698, 3699, 3700, 3701, 3702, 3703, 3704, 3705, 3706, 3707, 3708, 3709, 3710, 3711, 3712, 3713, 3714, 3715, 3716, 3717, 3718, 3719, 3720, 3721, 3722, 3723, 3724, 3725, 3726, 3727, 3728, 3729, 3730, 3731, 3732, 3733, 3734, 3735, 3736, 3737, 3738, 3739, 3740, 3741, 3742, 3743, 3744, 3745, 3746, 3747, 3748, 3749, 3750, 3751, 3752, 3753, 3754, 3755, 3756, 3757, 3758, 3759, 3760, 3761, 3762, 3763, 3764, 3765, 3766, 3767, 3768, 3769, 3770, 3771, 3772, 3773, 3774, 3775, 3776, 3777, 3778, 3779, 3780, 3781, 3782, 3783, 3784, 3785, 3786, 3787, 3788, 3789, 3790, 3791, 3792, 3793, 3794, 3795, 3796, 3797, 3798, 3799, 3800];
// 所有魔法封印编号  pvf路径etc/randomoption/randomoption.lst
// 所有装备改魔法封印，所有装备添加下面的标签,
//[random option] 
//      1
//部分装备不生效是因为装备等级 编辑etc/randomoption/optionquantity.etc添加装备等级
var all_random_option = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 51, 52, 53, 54, 55, 56, 57, 58, 60, 61, 62, 63, 64, 65, 66, 67, 70, 71, 72, 73, 74, 75, 76, 77, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 96, 97, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 130, 131, 132, 133, 134, 140, 141, 142, 143, 144, 145, 150, 151, 152, 153, 240, 241, 242, 243, 244, 245, 246, 247];
/**物品每个字节解释
 * 1类型
 * 2-5装备id
 * 6 强化等级
 * 7-10 装备品级
 * 11-12 耐久度
 * 13-16 宝珠
 * 17 增幅 1体力 2精神 3力量 4智力
 * 18-19 增幅附加值
 * 31-32 异界气息
 * 37-50 魔法封印
 * 51 锻造等级
 */
/*游戏内定时公告业务逻辑开始*/
var msglist =
	[
		'<公告>\n【本服属于纯爆装版本】\n无需套娃做装备，本服装备都可通过深渊掉落！\n人人平等，全靠运气！下一个欧皇可能就是你！',
		'<公告>\n本服的装备很多，当勇士们陷入迷茫的时候，不如打开装备词典看看，是否有自己需要的装备，装备词典中完整的记录了所有装备的产出方式',
		'<公告>\n本服属于副本阶段性玩法：\n切记每个阶段都需要达到一定的抗魔值才能进入哦。越高级的副本，掉落的装备越好哦！',
		'<公告>\n抉择之沼大概率掉落史诗装备，大佬们每天千万不要忘记去刷哦',
		'<公告>\n针对细节帝，可以完成称号簿成就任务\n可以获得超高额外属性！',
		'<公告>\n角色初始化技能后,SP/TP点数会通过邮件形式返还给玩家，玩家可以放心初始化技能。'
	];

function SendRandMsg() {
	api_GameWorld_SendNotiPacketMessage(msglist[get_rand_int(msglist.length)], 0);
	api_scheduleOnMainThread_delay(SendRandMsg, null, 30000);
}
/*游戏内定时公告业务逻辑结束*/



//============================================= dp集成frida =============================================

/*
frida 官网地址: https://frida.re/

frida提供的js api接口文档地址: https://frida.re/docs/javascript-api/

关于dp2支持frida的说明, 请参阅: /dp2/lua/df/frida.lua
*/

// 入口点
// int frida_main(lua_State* ls, const char* args);
function frida_main(ls, _args) {
	// args是lua调用时传过来的字符串
	// 建议约定lua和js通讯采用json格式
	const args = _args.readUtf8String();

	// 在这里做你需要的事情
	console.log('[' + get_timestamp() + '] [frida] [info] frida main, args = ' + args);

	return 0;
}

// 当lua调用js时触发
// int frida_handler(lua_State* ls, int arg1, float arg2, const char* arg3);
function frida_handler(ls, arg1, arg2, _arg3) {
	const arg3 = _arg3.readUtf8String();

	// 如果需要通讯, 在这里编写逻辑
	// 比如: arg1是功能号, arg3是数据内容 (建议json格式)

	// just for test
	dp2_lua_call(arg1, arg2, arg3)

	return 0;
}

// 获取dp2的符号
// void* dp2_frida_resolver(const char* fname);
var __dp2_resolver = null;
function dp2_resolver(fname) {
	return __dp2_resolver(Memory.allocUtf8String(fname));
}

// 通讯 (调用lua)
// int lua_call(int arg1, float arg2, const char* arg3);
var __dp2_lua_call = null;
function dp2_lua_call(arg1, arg2, _arg3) {
	var arg3 = null;
	if (_arg3 != null) {
		arg3 = Memory.allocUtf8String(_arg3);
	}
	return __dp2_lua_call(arg1, arg2, arg3);
}

// 准备工作
function setup() {
	//dp 安装 frida的
	var addr = Module.getExportByName('libdp2.so', 'dp2_frida_resolver');
	__dp2_resolver = new NativeFunction(addr, 'pointer', ['pointer']);

	addr = dp2_resolver('lua.call');
	__dp2_lua_call = new NativeFunction(addr, 'int', ['int', 'float', 'pointer']);

	addr = dp2_resolver('frida.main');
	Interceptor.replace(addr, new NativeCallback(frida_main, 'int', ['pointer', 'pointer']));

	addr = dp2_resolver('frida.handler');
	Interceptor.replace(addr, new NativeCallback(frida_handler, 'int', ['pointer', 'int', 'float', 'pointer']));

	Interceptor.flush();
	console.log('[' + get_timestamp() + '] [frida] [info] -------------------------- setup success ---------------------------');

	// frida自己的配置
	start()

}

//延迟加载插件
function awake() {
	//Hook check_argv
	console.log('[' + get_timestamp() + '] [frida] [info] ------------------------------- awake ------------------------------');
	Interceptor.attach(ptr(0x829EA5A),
		{
			onEnter: function (args) { },
			onLeave: function (retval) {
				//等待check_argv函数执行结束 再加载插件
				console.log('[' + get_timestamp() + '] [frida] [info] ------------------------------- setup -------------------------------');
				setup();
			}
		});
}

rpc.exports = {
	init: function (stage, parameters) {
		console.log('[' + get_timestamp() + '] [frida] [info] Frida Init Stage:' + stage);

		if (stage == 'early') {
			//awake();
			setup();
		} else {
			//热重载:  直接加载
			console.log('[' + get_timestamp() + '] [frida] [info] ------------------------------- reload ------------------------------');
			setup();
		}
	},
	dispose: function () {
		event_rankinfo_save_to_db();
		uninit_db();
		console.log('[' + get_timestamp() + '] [frida] [info] ------------------------------ dispose ------------------------------');
	}
};




function startOnlineGifts_new() {
	api_scheduleOnMainThread_delay(startOnlineGifts_new, null, 1000);
	var date = new Date();
	date = new Date(date.setHours(date.getHours() + 0));     //转换到本地时间
	var hour = date.getHours();
	var minute = date.getMinutes();
	var second = date.getSeconds();

	//遍历在线玩家列表
	var it = api_gameworld_user_map_begin();
	var end = api_gameworld_user_map_end();

	//判断在线玩家列表遍历是否已结束
	while (gameworld_user_map_not_equal(it, end)) {
		//当前被遍历到的玩家
		var user = api_gameworld_user_map_get(it);
		//只处理已登录角色
		if (CUser_get_state(user) >= 3) {
			var UID = CUser_get_acc_id(user);
			var charac_no = CUserCharacInfo_getCurCharacNo(user);
			api_MySQL_exec(mysql_personal_production, 'insert into joyclub_vip (charac_no,quest,vip) select ' + charac_no + ',0 ,0  from DUAL where not exists (select charac_no from joyclub_vip where charac_no=' + charac_no + ');');

		}
		api_gameworld_user_map_next(it);
	}
}

function api_joyclub_vip(user) {
	var value = null;
	var charac_no = CUserCharacInfo_getCurCharacNo(user); //角色id
	if (api_MySQL_exec(mysql_personal_production, "select vip from joyclub_vip where charac_no=" + charac_no + ";")) {
		if (MySQL_get_n_rows(mysql_personal_production) == 1) {
			if (MySQL_fetch(mysql_personal_production)) {
				value = api_MySQL_get_int(mysql_personal_production, 0);
			}
		}
	}
	return value;
}



var InterfacePacketBuf_put_str = new NativeFunction(ptr(0x081B73E4), 'int', ['pointer', 'pointer', 'int'], { "abi": "sysv" });
var CUser_SendPacket = new NativeFunction(ptr(0x867B8FE), 'int', ['pointer', 'int', 'pointer'], { "abi": "sysv" });

function api_SendHyperLinkChatMsg_emoji(user, strarr, msgtype, type, Symbol) {
	const bufferSize = 255;
	const strptr = Memory.alloc(bufferSize);
	let startlen = 0;
	let cnt = 0;
	// 准备表情符号数据
	const emojiBytes = Symbol >= 1 ? [0xc2, 0x80, 0x20, 0x1e, 0x20, Symbol, 0x1f] : [0xc2, 0x80, 0x20];
	strptr.add(startlen).writeByteArray(emojiBytes);
	startlen += emojiBytes.length;
	// 处理消息字符串数组

	for (const item of strarr) {
		const [strtype, msgContent, flags] = item;
		strptr.add(startlen).writeByteArray([0xc2, 0x80]);
		startlen += 2; // 更新起始长度
		const msgstr = (strtype === 'str') ? msgContent : '[' + api_CItem_GetItemName(msgContent) + ']';
		const str_ptr = Memory.allocUtf8String(msgstr);
		const str_len = strlen(str_ptr);
		strptr.add(startlen).writeByteArray(str_ptr.readByteArray(str_len));
		startlen += str_len;

		// 检查是否需要添加额外的字节
		if (flags[3] === 255) {
			strptr.add(startlen).writeByteArray([0xc2, 0x80]);
			startlen += 2;
			cnt++;
		}
	}
	// 结束字符串并准备数据包
	strptr.add(startlen).writeByteArray([0xc2, 0x80]);
	startlen += 2;
	const packet_guard = api_PacketGuard_PacketGuard();
	InterfacePacketBuf_put_header(packet_guard, 0, 370);
	InterfacePacketBuf_put_byte(packet_guard, msgtype);
	InterfacePacketBuf_put_short(packet_guard, 0);
	InterfacePacketBuf_put_byte(packet_guard, 0);
	InterfacePacketBuf_put_int(packet_guard, startlen);
	InterfacePacketBuf_put_str(packet_guard, strptr, startlen);
	InterfacePacketBuf_put_byte(packet_guard, cnt);
	// 处理附加信息
	for (const item of strarr) {
		const [_, msgtype, flags] = item;
		if (flags[3] === 255) {
			const RbgInfoptr = Memory.alloc(104);
			RbgInfoptr.writeByteArray(flags);
			// 处理消息类型
			if (typeof msgtype === 'number') {
				RbgInfoptr.add(0x4).writeU32(msgtype);
				const Citem = CDataManager_find_item(G_CDataManager(), msgtype);
				if (!CItem_is_stackable(Citem)) {
					RbgInfoptr.add(0x8).writeU32(get_rand_int(0));
					RbgInfoptr.add(0xe).writeU16(CEquipItem_get_endurance(Citem));
				}
			}
			InterfacePacketBuf_put_binary(packet_guard, RbgInfoptr, 104);
		}
	}
	// 完成数据包
	InterfacePacketBuf_finalize(packet_guard, 1);
	// 根据类型发送数据包
	if (type === 1) {
		CUser_SendPacket(user, 1, packet_guard);
	}
	else {
		GameWorld_send_all_with_state(G_GameWorld(), packet_guard, 3); // 只给状态 >= 3 的玩家发送公告
	}
	// 清理数据包
	Destroy_PacketGuard_PacketGuard(packet_guard);
}


var DGN_ID = {};

var globalData =
{
	acquiredItems: {},
	epicItems: {}
};

function Prompt_to_drop(user, item_id) {
	var itemData = CDataManager_find_item(G_CDataManager(), item_id);
	var Rarity = CItem_getRarity(itemData); // 稀有度
	var charac_no = CUserCharacInfo_getCurCharacNo(user); // 获取当前角色编号
	// 记录获得的特定道具数量
	if (Rarity == 4) {
		if (!globalData.acquiredItems[charac_no]) {
			globalData.acquiredItems[charac_no] = {};
		}
		if (globalData.acquiredItems[charac_no][item_id]) {
			globalData.acquiredItems[charac_no][item_id]++;
		}
		else {
			globalData.acquiredItems[charac_no][item_id] = 1;
		}
	}
	if (Rarity == 4) {
		if (!globalData.epicItems[charac_no]) {
			globalData.epicItems[charac_no] = {};
		}
		if (globalData.epicItems[charac_no][item_id]) {
			globalData.epicItems[charac_no][item_id]++;
		}
		else {
			globalData.epicItems[charac_no][item_id] = 1;
		}
	}
}

function api_CUser_Rarity_Item(user, args, item_id, item_nu) {
	var itemData = CDataManager_find_item(G_CDataManager(), item_id);
	var needLevel = CItem_getUsableLevel(itemData);  //等级
	var Rarity = CItem_getRarity(itemData); // 稀有度

	if (Rarity == 0) {
		api_SendHyperLinkChatMsg_emoji(user,
			[
				['str', args, [255, 255, 0, 255]],
				['item', item_id, [255, 255, 255, 255]],
				['str', '' + item_nu + '个', [255, 255, 0, 255]],
			], 14, 0, 0);
		api_CUser_AddItem(user, item_id, item_nu)
	}
	if (Rarity == 1) {
		api_SendHyperLinkChatMsg_emoji(user,
			[
				['str', args, [255, 255, 0, 255]],
				['item', item_id, [104, 213, 237, 255]],
				['str', '' + item_nu + '个', [255, 255, 0, 255]],
			], 14, 0, 0);
		api_CUser_AddItem(user, item_id, item_nu)
	}
	if (Rarity == 2) {
		api_SendHyperLinkChatMsg_emoji(user,
			[
				['str', args, [255, 255, 0, 255]],
				['item', item_id, [179, 107, 255, 255]],
				['str', '' + item_nu + '个', [255, 255, 0, 255]],
			], 14, 0, 0);
		api_CUser_AddItem(user, item_id, item_nu)
	}
	if (Rarity == 3) {
		api_SendHyperLinkChatMsg_emoji(user,
			[
				['str', args, [255, 255, 0, 255]],
				['item', item_id, [255, 0, 240, 255]],
				['str', '' + item_nu + '个', [255, 255, 0, 255]],
			], 14, 0, 0);
		api_CUser_AddItem(user, item_id, item_nu)
	}
	if (Rarity == 4) {
		api_SendHyperLinkChatMsg_emoji(user,
			[
				['str', args, [255, 255, 0, 255]],
				['item', item_id, [255, 170, 0, 255]],
				['str', '' + item_nu + '个', [255, 255, 0, 255]],
			], 14, 0, 0);
		api_CUser_AddItem(user, item_id, item_nu)
	}
	if (Rarity == 5) {
		api_SendHyperLinkChatMsg_emoji(user,
			[
				['str', args, [255, 255, 0, 255]],
				['item', item_id, [255, 102, 102, 255]],
				['str', '' + item_nu + '个', [255, 255, 0, 255]],
			], 14, 0, 0);
		api_CUser_AddItem(user, item_id, item_nu)
	}
}


//点券充值
function formatGoldAmount(amount) {
	return amount.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// 用户使用次数记录
var userUsageCount = {};

function rechargeCeraBasedOnItemId(user, item_id, charac_no) {

	var itemToCeraMapping = {
		202404753: [100, 0, 0, 0, 0],
		202404754: [1000, 0, 0, 0, 0],
		202404755: [10000, 0, 0, 0, 0],
		202404756: [100000, 1, 33, 11111, 33333]
	};

	if (itemToCeraMapping.hasOwnProperty(item_id)) {
		var [PriceCera, canHaveExtra, chance, randomMin, randomMax] = itemToCeraMapping[item_id];
		var extraCera = 0;
		var userKey = charac_no + '_' + item_id;
		// 更新用户使用次数
		userUsageCount[userKey] = (userUsageCount[userKey] || 0) + 1;
		// 计算是否应当提供保底额外奖励
		var isGuaranteedExtra = userUsageCount[userKey] % 10 === 0;
		var chance = 33;
		// 判断是否参与额外奖励
		if (canHaveExtra) {
			var participateIn = get_random_int(1, 101);

			if (participateIn <= chance) {
				//随机点券个数
				extraCera = get_random_int(randomMin, randomMax + 1);
			}
		}
		api_recharge_cash_cera(user, PriceCera + extraCera);

		api_SendHyperLinkChatMsg_emoji(user, //正常充值
			[
				['str', '土豪玩家', [255, 0, 162, 255]],
				['str', '[' + api_CUserCharacInfo_getCurCharacName(user) + ']', [255, 255, 0, 255]],
				['str', '成功充值', [255, 0, 162, 255]],
				['str', ' ' + formatGoldAmount(PriceCera + extraCera) + '', [250, 255, 0, 255]],
				['str', ' 点券', [255, 0, 162, 255]],
			], 0, 0, 35);

		if (extraCera > 0)//活动额外提示
		{
			api_SendHyperLinkChatMsg_emoji(user,
				[
					['str', '包含充值活动奖励 ', [250, 255, 0, 255]],
					['str', ' ' + extraCera + '', [250, 255, 255, 255]],
					['str', ' 点券', [250, 255, 0, 255]],
				], 0, 0, 1);
		}
	}
}



var reward_config = {};
var reward_save_db = {};
var reward_save_db_list = [];

//道具红包
function send_reward_all(user, item_id) {
	reward_save_db = {};
	var arr = reward_config[item_id]
	var flag = false;
	var name = '';
	if (arr != undefined) {
		switch (parseInt(arr[1])) {
			case 1:
				if (parseInt(arr[0]) == 1) {
					if (CUser_getCera(user) >= arr[2]) {
						flag = true;
						name = '[' + arr[2] + '点券]'
					}
				} else {
					flag = true;
					name = '[' + arr[2] + '点券]'
				}
				break;
			case 2:
				if (parseInt(arr[0]) == 1) {
					if (CUser_getCeraPoint(user) >= arr[2]) {
						flag = true;
						name = '[' + arr[2] + '代币]'
					}
				} else {
					flag = true;
					name = '[' + arr[2] + '代币]'
				}
				break;
			case 3:
				if (parseInt(arr[0]) == 1) {
					if (CInventory_get_money(CUserCharacInfo_getCurCharacInvenW(user)) >= arr[2]) {
						flag = true;
						name = '[' + arr[2] + '金币]'
						CInventory_use_money(CUserCharacInfo_getCurCharacInvenW(user), parseInt(arr[2]), 0, 0)
						CUser_send_itemspace(user, ENUM_ITEMSPACE_INVENTORY);
					}
				} else {
					flag = true;
					name = '[' + arr[2] + '金币]'
				}
				break;
			default:
				if (parseInt(arr[0]) == 1) {
					var q = get_your_itemcount(user, parseInt(arr[1]))
					if (q >= arr[2]) {
						flag = true;
						name = '[' + arr[2] + '个' + api_CItem_GetItemName(parseInt(arr[1])) + ']'
						set_your_itemcount(user, parseInt(arr[1]), q, parseInt(arr[2]))
					}
				}
				else {
					flag = true;
					name = '[' + arr[2] + '个' + api_CItem_GetItemName(parseInt(arr[1])) + ']'
				}
				break;
		}
	}
	if (!flag) {
		api_CUser_SendNotiPacketMessage(user, '您背包中的' + api_CItem_GetItemName(parseInt(arr[1])) + '数量不足' + api_CItem_GetItemName(parseInt(arr[2])) + '个\r\n' + api_CItem_GetItemName(item_id) + '已经返还到您的背包', 0);
		api_scheduleOnMainThread_delay(api_CUser_AddItem, [user, item_id, 1], 1);
	}
	else {
		var charac_no = CUserCharacInfo_getCurCharacNo(user)
		var temp = [];
		for (var i in arr) {
			temp.push(arr[i])
		}
		temp.push([])
		temp.push([])
		var charac_name = api_CUserCharacInfo_getCurCharacName(user)
		temp.push(charac_name)
		reward_save_db[charac_no + "_" + item_id] = temp;

		api_SendHyperLinkChatMsg_emoji(user, //正常充值
			[
				['str', '玩家', [255, 255, 0, 255]],
				['str', '[' + charac_name + ']', [250, 0, 0, 255]],
				['str', '发红包啦!\n\n', [255, 255, 0, 255]],
				['str', '红包内容: ', [250, 255, 0, 255]],
				['str', '' + name + '\r', [250, 0, 0, 255]],
				['str', '可领取人数: ' + temp[3] + '人', [255, 255, 0, 255]],
				['str', '使用服务器喇叭输入下方口令即可领取红包\r\n', [255, 255, 0, 255]],
				['str', '' + (temp[4]) + '', [255, 255, 0, 255]],
			], 14, 0, 34);


		//api_GameWorld_SendNotiPacketMessage('玩家[' + charac_name + ']发红包啦!\r\n红包内容:' + name + '\r可领取人数: ' + temp[3] + '人\r\n使用服务器喇叭输入下方口令即可领取红包\r\n' + (temp[4]), 14)
		event_reward_save_to_db();
	}
}

/**
 * 用于加载本地json
 * @param {string} path 需要加载的json路径
 * @returns 返回加载的json数据
 */
function load_json(path) {
	var data = api_read_file(path, 'r', 10 * 1024 * 1024);
	return JSON.parse(data);
}

//从数据库载入红包数据
function event_reward_load_from_db() {
	reward_save_db_list = [];
	reward_save_db = {};
	if (api_MySQL_exec(mysql_Prohibition_of_Cheating, "select event_id,event_info from reward_event ;")) {
		if (MySQL_get_n_rows(mysql_Prohibition_of_Cheating) > 0) {
			for (var i = 1; i <= MySQL_get_n_rows(mysql_Prohibition_of_Cheating); i++) {
				MySQL_fetch(mysql_Prohibition_of_Cheating);
				var id = api_MySQL_get_str(mysql_Prohibition_of_Cheating, 0);
				var info = api_MySQL_get_str(mysql_Prohibition_of_Cheating, 1);
				reward_save_db = JSON.parse(info);
				reward_save_db_list.push({
					id: id,
					info: reward_save_db
				});
			}

		}
	}
}

//存入红包数据
function event_reward_save_to_db() {
	if (JSON.stringify(reward_save_db) == "{}") {
		return;
	}
	api_MySQL_exec(mysql_Prohibition_of_Cheating, "insert into reward_event ( event_info) values ( '" + JSON.stringify(reward_save_db) + "');");
}

//更新领取红包数据
function event_reward_replace_to_db(id, temp) {
	if (JSON.stringify(reward_save_db) == "{}") {
		return;
	}
	api_MySQL_exec(mysql_Prohibition_of_Cheating, "replace into reward_event ( event_id,event_info) values ( '" + id + "','" + JSON.stringify(temp) + "');");
}

//删除已经领取完毕的红包数据
function event_reward_delete_to_db(id) {
	console.info("delete from reward_event where event_id =" + id);
	api_MySQL_exec(mysql_Prohibition_of_Cheating, "delete from reward_event where event_id =" + id + " ;");
}

//删除已经领取完毕的红包数据
function event_reward_delete_to_delete() {
	api_MySQL_exec(mysql_Prohibition_of_Cheating, "delete from reward_event;");
}

/**
* 删除奖励 并重新获取
*/
function reset_bonus_reset() {
	// api_GameWorld_SendNotiPacketMessage("刷新首爆",14);
	month_card_equip_gifts_log = {};
	month_card_equip_gifts = {};
	// api_GameWorld_SendNotiPacketMessage('重置首爆', 14);
	console.info("reset_bonus_reset");
	//删除奖励列表
	api_MySQL_exec(mysql_frida, "delete from reward_item ;");

	api_MySQL_exec(mysql_frida, "delete from already_reward_list ;");

	//重新加载奖励列表
	month_card_equip_gifts = load_json('month_card_equip_gifts.json');
	//重新随机奖励列表
	reset_bonus();

	//定时24后再执行一次
	//因为当前可能执行刷新首曝 所以需要确定下次自动刷新的时间
	//获取当前系统时间
	var cur_time = api_CSystemTime_getCurSec();

	//计算距离下次开启定时任务
	var delay_time = (3600 * EVENT_VILLAGEATTACK_START_HOUR) - (cur_time % (3600 * 24));

	if (delay_time <= 0)
		delay_time += 3600 * 24;

	console.info(+ delay_time / 3600 + 'hour');

	//定时开启活动 
	//定时删除数据库中的奖励信息并存储一个新的数据
	// api_scheduleOnMainThread_delay(reset_bonus_reset, null, delay_time*1000);
	api_scheduleOnMainThread_delay(reset_bonus_reset, null, delay_time * 1000);
}

/**
* 获取奖励 如果数据库中存在奖励则获取数据库中奖励 如果不存在 从json中随机50个
*/
function reset_bonus() {

	//将变量初始化
	month_card_equip_gifts = {};
	//month_card_equip_gifts_log = {};
	//查询当前数据库是否存在奖励
	api_MySQL_exec(mysql_frida, "select id ,reward ,reward from  reward_item where id = '1'");
	if (MySQL_get_n_rows(mysql_frida) > 0) {
		if (MySQL_get_n_rows(mysql_frida) == 1) {
			MySQL_fetch(mysql_frida);
			var reward_jsonstr = api_MySQL_get_str(mysql_frida, 1);
			month_card_equip_gifts = JSON.parse(reward_jsonstr);
		}

	} else {
		//随机获取50个奖励并将50个奖励存储到数据库中
		month_card_equip_gifts = load_json('month_card_equip_gifts.json');
		let keys = Object.keys(month_card_equip_gifts);
		let result = {};
		// Shuffle array
		for (let i = keys.length - 1; i > 0; i--) {
			const j = Math.floor(Math.random() * (i + 1));
			[keys[i], keys[j]] = [keys[j], keys[i]];
		}

		for (let i = 0; i < 50; i++) {
			result[keys[i]] = month_card_equip_gifts[keys[i]];
		}

		//随机50个奖励
		//将奖励获取key
		//通过数据库获取50个奖励
		api_MySQL_exec(mysql_frida, "insert into reward_item (id ,reward) values ('1', '" + JSON.stringify(result) + "');");
		month_card_equip_gifts = result;

	}
}



//发送物品连接信息
function sendMessage(user, text, item_id) {
	var packet_guard = api_PacketGuard_PacketGuard();
	// 先把包清空
	InterfacePacketBuf_clear(packet_guard);

	// 消息内容
	// 贴吧吴克说的比较笼统
	// 经过Hook GameWorld::make_packet_chat_msg_hyper_link 函数得知
	// 开头有两个0x80 结尾一个0x80 中间每段消息以两个0x80分割 发送两个物品聊天输出16进制字符串如下
	// 80 80 5b 44 4e 46 904b 71df 5546 5d 80 80 5b 44 4e 46 904b 71df 5546 3010 7121 6280 80fd 52a0 6210 3011 5d 80
	// 所以，两个段消息 消息内容应该是：'\x80\x80' + '测试信息：史诗颜色' + '\x80\x80' + '测试信息：神器颜色' + '\x80'
	// 以此类推

	var originalText = Memory.allocUtf8String('\x80\x80' + text + '\x80');
	var strLenth = strlen(originalText);

	// 转换颜色字符串
	var epicColorByte = colorStringToByteArray("#FF00F0FF");

	// 分配内存并填充二进制分段消息属性数据 这里通过 Hook 查看到 大小都是104字节截取 所以需要填充到104字节
	// 如果需要可以点开的数据，那么需要： 
	// 颜色字节 ff b1 00 ff    (获取装备/物品颜色)
	// 装备代码 2a 2c 0a 00    (顺序相反，666666这里变成了2a2c0a 实际应该是 0a2c2a)
	// 装备品级 48 00 8f 61    (获取装备品级 应该也是反的 没测试没计算 消耗品/材料理论上不需要这个)
	// 剩余填满104字节

	var epicColorData = Memory.alloc(104);
	var colorPadding = new Uint8Array(104);
	colorPadding.set(epicColorByte);
	Memory.writeByteArray(epicColorData, colorPadding);

	var equipCoolorStr;
	// 转换物品ID例子
	// var itemId = 26033;
	var itemData = CDataManager_find_item(G_CDataManager(), item_id);
	var inEquRarity = CItem_getRarity(itemData); // 稀有度 0x080F12D6
	console.log("inEquRarity:", inEquRarity)
	switch (inEquRarity) {
		case 0:
			equipCoolorStr = '#FFFFFFFF';
			break;
		case 1:
			equipCoolorStr = '#68D5EDFF';
			break;
		case 2:
			equipCoolorStr = '#B36BFFFF';
			break;
		case 3:
			equipCoolorStr = '#FF00F0FF';
		case 4:
			equipCoolorStr = '#FFB100FF';
			break;
		default:
			equipCoolorStr = '#FFB100FF';
			break;
	}
	var equipCoolorByte = colorStringToByteArray(equipCoolorStr);//颜色
	var itemIdByte = intToHexArray(item_id, true, 8);//物品id
	var itemNumByte = intToHexArray(100, true, 8);//物品数量(品级)

	// 分配内存并填充二进制数据
	var itemIdData = Memory.alloc(104);
	var combinedData = new Uint8Array(104);

	// 设置equipCoolorByte和itemIdByte
	combinedData.set(equipCoolorByte, 0);
	combinedData.set(itemIdByte, 4);
	combinedData.set(itemNumByte, 8);

	// 写入内存
	Memory.writeByteArray(itemIdData, combinedData);


	InterfacePacketBuf_put_header(packet_guard, 0, 370);
	InterfacePacketBuf_put_byte(packet_guard, 1);
	InterfacePacketBuf_put_short(packet_guard, 77);
	InterfacePacketBuf_put_byte(packet_guard, 1);
	InterfacePacketBuf_put_int(packet_guard, strLenth); // 文本长度
	InterfacePacketBuf_put_str(packet_guard, originalText, strLenth);// 文本,文本长度
	InterfacePacketBuf_put_byte(packet_guard, 10); // 有多少段文本
	InterfacePacketBuf_put_binary(packet_guard, itemIdData, 104);// 文本信息，文本长度，104是完整信息，可以点开
	//InterfacePacketBuf_put_binary(packet_guard, epicColorData, 3);// 第二个我只需要颜色部分，所以只有3的长度，这种点不开
	InterfacePacketBuf_finalize(packet_guard, 1);
	// 发给自己
	CUser_Send(user, packet_guard);
	Destroy_PacketGuard_PacketGuard(packet_guard);
}

//口令码
var reward_msg2 = {
	'tiankong': [8386, 1],
	'vip111': [3330, 300],
	'vip666': [122140005, 1, 36, 50],
	'vip888': [3330, 300],
	'vip999': [3209, 10, 4343, 10, 4176, 10, 4083, 10, 3037, 500],
	'fuli666': [1205, 2, 10096249, 10]
};


function hook_characterMessageLog() {
	Interceptor.attach(ptr(0x086C9638),
		{
			onEnter: function (args) {
				var user = args[1];
				var charac_name = api_CUserCharacInfo_getCurCharacName(user);
				var reason = args[2].toInt32();
				var msg = args[3].readUtf8String(-1);
				this.notice = null;
				this.notice2 = null;
				//查询当前角色id
				var UID = CUser_get_acc_id(user);
				if (reason == 11) {

					var charac_no = CUserCharacInfo_getCurCharacNo(user)
					event_reward_load_from_db();
					console.info(reward_save_db_list.length);
					for (let index = 0; index < reward_save_db_list.length; index++) {
						var item = reward_save_db_list[index];
						reward_save_db = item.info;
						var id = item.id;
						console.info(id);
						var flag = false;
						for (var i in reward_save_db) {
							var arr = reward_save_db[i];
							if (arr[4] != msg) {
								flag = true;
								break;
							}
							if (arr[7] != undefined && arr[7].length > 0) {
								for (let name_index = 0; name_index < arr[7].length; name_index++) {
									var already_name = arr[7][name_index][1];

									if (already_name == charac_name && arr[4] == msg) {
										flag = true;
										break;
									}

								}

							}

						}
						if (flag) {
							continue;
						}


						for (var i in reward_save_db) {

							var arr = reward_save_db[i];
							if ((msg == arr[5] || msg == arr[4]) && arr[3] > 0 && (arr[6].indexOf(charac_no) < 0)) {
								var q = 1;
								if (arr[3] == 1) {
									q = arr[2]
								}
								else {
									q = get_random_int(1, parseInt(arr[2] / 2))
								}

								switch (parseInt(arr[1])) {
									case 1:
										api_recharge_cash_cera(user, q)
										this.notice = '玩家[' + charac_name + ']抢到了' + q + '点券';
										break;
									case 2:
										api_recharge_cash_cera_point(user, q)
										this.notice = '玩家[' + charac_name + ']抢到了' + q + '代币';
										break;
									case 3:
										CInventory_gain_money(CUserCharacInfo_getCurCharacInvenW(user), q, 0, 0, 0)
										this.notice = '玩家[' + charac_name + ']抢到了' + q + '金币';
										CUser_send_itemspace(user, ENUM_ITEMSPACE_INVENTORY);
										break;
									default:
										api_CUser_AddItem(user, arr[1], q)
										this.notice = '玩家[' + charac_name + ']抢到了' + q + '个' + api_CItem_GetItemName(parseInt(arr[1])) + '';
										break;
								}
								arr[3] -= 1;
								arr[2] -= q;
								arr[6].push(charac_no)
								arr[7].push([charac_no, charac_name, q])
								if (arr[3] <= 0) {
									arr[7].sort(function (a, b) {
										return b[2] - a[2];
									})
									this.notice2 = "玩家" + arr[8] + "的口令红包已被领取完毕\r\n 玩家" + arr[7][0][1] + "的手气最佳";
								}
							}
							reward_save_db[i] = arr;
						}
						if (arr[3] <= 0) {
							event_reward_delete_to_db(id);
						} else {
							event_reward_replace_to_db(id, reward_save_db);
						}
						reward_save_db_list = [];
						reward_save_db = {};
						break;

					}

				}
				else if (reason == 3) {

					// //普通消息
					// if (msg == '查询首爆')
					// {
					//     reset_bonus();
					// 	console.info(month_card_equip_gifts);
					// 	for (var i in month_card_equip_gifts)
					// 	{
					// 		var txt = "[" + api_CItem_GetItemName(parseInt(i)) + "]";
					// 		var item_id = parseInt(i);
					// 		var date = new Date()
					// 		if (month_card_equip_gifts_log[item_id] == undefined || month_card_equip_gifts_log[item_id] == null || parseInt(month_card_equip_gifts_log[item_id][1] / (86400000)) != parseInt(date.getTime() / (86400000)))
					// 		{
					// 			txt += "的今日奖励未领取"
					// 		}
					// 		else
					// 		{
					// 			txt += "已被玩家" + month_card_equip_gifts_log[item_id][2] + "领取\r\n领取时间：";
					// 			date = new Date(parseInt(month_card_equip_gifts_log[item_id][1]));
					// 			var year = date.getFullYear().toString();
					// 			var month = (date.getMonth() + 1).toString();
					// 			var day = date.getDate().toString();
					// 			var hour = date.getHours().toString();
					// 			var minute = date.getMinutes().toString();
					// 			var second = date.getSeconds().toString();
					// 			//时间戳
					// 			var timestamp = year + '-' + month + '-' + day + ' ' + hour + ':' + minute + ':' + second;
					// 			txt += timestamp;
					// 		}
					// 		api_CUser_SendNotiPacketMessage(user, txt, 2)
					// 	}
					// }
					// var charac_no = CUserCharacInfo_getCurCharacNo(user); 

					// if(charac_no == 8 && msg =='刷新首爆'){
					//     api_CUser_SendNotiPacketMessage(user, '首爆奖励已刷新，此消息只有GM可见', 1);
					// 	//重新随机奖励列表
					// 	reset_bonus();
					// 	reset_bonus_reset();
					// }
					if (msg == '查询红包') {

						//查询红包口令
						event_reward_load_from_db();
						var str = [];
						var charac_name = api_CUserCharacInfo_getCurCharacName(user);
						str.push("当前未领取的红包口令:\n");
						for (let index = 0; index < reward_save_db_list.length; index++) {
							var item = reward_save_db_list[index];

							reward_save_db = item.info;
							var id = item.id;
							var flag = false;
							for (var i in reward_save_db) {
								var arr = reward_save_db[i];
								console.info(arr[7].length);
								if (arr[7].length > 0) {
									for (let name_index = 0; name_index < arr[7].length; name_index++) {
										var already_name = arr[7][name_index][1];
										if (already_name == charac_name) {
											flag = true;
											break;
										}

									}
								}

								if (!flag && arr[4] != undefined) {
									str.push("\t\t" + "来自" + arr[8] + "的口令红包\n口令：" + arr[4]);
								}
							}
						}

						for (let index = 0; index < str.length; index++) {
							var str_send = str[index];
							api_CUser_SendNotiPacketMessage(user, str_send, 7);

						}

					} else if (reward_msg2.hasOwnProperty(msg)) {
						var charac_name = api_CUserCharacInfo_getCurCharacName(user);
						api_MySQL_exec(mysql_frida, "select user_no from account_reward where user_no = '" + UID + "' and msg = '" + msg + "';");
						//从数据库中查询角色名
						if (MySQL_get_n_rows(mysql_frida) == 0) {

							var reward = reward_msg2[msg];
							console.info(reward);
							var result = [];
							for (let index = 0; index < reward.length; index += 2) {
								const item = reward[index];
								const count = reward[index + 1];
								var reward_name = api_CItem_GetItemName(item);
								result.push([item, count]);
								api_CUser_SendNotiPacketMessage(user, '恭喜您获得' + reward_name + ' ' + count + ' 个', 7);
							}

							api_CUser_Add_Item_list(user, result);
							api_MySQL_exec(mysql_frida, "insert into account_reward (user_no , msg) values ('" + UID + "','" + msg + "');");

						} else {
							api_CUser_SendNotiPacketMessage(user, '当前账号已经领取过这个奖励了，勇士请不要贪心哦!', 7);
						}
					} else if (msg == '華貴的史詩寶珠') {
						sendMessage(user, "[使徒卡恩 宝珠]", 490702510);
						sendMessage(user, "[使徒卡西利亚斯 宝珠]", 490702511);
						sendMessage(user, "[使徒普雷 宝珠]", 490702512);
						sendMessage(user, "[使徒卢克 宝珠]", 490702513);
						sendMessage(user, "[使徒巴卡尔 宝珠]", 490702514);
						sendMessage(user, "[使徒希洛克 宝珠]", 490702515);
						sendMessage(user, "[使徒罗特斯 宝珠]", 490702516);
						sendMessage(user, "[使徒赫尔德 宝珠]", 490702517);
						sendMessage(user, "[使徒米歇尔 宝珠]", 490702518);
						sendMessage(user, "[使徒安徒恩 宝珠]", 490702519);
						sendMessage(user, "[使徒狄瑞吉 宝珠]", 490702520);
					}
				}
			},
			onLeave: function (retval) {
				if (this.notice != null) {
					api_scheduleOnMainThread_delay(api_GameWorld_SendNotiPacketMessage, [this.notice, 14], 50)
					this.notice = null;
				}
				if (this.notice2 != null) {
					api_scheduleOnMainThread_delay(api_GameWorld_SendNotiPacketMessage, [this.notice2, 14], 50)
					this.notice2 = null;
				}
			}
		});
}


/**重置sp  tp */
function event_select_sptp(charac_no) {
	var selectQuery = "select id,charac_no,sp_item,tp_item FROM frida.init_sp_tp WHERE charac_no='" + charac_no + "';";
	if (api_MySQL_exec(mysql_frida, selectQuery)) {
		if (MySQL_get_n_rows(mysql_frida) == 1) {
			MySQL_fetch(mysql_frida);
			var old_sp_item_json = api_MySQL_get_str(mysql_frida, 2);
			var old_sp_item = JSON.parse(old_sp_item_json);
			var old_tp_item_json = api_MySQL_get_str(mysql_frida, 3);
			var old_tp_item = JSON.parse(old_tp_item_json);
			api_MySQL_exec(mysql_frida, "delete from frida.init_sp_tp WHERE charac_no='" + charac_no + "' ;");
			return [old_sp_item, old_tp_item];
		}
	}
	return [[], []];
}

/**返还sp tp */
function return_sp_tp(user) {
	var charac_no = CUserCharacInfo_getCurCharacNo(user);
	var [sp_item, tp_item] = event_select_sptp(charac_no);
	if (sp_item.length > 0) {
		var item_list = [];
		for (let index = 0; index < sp_item.length; index += 2) {
			var item = [];
			const sp_item_index = sp_item[index];
			const sp_item_count = sp_item[index + 1];
			if (sp_item_count == 0) {
				continue;
			}
			item.push(sp_item_index);
			item.push(sp_item_count);
			item_list.push(item);
		}
		api_WongWork_CMailBoxHelper_ReqDBSendNewSystemMultiMail(charac_no, 'SP书补偿邮件', '这是您累计用过的所有SP技能书', 0, item_list);
	}
	if (tp_item.length > 0) {
		for (let index = 0; index < tp_item.length; index += 2) {

			const tp_item_index = tp_item[index];
			const tp_item_count = tp_item[index + 1];
			if (tp_item_count == 0) {
				continue;
			}
			for (let i = 1; i <= tp_item_count; i++) {
				var item_list = [];
				var item = [];
				item.push(tp_item_index);
				item.push(1);
				item_list.push(item);
				api_WongWork_CMailBoxHelper_ReqDBSendNewSystemMultiMail(charac_no, 'TP书补偿邮件', '这是您累计用过的所有TP技能书', 0, item_list);
			}
		}
	}
}

/**新增sp tp */
function event_save_sptp(charac_no, sp_item, tp_item) {
	var selectQuery = "select id,charac_no,sp_item,tp_item FROM frida.init_sp_tp WHERE charac_no='" + charac_no + "';";
	console.info(selectQuery);
	if (api_MySQL_exec(mysql_frida, selectQuery)) {
		if (MySQL_get_n_rows(mysql_frida) == 1) {
			MySQL_fetch(mysql_frida);
			var id = api_MySQL_get_int(mysql_frida, 0);
			var old_sp_item_json = api_MySQL_get_str(mysql_frida, 2);
			var old_sp_item = JSON.parse(old_sp_item_json);
			var old_tp_item_json = api_MySQL_get_str(mysql_frida, 3);
			var old_tp_item = JSON.parse(old_tp_item_json);
			//判断当前使用是否为sp书
			if (sp_item.length > 0) {
				for (let index = 0; index < old_sp_item.length; index += 2) {
					const item_id = old_sp_item[index];
					if (item_id == sp_item[0]) {
						old_sp_item[index + 1] = ++old_sp_item[index + 1];
					}

				}
			}
			//判断当前使用是否为sp书
			if (tp_item.length > 0) {
				for (let index = 0; index < old_tp_item.length; index += 2) {
					const item_id = old_tp_item[index];
					if (item_id == tp_item[0]) {
						old_tp_item[index + 1] = ++old_tp_item[index + 1];
					}
				}
			}
			api_MySQL_exec(mysql_frida, "replace into init_sp_tp (id,charac_no,sp_item,tp_item) values (" + id + ",'" + charac_no + "', '" + JSON.stringify(old_sp_item) + "','" + JSON.stringify(old_tp_item) + "' );");
			console.log('event_save_sptp_Success');
		}
		else {
			var sp_item_result = [1031, 0, 1038, 0];
			var tp_item_result = [1204, 0, 1205, 0];
			//判断当前使用是否为sp书
			if (sp_item.length > 0) {
				for (let index = 0; index < sp_item_result.length; index += 2) {
					const item_id = sp_item_result[index];
					console.info(item_id);
					if (item_id == sp_item[0]) {
						sp_item_result[index + 1] = ++sp_item_result[index + 1];
					}

				}
			}
			//判断当前使用是否为sp书
			if (tp_item.length > 0) {
				for (let index = 0; index < tp_item_result.length; index += 2) {
					const item_id = tp_item_result[index];
					if (item_id == tp_item[0]) {
						tp_item_result[index + 1] = ++tp_item_result[index + 1];
					}

				}
			}
			api_MySQL_exec(mysql_frida, "insert into init_sp_tp (charac_no,sp_item,tp_item) values ('" + charac_no + "', '" + JSON.stringify(sp_item_result) + "','" + JSON.stringify(tp_item_result) + "' );");
			console.log('event_save_sptp_Success');
		}
	}
}



//这个要加到你的启动函数里，功能为hook 特殊物品使用
function increase_status() {
	Interceptor.attach(ptr(0x086657FC),
		{
			onEnter: function (args) {
				this.user = args[0]
				var item_id = CInventory_GetInvenRef(CUserCharacInfo_getCurCharacInvenR(this.user), 1, args[1].toInt32()).add(2).readU32()
				console.info('item_id', item_id);
				this.type = 'sp'
				this.num = 0;
				//角色uid
				this.charac_no = CUserCharacInfo_getCurCharacNo(this.user);
				this.sp_item = [];
				this.tp_item = [];
				switch (item_id) {
					case 1031:
						this.num = 5; this.type = 'sp';
						this.sp_item.push(item_id);
						this.sp_item.push(1);
						break;
					case 1038:
						this.num = 20; this.type = 'sp';
						this.sp_item.push(item_id);
						this.sp_item.push(1);
						break;
					case 1204:
						this.num = 1; this.type = 'tp';
						this.tp_item.push(item_id);
						this.tp_item.push(1);
						break;
					case 1205:
						this.num = 5; this.type = 'tp';
						this.tp_item.push(item_id);
						this.tp_item.push(1);
						break;
				}
			},
			onLeave: function (retval) {
				var level = CUserCharacInfo_get_charac_level(this.user);
				//this.user//用户指针
				if (this.num > 0) {
					event_save_sptp(this.charac_no, this.sp_item, this.tp_item)
				}
			}
		});
}
// 获取副本名字api
function api_CDungeon_getDungeonName(dungeon_id) {
	var cdungeon = CDataManager_find_dungeon(G_CDataManager(), dungeon_id);
	if (!cdungeon.isNull()) {
		return ptr(CDungeon_getDungeonName(cdungeon)).readUtf8String(-1);
	}
	return dungeon_id.toString();
}


/**-------------------------------------------------禁止进入指定副本---------------------------------------------**/

/**
 * @param Price_to_anti_evil 对应的是装备中的[value]，如装备中value的值是100，在下面的数组中var Price_to_anti_evil = {100: 1}这样表示这件装备抗魔值为1
 * 所以最好value的值要另类一点，不然会出现误判，比如改为12111等等，
 * @param 只遍历装备栏，不含时装光环
 */
function BanEnterDungeon() {
	Interceptor.attach(ptr(0x081C7F32), {
		onEnter: function (args) {
			this.user = args[1];
			this.party = CUser_GetParty(this.user);
			var msg_base = args[2];
			this.dgn_id = msg_base.add(13).readU16(); // 副本id
			this.dgn_diff = msg_base.add(15).readU8(); // 副本难度
		},
		onLeave: function (retval) {
			var dgnname = api_CDungeon_getDungeonName(this.dgn_id);
			var difficultyMap = {
				0: "普通级",
				1: "冒险级",
				2: "勇士级",
				3: "王者级",
				4: "英雄级"
			};
			if (!this.party.isNull()) {
				for (var i = 0; i < 4; ++i) {
					var tuser = CParty_get_user(this.party, i);
					if (!tuser.isNull()) {
						var charac_name = api_CUserCharacInfo_getCurCharacName(tuser);
						var inven = CUserCharacInfo_getCurCharacInvenR(tuser);
						var total_anti_evil_count = 0;

						var Price_to_anti_evil = {
							10: 10,//上方有说明，第一个数值对应pvf装备中的value，现在代表如果pvf中的装备value值是20，那么进入副本的时候，抗魔值等于1
							15: 15,
							18: 18,
							20: 20,
							22: 22,
							25: 25,
							30: 30,
							35: 35,
							50: 50,
							60: 60,
							// 更多等级可以在这里继续添加
						};

						for (var j = 0; j < 25; j++) {
							var equ = CInventory_GetInvenRef(inven, INVENTORY_TYPE_BODY, j);
							var item_id = Inven_Item_getKey(equ);
							var item = CDataManager_find_item(G_CDataManager(), item_id);

							if (!item.isNull()) {
								var Price = CItem_getSellPrice(item);
								if (Price_to_anti_evil.hasOwnProperty(Price)) {
									total_anti_evil_count += Price_to_anti_evil[Price];
								}
							}
						}

						var dgn_requirements = {

							86: { 0: 20, 1: 60, 2: 120, 3: 150, 4: 200 },//列车上的海贼----86二阶段
							87: { 0: 20, 1: 60, 2: 120, 3: 150, 4: 200 },//夺回西部线----87	
							92: { 0: 20, 1: 60, 2: 120, 3: 150, 4: 200 },//雾都赫伊斯----92	
							93: { 0: 20, 1: 60, 2: 120, 3: 150, 4: 200 },//阿登高地----93	
							62: { 0: 20, 1: 60, 2: 120, 3: 150, 4: 200 },//哥布林王国----62
							63: { 0: 20, 1: 60, 2: 120, 3: 150, 4: 200 },//蠕动之城----63	
							64: { 0: 20, 1: 60, 2: 120, 3: 150, 4: 200 },//兰蒂卢斯的鹰犬----64		
							65: { 0: 20, 1: 60, 2: 120, 3: 150, 4: 200 },//巴卡尔之城----65			
							66: { 0: 20, 1: 60, 2: 120, 3: 150, 4: 200 },//虚无之境----66	
							67: { 0: 20, 1: 60, 2: 120, 3: 150, 4: 200 },//黑色大地----67							
							33: { 0: 150, 1: 180, 2: 250, 3: 300, 4: 350 },//王的遗迹----三阶段
							1500: { 0: 150, 1: 180, 2: 250, 3: 300, 4: 350 },//比尔马克帝国试验场
							1501: { 0: 150, 1: 180, 2: 250, 3: 300, 4: 350 },//悲鸣洞穴
							1502: { 0: 150, 1: 180, 2: 250, 3: 300, 4: 350 },//诺伊佩拉	
							1504: { 0: 150, 1: 180, 2: 250, 3: 300, 4: 350 },//幽灵列车		
							1506: { 0: 150, 1: 180, 2: 250, 3: 300, 4: 350 },//痛苦之村列瑟芬
							1507: { 0: 150, 1: 180, 2: 250, 3: 300, 4: 350 },//卡勒特指挥部							
							8500: { 0: 150, 1: 180, 2: 250, 3: 300, 4: 350 },//	伤城	
							8503: { 0: 150, 1: 180, 2: 250, 3: 300, 4: 350 },//哀泣之穴			
							8504: { 0: 150, 1: 180, 2: 250, 3: 300, 4: 350 },//呐喊之地
							8505: { 0: 150, 1: 180, 2: 250, 3: 300, 4: 350 },//失心迷宫	
							8507: { 0: 150, 1: 180, 2: 250, 3: 300, 4: 350 },//破灭峡谷		
							8508: { 0: 150, 1: 180, 2: 250, 3: 300, 4: 350 },//永恒殿堂	
							200: { 0: 200, 1: 250, 2: 300, 3: 350, 4: 400 },//魂.王的遗迹----四阶段
							201: { 0: 200, 1: 250, 2: 300, 3: 350, 4: 400 },//魂.比尔马克帝国试验场
							202: { 0: 200, 1: 250, 2: 300, 3: 350, 4: 400 },//魂.悲鸣洞穴
							203: { 0: 200, 1: 250, 2: 300, 3: 350, 4: 400 },//魂.诺伊佩拉	
							204: { 0: 200, 1: 250, 2: 300, 3: 350, 4: 400 },//魂.幽灵列车		
							205: { 0: 200, 1: 250, 2: 300, 3: 350, 4: 400 },//魂.痛苦之村列瑟芬
							206: { 0: 200, 1: 250, 2: 300, 3: 350, 4: 400 },//魂.卡勒特指挥部								
							// 更多副本要求可以在这里继续添加1：代表副本ID，大括号里面0:10代表普通级所需10抗魔值，1:12代表冒险级所需12点抗魔以此类推
						};

						if (dgn_requirements.hasOwnProperty(this.dgn_id) &&
							dgn_requirements[this.dgn_id].hasOwnProperty(this.dgn_diff) &&
							total_anti_evil_count < dgn_requirements[this.dgn_id][this.dgn_diff]) {
							api_CUser_SendNotiPacketMessage(this.user, '队伍中玩家[' + charac_name + '] 抗魔值低于' + dgn_requirements[this.dgn_id][this.dgn_diff] + '，无法进入 [' + dgnname + ' - ' + difficultyMap[this.dgn_diff] + ']', 37);
							retval.replace(1);
							CParty_ReturnToVillage(this.party);
						}
					}
				}
			}
		}
	});
}


const CParty_checkValidUser = new NativeFunction(ptr(0x8145868), 'int', ['pointer', 'int'], { "abi": "sysv" });

//获取当前角色所在队伍的成员数量
function api_GetPartyMemberNumber(Party) {
	if (Party.isNull()) {
		return 1;
	}
	var MemberCnt = 0;
	for (let i = 0; i <= 3; i++) {
		MemberCnt += CParty_checkValidUser(Party, i);
	}
	return MemberCnt;
}

var CUser_CheckCoolTimeItem = new NativeFunction(ptr(0x865E994), 'int', ['pointer', 'int'], { "abi": "sysv" });

const EpicPotionlist =
{
	100000: 0.2,
}

function EpicPotion() {
	var user = null;
	Interceptor.attach(ptr(0x81EB0C4),
		{
			onEnter: function (args) {
				user = args[1];
			},
			onLeave: function (retval) {
				user = null;
			}
		});

	Interceptor.attach(ptr(0x85B2412),
		{
			onEnter: function (args) {
				user = args[1];
			},
			onLeave: function (retval) {
				user = null;
			}
		});
	var CLuckPoint_getItemRarity = new NativeFunction(ptr(0x8550BE4), 'int', ['pointer', 'pointer', 'int', 'int'], { "abi": "sysv" });
	Interceptor.replace(ptr(0x8550BE4), new NativeCallback(function (a1, a2, roll, a4) {
		if (user == null) {
			return CLuckPoint_getItemRarity(a1, a2, roll, a4);
		}
		var Party = CUser_GetParty(user);
		//只生效在单人深渊模式且使用了药剂的状态下有效
		if (this.returnAddress == 0x853583a && CUser_CheckCoolTimeItem(user, 2600010) && api_GetPartyMemberNumber(Party) == 1) {
			var MaxRoll = a2.add(16).readU32();
			var odds = 1.0;//默认药剂的增加几率
			var charac_no = CUserCharacInfo_getCurCharacNo(user);
			if (EpicPotionlist[charac_no]) {//特殊VIP角色的几率
				odds = EpicPotionlist[charac_no];
			}
			var MyRoll = Math.floor(Math.min(roll + roll * odds, MaxRoll));
			return CLuckPoint_getItemRarity(a1, a2, MyRoll, a4);
		}
		return CLuckPoint_getItemRarity(a1, a2, roll, a4);
	}, 'int', ['pointer', 'pointer', 'int', 'int']));
}

function startOnlineGifts() {
	api_scheduleOnMainThread_delay(startOnlineGifts, null, 1000)
	var date = new Date();
	date = new Date(date.setHours(date.getHours() + 0));
	var hour = date.getHours();
	var minute = date.getMinutes();
	var second = date.getSeconds();

	for (var i in onlineGifts) {
		if (onlineGifts[i].hour == hour && onlineGifts[i].minute == minute && onlineGifts[i].second == second) {
			api_gameworld_foreach(giveOnlineGifts, onlineGifts[i])
			break
		}
	}
}


//获取道具类型
var CInventory_GetItemType = new NativeFunction(ptr(0x085018D2), 'int', ['pointer', 'int'], { "abi": "sysv" });
var CInventory_check_empty_count = new NativeFunction(ptr(0x08504F64), 'int', ['pointer', 'int', 'int'], { "abi": "sysv" });
var CInventory_check_empty_count = new NativeFunction(ptr(0x08504F64), 'int', ['pointer', 'int', 'int'], { "abi": "sysv" });

var CEquipItem_getSubType = new NativeFunction(ptr(0x833eecc), 'int', ['pointer'], { "abi": "sysv" });

var onlineGifts =
	[
		{
			hour: 9,//几点开启活动
			minute: 44,//几分时开启活动
			second: 59,//几秒时开启活动
			Text: "所有红包数据已清理",
		}
	]

function giveOnlineGifts(user, args) {
	api_CUser_SendNotiPacketMessage(user, args.Text, 14);
	event_reward_delete_to_delete()
}



/*
 * 跨界石： 将装备栏的第一个格子的装备移入到账号金库，自动找空的格子，所以可以同时移入多件
 */
function crossover(user, item_id, excludedItemIds) {
	// 跨界  将装备移入到账号金库
	var accountCargo = CUser_getAccountCargo(user);
	var emptyIndex = CAccountCargo_getEmptySlot(accountCargo);//金库格子
	var inven = CUserCharacInfo_getCurCharacInvenW(user);
	var equ = CInventory_GetInvenRef(inven, INVENTORY_TYPE_ITEM, 9);
	var itemId = Inven_Item_getKey(equ);
	// 检查是否排除了装备
	var isExcluded = false;
	if (itemId && excludedItemIds && excludedItemIds.length > 0) {
		for (var i = 0; i < excludedItemIds.length; i++) {
			if (itemId == excludedItemIds[i]) {
				isExcluded = true;
				break;
			}
		}
	}
	var qixi1 = equ.add(31).readU8();
	var qixi2 = equ.add(32).readU8();

	if (emptyIndex == -1 || !itemId || isExcluded || qixi1 > 0 || qixi2 > 0) {
		if (!itemId) {
			api_CUser_SendNotiPacketMessage(user, "跨界失败：装备栏第一格是空的！！！", 0);
		} else if (emptyIndex == -1) {
			api_CUser_SendNotiPacketMessage(user, "跨界失败：账号金库没有空的格子！！！", 0);
		} else if (isExcluded) {
			api_CUser_SendNotiPacketMessage(user, "跨界失败：该装备不可跨界！！！", 0);
		} else if (qixi1 > 0 || qixi2 > 0) {
			api_CUser_SendNotiPacketMessage(user, "跨界失败：装备栏第一格的装备拥有异界气息无法跨界！！！", 0);
		}
		const reward_item_lists = [[item_id, 1]];
		const Money = 0;
		var charac_no = CUserCharacInfo_getCurCharacNo(user);
		api_scheduleOnMainThread_delay(api_CUser_AddItem, [user, item_id, 1], 1);//道具返还间隔
	} else {


		var tag = CAccountCargo_InsertItem(accountCargo, equ, emptyIndex);
		if (tag == -1) {
			api_CUser_SendNotiPacketMessage(user, "跨界失败", 0);
		}
		else {
			Inven_Item_reset(equ);
			CUser_SendUpdateItemList(user, 1, 0, 9);
			CAccountCargo_SendItemList(accountCargo);
			api_CUser_SendNotiPacketMessage(user, "跨界成功：已存入第 " + (emptyIndex + 1) + " 个格子！", 0);
		}
	}
}

// 要排除的跨界装备ID列表
var excludedItemIds = [100050042, 100080010, 100070010, 100060012, 100090010, 100100011, 100130010, 100120010, 100110010, 100140010, 100200012, 100230011, 100220011, 100210011, 100240011, 100250012, 100280011, 100270011, 100260011, 100290011, 14167, 14126, 15330, 15302, 14949, 14904, 14543, 14502, 15694, 15667, 108040021, 35998, 36015, 35939, 35969, 22160, 22128, 20167, 20133, 24175, 24137, 31432, 31394, 36293, 36240, 28305, 28268, 30299, 30267, 31729, 31694, 22159, 22109, 34278, 34223, 32333, 32294, 29735, 29696, 35096, 35041, 37091, 37061, 29384, 39397, 27737, 27696, 29140, 29100, 27589, 27551, 32026, 31992, 20166, 20114, 33998, 33960, 31138, 31096, 24174, 24115, 33699, 33659, 35391, 35340, 35988, 35940, 33099, 33060, 27138, 27099, 28033, 27995, 33404, 33363, 30031, 29995, 35693, 35640, 37382, 37359, 37683, 37659];

var maxCreatureIds = [400990063, 400990060, 100990056, 63415, 63420, 400990075, 400990081, 400990078, 400890105, 400890127, 20190403, 63475, 27500222, 100330631, 100990034, 100990036, 400990092, 100990038, 400890115, 400990096, 400990054, 100990058, 400890125, 400990169, 400990265, 400990087, 100990044, 100990042, 100990046, 100990049, 400890119, 300380051, 300380050, 400890131, 100990051, 100990053, 400990446, 400890099, 400990170, 400890109, 2750039, 20086145, 2681465, 63231, 2747327, 63044, 63195, 63075, 63199, 63110, 63172, 63424, 2750000, 2681473, 63096, 63066, 63080, 20086146, 63032, 63052, 63207, 63084, 63060, 63090, 63002, 2681477, 63122, 63227, 63056, 63126, 2747329, 63152, 100330806, 63146, 100330804, 63120, 63116, 63114, 63012, 63008, 63072, 63003, 63243, 63233, 63082, 63149, 63094, 63196, 63187, 2747681, 63225, 2750025, 63246, 2747333, 63062, 400990223, 400990072, 400990180, 400990181, 400990186, 400990187, 400990056, 400990047, 400990201, 400990204, 400990205, 400990220, 400990214, 400990211, 400990212, 400990210, 400990252, 400990256, 400990257, 400890139, 400990024, 400990025, 400990248, 400990160, 400990163, 400990086, 400890153, 400890137, 400890148, 100330534, 400990166, 400890143, 400990224, 400990232, 400990198, 400890147, 400990222, 2747586, 400890142, 2747580, 400890133, 400990008, 400990011, 2747033, 100330947, 63194, 63190, 100330838, 400990200, 63193, 400990001, 400891006, 400891007, 400891008, 400891013, 35007001, 35007006, 35007004, 35007012, 35007008, 400890693, 400890690, 400890696, 400890557, 400890556, 400890573, 400890652, 400890654, 400993002];

// 顶阶宠物置换
function maxCreatureChange(user) {
	var inven = CUserCharacInfo_getCurCharacInvenW(user);
	var currentCreature = CInventory_GetInvenRef(inven, INVENTORY_TYPE_CREATURE, 0);
	var currentCreatureId = Inven_Item_getKey(currentCreature);
	if (maxCreatureIds.indexOf(currentCreatureId) == -1) {
		api_CUser_SendNotiPacketMessage(user, "顶阶宠物置换失败：宠物栏第一格[" + api_CItem_GetItemName(currentCreatureId) + "]不是顶阶宠物,已返还材料!", 0);
		api_CUser_Add_Item1(user, [[2651018, 100], [3340, 250], [3285, 2500]]);
		CUser_send_itemspace(user, ENUM_ITEMSPACE_INVENTORY);
	} else {
		var changeCreatureId = maxCreatureIds[get_random_int(0, 163)];
		Inven_Item_reset(currentCreature); // 移除现有宠物
		api_CUser_Add_Item1(user, [[changeCreatureId, 1]]);// 发送新宠物
		CUser_send_itemspace(user, ENUM_ITEMSPACE_CREATURE);
		api_GameWorld_SendNotiPacketMessage('恭喜玩家[' + api_CUserCharacInfo_getCurCharacName(user) + ']' + ']在地下城中获得了[' + api_CItem_GetItemName(changeCreatureId) + ']', 14);
	}
}

var maxAuraIds = [401590023, 202102142, 101590100, 101590560, 401590002, 401590005, 401590013, 302392817, 401590019, 401590026, 401590033, 401590037, 401590043, 401590062, 401590070, 401590073, 401590112, 401590035, 401590101, 401590105, 401590124, 101590046, 101590053, 101590059, 101590067, 101590081, 101590094, 101590075, 401590083, 406590000, 415590021, 100114514, 415554155, 401590068, 2748002, 101590012, 101590015, 101590018, 101590021, 101590024, 101590027, 101590030, 101590033, 101590036, 101590039, 101590042, 202205344, 42703, 42706, 101590002, 20223107, 20223110, 422310002, 42700
];

// 顶阶光环置换
function maxAuraChange(user) {
	var inven = CUserCharacInfo_getCurCharacInvenW(user);
	var currentAura = CInventory_GetInvenRef(inven, INVENTORY_TYPE_AVARTAR, 0);
	var currentAuraId = Inven_Item_getKey(currentAura);
	if (maxAuraIds.indexOf(currentAuraId) == -1) {
		api_CUser_SendNotiPacketMessage(user, "顶阶光环置换失败：时装栏第一格[" + api_CItem_GetItemName(currentAuraId) + "]不是顶阶光环,已返还材料!", 0);
		api_CUser_Add_Item1(user, [[2651018, 100], [3340, 250], [3285, 2500]]);
		CUser_send_itemspace(user, ENUM_ITEMSPACE_INVENTORY);
	} else {
		var changeAuraId = maxAuraIds[get_random_int(0, 54)];
		Inven_Item_reset(currentAura);
		api_CUser_Add_Item1(user, [[changeAuraId, 1]]);
		CUser_send_itemspace(user, ENUM_ITEMSPACE_AVATAR);
		api_GameWorld_SendNotiPacketMessage('恭喜玩家[' + api_CUserCharacInfo_getCurCharacName(user) + ']' + ']在地下城中获得了[' + api_CItem_GetItemName(changeAuraId) + ']', 14);
	}
}

var maxTitleIds = [400691004, 400691006, 400691009, 400691010, 400691012, 400691015, 400691016, 400691018, 400691020, 400691024, 400691027, 400691030, 400691032, 400691033, 400691034, 400691036, 400691045, 400691048, 400691051, 400691054, 400691057, 400691060, 400691063, 400691066, 400691069, 400691072, 400691075, 400691078, 400691081, 400691084, 400691087, 400691090, 400691093, 400691096, 400691097, 400691099, 400691102, 400691105, 400691108, 400691109, 400691117, 400691120, 400691123, 400691126, 400691129, 26833
];

// 顶阶称号置换
function maxTitleChange(user) {
	var inven = CUserCharacInfo_getCurCharacInvenW(user);
	var currentTitle = CInventory_GetInvenRef(inven, INVENTORY_TYPE_ITEM, 9);
	var currentTitleId = Inven_Item_getKey(currentTitle);
	if (maxTitleIds.indexOf(currentTitleId) == -1) {
		api_CUser_SendNotiPacketMessage(user, "顶阶称号置换失败：装备栏第一格[" + api_CItem_GetItemName(currentTitleId) + "]不是顶阶称号,已返还材料!", 0);
		api_CUser_Add_Item1(user, [[2651018, 100], [3340, 250], [3285, 2500]]);
		CUser_send_itemspace(user, ENUM_ITEMSPACE_INVENTORY);
	} else {
		var changeTitleId = maxTitleIds[get_random_int(0, 46)];
		Inven_Item_reset(currentTitle);
		api_CUser_Add_Item1(user, [[changeTitleId, 1]]);
		CUser_send_itemspace(user, ENUM_ITEMSPACE_INVENTORY);
		api_GameWorld_SendNotiPacketMessage('恭喜玩家[' + api_CUserCharacInfo_getCurCharacName(user) + ']' + ']在地下城中获得了[' + api_CItem_GetItemName(changeTitleId) + ']', 14);
	}
}

//装备继承
function equInherit(user) {
	var inven = CUserCharacInfo_getCurCharacInvenW(user);
	var equ = CInventory_GetInvenRef(inven, INVENTORY_TYPE_ITEM, 9);
	var itemId = Inven_Item_getKey(equ)
	if (Inven_Item_getKey(equ)) {
		//读取装备强化等级
		var upgrade_level = equ.add(6).readU8();
		var itemData = CDataManager_find_item(G_CDataManager(), itemId);
		var equ_type = itemData.add(141 * 4).readU32(); // 装备类型
		var sub_type = CEquipItem_GetSubType(itemData);
		var equRarity = CItem_GetRarity(itemData); // 稀有度  >=3  粉色以上
		var needLevel = CItem_GetUsableLevel(itemData);  //等级
		console.log("equ_type :" + equ_type)
		console.log("sub_type :" + sub_type)

		var useJob = "";
		for (var i = 60; i <= 70; i++) {
			useJob += itemData.add(i).readU8();
		}
		console.log(equ_type + "  " + useJob);

		if (equRarity < 3) {
			// 装备品级必须要求粉色以上，继承装备不满足要求
			api_CUser_SendNotiPacketMessage(user, "继承失败：装备品级必须要求粉色以上，继承装备不满足要求", 0);
			return;
		}
		if (needLevel < 55) {
			// 装备等级要大于50级以上，继承装备不满足要求
			api_CUser_SendNotiPacketMessage(user, "继承失败：装备等级要大于等于55级以上，继承装备不满足要求(" + needLevel + ")", 0);
			return;
		}
		var successTag = false;
		for (var i = 10; i <= 21; i++) {
			var equIn = CInventory_GetInvenRef(inven, INVENTORY_TYPE_BODY, i);
			if (Inven_Item_getKey(equIn)) {
				var inItemId = Inven_Item_getKey(equIn)
				var inItemData = CDataManager_find_item(G_CDataManager(), inItemId);
				var inEqu_type = inItemData.add(141 * 4).readU32(); // 装备类型
				var inEquRarity = CItem_GetRarity(inItemData); // 稀有度  >=3  粉色以上
				var inNeedLevel = CItem_GetUsableLevel(inItemData);  //等级
				console.log('equ_type a：' + equ_type + ',' + inEqu_type + ',' + inItemData.add(148).readU8())
				if (inEqu_type == equ_type) {
					if (inEqu_type == 10) {
						// 武器需要同职业
						var useJob = "";
						var inUseJob = "";
						for (var i = 60; i <= 70; i++) {
							useJob += itemData.add(i).readU8();
							inUseJob += inItemData.add(i).readU8();
						}
						if (useJob != inUseJob) {
							api_CUser_SendNotiPacketMessage(user, "继承失败：武器装备需要当前职业且同类型，穿戴装备不满足要求", 0);
							return;
						}
						var inSubType = CEquipItem_GetSubType(inItemData);
						if (sub_type != inSubType) {
							api_CUser_SendNotiPacketMessage(user, "继承失败：武器装备需要当前职业且同类型，穿戴装备不满足要求", 0);
							return;
						}
					}
					// 类型一直 才能继承
					if (inEquRarity < 3) {
						// 继承失败：装备品级必须要求粉色以上，穿戴装备不满足要求
						api_CUser_SendNotiPacketMessage(user, "继承失败：装备品级必须要求粉色以上，穿戴装备不满足要求", 0);
						return;
					}
					if (inNeedLevel < 55) {
						// 装备等级要大于50级以上，穿戴装备不满足要求
						api_CUser_SendNotiPacketMessage(user, "继承失败：装备等级要大于等于55级以上，穿戴装备不满足要求", 0);
						return;
					}
					// 强化
					var inUpgrade_level = equIn.add(6).readU8();
					// 增幅
					var zengfu = equ.add(17).readU16();
					// 锻造
					var duanzao = equ.add(51).readU8();
					// 宝珠
					var baozhu = equ.add(13).readU32();
					//魔法封印
					var seal1_lv = equ.add(37).readU8();
					var seal2_lv = equ.add(38).readU8();
					var seal3_lv = equ.add(39).readU8();
					var seal4_lv = equ.add(40).readU8();
					var seal5_lv = equ.add(41).readU8();
					var seal6_lv = equ.add(42).readU8();
					var seal7_lv = equ.add(43).readU8();
					var seal8_lv = equ.add(44).readU8();
					var seal9_lv = equ.add(45).readU8();
					var seal10_lv = equ.add(46).readU8();
					var seal11_lv = equ.add(47).readU8();
					var seal12_lv = equ.add(48).readU8();
					var seal13_lv = equ.add(49).readU8();
					var seal14_lv = equ.add(50).readU8();


					// 徽章

					var p0 = equ.add(37).add(0).readU8();
					var p1 = equ.add(37).add(3).readU8();
					var p2 = equ.add(37).add(6).readU8();
					var p3 = equ.add(37).add(1).readU8();
					var p4 = equ.add(37).add(2).readU8();
					var p5 = equ.add(37).add(4).readU8();
					var p6 = equ.add(37).add(5).readU8();
					var p7 = equ.add(37).add(7).readU8();
					var p8 = equ.add(37).add(8).readU8();

					if (inUpgrade_level <= upgrade_level) {
						//提升强化/增幅等级
						equIn.add(6).writeU8(upgrade_level);
						equIn.add(17).writeU16(zengfu);
						equIn.add(51).writeU8(duanzao);
						equIn.add(13).writeU32(baozhu);
						equIn.add(37).writeU8(seal1_lv);
						equIn.add(38).writeU8(seal2_lv);
						equIn.add(39).writeU8(seal3_lv);
						equIn.add(40).writeU8(seal4_lv);
						equIn.add(41).writeU8(seal5_lv);
						equIn.add(42).writeU8(seal6_lv);
						equIn.add(43).writeU8(seal7_lv);
						equIn.add(44).writeU8(seal8_lv);
						equIn.add(45).writeU8(seal9_lv);
						equIn.add(46).writeU8(seal10_lv);
						equIn.add(47).writeU8(seal11_lv);
						equIn.add(48).writeU8(seal12_lv);
						equIn.add(49).writeU8(seal13_lv);
						equIn.add(50).writeU8(seal14_lv);
						//赋予词条封印词条数量
						equIn.add(37).add(0).writeU8(p0);
						equIn.add(37).add(3).writeU8(p1);
						equIn.add(37).add(6).writeU8(p2);
						equIn.add(37).add(1).writeU8(p3);
						equIn.add(37).add(2).writeU8(p4);
						equIn.add(37).add(4).writeU8(p5);
						equIn.add(37).add(5).writeU8(p6);
						equIn.add(37).add(7).writeU8(p7);
						equIn.add(37).add(8).writeU8(p8);
						// 将原装备清除
						equ.add(6).writeU8(0);
						equ.add(17).writeU16(0);
						equ.add(51).writeU8(0);
						equ.add(13).writeU32(0);
						equ.add(37).writeU8(0);
						equ.add(38).writeU8(0);
						equ.add(39).writeU8(0);
						equ.add(40).writeU8(0);
						equ.add(41).writeU8(0);
						equ.add(42).writeU8(0);
						equ.add(43).writeU8(0);
						equ.add(44).writeU8(0);
						equ.add(45).writeU8(0);
						equ.add(46).writeU8(0);
						equ.add(47).writeU8(0);
						equ.add(48).writeU8(0);
						equ.add(49).writeU8(0);
						equ.add(50).writeU8(0);
						equ.add(37).add(0).writeU8(0);
						equ.add(37).add(3).writeU8(0);
						equ.add(37).add(6).writeU8(0);
						equ.add(37).add(1).writeU8(0);
						equ.add(37).add(2).writeU8(0);
						equ.add(37).add(4).writeU8(0);
						equ.add(37).add(5).writeU8(0);
						equ.add(37).add(7).writeU8(0);
						equ.add(37).add(8).writeU8(0);
						//通知客户端更新装备
						CUser_SendUpdateItemList(user, 1, 0, 9);
						CUser_SendUpdateItemList(user, 1, 3, i);
						CUser_SendUpdateItemList(user, 1, 3, 10);
						successTag = true;
						console.log("success！！！")
						api_CUser_SendNotiPacketMessage(user, "继承成功！！若属性不显示请选择角色或整理背包！", 6);
					}
					break;
				}
			}
		}
		if (!successTag) {
			// 失败 没有合适的装备，不符合装备
			api_CUser_SendNotiPacketMessage(user, "继承失败：没有合适的装备", 8);
		}
	}
}



//TODO排行榜前三名数组 默认数据   战力榜


var ranklist =
{
	"1":
	{
		"rank": 100,
		"characname": "牛市来了 ",
		"job": 0,
		"lev": 60,
		"Grow": 17,
		"Guilkey": 5,
		"Guilname": "至臻",
		"str": "老子天下第一！",
		"equip": [0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0]
	},

	"2":
	{
		"rank": 90,
		"characname": "今天你绿了吗 ",
		"job": 1,
		"lev": 60,
		"Grow": 17,
		"Guilkey": 5,
		"Guilname": "至臻",
		"str": "老子天下第二！",
		"equip": [0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0]
	},
	"3":
	{
		"rank": 80,
		"characname": "韭菜根都没了 ",
		"job": 2,
		"lev": 60,
		"Grow": 17,
		"Guilkey": 5,
		"Guilname": "至臻",
		"str": "老子天下第三！",
		"equip": [0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0]
	},
};



/**
 * 获得rank分（排名分数）
 * 适配花枝战力值数据库，其他请按照实际表进行适配
 * @param {string} characno
 * @returns 返回对应的战力值
 */
function GetRankNumber(charac_no) {
	var insertQuery = "SELECT ZLZ FROM d_starsky.zhanli WHERE CID='" + charac_no + "'";    //自行适配登录器战力表
	if (api_MySQL_exec(mysql_taiwan_cain, insertQuery)) {
		if (MySQL_get_n_rows(mysql_taiwan_cain) == 1) {
			MySQL_fetch(mysql_taiwan_cain);
			return parseInt(api_MySQL_get_str(mysql_taiwan_cain, 0));
		}
	}
}



/**
 * 获取自身排行版数据
 * 角色名处多家个空格用于屏蔽客户端内排行榜对显示框修改
 * 若要允许自行修改，请删除，并且删除默认初始中空格字符
 * @param {pointer} user 
 * @returns 
 */
function GetMyEquInfo(user) {
	var MyRanklist =
	{
		"rank": 0,
		"characname": "",
		"job": 0,
		"lev": 0,
		"Grow": 0,
		"Guilkey": 0,
		"Guilname": "",
		"str": "",
		"equip": []
	};
	var charac_no = CUserCharacInfo_getCurCharacNo(user);
	MyRanklist.rank = GetRankNumber(charac_no);
	console.log(MyRanklist.rank);
	MyRanklist.characname = api_CUserCharacInfo_getCurCharacName(user) + ""; //多个空格是为了屏蔽客户端自定义设置显示字符串
	MyRanklist.job = CUserCharacInfo_get_charac_job(user);
	MyRanklist.lev = CUserCharacInfo_get_charac_level(user);
	MyRanklist.Grow = CUserCharacInfo_getCurCharacGrowType(user);
	MyRanklist.Guilkey = CUserCharacInfo_get_charac_guildkey(user);
	MyRanklist.Guilname = api_CUser_GetGuildName(user);
	if (!MyRanklist.Guilname) {
		MyRanklist.Guilname = '偏爱网络'; //当公会不存在时，设置默认公会名字
	}
	var InvenW = CUserCharacInfo_getCurCharacInvenW(user);
	for (var i = 0; i <= 10; i++) {
		if (i != 9) {
			var inven_item = CInventory_GetInvenRef(InvenW, INVENTORY_TYPE_BODY, i);
			var item_id = Inven_Item_getKey(inven_item);
			MyRanklist.equip.push(item_id);
		}
		else {
			MyRanklist.equip.push(-1);
		}
	}
	return MyRanklist;
}

/**
 * 玩家下线时，保存自身信息并且和排行版进行排名
 * 调用方法：api_scheduleOnMainThread(SetRanking, [user]);//更新个人信息到排行榜
 * @param {pointer} user 
 */
function SetRanking(user) {
	var MyRanklist = GetMyEquInfo(user);
	log(JSON.stringify(MyRanklist));
	var existingIndex = Object.values(ranklist).findIndex(item => item.characname === MyRanklist.characname);//

	if (MyRanklist.rank) {
		if (existingIndex !== -1) {
			// 如果用户已经在排行榜中，更新他们的信息
			ranklist[existingIndex + 1] = MyRanklist;
		}
		else {
			// 如果用户不在排行榜中，将他们添加到排行榜
			ranklist["4"] = MyRanklist;
		}
		// 对排行榜进行排序
		const rankArray = Object.values(ranklist);
		rankArray.sort((a, b) => b.rank - a.rank);

		// 获取前三名玩家的信息
		const topThree = rankArray.slice(0, 3);

		const tmp = {};
		// 重新构建排行榜对象，仅包括前三名
		topThree.forEach((item, index) => {
			tmp[(index + 1).toString()] = item;
		});

		// 删除排行榜中排名为 "4" 的条目
		delete ranklist["4"];
		console.log(JSON.stringify(ranklist));
		ranklist = tmp;
	}
}

/**
 * //TODO排行榜下发 
 * api_scheduleOnMainThread(SendRankLits, [this.user, true]);//发送排行版到个人
 * @param {pointer} user
 * @param {boolean} all turn 全体下发 flash 单体下发
 */
function SendRankLits(user, all) {
	var packet_guard = api_PacketGuard_PacketGuard();
	InterfacePacketBuf_put_header(packet_guard, 0, 182);
	InterfacePacketBuf_put_byte(packet_guard, Object.keys(ranklist).length); //雕像数量
	for (var key in ranklist) {
		if (ranklist.hasOwnProperty(key)) {
			var charac_level = ranklist[key].lev; //等级
			var charac_job = ranklist[key].job; //职业
			var characGrowType = ranklist[key].Grow; //pvp段位
			var charac_name = ranklist[key].characname; //角色名
			var charac_Guilname = ranklist[key].Guilname; //公会名
			var charac_Guilkey = ranklist[key].Guilkey; //公会ID
			var equip = ranklist[key].equip; //装扮代码组
			api_InterfacePacketBuf_put_string(packet_guard, charac_name); //角色名
			InterfacePacketBuf_put_byte(packet_guard, charac_level); //等级
			InterfacePacketBuf_put_byte(packet_guard, charac_job); //职业
			InterfacePacketBuf_put_byte(packet_guard, characGrowType); //pvp段位
			api_InterfacePacketBuf_put_string(packet_guard, charac_Guilname); //公会名
			InterfacePacketBuf_put_int(packet_guard, charac_Guilkey); //公会ID
			for (var i = 0; i < equip.length; i++) {
				if (i != 9) {
					var item_id = equip[i]; //装扮id
				}
				else {
					item_id = -1
				}
				InterfacePacketBuf_put_int(packet_guard, item_id); //装扮id
			}
		}
	}
	InterfacePacketBuf_finalize(packet_guard, 1);
	if (all) {
		GameWorld_send_all(G_GameWorld(), packet_guard);
	}
	else {
		CUser_Send(user, packet_guard);
	}
	Destroy_PacketGuard_PacketGuard(packet_guard);
}

/**热载脚本时，加载排行版数据*/
function event_rankinfo_load_from_db() {
	if (api_MySQL_exec(mysql_frida, "select event_info from game_event where event_id = 'rankinfo';")) {
		if (MySQL_get_n_rows(mysql_frida) == 1) {
			MySQL_fetch(mysql_frida);
			var info = api_MySQL_get_str(mysql_frida, 0);
			ranklist = JSON.parse(info);
		}
	}
}

/**热载脚本时，存储排行版数据 */
function event_rankinfo_save_to_db() {
	try {
		api_MySQL_exec(mysql_frida, "replace into game_event (event_id, event_info) values ('rankinfo', '" + JSON.stringify(ranklist) + "');");
	} catch (error) {
	}
}







//随机强化装备
function random_upgrade(inven_item) {
	// 强化等级随机1-13
	var upgrade_level = get_random_int(1, 14);
	inven_item.add(6).writeU8(upgrade_level);
}
//随机宝珠
function random_monster_card2(inven_item) {
	var monster_card2 = all_monster_card2[get_random_int(0, all_monster_card2.length)];
	inven_item.add(13).writeUInt(monster_card2);
}
//随机增幅属性类型
function random_increase_type(inven_item) {
	//增幅类型 0为空 1-4体精力智
	var increase_type = 0;
	while (increase_type == 0) {
		//控制属性频率，使力智概率比体精高
		increase_type = get_random_int(3, 10) % 5;
	}
	inven_item.add(17).writeU8(increase_type);
}
//随机增幅附加数值
function random_increase_date(inven_item, user) {
	var user_level = CUserCharacInfo_get_charac_level(user);
	//装备id
	var item_id = Inven_Item_getKey(inven_item);
	//pvf中获取装备数据
	var item_data = CDataManager_find_item(G_CDataManager(), item_id);
	// 稀有度0-5 白蓝紫粉橙红
	var equ_rarity = CItem_GetRarity(item_data);
	// 装备等级
	var equ_level = CItem_GetUsableLevel(item_data);
	// 稀有度倍率
	var equ_rarity_ratio = 1 + equ_rarity / 2;
	// 装备等级倍率
	var equ_level_ratio = 1 + (equ_level + add_monster_level) / 10;
	// 人物等级倍率 和 装备等级倍率二选1
	var user_level_ratio = 1 + (user_level + add_monster_level) / 10;
	// 难度倍率
	var difficult_ratio = 1 + dungeon_difficult / 4;
	// 额外属性公式为 随机数 * (1+装备稀有度/x) * (1+(装备等级+额外怪物等级)/x) *(1+ 难度/4)
	// 蓝装比白板多50%额外属性, 30级比20级多33%, 英雄级掉落装备比普通级多1倍额外属性
	var random_data = get_random_int(500, 2000) * 0.01 * equ_rarity_ratio * user_level_ratio * difficult_ratio;
	var increase_date = random_data;
	//随机模式额外增加一倍
	if (random_monster) {
		increase_date += random_data;
	}
	//每多复制一个怪多20%属性
	if (copy_monster != 0) {
		increase_date += random_data * copy_monster * 0.2;
	}
	//最大额外属性65535
	if (increase_date < 65535) {
		inven_item.add(18).writeU16(increase_date);
	}
	else {
		inven_item.add(18).writeU16(65535);
	}
}
//随机异界气息
function random_increase_breath(inven_item) {
	//异界气息全为奇数 范围1-127
	var increase_breath1 = get_random_int(0, 63) * 2 + 1;
	var increase_breath2 = get_random_int(0, 63) * 2 + 1;
	//异界气息1跟2相等无效
	while (increase_breath2 == increase_breath1) {
		increase_breath2 = get_random_int(0, 63) * 2 + 1;
	}
	//写入后不能精炼裂魂系列装备
	inven_item.add(31).writeU8(increase_breath1);
	inven_item.add(32).writeU8(increase_breath2);
}
//随机魔法封印
function random_random_option(inven_item) {
	var random_option = all_random_option[get_random_int(0, all_random_option.length)];
	var random_option_date = get_random_int(1, 65535);
	inven_item.add(47).writeU8(random_option);
	inven_item.add(48).writeU16(random_option_date);
	inven_item.add(50).writeU8(3);
	for (var i = 0; i < 3; i++) {
		random_option = all_random_option[get_random_int(0, all_random_option.length)];
		random_option_date = get_random_int(1, 65535);
		inven_item.add(37 + i * 3).writeU8(random_option);
		inven_item.add(38 + i * 3).writeU16(random_option_date);
	}
}
//随机锻造等级
function random_increase_level(inven_item) {
	//锻造等级随机1-10
	var increase_level = get_random_int(1, 11);
	//装备id
	var item_id = Inven_Item_getKey(inven_item);
	//pvf中获取装备数据
	var item_data = CDataManager_find_item(G_CDataManager(), item_id);
	// 装备类型 10武器 12-15防具 上衣头肩下装鞋子腰带 17-21首饰 项链手镯戒指辅助魔法石
	var equ_type = item_data.add(141 * 4).readU32();
	//为装备时锻造
	if (equ_type == 10) {
		inven_item.add(51).writeU8(increase_level);
	}
}

// 增强装备属性
function enhanced_Equip() {
	// 是否是在副本里拾取的装备,只有从副本里捡的装备才会生效 可以将装备丢地上捡取刷属性
	var is_user_pickup_item = false;
	Interceptor.attach(ptr(0x085A3B98), {
		onEnter: function (args) {
			is_user_pickup_item = true;
		},
		onLeave: function (retval) {
			is_user_pickup_item = false;
		}
	});
	Interceptor.attach(ptr(0x08502D86), {
		onEnter: function (args) {
			this.user = args[0].readPointer();
		},
		onLeave: function (retval) {
			//获取道具的角色
			var user = this.user;
			// 强制增加装备属性模式, 强制生效模式可以将装备存仓库再取出刷属性
			if (!enhanced_equip) {
				// 增强副本模式开启并且且装备是从副本里捡的
				if (!enhance_dungeon || !is_user_pickup_item)
					return;
			}
			//物品栏新增物品的位置
			var slot = retval.toInt32();
			if (slot > 0) {
				//角色背包
				var inven = CUserCharacInfo_getCurCharacInvenW(user);
				//背包中新增的道具
				var inven_item = CInventory_GetInvenRef(inven, INVENTORY_TYPE_ITEM, slot);
				//过滤道具类型
				if (!Inven_Item_isEquipableItemType(inven_item))
					return;
				//随机强化装备
				random_upgrade(inven_item);
				//装备品质是最上级
				inven_item.add(7).writeUInt(0);
				//懒得修理装备的 ,将耐久直接设置为65535
				inven_item.add(11).writeU16(30);
				//随机宝珠
				random_monster_card2(inven_item);
				//随机增幅属性类型
				random_increase_type(inven_item);
				//随机增幅附加数值
				random_increase_date(inven_item, user);
				//随机4词条魔法封印
				random_random_option(inven_item);
				//随机异界气息 随机后不能精炼
				random_increase_breath(inven_item);
				//随机锻造等级
				random_increase_level(inven_item);
				CUser_SendUpdateItemList(user, 1, 0, slot);
			}
		}
	});
}

//增强游戏副本
function enhanced_Dungeon() {
	var user = null;
	var user_level = 0;
	//玩家杀死的怪物数量
	var kill_monster_num = 0;
	//进入副本函数 获取玩家参数
	Interceptor.attach(ptr(0x081C8102), {
		onEnter: function (args) {
			user = args[1];
			user_level = CUserCharacInfo_get_charac_level(user);
			kill_monster_num = 0;
		}
	});
	//选择难度时, 获取难度参数
	Interceptor.attach(ptr(0x085a0954), {
		onEnter: function (args) {
			dungeon_difficult = args[2].toInt32();
		}
	});
	// 如果怪物等级比人物高很多, 会导致经验不正常
	// 原版的经验比 普通1 冒险1.3 王者1.5 地狱1.9 英雄2.1
	Interceptor.attach(ptr(0x085A2488), {
		onEnter: function (args) {
			this.user = args[1];
			if (enhance_dungeon) {
				var user_level = CUserCharacInfo_get_charac_level(this.user);
				//难度倍率
				var difficult = 3 + dungeon_difficult;
				//经验倍率
				var level = 1 + add_monster_level / user_level * 2;
				var reward_exp = Math.floor(CUserCharacInfo_get_level_up_exp(this.user, user_level) / user_level / 300 * difficult * level);
				args[2].writeInt(reward_exp);
			}
		}
	});
	// hook杀死怪物函数，杀死怪物时总数量+1
	Interceptor.attach(ptr(0x085B5A4C), {
		onEnter: function (args) {
			kill_monster_num++;
		},
		onLeave: function (retval) {
		}
	});
	// 通关经验奖励 吃经验秘药加成
	Interceptor.attach(ptr(0x085AD278), {
		onEnter: function (args) {
			this.user = args[1];
			if (enhance_dungeon) {
				var user_level = CUserCharacInfo_get_charac_level(this.user);
				// 怪物数量倍率
				var monster_num = kill_monster_num / 300;
				// 难度倍率
				var difficult = 3 + dungeon_difficult;
				// 经验倍率
				var level = 1 + add_monster_level / user_level * 2;
				// 玩家百分比经验 * 所有倍率
				var reward_exp = Math.floor(CUserCharacInfo_get_level_up_exp(this.user, user_level) / user_level * monster_num * difficult * level);
				args[2].writeInt(reward_exp);
			}
		}
	});
	/**
	* 随机模式下,复制的怪物id,部分怪物无法被复制
	* 所以手动复制怪物编号到数组，再去除无法复制的编号
	* 提取pvf文件monster/monster.lst
	* 替换正则^`[\w\-_/.]*`$
	* 换行替换为逗号,复制到下面方括号内
	* var all_monster_id = [];
	* 下面的怪物编号提取至版本日期20130613的pvf，未去除无法复制的怪物
	* 遇到无法死亡的怪物
	* 可以使用遍历器获得怪物编号
	* 去除列表中的编号即可去除随机怪物
	*/
	var all_monster_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 19, 20, 21, 22, 23, 24, 25, 31, 32, 33, 34, 35, 37, 38, 39, 40, 50, 51, 52, 53, 60, 61, 63, 64, 65, 70, 71, 72, 75, 76, 77, 78, 80, 81, 82, 83, 84, 200, 201, 202, 210, 211, 212, 220, 221, 222, 250, 251, 252, 253, 260, 261, 262, 263, 264, 265, 266, 270, 271, 272, 273, 280, 281, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 413, 410, 411, 420, 421, 422, 430, 500, 501, 502, 600, 601, 602, 603, 604, 605, 606, 607, 610, 700, 701, 702, 704, 705, 711, 750, 751, 752, 760, 761, 762, 770, 771, 900, 901, 902, 903, 904, 905, 906, 907, 908, 909, 1000, 1001, 1006, 1010, 1011, 1012, 1013, 1014, 1016, 1017, 1019, 1020, 1021, 1022, 1030, 1031, 1032, 1033, 1034, 1038, 1039, 1040, 1041, 1042, 1043, 1050, 1051, 1052, 1053, 1060, 1061, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1100, 1101, 5001, 5002, 5003, 5004, 5005, 5006, 5007, 10000, 10001, 10002, 10003, 10004, 60001, 60002, 60003, 60004, 60005, 60006, 60007, 60008, 60009, 60010, 60011, 60012, 60013, 60014, 60015, 60016, 60017, 60018, 60019, 60020, 60021, 60022, 60023, 60024, 60025, 60030, 60040, 60041, 60042, 60043, 60044, 60045, 60046, 60050, 60060, 60061, 60062, 60063, 60065, 60066, 60100, 60101, 60102, 60103, 60104, 60105, 60106, 60107, 60108, 60109, 60110, 60111, 60112, 60113, 60114, 60115, 60116, 65000, 65001, 65002, 65003, 65004, 65005, 65006, 65007, 65008, 65009, 65010, 65011, 65012, 65015, 50000, 50001, 50002, 50003, 50004, 50005, 50006, 50007, 50008, 50009, 50010, 50011, 50012, 50023, 50024, 50030, 50031, 50032, 50033, 50034, 50062, 50063, 50064, 50065, 50066, 50067, 50068, 50069, 50070, 50071, 50072, 50073, 50074, 50075, 50076, 50077, 50078, 50079, 50080, 50081, 50082, 50083, 50084, 50085, 50086, 50087, 50088, 50089, 50090, 50091, 50092, 50093, 50094, 50095, 50096, 50097, 50098, 40001, 40002, 40003, 40004, 41001, 41002, 41003, 41004, 41005, 42001, 42002, 42003, 42004, 43001, 43002, 43003, 40005, 40006, 40007, 40008, 41006, 41007, 41008, 41009, 42005, 42006, 42007, 42008, 43004, 43005, 43006, 40009, 40010, 40011, 40012, 40013, 40014, 41010, 41011, 41012, 41013, 42009, 42010, 42011, 42012, 42013, 43007, 43008, 43009, 43010, 40015, 40016, 40017, 40018, 40019, 41014, 41015, 41016, 41017, 41018, 42014, 42015, 42016, 42017, 43011, 43012, 43013, 40020, 40021, 40022, 40023, 40024, 41019, 41020, 41021, 41022, 41023, 42018, 42019, 42020, 43014, 43015, 43016, 40025, 3000, 3001, 3002, 3010, 3011, 3012, 3013, 3014, 3015, 3016, 3017, 55001, 55002, 55003, 55004, 55005, 55006, 55007, 55008, 55009, 55010, 55011, 55012, 55013, 55014, 55015, 55016, 55017, 55018, 55019, 55020, 55021, 55022, 55023, 55024, 55025, 55026, 55027, 55028, 50501, 50502, 50503, 50504, 50505, 50506, 50507, 50508, 50509, 61700, 61701, 61702, 61703, 61704, 61705, 61706, 61707, 61708, 61709, 61710, 61711, 61712, 61713, 61714, 61715, 61716, 61717, 61718, 61719, 61720, 61721, 61722, 61723, 61724, 61725, 61726, 61727, 61728, 61729, 61730, 61731, 61732, 61733, 61734, 61735, 61736, 61738, 61739, 61740, 61760, 61761, 61762, 61763, 61764, 61765, 61766, 61767, 56701, 56702, 56703, 56704, 56705, 56706, 56707, 56708, 56709, 56710, 56711, 56712, 56713, 56714, 56715, 56716, 56717, 56718, 56719, 56720, 56721, 56722, 56723, 56724, 56727, 56728, 56729, 56401, 56404, 56405, 61402, 61404, 61405, 61496, 56406, 61495, 61494, 61493, 56450, 56452, 61450, 61451, 61452, 61453, 61454, 61455, 61456, 61457, 56407, 61407, 61408, 61409, 61410, 61411, 61412, 61413, 61414, 61415, 61416, 61419, 61420, 61422, 61423, 56408, 56409, 61400, 61401, 61421, 56410, 56411, 56412, 61424, 56418, 56419, 61425, 61426, 61427, 61428, 61429, 61430, 61431, 61432, 56413, 61433, 61434, 61435, 56414, 56415, 56416, 56417, 61100, 61101, 61102, 61103, 61104, 61105, 61106, 61108, 61109, 56101, 56102, 61110, 56103, 56104, 61111, 56105, 61112, 61113, 56106, 61114, 61115, 61116, 61118, 56107, 56108, 61119, 61121, 61122, 56109, 61123, 61124, 61125, 61126, 61127, 56110, 61128, 61129, 61130, 61131, 61132, 61133, 61134, 61135, 61136, 61137, 61138, 61139, 61140, 61141, 61142, 61459, 61497, 61498, 61499, 62500, 62501, 62502, 62503, 62504, 62505, 61143, 61144, 61145, 61146, 61147, 61148, 61149, 56112, 56113, 56114, 56115, 56116, 56117, 56123, 56436, 61150, 56424, 61152, 61153, 61154, 61155, 56124, 56125, 61156, 61158, 61159, 61160, 61161, 56126, 61162, 61163, 61164, 61165, 61171, 61172, 61173, 56128, 56129, 56130, 56131, 56132, 56133, 61174, 61175, 61176, 61177, 61178, 61179, 61180, 61181, 61182, 61183, 61184, 61185, 56134, 56135, 56136, 61186, 61187, 61188, 61189, 61190, 56137, 61191, 61192, 61193, 61194, 56139, 62106, 62107, 56140, 62109, 62110, 62111, 62113, 62114, 62115, 56141, 62116, 56142, 62117, 62118, 62119, 62120, 62125, 56143, 62126, 56144, 56145, 62127, 62128, 62130, 62131, 56146, 62132, 62133, 62134, 62135, 62136, 62137, 56147, 56148, 56149, 56150, 62138, 62139, 62140, 56151, 56152, 62141, 62142, 62143, 62144, 62145, 62146, 62147, 62148, 62149, 62150, 62151, 62152, 62153, 56153, 62154, 62155, 62156, 62157, 56154, 62158, 62159, 62160, 62161, 56155, 56156, 56157, 62105, 62108, 62506, 62507, 62508, 62509, 62510, 62511, 62512, 62112, 56158, 62121, 62122, 62123, 62124, 62513, 62514, 62515, 62516, 56159, 56160, 56161, 56162, 56163, 62517, 62518, 62519, 62520, 62521, 62522, 62523, 61508, 61509, 61510, 61511, 61513, 61514, 61515, 61516, 61517, 61518, 61519, 61520, 61521, 61522, 61523, 61524, 61525, 61526, 61527, 61528, 61529, 61530, 61531, 61532, 61533, 56501, 56502, 56503, 56505, 56506, 56507, 61800, 61801, 61802, 61803, 61805, 61806, 61807, 61808, 61809, 61810, 61811, 61812, 61814, 61300, 61301, 61303, 61304, 61305, 61306, 61307, 61320, 61321, 61323, 61325, 61326, 61327, 61328, 61329, 61330, 61331, 61332, 61333, 61334, 61335, 61336, 61337, 61338, 61339, 61340, 61341, 61342, 61343, 61344, 61345, 61346, 61347, 61348, 61349, 61350, 61351, 61352, 61353, 61354, 61355, 56301, 56302, 56303, 56034, 56035, 56036, 56037, 56038, 56039, 61202, 61203, 61204, 61208, 61209, 61210, 61211, 56007, 61218, 61219, 61220, 61221, 61222, 56008, 56010, 56011, 61223, 61224, 61225, 61231, 61226, 61227, 61228, 56012, 61229, 61230, 56015, 61232, 61233, 56016, 61234, 56017, 61235, 56021, 56022, 61236, 61237, 56023, 61239, 61240, 61241, 61238, 56024, 56025, 56026, 56027, 56028, 56018, 56019, 56020, 61242, 61243, 61244, 61245, 61246, 61247, 61263, 56029, 56030, 56031, 56032, 61266, 61267, 61268, 56033, 61269, 63007, 59016, 59017, 56040, 56041, 56042, 56043, 56044, 56045, 56046, 56047, 56048, 61264, 61265, 61248, 61249, 61250, 61251, 61252, 61253, 61254, 61255, 61256, 61257, 61258, 61259, 61260, 61261, 61262, 56049, 56402, 61278, 61279, 61282, 61274, 61275, 61276, 61270, 56052, 61277, 61280, 56050, 56051, 58002, 61283, 61284, 61285, 61281, 61286, 61287, 56053, 56054, 61288, 61289, 61290, 61291, 61292, 61293, 61294, 61272, 61273, 61295, 56055, 56056, 56057, 56058, 56059, 56060, 56061, 61000, 61001, 61002, 56801, 56802, 56803, 61003, 61004, 56000, 61007, 61008, 56001, 61010, 61011, 61012, 61015, 56004, 61016, 61436, 61437, 61438, 61439, 61440, 61441, 61442, 61443, 61804, 61458, 56422, 61460, 61461, 61462, 61463, 61482, 61483, 61005, 61006, 61017, 61018, 61009, 56002, 61216, 56006, 61014, 56005, 61013, 62000, 62001, 62002, 56423, 62003, 62004, 62005, 62006, 62007, 62008, 62009, 62010, 62011, 56420, 56421, 61213, 61214, 61215, 62012, 62013, 62014, 62015, 62016, 56009, 62018, 62021, 56427, 61464, 56426, 61815, 61816, 61817, 61818, 61819, 61820, 61821, 61822, 61823, 61824, 61825, 61826, 61827, 61828, 61829, 61830, 61831, 61832, 61833, 61834, 61835, 61195, 61196, 61197, 61198, 61199, 62100, 62101, 62102, 62103, 62104, 61836, 61837, 61838, 61839, 61840, 61841, 61842, 61843, 61844, 61845, 61846, 61847, 61848, 61849, 61850, 61465, 61466, 61467, 61468, 61469, 61470, 61471, 61472, 61473, 61474, 61475, 61476, 61477, 61478, 56428, 56429, 56430, 56431, 56432, 56433, 56434, 61479, 56435, 61480, 61481, 61484, 61485, 61490, 61491, 61492, 61535, 59000, 59001, 59002, 59003, 59005, 59006, 59007, 59008, 63000, 63001, 63002, 63003, 63004, 63005, 63006, 56013, 56014, 63008, 63009, 56437, 56438, 56439, 56440, 56441, 56442, 56443, 56444, 56445, 56446, 61487, 61488, 61489, 59011, 59013, 59014, 59015, 63010, 63011, 63012, 63013, 63014, 59012, 56447, 56448, 59009, 63018, 63019, 63020, 56449, 56451, 61500, 56453, 63499, 63500, 61504, 61505, 61507, 61540, 61541, 61542, 61543, 61544, 61545, 61546, 61547, 56454, 56455, 61548, 61549, 61550, 61551, 61600, 61601, 56456, 61602, 61603, 56457, 61604, 61605, 59018, 59019, 63021, 63022, 63023, 59020, 59021, 59022, 59023, 59024, 59025, 59026, 59027, 56466, 61606, 61607, 61608, 61609, 61610, 61611, 61612, 61613, 61614, 64000, 64001, 61627, 61628, 61629, 61630, 61631, 58000, 56476, 56468, 56425, 63024, 63025, 63026, 63027, 63028, 63029, 63030, 59028, 59029, 59030, 58005, 59037, 63031, 63032, 59032, 59033, 59034, 63033, 63035, 63036, 59035, 59036, 63037, 63038, 63039, 63040, 63041, 63042, 63043, 63044, 56730, 56731, 56732, 56733, 56734, 61750, 61758, 61757, 61756, 61755, 56738, 56737, 56736, 56735, 61745, 56726, 61743, 56725, 61741, 61742, 56740, 56741, 61737, 61748, 56742, 56743, 61752, 61753, 61615, 61616, 61617, 61618, 61619, 61620, 56471, 56472, 56473, 56474, 61621, 61622, 61623, 58001, 56403, 61624, 61625, 61626, 56475, 64594, 64595, 64596, 64597, 64598, 64599, 64600, 64601, 64602, 64603, 64604, 64605, 64606, 64607, 64615, 64620, 64621, 64622, 64623, 64624, 64625, 64626, 64627, 64628, 64629, 64630, 64631, 64632, 64633, 64634, 64635, 64616, 64636, 64637, 64638, 64617, 64639, 64640, 64641, 64619, 64642, 64643, 64644, 64618, 64645, 64646, 64647, 64612, 64648, 64649, 64650, 64614, 64654, 64655, 64656, 64611, 64657, 64658, 64659, 64002, 64003, 64004, 64005, 64006, 58003, 58004, 56469, 56747, 62782, 64007, 64008, 64009, 64010, 64011, 64012, 64024, 64013, 64014, 64015, 61632, 56467, 64016, 64017, 64018, 64019, 56460, 56458, 56459, 56461, 56462, 56463, 56464, 56465, 58006, 58007, 61633, 56470, 64020, 61634, 61635, 64021, 64022, 64023, 63045, 63046, 63047, 59031, 59038, 63048, 62617, 62616, 62615, 62613, 62611, 62609, 62608, 62607, 62606, 62605, 57000, 62604, 62603, 62602, 62601, 62600, 57005, 57004, 57003, 62622, 62621, 62620, 62619, 57002, 62618, 57001, 62627, 62626, 62625, 62624, 62632, 62631, 62630, 62651, 62650, 62649, 62648, 62647, 62646, 62645, 62644, 62643, 62642, 62641, 62640, 62639, 62638, 62637, 62636, 62635, 62634, 62656, 62655, 62653, 62652, 62662, 62661, 62660, 62659, 62658, 62657, 62623, 62614, 62612, 62610, 62663, 57007, 62654, 62633, 57006, 62629, 62628, 62673, 62672, 62671, 62670, 62669, 62668, 62667, 62666, 62665, 62664, 62678, 62677, 62676, 62675, 62674, 62686, 62685, 62684, 62683, 62682, 62681, 62680, 62679, 62699, 62698, 62697, 62696, 62695, 62694, 62693, 62692, 62691, 62688, 62690, 62689, 62687, 62701, 62700, 62710, 62709, 62708, 62707, 62706, 62705, 62704, 62703, 62702, 62763, 62762, 62761, 62760, 62759, 62758, 62757, 62756, 62755, 62754, 62753, 62752, 62751, 62750, 62749, 62748, 62747, 62746, 62745, 62744, 62743, 62742, 62741, 57011, 62739, 62738, 62740, 62737, 57010, 62736, 62735, 62734, 62733, 62732, 62731, 62726, 62725, 62724, 57009, 57008, 62723, 62722, 62721, 62720, 62719, 62730, 62729, 62728, 62727, 62718, 62717, 62712, 62716, 62715, 62714, 62711, 62713, 57015, 57014, 62765, 62764, 57013, 57012, 62766, 62767, 62768, 62769, 62770, 62771, 62772, 57016, 57017, 57018, 62773, 62774, 62775, 62776, 62777, 62778, 62779, 62780, 62781, 65500, 65013, 65014, 61744, 56748, 61747, 61746, 61749, 56749, 61751, 61754, 61759, 56750, 56751, 61775, 56753, 61781, 61782, 56757, 61798, 56762, 56739, 61797, 56744, 62225, 62226, 62254, 62255, 62286, 62287, 56759, 56760, 62320, 61768, 61769, 61770, 61771, 56745, 56746, 56752, 56754, 61773, 61774, 61778, 56755, 56756, 56758, 56761, 61785, 56767, 61786, 61787, 61789, 61790, 61793, 61792, 61772, 56763, 61776, 61777, 61779, 61780, 61783, 61784, 61788, 62207, 62216, 56768, 62238, 62239, 56772, 62240, 62241, 62242, 62243, 56775, 56776, 62244, 56777, 56778, 56477, 56478, 61636, 61637, 61638, 61639, 61641, 61643, 61646, 61648, 61651, 61652, 61640, 61642, 61644, 61645, 61647, 61649, 61650, 61653, 61654, 61655, 61656, 65016, 57101, 57102, 57103, 65101, 62024, 62025, 62026];
	// apc列表同理, pvf位置aicharacter/aicharacter.lst
	var all_apc_id = [201, 202, 203, 204, 205, 301, 305, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 419, 420, 421, 422, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434, 435, 436, 437, 438, 439, 440, 441, 442, 443, 444, 445, 500, 501, 600, 601, 602, 603, 604, 605, 606, 607, 608, 609, 610, 611, 612, 613, 614, 615, 616, 617, 618, 619, 620, 621, 622, 900, 902, 1301, 1400, 1401, 1501, 1502, 1503, 1504, 1505, 1506, 1507, 1508, 1510, 1511, 1512, 1513, 1514, 1515, 1516, 1517, 1518, 1519, 1600, 1601, 5002, 5003, 5004, 5201, 5202, 5301, 5302, 5303, 5304, 5305, 5306, 5307, 5308, 5309, 5310, 5311, 5312, 5313, 5400, 5401, 5402, 5403, 5404, 5405, 5406, 5407, 5408, 5409, 5410, 5411, 5412, 5413, 5414, 5415, 5416, 5417, 5418, 5419, 5600, 5601, 5602, 5603, 5604, 5605, 5606, 5607, 5608, 5609, 5610, 5611, 5612, 5613, 5900, 5901, 6400, 6401, 6500, 6501, 6502, 6503, 6504, 6505, 6506, 6507, 6600, 6601, 10201, 10202, 10203, 10301, 10302, 10304, 10305, 10306, 10401, 10402, 10403, 10404, 10405, 10406, 10407, 10408, 10409, 10410, 10411, 10412, 10413, 10414, 10415, 10416, 10417, 10418, 10419, 10420, 10421, 10422, 10504, 10600, 10601, 10602, 10603, 10604, 10605, 10606, 10607, 10608, 10609, 10610, 10611, 10612, 10613, 10614, 10615, 10616, 10618, 10620, 10621, 10622, 10623, 10624, 10625, 10626, 10627, 10628, 10629, 10900, 10901, 10902, 10903, 11400, 11401, 11500, 11501, 11502, 11503, 11504, 11505, 11506, 11507, 11508, 11509, 11510, 11511, 11512, 11513, 11514, 11515, 11516, 11517, 11518, 11600, 15201, 15202, 15203, 15204, 15205, 15206, 15207, 15301, 15303, 15401, 15402, 15403, 15404, 15405, 15406, 15407, 15408, 15409, 15410, 15411, 15412, 15413, 15414, 15415, 15416, 15417, 15418, 15501, 15502, 15600, 15601, 15602, 15603, 15604, 15605, 15606, 15607, 15608, 15801, 15900, 15901, 15902, 15903, 16400, 16501, 16502, 16503, 16504, 16505, 16506, 16507, 16508, 16509, 16510, 16511, 16512, 16513, 16514, 16515, 16516, 16517, 16601, 16602, 16603, 16604, 16605, 16606, 16607, 16608, 16609, 16610, 16611, 16612, 16613, 16614, 16615, 16616, 16617, 16618, 20002, 20201, 20301, 20302, 20303, 20401, 20402, 20403, 20404, 20405, 20406, 20407, 20408, 20409, 20410, 20411, 20412, 20413, 20414, 20415, 20417, 20418, 20420, 20421, 20422, 20423, 20424, 20425, 20426, 20427, 20428, 20429, 20430, 20431, 20432, 20433, 20434, 20435, 20436, 20437, 20438, 20439, 20440, 20441, 20442, 20443, 20444, 20445, 20446, 20500, 20501, 20600, 20601, 20603, 20604, 20605, 20606, 20607, 20608, 20609, 20610, 20611, 20612, 20613, 20614, 20615, 20616, 20900, 20901, 20902, 21400, 21401, 21500, 21501, 21502, 21503, 21504, 21505, 21506, 21507, 21600, 21601, 21602, 21603, 21604, 21605, 25301, 25302, 25303, 25304, 25305, 25306, 25400, 25401, 25402, 25403, 25404, 25405, 25406, 25407, 25408, 25409, 25410, 25411, 25617, 25618, 25619, 25620, 25621, 25622, 25623, 25624, 25900, 26501, 26502, 26503, 26504, 26505, 26506, 26507, 26508, 26509, 26510, 26511, 26512, 26601, 26602, 30001, 30002, 30003, 30004, 30301, 30302, 30303, 30304, 30401, 30402, 30403, 30404, 30405, 30406, 30407, 30408, 30409, 30410, 30411, 30900, 30901, 31401, 31501, 31502, 31503, 31504, 31505, 31506, 31507, 31508, 31600, 35001, 35002, 35003, 35004, 35900, 35901, 35902, 35903, 36400, 36401, 36402, 36403, 36404, 36405, 36500, 36501, 36502, 36503, 36504, 40401, 40402, 40900, 40901, 41401];
	// 随机模式下,复制的bossid,将boos填写到下面数组中
	var all_boss_id = [15, 17, 251, 711, 1010, 3000, 61456, 62116];
	// 正常模式下 无法正常复制怪物的地图id 测试地图清风1031所有地图
	var skip_map_id = [16348, 16349, 16350, 16351, 16352, 16353, 16354, 17057, 17024, 17025, 17702, 17703, 60052, 17100, 17101];
	// 正常模式下 无法正常复制怪物的怪物id 测试地图清风1031所有地图
	var skip_monster_id = [71, 61496, 61105, 61103, 61110, 61805, 1034, 1030, 62123, 62515, 56160, 61228, 61226, 64016, 61273];
	// 副本刷怪函数 控制副本内怪物的数量和属性
	var read_f = new NativeFunction(ptr(0x08151612), 'int', ['pointer', 'pointer'], { "abi": "sysv" });
	Interceptor.attach(ptr(0x08151612), {
		//当前刷怪的副本id
		onEnter: function (args) {
			var map_info = args[0];
			var monster = args[1];
			//否直接退出
			if (!enhance_dungeon)
				return;
			//16 地图编号, pvf位置map/map.lst
			var map_id = map_info.add(4);
			//怪物攻城副本，神牛已经写好hook函数了所以这里直接返回
			if ((map_id.readU16() >= 40001) && (map_id.readU16() <= 40095))
				return;
			//16 怪物uid
			var monster_uid = monster.add(4);
			/**8 怪物类型
			 * 地图文件中类型为0 3 5 8
			 * 0对应普通怪
			 * 写入为1对应精英紫名怪,普通怪物的1.5倍属性 英雄级下为橙名,2倍普通怪属性
			 * 写入为2对应不灭粉名怪,普通怪物的3倍属性 英雄级下为2倍普通怪属性
			 * 3对应Boss粉名怪,普通怪物的2.5倍属性
			 * 部分怪为boss时比精英怪多额外招式,比如机械牛为boss时招式比精英怪多
			 * 复制模式下 boss房杀死所有怪才会结算,防止杀死一个boss直接结算
			 * 5对应apc型小怪,如月光酒馆的阿甘左
			 * 8对应apc型boss,如绝望之塔的每层boss
			 * apc修改等级无效,复制无效
			*/
			var monster_type = monster.add(8);
			//int 怪物编号, pvf编号位置monster/monster.lst
			//怪物类型为apc时, pvf编号位置aicharacter/aicharacter.lst
			var monster_id = monster.add(12);
			//8 怪物等级,根据地图文件来定,一般为0时跟随副本等级
			var monster_level = monster.add(16);
			//设置怪物等级
			var new_monster_level = user_level + add_monster_level;
			//怪物等级最高127
			if (new_monster_level < 127) {
				monster_level.writeU8(new_monster_level);
			} else {
				monster_level.writeU8(127);
			}
			//怪物类型为0，也就是普通小怪
			if (monster_type.readU8() == 0) {
				// 英雄级 怪物类型 是伪装粉名怪 会闪退，
				if (dungeon_difficult != 4) {
					//设置紫名 粉名 各占一半
					monster_type.writeU8(get_random_int(1, 3));
				} else {
					//只设置为橙名怪
					monster_type.writeU8(1);
				}
				if (!is_skip_monster(skip_monster_id, monster_id.readUInt())) {
					if (!is_skip_monster(skip_map_id, map_id.readUInt())) {
						if (copy_monster != 0) {
							//额外生成怪物数量
							var cnt = copy_monster;
							while (cnt > 0) {
								--cnt;
								if (random_monster) {
									//随机生成怪物从数组all_monster_id取,确保数组内没有无法复制的怪物id
									monster_id.writeUInt(all_monster_id[get_random_int(0, all_monster_id.length)]);
								}
								//为当前地图刷新额外的怪物
								read_f(map_info, monster);
								monster.writeUInt(monster.readInt() + 1000);
								monster_uid.writeU16(monster_uid.readU16() + 1000);
							}
						}
						if (random_monster) {
							monster_id.writeUInt(all_monster_id[get_random_int(0, all_monster_id.length)]);
						}
					}
				}
			} else if (monster.add(8).readU8() == 3) { //怪物类型为3，也就是boss
				if (!is_skip_monster(skip_monster_id, monster_id.readU16())) {
					if (!is_skip_monster(skip_map_id, map_id.readUInt())) {
						if (copy_monster != 0) {
							//复制boss不能直接生成, 否则杀死第一个boss直接结算
							//read_f(map_info, monster);
							//共生成设置的 怪物数量+3
							var cnt = copy_monster + 3;
							while (cnt > 0) {
								--cnt;
								//新增怪物index
								monster.writeUInt(monster.readUInt() + 1);
								//新增怪物uid
								monster_uid.writeU16(monster_uid.readU16() + 1);
								if (random_monster) {
									//从boss列表中生成boss
									monster_id.writeUInt(all_boss_id[get_random_int(0, all_boss_id.length)]);
								}
								//生成副本boss
								read_f(map_info, monster);
							}
						}
						if (random_monster) {
							monster_id.writeUInt(all_boss_id[get_random_int(0, all_boss_id.length)]);
						}
					}
				}
			} else {//剩下情况就是5跟8的情况,apc等级写死在pvf中,无法新增数量，只能随机
				if (random_monster) {
					//从apc列表中生成apc
					monster_id.writeUInt(all_apc_id[get_random_int(0, all_apc_id.length)]);
				}
			}
		}
	});
}
// 判断是否应该被跳过
function is_skip_monster(array, id) {
	for (let index = 0; index < array.length; index++) {
		if (id == array[index])
			return true;
	}
	return false;
}


//忽略副本门口禁止摆摊
function Privatestore_IgnoreNearDungeon() {
	Interceptor.attach(ptr(0x085C5082), {
		onEnter: function (args) {
		},
		onLeave: function (retval) {
			//获取返回值
			var returnValue = retval.toInt32();
			console.log('Return Value:' + returnValue);
			//强制返回1
			retval.replace(1);
		}
	});
}

//关闭NPC回购
function disable_redeem_item() {
	Interceptor.attach(ptr(0x085F7BE0), {
		onEnter: function (args) {
			//console.log("disable_redeem_item ="+ args)

		},
		onLeave: function (retval) {
			var returnValue = retval.toInt32();
			console.log("Return Value = " + returnValue);
			retval.replace(1);
		}
	});
}

/*修复积分商城错误发包导致无法界面卡死的BUG*/
function Hook_Arad_MileageProcess_BuySuccess() {
	Interceptor.replace(ptr(0x819E220), new NativeCallback(function (a1, user, buyno, itemcnt, a5, MileageNumber, a7, a8, a9) {
		Hook_Arad_MileageProcess_BuyMileageItem(user, MileageNumber);
		CUser_SendCashData(user, 0);
		let packetGuard = new PacketGuard();
		InterfacePacketBuf_put_header(packetGuard, 1, 67);
		InterfacePacketBuf_put_byte(packetGuard, 1);
		InterfacePacketBuf_put_byte(packetGuard, a5);
		InterfacePacketBuf_put_int(packetGuard, 11);
		InterfacePacketBuf_put_int(packetGuard, buyno);
		InterfacePacketBuf_put_int(packetGuard, a7);
		InterfacePacketBuf_put_int(packetGuard, a8);
		InterfacePacketBuf_put_int(packetGuard, -1);
		InterfacePacketBuf_put_short(packetGuard, 0); // Insert appropriate values for the short parameters
		InterfacePacketBuf_put_short(packetGuard, 0); // Insert appropriate values for the short parameters
		InterfacePacketBuf_put_int(packetGuard, -1);
		InterfacePacketBuf_put_int(packetGuard, 0); // Insert appropriate value for the int parameter
		InterfacePacketBuf_finalize(packetGuard, 1);
		CUser_Send(user, packetGuard.getBuffer());
		DestroyPacketGuard(packetGuard);
	}, 'void', ['int', 'pointer', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'int']));
}

function Hook_Arad_MileageProcess_BuyMileageItem() {
	Interceptor.replace(ptr(0x819DD4e), new NativeCallback(function (thisPtr, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, src, a15) {
		let v15 = G_CDataManager();
		let Goods = CDataManager_FindGoods(v15, a3);
		if (!Goods)
			return 21;

		let item = 0;
		let v25 = { low: 0, high: 0 }; // 定义一个对象来存储两个整数值
		if (CCeraShopGoods_GetSubGroupIndex(Goods) !== 1) {
			let v17 = G_CDataManager();
			item = CDataManager_find_item(v17, a4);
			if (!item)
				return 21;
			CItem_GetPrice(item, v25.low); // 将第一个整数值存储在 low 属性中
			v25.high = a5; // 将第二个整数值存储在 high 属性中
		}

		if (CUser_GetMileage(a2) < a11)
			return 1005;

		let v41 = 0;
		let v40 = 0;
		let v39 = [];
		let SubGroupIndex = CCeraShopGoods_GetSubGroupIndex(Goods);
		switch (SubGroupIndex) {
			case 0:
				let CurCharacInvenW = CUserCharacInfo_getCurCharacInvenW(a2);
				let v45 = CInventory_AddAvatarItem(CurCharacInvenW, a4, a8, 0, a9, a10, src, 0, 0, 0);
				if (v45 >= 0) {
					CUser_SendUpdateItemList(a2, 1, 1, v45);
				} else {
					let s = RDARScriptStringManager_findString(g_scriptStringManager_, 4, "game_server_msg_104", 0);
					WongWork_CMailBoxHelper_ReqDBSendNewAvatarMailCashShop(a2, CUserCharacInfo_getCurCharacNo(a2), a4, a8, a9, a10, src, s, strlen(s), v23);
				}
				break;
			case 1:
				WongWork_CCeraShop__processCoin(thisPtr, a2, a5, 1);
				break;
			case 2:
			case 7:
			case 9:
				WongWork_CCeraShop__processItem(thisPtr, a2, v25.low, v25.high, a6, a7, a8, a9, a10, a11, a12, a13, src, a15);
				break;
			case 3:
				let ExpirationDate = CItem_getExpirationDate(item);
				let UsablePeriod = CItem_getUsablePeriod(item);
				WongWork_CCeraShop__processCreature(thisPtr, a2, v25.low, v25.high, a6, a7, a8, a9, a10, a11, a12, a13, src, a15, v41, v40, 1, UsablePeriod, ExpirationDate);
				break;
			default:
				break;
		}

		if (!v40) {
			Arad_MileageProcess_BuySuccess(thisPtr, a2, a3, a5, v41, a11, a12, a13, v39);
			ItemVendingMachine_BillingRecord(thisPtr, a2, a3, SubGroupIndex, a11, src, "mileage item", a5, 0, 0);
		}

		return v40;
	}, 'int', ['pointer', 'pointer', 'int', 'uint', 'ushort', 'int', 'int', 'int', 'char', 'char', 'int', 'int', 'int', 'pointer', 'pointer']));
}





/*修复代币券会导致积分增加的BUG */
function FixCeraPointADD() {
	Memory.protect(ptr('0x08179043'), 1, 'rwx');
	Memory.writeByteArray(ptr('0x08179043'), [0xB8]);
	Memory.protect(ptr('0x0817904E'), 1, 'rwx');
	Memory.writeByteArray(ptr('0x0817904E'), [0xAD]);
}

//练习模式修复
function FixPracticemode() {
	let fixptr = ptr(0x81C820A);
	Memory.protect(fixptr, 6, 'rwx');
	Memory.writeByteArray(fixptr, [0xE9, 0xC6, 0x0, 0x0, 0x0, 0x90]);
}



// 购买记录新增
function purchase_record_filing_insert(accountId, itemId, cumulativeQuantity) {
	if (cumulativeQuantity == 0) {
		api_MySQL_exec(mysql_frida, "insert INTO gift_pack_return_award (account_id, item_id, cumulative_quantity) VALUES (" + accountId + "," + itemId + "," + cumulativeQuantity + ")");
	}
}


// 购买记录修改
function purchase_record_filing_update(accountId, itemId, cumulativeQuantity) {
	api_MySQL_exec(mysql_frida, "REPLACE INTO gift_pack_return_award (account_id, item_id, cumulative_quantity) VALUES (" + accountId + "," + itemId + "," + cumulativeQuantity + ")");
}

// 从数据库载入账号购买记录
function load_purchase_records_from_the_database(accountId) {
	if (api_MySQL_exec(mysql_frida, "select cumulative_quantity from gift_pack_return_award where account_id = " + accountId + ";")) {
		if (MySQL_get_n_rows(mysql_frida) == 1) {
			MySQL_fetch(mysql_frida);
			return api_MySQL_get_str(mysql_frida, 0);
		} else {
			return 0;
		}
	} else {
		return 0;
	}
}

/**
 * 多买多送
 *
 * @param user
 * @param account_id 账号ID
 * @param item_id 道具ID
 * @param item_cnt 数量
 */
function gift_pack_return_award(user, account_id, item_id, item_cnt) {
	var playerName = api_CUserCharacInfo_getCurCharacName(user);
	const cumulativeQuantity = load_purchase_records_from_the_database(account_id);

	if (cumulativeQuantity == 0) {
		purchase_record_filing_insert(account_id, item_id, cumulativeQuantity)
	}

	const quantity = load_purchase_records_from_the_database(account_id);
	const a = parseInt(item_cnt);
	const b = parseInt(quantity);
	const number = a + b;

	const charac_no = CUserCharacInfo_getCurCharacNo(user);
	const itemName = api_CItem_GetItemName(item_id);

	if (8386 == item_id) {
		purchase_record_filing_update(account_id, item_id, number);

		if (1 == number) {
			const item_list = [
				[3037, 1]
			];
			api_WongWork_CMailBoxHelper_ReqDBSendNewSystemMultiMail(charac_no, "DNF管理员", "DNF台服运营商不会已任何形式索要你的用户名密码请你不要邮寄关于您账号密码的任何信息!", 0, item_list);
			api_GameWorld_SendNotiPacketMessage("这是" + playerName + "玩家其账号购买的第：<" + number + ">套[" + itemName + "]装扮奖励XX已发送至其当前购买角色的邮箱!", 14);
		}

		if (3 == number) {
			const item_list = [
				[3037, 2]
			];
			api_WongWork_CMailBoxHelper_ReqDBSendNewSystemMultiMail(charac_no, "GM台服官方邮件", "DNF台服运营商不会已任何形式索要你的用户名密码请你不要邮寄关于您账号密码的任何信息!", 0, item_list);
			api_GameWorld_SendNotiPacketMessage("这是" + playerName + "玩家其账号购买的第：<" + number + ">套[" + itemName + "]装扮奖励XX已发送至其当前购买角色的邮箱!", 14);
		}

		if (5 == number) {
			const item_list = [
				[3037, 5]
			];
			api_WongWork_CMailBoxHelper_ReqDBSendNewSystemMultiMail(charac_no, "GM台服官方邮件", "DNF台服运营商不会已任何形式索要你的用户名密码请你不要邮寄关于您账号密码的任何信息!", 0, item_list);
			api_GameWorld_SendNotiPacketMessage("这是" + playerName + "玩家其账号购买的第：<" + number + ">套[" + itemName + "]装扮奖励XX已发送至其当前购买角色的邮箱!", 14);
		}
	}
}


//------------------------------------史诗数量竞赛--------------------------------------------------
function start_events() {
	var date = new Date();
	date = new Date(date.setHours(date.getHours() + 0));

	var hour = date.getHours();
	var minute = date.getMinutes();
	var second = date.getSeconds();

	var currentTime = date.getTime();
	var nextTime = 60000 - currentTime % 60000;
	api_scheduleOnMainThread_delay(start_events, null, nextTime)

	console.log(hour + ":" + minute + ":" + second);
	//在这里修改开始时间
	if (hour == 20 && minute == 0 && second == 0) {
		//史诗大比拼
		console.log("start_events: epicSumRask");
		epicSumRask();
	}
	if (hour == 20 && minute == 1 && second == 0) {
		//史诗大比拼
		console.log("start_events: epicOnceRask");
		epicOnceRask();
	}
}
//------------------------------------史诗数量竞赛开始--------------------------------------------------
function epicSumRask() {
	//3秒后开始
	api_scheduleOnMainThread_delay(startEpicSumRask, null, 3000);
	//启动定时任务1小时后进行数量结算
	api_scheduleOnMainThread_delay(endEpicRask, null, 3600000);
}

//是否开启
var epicRaskFlag = false;

//记录史诗数据
var epicRaskRcord = {}

//记录史诗比拼类型
var epicRaskType = '';

//记录本次的史诗掉落
function writeEpicNum(user, num) {
	if (epicRaskFlag) {
		if (epicRaskType == 'sum') {
			//总数竞赛
			var userName = api_CUserCharacInfo_getCurCharacName(user);
			var charNo = CUserCharacInfo_getCurCharacNo(user);
			var epicRask = epicRaskRcord[charNo];
			var nowNum = 0;
			if (epicRask == undefined || epicRask == null) {
				epicRask = {};
				epicRask['charNo'] = charNo;
				epicRask['userName'] = userName;
				epicRask['nowNum'] = 0;
			}
			nowNum = epicRask['nowNum'];
			nowNum = nowNum + num;
			epicRask['nowNum'] = nowNum;
			epicRaskRcord[charNo] = epicRask;
			api_CUser_SendNotiPacketMessage(user, "史诗大比拼进行中，您当前史诗总数【" + nowNum + "】个", 6);
		} else if (epicRaskType == 'once') {
			//单次最多竞赛
			var userName = api_CUserCharacInfo_getCurCharacName(user);
			var charNo = CUserCharacInfo_getCurCharacNo(user);
			var epicRask = epicRaskRcord[charNo];
			var nowNum = 0;
			if (epicRask == undefined || epicRask == null) {
				epicRask = {};
				epicRask['charNo'] = charNo;
				epicRask['userName'] = userName;
				epicRask['nowNum'] = 0;
			}
			nowNum = epicRask['nowNum'];
			if (num > nowNum) {
				epicRask['nowNum'] = num;
				epicRaskRcord[charNo] = epicRask;
			}
			var nums = epicRask['nowNum'];
			api_CUser_SendNotiPacketMessage(user, "史诗大比拼进行中，您当前单次深渊最多史诗个数为【" + nums + "】个", 6);
		}
	}
}

//开始史诗竞赛
function startEpicSumRask() {
	epicRaskFlag = true;
	epicRaskType = 'sum';
	//播报开始
	api_GameWorld_SendNotiPacketMessage('史诗大比拼开始啦！', 14);
	api_GameWorld_SendNotiPacketMessage('接下来的1个小时时间内，获得史诗个数最多的前三名可以获得盲盒奖励哦，大家加油吧！', 14);
	//清空记录
	epicRaskRcord = {}
	//清空数据库
	api_MySQL_exec(mysql_frida, "delete from frida.epic_rask;");
}


//结束史诗竞赛
function endEpicRask() {
	epicRaskFlag = false;
	//数据入库
	for (var key in epicRaskRcord) {
		var epicRask = epicRaskRcord[key];
		var charNo = epicRask['charNo'];
		var userName = epicRask['userName'];
		var nowNum = epicRask['nowNum'];
		api_MySQL_exec(mysql_frida, "insert into frida.epic_rask(char_no,char_name,epic_num) value (" + charNo + ",'" + userName + "'," + nowNum + ");");
	}
	api_GameWorld_SendNotiPacketMessage('史诗大比拼时间到，开始进行奖励计算！', 14);
	//发放奖励
	var mysql_t = "select char_no,char_name,epic_num from frida.epic_rask order by epic_num desc limit 3;";
	if (api_MySQL_exec(mysql_frida, mysql_t)) {
		var n = MySQL_get_n_rows(mysql_frida);
		if (n == 0) {
			api_GameWorld_SendNotiPacketMessage('非常可惜无人获得奖励！', 14);
		} else {
			for (var i = 0; i < n; i++) {
				MySQL_fetch(mysql_frida);
				var charNo = api_MySQL_get_int(mysql_frida, 0);
				var userName = api_MySQL_get_str(mysql_frida, 1);
				var nowNum = api_MySQL_get_int(mysql_frida, 2);
				if (i == 0) {
					//第一名
					api_GameWorld_SendNotiPacketMessage(' - 玩家【' + userName + '】获得第一名，史诗数量' + nowNum + "个", 14);
					var reward_item_list = [];
					reward_item_list.push([8068, 20]);
					api_WongWork_CMailBoxHelper_ReqDBSendNewSystemMultiMail(charNo, "史诗大比拼", "恭喜您，您是史诗大比拼第一名！", 0, reward_item_list);
				} else if (i == 1) {
					//第二名
					api_GameWorld_SendNotiPacketMessage(' - 玩家【' + userName + '】获得第二名，史诗数量' + nowNum + "个", 14);
					var reward_item_list = [];
					reward_item_list.push([8068, 15]);
					api_WongWork_CMailBoxHelper_ReqDBSendNewSystemMultiMail(charNo, "史诗大比拼", "恭喜您，您是史诗大比拼第一名！", 0, reward_item_list);
				} else if (i == 2) {
					//第三名
					api_GameWorld_SendNotiPacketMessage(' - 玩家【' + userName + '】获得第三名，史诗数量' + nowNum + "个", 14);
					var reward_item_list = [];
					reward_item_list.push([8068, 10]);
					api_WongWork_CMailBoxHelper_ReqDBSendNewSystemMultiMail(charNo, "史诗大比拼", "恭喜您，您是史诗大比拼第一名！", 0, reward_item_list);
				}
			}
			api_GameWorld_SendNotiPacketMessage('史诗大比拼奖励已发放，大家玩的开心！', 14);
		}
	}
}


//------------------------------------史诗数量竞赛结束--------------------------------------------------

//------------------------------------史诗单次数量竞赛开始--------------------------------------------------
function epicOnceRask() {
	//3秒后开始
	api_scheduleOnMainThread_delay(startEpicOnceRask, null, 3000);
	//启动定时任务1小时后进行数量结算
	api_scheduleOnMainThread_delay(endEpicRask, null, 3600000);
}

//开始史诗竞赛
function startEpicOnceRask() {
	epicRaskFlag = true;
	epicRaskType = 'once';
	//播报开始
	api_GameWorld_SendNotiPacketMessage('史诗大比拼开始啦！', 14);
	api_GameWorld_SendNotiPacketMessage('接下来的1个小时时间内，单次深渊获得史诗个数最多的前三名（个数相同随机）可以获得盲盒奖励哦，大家加油吧！', 14);
	//清空记录
	epicRaskRcord = {}
	//清空数据库
	api_MySQL_exec(mysql_frida, "delete from frida.epic_rask;");
}

//------------------------------------史诗单次数量竞赛结束--------------------------------------------------


//--------------------------------------副本抽奖-开始---------------------------------------------------

function send_dungeon_luck_reward() {
	var date = new Date();
	date = new Date(date.setHours(date.getHours() + 0));     //转换到本地时间

	var hour = date.getHours();
	var minute = date.getMinutes();
	var second = date.getSeconds();
	var currentTime = date.getTime();
	var nextTime = 60000 - currentTime % 60000;
	api_scheduleOnMainThread_delay(send_dungeon_luck_reward, null, nextTime)

	if (hour == 15 && minute == 0 && second == 0) {
		console.log(hour + ":" + minute + ":" + second);
		//获取昨日全服总计抽奖次数
		var lucks_all = get_dungeon_lucks_all_1();
		var reward_all = lucks_all * 10000;
		//获取昨日抽奖名单
		var date_t = get_time_stamp_1();
		var mysql_t = "select charac_no from dungeon_lucks where luck_date='" + date_t + "';";
		if (api_MySQL_exec(mysql_frida, mysql_t)) {
			var charac_arr = [];
			var n = MySQL_get_n_rows(mysql_frida);
			if (n == 0) {
				api_GameWorld_SendNotiPacketMessage("昨日全服抽奖次数为0", 14);
			} else {
				for (var k = 0; k < n; k++) {
					MySQL_fetch(mysql_frida);
					charac_arr.push(api_MySQL_get_int(mysql_frida, 0));
				}
				console.log("charac_arr: " + charac_arr);
				//默认抽取5个玩家
				var j = 5;
				if (n < 5) {
					//如果参与抽奖的玩家数量不足5个，则按玩家人数抽奖
					j = n;
				}
				var bili = [0.4, 0.25, 0.1, 0.08, 0.02];
				var reward_name = ['一等奖', '二等奖', '三等奖', '四等奖', '五等奖'];
				for (var i = 0; i < j; i++) {
					var cera_amounts = reward_all * bili[i];
					var randomIndex = Math.floor(Math.random() * j);
					var charac_no = charac_arr[randomIndex];
					var account_id = get_acc_id_by_char_no(charac_no);
					var user = GameWorld_find_user_from_world_byaccid(G_GameWorld(), parseInt(account_id));

					api_recharge_cash_cera(user, parseInt(cera_amounts));
					api_GameWorld_SendNotiPacketMessage("恭喜玩家[" + api_get_charac_name_by_charac_no(charac_no) + " ]在昨日副本抽奖中抽中了" + reward_name[i] + "，\n获得了：" + cera_amounts + "点券", 14);
					charac_arr = filetr_diy(charac_arr, charac_no);
				}
			}
		}
	}
}

function get_acc_id_by_char_no(charac_no) {

	var mysql_t = "select m_id from charac_info where charac_no=" + charac_no + ";";
	if (api_MySQL_exec(mysql_taiwan_cain, mysql_t)) {
		var n = MySQL_get_n_rows(mysql_taiwan_cain);
		if (n == 0) {
			return -1;
		} else {
			MySQL_fetch(mysql_taiwan_cain);
			return api_MySQL_get_int(mysql_taiwan_cain, 0);
		}
	}
}

function get_time_stamp_1() {
	var date = new Date();
	date = new Date(date.setHours(date.getHours() - 24));     //转换到本地时间
	var year = date.getFullYear().toString();
	var month = (date.getMonth() + 1).toString();
	var day = date.getDate().toString();
	return month + "-" + day;
}

//删除数组中所有指定的值
function filetr_diy(arr, a) {
	// let arr = [1, 1, 2, 3, 4, 5, 4, 4, 3, 2, 1, 1, 1, 2, 2];
	for (var i = arr.length - 1; i >= 0; i--) {
		if (arr[i] === a) {
			arr.splice(i, 1);
		}
	}
	return arr;
}

//查询今日当前角色抽奖次数
function get_dungeon_lucks(user) {
	var charac_no = CUserCharacInfo_getCurCharacNo(user);
	var date_t = get_time_stamp();
	var mysql_t = "select count(*) from dungeon_lucks where charac_no=" + charac_no + " and luck_date='" + date_t + "';";
	if (api_MySQL_exec(mysql_frida, mysql_t)) {
		var n = MySQL_get_n_rows(mysql_frida);
		// console.log("n:"+n);
		if (n == 0) {
			return 0;
		} else {
			MySQL_fetch(mysql_frida);
			return api_MySQL_get_int(mysql_frida, 0);
		}
	}
}

//查询今日所有角色抽奖次数
function get_dungeon_lucks_all() {
	var date_t = get_time_stamp();
	var mysql_t = "select count(*) from dungeon_lucks where luck_date='" + date_t + "';";
	if (api_MySQL_exec(mysql_frida, mysql_t)) {
		var n = MySQL_get_n_rows(mysql_frida);
		// console.log("n:"+n);
		if (n == 0) {
			return 0;
		} else {
			MySQL_fetch(mysql_frida);
			return api_MySQL_get_int(mysql_frida, 0);
		}
	}
}

//查询昨日所有角色抽奖次数
function get_dungeon_lucks_all_1() {
	var date_t = get_time_stamp_1();
	var mysql_t = "select count(*) from dungeon_lucks where luck_date='" + date_t + "';";
	if (api_MySQL_exec(mysql_frida, mysql_t)) {
		var n = MySQL_get_n_rows(mysql_frida);
		// console.log("n:"+n);
		if (n == 0) {
			return 0;
		} else {
			MySQL_fetch(mysql_frida);
			return api_MySQL_get_int(mysql_frida, 0);
		}
	}
}

//获取昨天的日期
function get_time_stamp() {
	var date = new Date();
	date = new Date(date.setHours(date.getHours() + 0));     //转换到本地时间
	var year = date.getFullYear().toString();
	var month = (date.getMonth() + 1).toString();
	var day = date.getDate().toString();
	return month + "-" + day;
}

//获取昨天的日期
function get_time_stamp_1() {
	var date = new Date();
	date = new Date(date.setHours(date.getHours() - 24));     //转换到本地时间
	var year = date.getFullYear().toString();
	var month = (date.getMonth() + 1).toString();
	var day = date.getDate().toString();
	return month + "-" + day;
}

//根据角色id查询角色名
function api_get_charac_name_by_charac_no(charac_no) {
	//从数据库中查询角色名
	if (api_MySQL_exec(mysql_taiwan_cain, "select charac_name from charac_info where charac_no=" + charac_no + ";")) {
		if (MySQL_get_n_rows(mysql_taiwan_cain) == 1) {
			if (MySQL_fetch(mysql_taiwan_cain)) {
				var charac_name = api_MySQL_get_str(mysql_taiwan_cain, 0);
				return charac_name;
			}
		}
	}
	return charac_no.toString();
}

function broadcast_dungeon_lucks(user, dgn_id) {
	var lucks = get_dungeon_lucks(user);
	var lucks_all = get_dungeon_lucks_all();
	var user_name = api_CUserCharacInfo_getCurCharacName(user);
	var str_send = "今日全服所有角色抽奖次数总计为： " + lucks_all + "次";
	api_CUser_SendNotiPacketMessage(user, str_send, 6);
	str_send = "当前角色[" + user_name + "]今日的抽奖次数为： " + lucks + "次";
	api_CUser_SendNotiPacketMessage(user, str_send, 7);

	var reward_all = lucks_all * 10000;
	api_GameWorld_SendNotiPacketMessage("恭喜[" + user_name + "]闯入了[" + api_CDungeon_getDungeonName(dgn_id) + "]\n龙魂秘境奖池金额已累积到： " + reward_all + "点券\n每晚12点进行抽奖", 14);

	api_GameWorld_SendNotiPacketMessage("             一等奖奖励： " + reward_all * 0.4 + "点券\n          二等奖奖励： " + reward_all * 0.25 + "点券\n          三等奖奖励： " + reward_all * 0.1 + "点券\n          四等奖奖励： " + reward_all * 0.08 + "点券\n          五等奖奖励： " + reward_all * 0.02 + "点券\n", 14);
}


function Add_lucky_draw(user, dgn_id) {
	var charac_no = CUserCharacInfo_getCurCharacNo(user);
	var date_t = get_time_stamp();
	if (dgn_id == 3500) {
		var mysql_t = "insert into dungeon_lucks(charac_no, luck_date) values(" + charac_no + ", '" + date_t + "');";
		api_MySQL_exec(mysql_frida, mysql_t)
	} else {
		var n = 5;
		if (dgn_id == 3502) {
			n = 10;
		}
		for (var i = 0; i < n; i++) {
			var mysql_t = "insert into dungeon_lucks(charac_no, luck_date) values(" + charac_no + ", '" + date_t + "');";
			api_MySQL_exec(mysql_frida, mysql_t)
		}
	}
	broadcast_dungeon_lucks(user, dgn_id);
	// console.log(mysql_t);
}

//--------------------------------------副本抽奖-结束---------------------------------------------------

/**-------------------------------------------------------保底抽奖--------------------------------------------**/
var prizes = [];
var super_reward = [];
var max_time_list = [];
/**-------------------------------------------------------保底抽奖开始--------------------------------------------**/
function init_chouj_db() {
	prizes = [
		{ item_id: 490009337, item_num: 1, item_weight: 1000, is_broadcast: 0, is_super_reward: 0 },//赛丽亚的金币----490009337	
		{ item_id: 3330, item_num: 50, item_weight: 800, is_broadcast: 0, is_super_reward: 0 },//深渊派对邀请函
		{ item_id: 3171, item_num: 50, item_weight: 800, is_broadcast: 0, is_super_reward: 0 },//炉岩炭
		{ item_id: 3326, item_num: 50, item_weight: 800, is_broadcast: 0, is_super_reward: 0 },//强烈的气息
		{ item_id: 3242, item_num: 10, item_weight: 800, is_broadcast: 0, is_super_reward: 0 },//矛盾的结晶体
		{ item_id: 3311, item_num: 10, item_weight: 800, is_broadcast: 0, is_super_reward: 0 },//异次元碎片
		{ item_id: 3037, item_num: 100, item_weight: 800, is_broadcast: 0, is_super_reward: 0 },//无色小晶块----3037
		{ item_id: 3285, item_num: 50, item_weight: 800, is_broadcast: 0, is_super_reward: 0 },//透明的宇宙灵魂----3285
		{ item_id: 2675818, item_num: 1, item_weight: 1000, is_broadcast: 0, is_super_reward: 0 }, //时装潜能属性转换器	
		{ item_id: 10000541, item_num: 1, item_weight: 500, is_broadcast: 0, is_super_reward: 0 }, //魔界抗疲劳秘药30点
		{ item_id: 15, item_num: 10, item_weight: 500, is_broadcast: 0, is_super_reward: 0 },      //装备品级调整箱----15
		{ item_id: 14, item_num: 2, item_weight: 500, is_broadcast: 0, is_super_reward: 0 },       //黄金蜜蜡----14
		{ item_id: 2600025, item_num: 1, item_weight: 500, is_broadcast: 0, is_super_reward: 0 },  //强化秘药----2600025
		{ item_id: 2600022, item_num: 5, item_weight: 500, is_broadcast: 0, is_super_reward: 0 },  //霸体护甲药水----2600022
		{ item_id: 2600656, item_num: 5, item_weight: 500, is_broadcast: 0, is_super_reward: 0 },  //斗神之吼秘药----2600656
		{ item_id: 3340, item_num: 1, item_weight: 200, is_broadcast: 0, is_super_reward: 0 },     //元宝----3340			
		{ item_id: 69000335, item_num: 1, item_weight: 300, is_broadcast: 0, is_super_reward: 0 }, //+10 装备强化券----69000335
		{ item_id: 202304582, item_num: 1, item_weight: 300, is_broadcast: 0, is_super_reward: 0 },//+11 装备强化券----202304582
		{ item_id: 202304589, item_num: 1, item_weight: 200, is_broadcast: 1, is_super_reward: 0 },//+12 钻石装备强化券----202304589
		{ item_id: 202304597, item_num: 1, item_weight: 200, is_broadcast: 1, is_super_reward: 0 },//+13 钻石装备强化券----202304597
		{ item_id: 202304637, item_num: 1, item_weight: 500, is_broadcast: 0, is_super_reward: 0 },//+9 钻石装备增幅券----202304637
		{ item_id: 202304621, item_num: 1, item_weight: 500, is_broadcast: 0, is_super_reward: 0 },//+7 钻石装备增幅券----202304621
		{ item_id: 202304636, item_num: 1, item_weight: 200, is_broadcast: 0, is_super_reward: 0 },//+9 翡翠装备增幅券----202304636
		{ item_id: 690000767, item_num: 1, item_weight: 1000, is_broadcast: 0, is_super_reward: 0 },//装备强化保护券----690000767
		{ item_id: 1286, item_num: 1, item_weight: 200, is_broadcast: 0, is_super_reward: 0 },//纯净的增幅书----1286
		{ item_id: 3209, item_num: 1, item_weight: 300, is_broadcast: 0, is_super_reward: 0 },//免疫胶囊
		{ item_id: 4083, item_num: 1, item_weight: 300, is_broadcast: 0, is_super_reward: 0 },//宁神符咒
		{ item_id: 4176, item_num: 1, item_weight: 300, is_broadcast: 0, is_super_reward: 0 },//神圣的刀刃
		{ item_id: 4343, item_num: 1, item_weight: 300, is_broadcast: 0, is_super_reward: 0 },//免疫魔法书
		{ item_id: 4421, item_num: 1, item_weight: 300, is_broadcast: 0, is_super_reward: 0 },//幽灵罗盘
		{ item_id: 4430, item_num: 1, item_weight: 300, is_broadcast: 0, is_super_reward: 0 },//赫尔德的庇佑
		{ item_id: 4791, item_num: 1, item_weight: 300, is_broadcast: 0, is_super_reward: 0 },//助力燃料
		{ item_id: 2600010, item_num: 1, item_weight: 500, is_broadcast: 1, is_super_reward: 0 },  //欧气药水
		{ item_id: 100011400, item_num: 1, item_weight: 50, is_broadcast: 1, is_super_reward: 0 },//暗夜使者随机符文礼盒
		{ item_id: 100011401, item_num: 1, item_weight: 50, is_broadcast: 1, is_super_reward: 0 },//格斗家随机符文礼盒
		{ item_id: 100011402, item_num: 1, item_weight: 50, is_broadcast: 1, is_super_reward: 0 },//鬼剑士随机符文礼盒
		{ item_id: 100011403, item_num: 1, item_weight: 50, is_broadcast: 1, is_super_reward: 0 },//魔法师随机符文礼盒
		{ item_id: 100011404, item_num: 1, item_weight: 50, is_broadcast: 1, is_super_reward: 0 },//神枪手随机符文礼盒
		{ item_id: 100011405, item_num: 1, item_weight: 50, is_broadcast: 1, is_super_reward: 0 },//圣职者随机符文礼盒
		{ item_id: 979848065, item_num: 1, item_weight: 20, is_broadcast: 1, is_super_reward: 0 },//第1期天空
		{ item_id: 979848066, item_num: 1, item_weight: 20, is_broadcast: 1, is_super_reward: 0 },//第2期天空
		{ item_id: 979848067, item_num: 1, item_weight: 20, is_broadcast: 1, is_super_reward: 0 },//第3期天空
		{ item_id: 979848068, item_num: 1, item_weight: 20, is_broadcast: 1, is_super_reward: 0 },//第4期天空
		{ item_id: 979848069, item_num: 1, item_weight: 20, is_broadcast: 1, is_super_reward: 0 },//第5期天空
		{ item_id: 979848070, item_num: 1, item_weight: 20, is_broadcast: 1, is_super_reward: 0 },//第6期天空
		{ item_id: 979848071, item_num: 1, item_weight: 20, is_broadcast: 1, is_super_reward: 0 },//第7期天空
		{ item_id: 979848072, item_num: 1, item_weight: 20, is_broadcast: 1, is_super_reward: 0 },//第8期天空
		{ item_id: 979848073, item_num: 1, item_weight: 20, is_broadcast: 1, is_super_reward: 0 },//第9期天空
		{ item_id: 979848074, item_num: 1, item_weight: 20, is_broadcast: 1, is_super_reward: 0 },//第10期天空
		{ item_id: 979848075, item_num: 1, item_weight: 20, is_broadcast: 1, is_super_reward: 0 },//第11期天空
		{ item_id: 979848076, item_num: 1, item_weight: 20, is_broadcast: 1, is_super_reward: 0 },//第12期天空
		{ item_id: 979848077, item_num: 1, item_weight: 20, is_broadcast: 1, is_super_reward: 0 },//第13期天空
		{ item_id: 979848078, item_num: 1, item_weight: 20, is_broadcast: 1, is_super_reward: 0 },//第14期天空
		{ item_id: 7576, item_num: 1, item_weight: 20, is_broadcast: 1, is_super_reward: 0 },//一次性装备跨界石
		{ item_id: 7994, item_num: 1, item_weight: 20, is_broadcast: 1, is_super_reward: 0 },//复古称号随机盲盒
		{ item_id: 7995, item_num: 1, item_weight: 20, is_broadcast: 1, is_super_reward: 0 },//复古光环随机盲盒
		{ item_id: 10008752, item_num: 1, item_weight: 15, is_broadcast: 1, is_super_reward: 0 },//三国龙临光环装扮礼盒
		{ item_id: 10008769, item_num: 1, item_weight: 15, is_broadcast: 1, is_super_reward: 0 },//三国名将宠物礼盒
		{ item_id: 10008772, item_num: 1, item_weight: 15, is_broadcast: 1, is_super_reward: 0 },//三国特别称号礼盒
		{ item_id: 2021458855, item_num: 1, item_weight: 100, is_broadcast: 1, is_super_reward: 0 },//+10装备增幅券随机礼盒
		{ item_id: 2021458856, item_num: 1, item_weight: 100, is_broadcast: 1, is_super_reward: 0 },//+11装备增幅券随机礼盒
		{ item_id: 2021458857, item_num: 1, item_weight: 100, is_broadcast: 1, is_super_reward: 0 },//+12装备增幅券随机礼盒
		{ item_id: 2021458858, item_num: 1, item_weight: 100, is_broadcast: 1, is_super_reward: 0 },//+13装备增幅券随机礼盒
		{ item_id: 8239, item_num: 1, item_weight: 500, is_broadcast: 1, is_super_reward: 0 },//+10~14装备保护卷
		{ item_id: 8240, item_num: 1, item_weight: 100, is_broadcast: 1, is_super_reward: 0 },//+10~15装备保护卷
		{ item_id: 10002598, item_num: 1, item_weight: 50, is_broadcast: 1, is_super_reward: 0 },//一印记随机宝珠
		{ item_id: 10002597, item_num: 1, item_weight: 40, is_broadcast: 1, is_super_reward: 0 },//二印记随机宝珠
		{ item_id: 10002599, item_num: 1, item_weight: 35, is_broadcast: 1, is_super_reward: 0 },//三印记随机宝珠
		{ item_id: 888888, item_num: 1, item_weight: 10, is_broadcast: 1, is_super_reward: 1 }//荣耀水晶
	];
	for (let i = 0; i < prizes.length; i++) {
		const element = prizes[i];
		if (element.is_super_reward == 1) {
			super_reward.push(
				{ item_id: element.item_id, item_num: element.item_num, is_broadcast: element.is_broadcast }
			);
		}
	}
}

function chouJ(user, type, stk_id) {
	// max_time: 保底次数
	var max_time = 200;

	// 抽奖道具名字
	var stkName = api_CItem_GetItemName(stk_id);
	var times = get_user_lucks(user, type);
	api_CUser_SendNotiPacketMessage(user, "当前角色 ： [ " + api_CUserCharacInfo_getCurCharacName(user) + " ]\n目前[" + stkName + "]的幸运值为：  " + times + "/" + max_time + " \n幸运值越高，获得稀有道具的概率越高\n累积" + max_time + "点幸运值后，必出【荣耀水晶】", 8);
	// 计算权重总和
	var totalWeight = 0;
	for (var i = 0; i < prizes.length; i++) {
		totalWeight += prizes[i].item_weight;
	}
	// 计算随机数
	var random = Math.floor(Math.random() * totalWeight);
	// 根据随机数计算中奖项
	var stepWeight = 0;

	var reward_item_list = [];
	var is_broadcast = 0;
	var itemName = "";
	var reward_pool = null;
	for (var i = 0; i < prizes.length; i++) {
		stepWeight += prizes[i].item_weight + times * max_time / 50;
		if (random < stepWeight) {
			reward_pool = prizes;
			if (prizes[i].is_super_reward == 1) {
				set_user_lucks(user, type, 0);
				api_CUser_SendNotiPacketMessage(user, "【恭喜获得荣耀水晶】\n已重置当前角色[ " + api_CUserCharacInfo_getCurCharacName(user) + " ]的幸运值", 8);

			} else if (times > max_time - 1) {
				var super_reward_lenth = super_reward.length;
				i = Math.floor(Math.random() * super_reward_lenth);
				set_user_lucks(user, type, 0);
				api_CUser_SendNotiPacketMessage(user, "【恭喜获得荣耀水晶】\n已重置当前角色[ " + api_CUserCharacInfo_getCurCharacName(user) + " ]的幸运值", 8);
				reward_pool = super_reward;
			}
			reward_item_list = [
				[reward_pool[i].item_id, reward_pool[i].item_num],
				[666666, 3],
				[666888, 3],
			];
			is_broadcast = reward_pool[i].is_broadcast;
			itemName = api_CItem_GetItemName(reward_pool[i].item_id);
			var itemNum = reward_pool[i].item_num;
			api_CUser_Add_Item1(user, reward_item_list);
			if (is_broadcast == 1) {
				//世界广播
				api_GameWorld_SendNotiPacketMessage('恭喜玩家： 【' + api_CUserCharacInfo_getCurCharacName(user) + '】 运气爆棚！\n从' + stkName + '中获得了 [ ' + itemName + ' ]*' + itemNum, 14);
			}
			break;
		}
	}
}

//获取道具名
var CItem_GetItemName = new NativeFunction(ptr(0x811ED82), 'pointer', ['pointer'], { "abi": "sysv" });

//获取道具名字
function api_CItem_GetItemName(item_id) {
	var citem = CDataManager_find_item(G_CDataManager(), item_id);
	if (!citem.isNull()) {
		return CItem_GetItemName(citem).readUtf8String(-1);
	}

	return item_id.toString();
}

//显示ui窗口
function api_CUser_Add_Item1(user, item_list) {
	for (var i = 0; i < item_list.length; i++) {
		api_CUser_AddItem(user, item_list[i][0], item_list[i][1]);//背包增加道具
	}
	SendItemWindowNotification(user, item_list);
}

function SendItemWindowNotification(user, item_list) {
	var packet_guard = api_PacketGuard_PacketGuard();
	InterfacePacketBuf_put_header(packet_guard, 1, 163); //协议 ENUM_NOTIPACKET_POWER_WAR_PROLONG
	InterfacePacketBuf_put_byte(packet_guard, 1); //默认1
	InterfacePacketBuf_put_short(packet_guard, 0); //槽位id 填入0即可
	InterfacePacketBuf_put_int(packet_guard, 0); //未知 0以上即可
	InterfacePacketBuf_put_short(packet_guard, item_list.length); //道具组数
	//写入道具代码和道具数量
	for (var i = 0; i < item_list.length; i++) {
		InterfacePacketBuf_put_int(packet_guard, item_list[i][0]); //道具代码
		InterfacePacketBuf_put_int(packet_guard, item_list[i][1]); //道具数量 装备/时装时 任意均可
	}
	InterfacePacketBuf_finalize(packet_guard, 1); //确定发包内容
	CUser_Send(user, packet_guard); //发包
	Destroy_PacketGuard_PacketGuard(packet_guard); //清空buff区
}
//显示ui窗口

//弹窗礼品包
//header_enum 协议编码
function SendItemWindowNotification1(user, item_list, header_enum) {
	var packet_guard = api_PacketGuard_PacketGuard();
	InterfacePacketBuf_put_header(packet_guard, 1, header_enum); //协议 ENUM_NOTIPACKET_POWER_WAR_PROLONG 163  600
	InterfacePacketBuf_put_byte(packet_guard, 1); //默认1
	InterfacePacketBuf_put_short(packet_guard, 0); //槽位id 填入0即可
	InterfacePacketBuf_put_int(packet_guard, 0); //未知 0以上即可
	InterfacePacketBuf_put_short(packet_guard, item_list.length); //道具组数
	//写入道具代码和道具数量
	for (var i = 0; i < item_list.length; i++) {
		api_CUser_AddItem(user, item_list[i][0], item_list[i][1])//背包增加道具
		InterfacePacketBuf_put_int(packet_guard, item_list[i][0]); //道具代码
		InterfacePacketBuf_put_int(packet_guard, item_list[i][1]); //道具数量 装备/时装时 任意均可
	}
	InterfacePacketBuf_finalize(packet_guard, 1); //确定发包内容
	CUser_Send(user, packet_guard); //发包
	Destroy_PacketGuard_PacketGuard(packet_guard); //清空buff区
}

function get_empty_nums(user) {
	var inven = CUserCharacInfo_getCurCharacInvenW(user);

}

function get_user_lucks(user, type) {
	var accId = CUserCharacInfo_getCurCharacNo(user);
	var ret_num = 0;
	var mysql_t = "select luck_points from frida.chouj_limit_acc where uid=" + accId + " and limit_type=" + type + ";";
	// console.log(mysql_t);
	if (api_MySQL_exec(mysql_frida, mysql_t)) {
		var n = MySQL_get_n_rows(mysql_frida);
		// console.log("n:"+n);
		if (n == 0) {
			console.log("if n==0");
			api_MySQL_exec(mysql_frida, "insert into frida.chouj_limit_acc values(" + accId + ",1,0);");
			api_MySQL_exec(mysql_frida, "insert into frida.chouj_limit_acc values(" + accId + ",2,0);");
		} else if (n == 1) {
			// console.log("if n==1");
			MySQL_fetch(mysql_frida);
			var luck_points = api_MySQL_get_int(mysql_frida, 0);
			ret_num = luck_points;
			// console.log("luck_points:"+luck_points);
		}
	}
	api_MySQL_exec(mysql_frida, "update frida.chouj_limit_acc set luck_points=luck_points+1 where uid=" + accId + " and limit_type=" + type + ";");
	return ret_num + 1;
}

function set_user_lucks(user, type, luck_points) {
	var accId = CUserCharacInfo_getCurCharacNo(user);
	api_MySQL_exec(mysql_frida, "update frida.chouj_limit_acc set luck_points=" + luck_points + " where uid=" + accId + " and limit_type=" + type + ";");

}

var Stream_operator_p = new NativeFunction(ptr(0x0861C796), 'int', ['pointer', 'int'], { "abi": "sysv" });

function getUserAccId(cargoRef) {
	if (cargoRef == 0) {
		return -1;
	}
	var userAddr = ptr(cargoRef.readU32());
	if (userAddr == 0) {
		return -1;
	}
	return CUser_get_acc_id(userAddr);
}

//世界广播(频道内公告)
function api_GameWorld_SendNotiPacketMessage(msg, msg_type) {
	var packet_guard = api_PacketGuard_PacketGuard();
	InterfacePacketBuf_put_header(packet_guard, 0, 12);
	InterfacePacketBuf_put_byte(packet_guard, msg_type);
	InterfacePacketBuf_put_short(packet_guard, 0);
	InterfacePacketBuf_put_byte(packet_guard, 0);
	api_InterfacePacketBuf_put_string(packet_guard, msg);
	InterfacePacketBuf_finalize(packet_guard, 1);
	GameWorld_send_all_with_state(G_GameWorld(), packet_guard, 3); //只给state >= 3 的玩家发公告
	Destroy_PacketGuard_PacketGuard(packet_guard);
}

/**-------------------------------------------------------保底抽奖结束--------------------------------------------**/

/**-------------------------------------------------------十连抽盒子--------------------------------------------**/

function rewaditem(user, stk_id) {
	var type = 1;
	var max_time = 200;
	var item_list = [];
	// var array = [];
	var totalWeight = 0;
	var superRewardName = api_CItem_GetItemName(888888);
	var stkName = api_CItem_GetItemName(stk_id);
	//普通奖励[道具ID,数量,是否公告]
	for (var i = 0; i < prizes.length; i++) {
		var element = prizes[i];
		totalWeight += prizes[i].item_weight;
		// array.push([element.item_id,element.item_num,element.is_broadcast]);
	}

	for (var j = 0; j < 10; j++) {
		console.log(j);
		var times = get_user_lucks(user, type);
		api_CUser_SendNotiPacketMessage(user, "当前角色 ： [ " + api_CUserCharacInfo_getCurCharacName(user) + " ]\n目前[" + stkName + "]的幸运值为：  " + times + "/" + max_time + " \n幸运值越高，获得稀有道具的概率越高\n累积" + max_time + "点幸运值后，必出【" + superRewardName + "】", 8);
		// 计算随机数
		var random = Math.floor(Math.random() * totalWeight);
		// 根据随机数计算中奖项
		var stepWeight = 0;
		var reward_pool = null;
		for (var i = 0; i < prizes.length; i++) {
			stepWeight += prizes[i].item_weight;
			if (random < stepWeight) {
				reward_pool = prizes;
				if (prizes[i].is_super_reward == 1) {
					set_user_lucks(user, type, 0);
					api_CUser_SendNotiPacketMessage(user, "【恭喜获得" + superRewardName + "】\n已重置当前角色[ " + api_CUserCharacInfo_getCurCharacName(user) + " ]的幸运值", 8);

				} else if (times > max_time - 1) {
					var super_reward_lenth = super_reward.length;
					i = Math.floor(Math.random() * super_reward_lenth);
					set_user_lucks(user, type, 0);
					api_CUser_SendNotiPacketMessage(user, "【恭喜获得" + superRewardName + "】\n已重置当前角色[ " + api_CUserCharacInfo_getCurCharacName(user) + " ]的幸运值", 8);
					reward_pool = super_reward;
				}
				item_list.push([reward_pool[i].item_id, reward_pool[i].item_num, reward_pool[i].is_broadcast]);
				if (reward_pool[i].is_broadcast == 1) {
					//世界广播
					var itemName = api_CItem_GetItemName(reward_pool[i].item_id);
					var itemNum = reward_pool[i].item_num;
					api_GameWorld_SendNotiPacketMessage('恭喜玩家： 【' + api_CUserCharacInfo_getCurCharacName(user) + '】 运气爆棚！\n从' + stkName + '中获得了 [ ' + itemName + ' ]*' + itemNum, 14);
				}
				break;
			}
		}
	}
	item_list.push([666666, 30, 0]);
	item_list.push([666888, 30, 0]);
	console.log("item_list");
	console.log(item_list);
	console.log("item_list");
	return item_list;
}

function SendCreateDnf(user, item_list) {
	var packet_guard = api_PacketGuard_PacketGuard();
	InterfacePacketBuf_put_header(packet_guard, 1, 600);
	InterfacePacketBuf_put_byte(packet_guard, 1);
	var charac_no = CUserCharacInfo_getCurCharacNo(user);
	var itemsToSend = [];
	var itemsToSend2 = [];
	InterfacePacketBuf_put_byte(packet_guard, item_list.length);

	var pos = item_list.length - 10;
	var specialItems = item_list.slice(-pos);
	item_list = item_list.slice(0, -pos);
	for (var i = 0; i < item_list.length; i++) {        //获取普通奖励
		InterfacePacketBuf_put_int(packet_guard, item_list[i][0]);  //道具代码
		InterfacePacketBuf_put_byte(packet_guard, item_list[i][1]);  //道具数量
		var daoju = api_CUser_AddItem(user, item_list[i][0], item_list[i][1]);
		if (daoju === -1) {
			itemsToSend.push([item_list[i][0], item_list[i][1]]);
		}
	}


	for (var j = 0; j < specialItems.length; j++) {         //获取特殊奖励
		InterfacePacketBuf_put_int(packet_guard, specialItems[j][0]);  //道具代码
		InterfacePacketBuf_put_byte(packet_guard, specialItems[j][1]);  //道具数量
		var daoju2 = api_CUser_AddItem(user, specialItems[j][0], specialItems[j][1]);
		if (daoju2 === -1) {
			itemsToSend2.push(specialItems[j][0], specialItems[j][1]);
		}

	}
	InterfacePacketBuf_finalize(packet_guard, 1);
	CUser_Send(user, packet_guard);
	Destroy_PacketGuard_PacketGuard(packet_guard);

	if (itemsToSend.length > 0) {
		api_WongWork_CMailBoxHelper_ReqDBSendNewSystemMultiMail(charac_no, 'GM', '你的背包已满,注意邮件查收！', 0, itemsToSend);
	}

	if (itemsToSend2.length > 0) {
		api_WongWork_CMailBoxHelper_ReqDBSendNewSystemMultiMail(charac_no, 'GM', '额外奖励邮件,请注意查收！', 0, itemsToSend);
	}
	itemsToSend.length = 0;
	itemsToSend2.length = 0;

}
/**-------------------------------------------------------结束--------------------------------------------**/

/**-------------------------------------------------------时装潜能开始--------------------------------------------**/
function get_random_int(min, max) {
	return Math.floor(Math.random() * (max - min)) + min;
}

function hidden_option() {
	//关闭系统分配属性
	Memory.protect(ptr(0x08509D49), 3, 'rwx');
	ptr(0x08509D49).writeByteArray([0xEB]);

	//下发时装潜能属性
	Memory.protect(ptr(0x08509D34), 3, 'rwx');
	ptr(0x08509D34).writeUShort(get_random_int(1, 64)); //属性(1 ~ 63)
}

function start_hidden_option() {
	Interceptor.attach(ptr(0x08509B9E), {
		onEnter: function (args) {
			hidden_option(); //go~~~
		},
		onLeave: function (retval) { }
	});

	Interceptor.attach(ptr(0x0817EDEC), {
		onEnter: function (args) { },
		onLeave: function (retval) {
			retval.replace(1); //return 1;
		}
	});
}

/**-------------------------------------------------------时装潜能结束--------------------------------------------**/

/**-------------------------------------------------------角色扩展开始--------------------------------------------**/
function KuoZ(user, item_id) {
	var accId = CUser_get_acc_id(user);
	var count = 0;
	if (api_MySQL_exec(mysql_d_taiwan, "select count from limit_create_character where m_id='" + accId + "';")) {
		if (MySQL_get_n_rows(mysql_d_taiwan) == 1) {
			if (MySQL_fetch(mysql_d_taiwan)) {
				count = api_MySQL_get_int(mysql_d_taiwan, 0);
			}
		}
	}
	if (count == 0) {
		api_CUser_SendNotiPacketMessage(user, "当前可创建角色数量达到上限，请先创建新的角色后再使用本道具！", 0);
		api_scheduleOnMainThread_delay(api_CUser_AddItem, [user, item_id, 1], 1);//道具返还间隔
	} else {

		api_MySQL_exec(mysql_frida, "update d_taiwan.limit_create_character set count=count-1 where count> 0 and m_id='" + accId + "';");
		api_CUser_SendNotiPacketMessage(user, "使用成功，可新建角色数量+1", 0);
		api_CUser_ReturnToSelectCharacList(user);
	}
}
/**-------------------------------------------------------角色扩展结束--------------------------------------------**/

/**-------------------------------------------------------装备解锁开始--------------------------------------------**/
function itemunLock(user, item_id) {
	var inven = CUserCharacInfo_getCurCharacInvenW(user);//获取背包
	var equ = CInventory_GetInvenRef(inven, INVENTORY_TYPE_ITEM, 9);//获取

	var Item_Id = Inven_Item_getKey(equ)
	if (!Item_Id) {
		send_windows_pack_233(user, "注意： 物品栏第一格没有装备！", 1);
		const reward_item_lists = [[item_id, 1]];
		const Money = 0;
		var charac_no = CUserCharacInfo_getCurCharacNo(user);
		api_scheduleOnMainThread_delay(api_CUser_AddItem, [user, item_id, 1], 1);//道具返还间隔
		return
	}
	var inItemData = CDataManager_find_item(G_CDataManager(), Item_Id); //获取pvf数据
	var inEqu_type = inItemData.add(141 * 4).readU32(); // 装备类型

	equ.add(20).writeU8(0)
	//CUser_SendUpdateItemList(user, 1, 0, 9);
	//CUser_RemoveItemLock(equ,user,INVENTORY_TYPE_ITEM, 9);//移除装备锁(道具，user，背包栏，背包槽)
	//CInventory_SendItemLockListInven(inven);//刷新锁子图标

	send_windows_pack_233(user, "清除装备锁成功, 请整理背包刷新状态！", 1);
}
/**-------------------------------------------------------装备解锁结束--------------------------------------------**/


/**********************************自定义翻牌奖励业务逻辑开始********************************************/
var CParty_GetMemberSlotNo = new NativeFunction(ptr(0x859AC7C), 'int', ['pointer', 'pointer'],
	{
		"abi": "sysv"
	});
//金币牌
const GodCardItemlist = {
	243: [[10093972, 1], [10093972, 2], [10093972, 3], [10093972, 4], [10093972, 5], [10093972, 6], [10093972, 7], [10093972, 8], [10093972, 9], [10093972, 10], [10093972, 11], [10093972, 12], [10093972, 13], [10093972, 14], [10093972, 15], [10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5]],
	244: [[10093972, 1], [10093972, 2], [10093972, 3], [10093972, 4], [10093972, 5], [10093972, 6], [10093972, 7], [10093972, 8], [10093972, 9], [10093972, 10], [10093972, 11], [10093972, 12], [10093972, 13], [10093972, 14], [10093972, 15], [10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5]],
	245: [[10093972, 1], [10093972, 2], [10093972, 3], [10093972, 4], [10093972, 5], [10093972, 6], [10093972, 7], [10093972, 8], [10093972, 9], [10093972, 10], [10093972, 11], [10093972, 12], [10093972, 13], [10093972, 14], [10093972, 15], [10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5]],
	246: [[10093972, 1], [10093972, 2], [10093972, 3], [10093972, 4], [10093972, 5], [10093972, 6], [10093972, 7], [10093972, 8], [10093972, 9], [10093972, 10], [10093972, 11], [10093972, 12], [10093972, 13], [10093972, 14], [10093972, 15], [10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5]],
	247: [[10093972, 1], [10093972, 2], [10093972, 3], [10093972, 4], [10093972, 5], [10093972, 6], [10093972, 7], [10093972, 8], [10093972, 9], [10093972, 10], [10093972, 11], [10093972, 12], [10093972, 13], [10093972, 14], [10093972, 15], [10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5]],
	220: [[10093972, 1], [10093972, 2], [10093972, 3], [10093972, 4], [10093972, 5], [10093972, 6], [10093972, 7], [10093972, 8], [10093972, 9], [10093972, 10], [10093972, 11], [10093972, 12], [10093972, 13], [10093972, 14], [10093972, 15], [10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5]],
	225: [[10093972, 1], [10093972, 2], [10093972, 3], [10093972, 4], [10093972, 5], [10093972, 6], [10093972, 7], [10093972, 8], [10093972, 9], [10093972, 10], [10093972, 11], [10093972, 12], [10093972, 13], [10093972, 14], [10093972, 15], [10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5]]
};

//普通牌
const PlainCardItemlist = {
	243: [[10093972, 1], [10093972, 2], [10093972, 3], [10093972, 4], [10093972, 5], [10093972, 6], [10093972, 7], [10093972, 8], [10093972, 9], [10093972, 10], [10093972, 11], [10093972, 12], [10093972, 13], [10093972, 14], [10093972, 15], [10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5]],
	244: [[10093972, 1], [10093972, 2], [10093972, 3], [10093972, 4], [10093972, 5], [10093972, 6], [10093972, 7], [10093972, 8], [10093972, 9], [10093972, 10], [10093972, 11], [10093972, 12], [10093972, 13], [10093972, 14], [10093972, 15], [10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5]],
	245: [[10093972, 1], [10093972, 2], [10093972, 3], [10093972, 4], [10093972, 5], [10093972, 6], [10093972, 7], [10093972, 8], [10093972, 9], [10093972, 10], [10093972, 11], [10093972, 12], [10093972, 13], [10093972, 14], [10093972, 15], [10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5]],
	246: [[10093972, 1], [10093972, 2], [10093972, 3], [10093972, 4], [10093972, 5], [10093972, 6], [10093972, 7], [10093972, 8], [10093972, 9], [10093972, 10], [10093972, 11], [10093972, 12], [10093972, 13], [10093972, 14], [10093972, 15], [10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5]],
	247: [[10093972, 1], [10093972, 2], [10093972, 3], [10093972, 4], [10093972, 5], [10093972, 6], [10093972, 7], [10093972, 8], [10093972, 9], [10093972, 10], [10093972, 11], [10093972, 12], [10093972, 13], [10093972, 14], [10093972, 15], [10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5]],
	220: [[100300002], [2023102077], [100200005], [100200013], [100200103], [190108101], [190108301], [190108401], [190108501], [20191127], [160929141], [100230004], [100230009], [100230123], [100230479], [160927006], [160929116], [160929136], [160929166], [20191117], [100220004], [100220009], [100220136], [160929101], [160929106], [160929126], [20191122], [160929156], [100210004], [100210012], [100210107], [160927026], [160927031], [160929151], [190118601], [190118701], [210483], [160929146], [100240004], [100240009], [100240060], [160929121], [160929131], [160929161], [20191132], [100050019], [100050050], [100050202], [190108102], [190108302], [190108402], [190108502], [20191128], [160929142], [100080004], [100080009], [100080137], [100080525], [160927007], [160929117], [160929137], [160929167], [20191118], [100070004], [100070009], [100070157], [160929102], [160929107], [160929127], [160929157], [20191123], [100060006], [100060016], [100060130], [160927027], [160927032], [160929152], [190118602], [190118702], [210482], [160929147], [100090004], [100090009], [100090073], [160929122], [160929132], [160929162], [20191133], [2023102051], [100100005], [100100012], [100100132], [190108103], [190108303], [190108403], [190108503], [20191129], [160929143], [100130004], [100130009], [100130131], [100130511], [160927008], [160929118], [160929138], [160929168], [20191119], [100120004], [100120009], [100120150], [160929103], [160929108], [160929128], [160929158], [20191124], [100110004], [100110011], [100110118], [160927028], [160927033], [160929153], [190118603], [190118703], [160929148], [210486], [100140004], [100140009], [100140068], [160929123], [160929133], [160929163], [20191134], [100320004], [2023102087], [2023102040], [100250005], [100250013], [100250108], [190108104], [190108304], [190108404], [190108504], [20191130], [160929144], [100280004], [100280009], [100280109], [100280474], [160927009], [160929119], [160929139], [160929169], [20191120], [100270004], [100270009], [100270133], [160929104], [160929109], [160929129], [160929159], [20191125], [100260004], [100260013], [100260109], [160927029], [160927034], [160929154], [190118604], [190118704], [160929149], [210484], [100290004], [100290009], [100290063], [160929124], [160929134], [160929164], [20191135], [100150005], [100150012], [100150123], [190108105], [190108305], [190108405], [190108505], [20191131], [160929145], [100180004], [100180009], [100180123], [100180479], [160927010], [160929120], [160929140], [160929170], [20191121], [100170004], [100170009], [100170141], [160929105], [160929110], [160929130], [20191126], [160929160], [100160004], [100160011], [100160085], [160927030], [160927035], [160929155], [190118605], [190118705], [210485], [160929150], [100190004], [100190009], [100190057], [160929125], [160929135], [160929165], [20191136], [100340040], [100340041], [100340042], [100340043], [100340044], [100340045], [100340046], [100340047], [100340048], [100340049], [100340050], [100340051], [100340052], [100340053], [100340054], [100340055], [100340056], [100340057], [100340058], [100340059], [100340060], [100340061], [100340062], [100340063], [100340064], [100340065], [100340066], [100340067], [100340068], [100340069], [100340070], [100340071], [100340072], [100340105], [100340106], [100340107], [100340108], [100340109], [100340110], [100340111], [100340112], [100340113], [100340114], [100340115], [100340116], [100340117], [100340118], [100340119], [100340120], [100340121], [100340122], [100340123], [100340124], [100340125], [100340126], [100340127], [100340128], [100340129], [100340130], [100340131], [100340132], [100340133], [100340134], [100340135], [100340136], [100340310], [100340311], [100340312], [100340313], [100340314], [100340315], [100340316], [100340317], [100340318], [100340319], [100340320], [100340321], [100340322], [100340327], [100340336], [100340347], [100310002], [102040024], [102020024], [102010090], [102000028], [102030023], [104010018], [104020019], [104040021], [104030021], [104000022], [106040020], [106020019], [106010021], [106000021], [106030022], [108030020], [108000021], [108010019], [108040019], [108020019], [101040019], [101030018], [101010021], [101020023], [101000004], [109000019], [109010018], [109020018], [100300079], [100300080], [100300081], [100300082], [100300083], [100300329], [100300330], [100300331], [100300333], [100300334], [100300497], [100300505], [100300506], [100300507], [100310804], [100310805], [100310806], [100310807], [100310813], [100310814], [100350107], [100350108], [100350109], [100350110], [100350111], [100350112], [100350696], [100350697], [100350698], [100350699], [100352608], [100352611], [100352612], [100352613], [100352614], [100352615], [100352616], [100352617], [100352618], [100352619], [370105101], [370325005], [370325015], [370325035], [370325045], [370325055], [370325065], [370326014], [370327012], [370418001], [370418011], [370419001], [370422001], [370423001], [370423011], [370426001], [370427001], [370428001], [370502001], [370502301], [370504001], [370727001], [370728001], [370730001], [100320084], [100320085], [100320086], [100320087], [100320088], [100320089], [100320090], [100320091], [100320618], [100320619], [100320620], [100320625], [100320626], [100322054], [100322055], [100322056], [100322057], [100322058], [100322059], [100322060], [100322061], [100322062], [100322063], [100322064], [100322065], [100322066], [100322067], [100322068], [100322069], [100322070], [100322071], [100340349], [100340350], [100340351], [100340352], [100340353], [100340354], [100340355], [100340356], [100341603], [100341604], [100341605], [100341606], [100341607], [100341608], [100341609], [100341610], [100341611], [100341612], [100341613], [100341614], [100341619], [100344252], [100344253], [100344254], [100344255], [100344256], [100344257], [100344258], [100344259], [100344260], [100344262], [370105102], [370325001], [370325011], [370325031], [370325041], [370325051], [370325061], [370326013], [370327011], [370418002], [370418012], [370419002], [370422002], [370423002], [370423012], [370426002], [370427002], [370428002], [370502002], [370502302], [370504002], [370727002], [370728002], [370730002], [100310072], [100310073], [100310074], [100310546], [100310547], [100310548], [100310553], [100310554], [100312195], [100312196], [100312198], [100312199], [100312200], [100312201], [100312202], [100312204], [100312205]],
	225: [[100300002], [2023102077], [100200005], [100200013], [100200103], [190108101], [190108301], [190108401], [190108501], [20191127], [160929141], [100230004], [100230009], [100230123], [100230479], [160927006], [160929116], [160929136], [160929166], [20191117], [100220004], [100220009], [100220136], [160929101], [160929106], [160929126], [20191122], [160929156], [100210004], [100210012], [100210107], [160927026], [160927031], [160929151], [190118601], [190118701], [210483], [160929146], [100240004], [100240009], [100240060], [160929121], [160929131], [160929161], [20191132], [100050019], [100050050], [100050202], [190108102], [190108302], [190108402], [190108502], [20191128], [160929142], [100080004], [100080009], [100080137], [100080525], [160927007], [160929117], [160929137], [160929167], [20191118], [100070004], [100070009], [100070157], [160929102], [160929107], [160929127], [160929157], [20191123], [100060006], [100060016], [100060130], [160927027], [160927032], [160929152], [190118602], [190118702], [210482], [160929147], [100090004], [100090009], [100090073], [160929122], [160929132], [160929162], [20191133], [2023102051], [100100005], [100100012], [100100132], [190108103], [190108303], [190108403], [190108503], [20191129], [160929143], [100130004], [100130009], [100130131], [100130511], [160927008], [160929118], [160929138], [160929168], [20191119], [100120004], [100120009], [100120150], [160929103], [160929108], [160929128], [160929158], [20191124], [100110004], [100110011], [100110118], [160927028], [160927033], [160929153], [190118603], [190118703], [160929148], [210486], [100140004], [100140009], [100140068], [160929123], [160929133], [160929163], [20191134], [100320004], [2023102087], [2023102040], [100250005], [100250013], [100250108], [190108104], [190108304], [190108404], [190108504], [20191130], [160929144], [100280004], [100280009], [100280109], [100280474], [160927009], [160929119], [160929139], [160929169], [20191120], [100270004], [100270009], [100270133], [160929104], [160929109], [160929129], [160929159], [20191125], [100260004], [100260013], [100260109], [160927029], [160927034], [160929154], [190118604], [190118704], [160929149], [210484], [100290004], [100290009], [100290063], [160929124], [160929134], [160929164], [20191135], [100150005], [100150012], [100150123], [190108105], [190108305], [190108405], [190108505], [20191131], [160929145], [100180004], [100180009], [100180123], [100180479], [160927010], [160929120], [160929140], [160929170], [20191121], [100170004], [100170009], [100170141], [160929105], [160929110], [160929130], [20191126], [160929160], [100160004], [100160011], [100160085], [160927030], [160927035], [160929155], [190118605], [190118705], [210485], [160929150], [100190004], [100190009], [100190057], [160929125], [160929135], [160929165], [20191136], [100340040], [100340041], [100340042], [100340043], [100340044], [100340045], [100340046], [100340047], [100340048], [100340049], [100340050], [100340051], [100340052], [100340053], [100340054], [100340055], [100340056], [100340057], [100340058], [100340059], [100340060], [100340061], [100340062], [100340063], [100340064], [100340065], [100340066], [100340067], [100340068], [100340069], [100340070], [100340071], [100340072], [100340105], [100340106], [100340107], [100340108], [100340109], [100340110], [100340111], [100340112], [100340113], [100340114], [100340115], [100340116], [100340117], [100340118], [100340119], [100340120], [100340121], [100340122], [100340123], [100340124], [100340125], [100340126], [100340127], [100340128], [100340129], [100340130], [100340131], [100340132], [100340133], [100340134], [100340135], [100340136], [100340310], [100340311], [100340312], [100340313], [100340314], [100340315], [100340316], [100340317], [100340318], [100340319], [100340320], [100340321], [100340322], [100340327], [100340336], [100340347], [100310002], [102040024], [102020024], [102010090], [102000028], [102030023], [104010018], [104020019], [104040021], [104030021], [104000022], [106040020], [106020019], [106010021], [106000021], [106030022], [108030020], [108000021], [108010019], [108040019], [108020019], [101040019], [101030018], [101010021], [101020023], [101000004], [109000019], [109010018], [109020018], [100300079], [100300080], [100300081], [100300082], [100300083], [100300329], [100300330], [100300331], [100300333], [100300334], [100300497], [100300505], [100300506], [100300507], [100310804], [100310805], [100310806], [100310807], [100310813], [100310814], [100350107], [100350108], [100350109], [100350110], [100350111], [100350112], [100350696], [100350697], [100350698], [100350699], [100352608], [100352611], [100352612], [100352613], [100352614], [100352615], [100352616], [100352617], [100352618], [100352619], [370105101], [370325005], [370325015], [370325035], [370325045], [370325055], [370325065], [370326014], [370327012], [370418001], [370418011], [370419001], [370422001], [370423001], [370423011], [370426001], [370427001], [370428001], [370502001], [370502301], [370504001], [370727001], [370728001], [370730001], [100320084], [100320085], [100320086], [100320087], [100320088], [100320089], [100320090], [100320091], [100320618], [100320619], [100320620], [100320625], [100320626], [100322054], [100322055], [100322056], [100322057], [100322058], [100322059], [100322060], [100322061], [100322062], [100322063], [100322064], [100322065], [100322066], [100322067], [100322068], [100322069], [100322070], [100322071], [100340349], [100340350], [100340351], [100340352], [100340353], [100340354], [100340355], [100340356], [100341603], [100341604], [100341605], [100341606], [100341607], [100341608], [100341609], [100341610], [100341611], [100341612], [100341613], [100341614], [100341619], [100344252], [100344253], [100344254], [100344255], [100344256], [100344257], [100344258], [100344259], [100344260], [100344262], [370105102], [370325001], [370325011], [370325031], [370325041], [370325051], [370325061], [370326013], [370327011], [370418002], [370418012], [370419002], [370422002], [370423002], [370423012], [370426002], [370427002], [370428002], [370502002], [370502302], [370504002], [370727002], [370728002], [370730002], [100310072], [100310073], [100310074], [100310546], [100310547], [100310548], [100310553], [100310554], [100312195], [100312196], [100312198], [100312199], [100312200], [100312201], [100312202], [100312204], [100312205]]
};

//黑钻牌
const VipCardItemlist = {
	243: [[10093972, 1], [10093972, 2], [10093972, 3], [10093972, 4], [10093972, 5], [10093972, 6], [10093972, 7], [10093972, 8], [10093972, 9], [10093972, 10], [10093972, 11], [10093972, 12], [10093972, 13], [10093972, 14], [10093972, 15], [10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5]],
	244: [[10093972, 1], [10093972, 2], [10093972, 3], [10093972, 4], [10093972, 5], [10093972, 6], [10093972, 7], [10093972, 8], [10093972, 9], [10093972, 10], [10093972, 11], [10093972, 12], [10093972, 13], [10093972, 14], [10093972, 15], [10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5]],
	245: [[10093972, 1], [10093972, 2], [10093972, 3], [10093972, 4], [10093972, 5], [10093972, 6], [10093972, 7], [10093972, 8], [10093972, 9], [10093972, 10], [10093972, 11], [10093972, 12], [10093972, 13], [10093972, 14], [10093972, 15], [10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5]],
	246: [[10093972, 1], [10093972, 2], [10093972, 3], [10093972, 4], [10093972, 5], [10093972, 6], [10093972, 7], [10093972, 8], [10093972, 9], [10093972, 10], [10093972, 11], [10093972, 12], [10093972, 13], [10093972, 14], [10093972, 15], [10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5]],
	247: [[10093972, 1], [10093972, 2], [10093972, 3], [10093972, 4], [10093972, 5], [10093972, 6], [10093972, 7], [10093972, 8], [10093972, 9], [10093972, 10], [10093972, 11], [10093972, 12], [10093972, 13], [10093972, 14], [10093972, 15], [10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5]],
	220: [[100300002], [2023102077], [100200005], [100200013], [100200103], [190108101], [190108301], [190108401], [190108501], [20191127], [160929141], [100230004], [100230009], [100230123], [100230479], [160927006], [160929116], [160929136], [160929166], [20191117], [100220004], [100220009], [100220136], [160929101], [160929106], [160929126], [20191122], [160929156], [100210004], [100210012], [100210107], [160927026], [160927031], [160929151], [190118601], [190118701], [210483], [160929146], [100240004], [100240009], [100240060], [160929121], [160929131], [160929161], [20191132], [100050019], [100050050], [100050202], [190108102], [190108302], [190108402], [190108502], [20191128], [160929142], [100080004], [100080009], [100080137], [100080525], [160927007], [160929117], [160929137], [160929167], [20191118], [100070004], [100070009], [100070157], [160929102], [160929107], [160929127], [160929157], [20191123], [100060006], [100060016], [100060130], [160927027], [160927032], [160929152], [190118602], [190118702], [210482], [160929147], [100090004], [100090009], [100090073], [160929122], [160929132], [160929162], [20191133], [2023102051], [100100005], [100100012], [100100132], [190108103], [190108303], [190108403], [190108503], [20191129], [160929143], [100130004], [100130009], [100130131], [100130511], [160927008], [160929118], [160929138], [160929168], [20191119], [100120004], [100120009], [100120150], [160929103], [160929108], [160929128], [160929158], [20191124], [100110004], [100110011], [100110118], [160927028], [160927033], [160929153], [190118603], [190118703], [160929148], [210486], [100140004], [100140009], [100140068], [160929123], [160929133], [160929163], [20191134], [100320004], [2023102087], [2023102040], [100250005], [100250013], [100250108], [190108104], [190108304], [190108404], [190108504], [20191130], [160929144], [100280004], [100280009], [100280109], [100280474], [160927009], [160929119], [160929139], [160929169], [20191120], [100270004], [100270009], [100270133], [160929104], [160929109], [160929129], [160929159], [20191125], [100260004], [100260013], [100260109], [160927029], [160927034], [160929154], [190118604], [190118704], [160929149], [210484], [100290004], [100290009], [100290063], [160929124], [160929134], [160929164], [20191135], [100150005], [100150012], [100150123], [190108105], [190108305], [190108405], [190108505], [20191131], [160929145], [100180004], [100180009], [100180123], [100180479], [160927010], [160929120], [160929140], [160929170], [20191121], [100170004], [100170009], [100170141], [160929105], [160929110], [160929130], [20191126], [160929160], [100160004], [100160011], [100160085], [160927030], [160927035], [160929155], [190118605], [190118705], [210485], [160929150], [100190004], [100190009], [100190057], [160929125], [160929135], [160929165], [20191136], [100340040], [100340041], [100340042], [100340043], [100340044], [100340045], [100340046], [100340047], [100340048], [100340049], [100340050], [100340051], [100340052], [100340053], [100340054], [100340055], [100340056], [100340057], [100340058], [100340059], [100340060], [100340061], [100340062], [100340063], [100340064], [100340065], [100340066], [100340067], [100340068], [100340069], [100340070], [100340071], [100340072], [100340105], [100340106], [100340107], [100340108], [100340109], [100340110], [100340111], [100340112], [100340113], [100340114], [100340115], [100340116], [100340117], [100340118], [100340119], [100340120], [100340121], [100340122], [100340123], [100340124], [100340125], [100340126], [100340127], [100340128], [100340129], [100340130], [100340131], [100340132], [100340133], [100340134], [100340135], [100340136], [100340310], [100340311], [100340312], [100340313], [100340314], [100340315], [100340316], [100340317], [100340318], [100340319], [100340320], [100340321], [100340322], [100340327], [100340336], [100340347], [100310002], [102040024], [102020024], [102010090], [102000028], [102030023], [104010018], [104020019], [104040021], [104030021], [104000022], [106040020], [106020019], [106010021], [106000021], [106030022], [108030020], [108000021], [108010019], [108040019], [108020019], [101040019], [101030018], [101010021], [101020023], [101000004], [109000019], [109010018], [109020018], [100300079], [100300080], [100300081], [100300082], [100300083], [100300329], [100300330], [100300331], [100300333], [100300334], [100300497], [100300505], [100300506], [100300507], [100310804], [100310805], [100310806], [100310807], [100310813], [100310814], [100350107], [100350108], [100350109], [100350110], [100350111], [100350112], [100350696], [100350697], [100350698], [100350699], [100352608], [100352611], [100352612], [100352613], [100352614], [100352615], [100352616], [100352617], [100352618], [100352619], [370105101], [370325005], [370325015], [370325035], [370325045], [370325055], [370325065], [370326014], [370327012], [370418001], [370418011], [370419001], [370422001], [370423001], [370423011], [370426001], [370427001], [370428001], [370502001], [370502301], [370504001], [370727001], [370728001], [370730001], [100320084], [100320085], [100320086], [100320087], [100320088], [100320089], [100320090], [100320091], [100320618], [100320619], [100320620], [100320625], [100320626], [100322054], [100322055], [100322056], [100322057], [100322058], [100322059], [100322060], [100322061], [100322062], [100322063], [100322064], [100322065], [100322066], [100322067], [100322068], [100322069], [100322070], [100322071], [100340349], [100340350], [100340351], [100340352], [100340353], [100340354], [100340355], [100340356], [100341603], [100341604], [100341605], [100341606], [100341607], [100341608], [100341609], [100341610], [100341611], [100341612], [100341613], [100341614], [100341619], [100344252], [100344253], [100344254], [100344255], [100344256], [100344257], [100344258], [100344259], [100344260], [100344262], [370105102], [370325001], [370325011], [370325031], [370325041], [370325051], [370325061], [370326013], [370327011], [370418002], [370418012], [370419002], [370422002], [370423002], [370423012], [370426002], [370427002], [370428002], [370502002], [370502302], [370504002], [370727002], [370728002], [370730002], [100310072], [100310073], [100310074], [100310546], [100310547], [100310548], [100310553], [100310554], [100312195], [100312196], [100312198], [100312199], [100312200], [100312201], [100312202], [100312204], [100312205]],
	225: [[100300002], [2023102077], [100200005], [100200013], [100200103], [190108101], [190108301], [190108401], [190108501], [20191127], [160929141], [100230004], [100230009], [100230123], [100230479], [160927006], [160929116], [160929136], [160929166], [20191117], [100220004], [100220009], [100220136], [160929101], [160929106], [160929126], [20191122], [160929156], [100210004], [100210012], [100210107], [160927026], [160927031], [160929151], [190118601], [190118701], [210483], [160929146], [100240004], [100240009], [100240060], [160929121], [160929131], [160929161], [20191132], [100050019], [100050050], [100050202], [190108102], [190108302], [190108402], [190108502], [20191128], [160929142], [100080004], [100080009], [100080137], [100080525], [160927007], [160929117], [160929137], [160929167], [20191118], [100070004], [100070009], [100070157], [160929102], [160929107], [160929127], [160929157], [20191123], [100060006], [100060016], [100060130], [160927027], [160927032], [160929152], [190118602], [190118702], [210482], [160929147], [100090004], [100090009], [100090073], [160929122], [160929132], [160929162], [20191133], [2023102051], [100100005], [100100012], [100100132], [190108103], [190108303], [190108403], [190108503], [20191129], [160929143], [100130004], [100130009], [100130131], [100130511], [160927008], [160929118], [160929138], [160929168], [20191119], [100120004], [100120009], [100120150], [160929103], [160929108], [160929128], [160929158], [20191124], [100110004], [100110011], [100110118], [160927028], [160927033], [160929153], [190118603], [190118703], [160929148], [210486], [100140004], [100140009], [100140068], [160929123], [160929133], [160929163], [20191134], [100320004], [2023102087], [2023102040], [100250005], [100250013], [100250108], [190108104], [190108304], [190108404], [190108504], [20191130], [160929144], [100280004], [100280009], [100280109], [100280474], [160927009], [160929119], [160929139], [160929169], [20191120], [100270004], [100270009], [100270133], [160929104], [160929109], [160929129], [160929159], [20191125], [100260004], [100260013], [100260109], [160927029], [160927034], [160929154], [190118604], [190118704], [160929149], [210484], [100290004], [100290009], [100290063], [160929124], [160929134], [160929164], [20191135], [100150005], [100150012], [100150123], [190108105], [190108305], [190108405], [190108505], [20191131], [160929145], [100180004], [100180009], [100180123], [100180479], [160927010], [160929120], [160929140], [160929170], [20191121], [100170004], [100170009], [100170141], [160929105], [160929110], [160929130], [20191126], [160929160], [100160004], [100160011], [100160085], [160927030], [160927035], [160929155], [190118605], [190118705], [210485], [160929150], [100190004], [100190009], [100190057], [160929125], [160929135], [160929165], [20191136], [100340040], [100340041], [100340042], [100340043], [100340044], [100340045], [100340046], [100340047], [100340048], [100340049], [100340050], [100340051], [100340052], [100340053], [100340054], [100340055], [100340056], [100340057], [100340058], [100340059], [100340060], [100340061], [100340062], [100340063], [100340064], [100340065], [100340066], [100340067], [100340068], [100340069], [100340070], [100340071], [100340072], [100340105], [100340106], [100340107], [100340108], [100340109], [100340110], [100340111], [100340112], [100340113], [100340114], [100340115], [100340116], [100340117], [100340118], [100340119], [100340120], [100340121], [100340122], [100340123], [100340124], [100340125], [100340126], [100340127], [100340128], [100340129], [100340130], [100340131], [100340132], [100340133], [100340134], [100340135], [100340136], [100340310], [100340311], [100340312], [100340313], [100340314], [100340315], [100340316], [100340317], [100340318], [100340319], [100340320], [100340321], [100340322], [100340327], [100340336], [100340347], [100310002], [102040024], [102020024], [102010090], [102000028], [102030023], [104010018], [104020019], [104040021], [104030021], [104000022], [106040020], [106020019], [106010021], [106000021], [106030022], [108030020], [108000021], [108010019], [108040019], [108020019], [101040019], [101030018], [101010021], [101020023], [101000004], [109000019], [109010018], [109020018], [100300079], [100300080], [100300081], [100300082], [100300083], [100300329], [100300330], [100300331], [100300333], [100300334], [100300497], [100300505], [100300506], [100300507], [100310804], [100310805], [100310806], [100310807], [100310813], [100310814], [100350107], [100350108], [100350109], [100350110], [100350111], [100350112], [100350696], [100350697], [100350698], [100350699], [100352608], [100352611], [100352612], [100352613], [100352614], [100352615], [100352616], [100352617], [100352618], [100352619], [370105101], [370325005], [370325015], [370325035], [370325045], [370325055], [370325065], [370326014], [370327012], [370418001], [370418011], [370419001], [370422001], [370423001], [370423011], [370426001], [370427001], [370428001], [370502001], [370502301], [370504001], [370727001], [370728001], [370730001], [100320084], [100320085], [100320086], [100320087], [100320088], [100320089], [100320090], [100320091], [100320618], [100320619], [100320620], [100320625], [100320626], [100322054], [100322055], [100322056], [100322057], [100322058], [100322059], [100322060], [100322061], [100322062], [100322063], [100322064], [100322065], [100322066], [100322067], [100322068], [100322069], [100322070], [100322071], [100340349], [100340350], [100340351], [100340352], [100340353], [100340354], [100340355], [100340356], [100341603], [100341604], [100341605], [100341606], [100341607], [100341608], [100341609], [100341610], [100341611], [100341612], [100341613], [100341614], [100341619], [100344252], [100344253], [100344254], [100344255], [100344256], [100344257], [100344258], [100344259], [100344260], [100344262], [370105102], [370325001], [370325011], [370325031], [370325041], [370325051], [370325061], [370326013], [370327011], [370418002], [370418012], [370419002], [370422002], [370423002], [370423012], [370426002], [370427002], [370428002], [370502002], [370502302], [370504002], [370727002], [370728002], [370730002], [100310072], [100310073], [100310074], [100310546], [100310547], [100310548], [100310553], [100310554], [100312195], [100312196], [100312198], [100312199], [100312200], [100312201], [100312202], [100312204], [100312205]]
};
//自定义特权普通牌子
const privilege_PlainCardItemlist = {
	//副本id: [[道具id, 数量], [道具id, 数量], ...]
	243: [[10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5], [10093974, 6], [10093974, 7], [10093974, 8], [10093974, 9], [10093974, 10], [10093974, 11], [10093974, 12], [10093974, 13], [10093974, 14], [10093974, 15]],
	244: [[10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5], [10093974, 6], [10093974, 7], [10093974, 8], [10093974, 9], [10093974, 10], [10093974, 11], [10093974, 12], [10093974, 13], [10093974, 14], [10093974, 15]],
	245: [[10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5], [10093974, 6], [10093974, 7], [10093974, 8], [10093974, 9], [10093974, 10], [10093974, 11], [10093974, 12], [10093974, 13], [10093974, 14], [10093974, 15]],
	246: [[10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5], [10093974, 6], [10093974, 7], [10093974, 8], [10093974, 9], [10093974, 10], [10093974, 11], [10093974, 12], [10093974, 13], [10093974, 14], [10093974, 15]],
	247: [[10093974, 1], [10093974, 2], [10093974, 3], [10093974, 4], [10093974, 5], [10093974, 6], [10093974, 7], [10093974, 8], [10093974, 9], [10093974, 10], [10093974, 11], [10093974, 12], [10093974, 13], [10093974, 14], [10093974, 15]]
};
/**
 * 调用方法：在初始函数 HOOK_CParty_SetCardNumber();
 * 自定义黄金卡片的爆率池
 */
function HOOK_CParty_SetCardNumber() {
	Interceptor.attach(ptr(0x85B415A),
		{
			onEnter: function (args) {
				var CParty = args[0];
				var user = args[1];
				var CardType = args[3].toInt32();
				var MemberSlotNo = CParty_GetMemberSlotNo(CParty, user); //队员序号
				//处理黄金卡
				if (CardType === 1) {
					var Dungeon_ID = CDungeon_get_index(CParty.add(812 * 4)); //取队伍副本ID
					if (!GodCardItemlist.hasOwnProperty(Dungeon_ID)) {
						return 0;
					}
					var Itemlist = GodCardItemlist[Dungeon_ID][get_rand_int(GodCardItemlist[Dungeon_ID].length)];
					var Item_id = Itemlist[0];
					var Item_cnt = Itemlist[1];
					var CurCharacInvenR = CUserCharacInfo_getCurCharacInvenR(user);
					var ItemType = CInventory_GetItemType(CurCharacInvenR, Item_id); //道具类型
					//消耗品 材料 副职业材料
					if (ItemType == 2 || ItemType == 3 || ItemType == 12) {
						CParty.add(122 * MemberSlotNo + 1965).writeU8(0);
						CParty.add(122 * MemberSlotNo + 1966).writeU8(ItemType); //背包索引
						CParty.add(122 * MemberSlotNo + 1967).writeU32(Item_id); //道具代码
						if (Item_cnt === 0) {
							CParty.add(122 * MemberSlotNo + 1972).writeU32(1);
						}
						CParty.add(122 * MemberSlotNo + 1972).writeU32(Item_cnt); //道具数量
					}
					else {
						var Citem = CDataManager_find_item(G_CDataManager(), Item_id); //获取道具在pvf文件内容
						var durability = CEquipItem_get_endurance(Citem); //装备耐久度
						var AttachType = CItem_getAttachType(Citem); //交易类型
						if (AttachType === 3) {
							CParty.add(122 * MemberSlotNo + 1965).writeU8(1);
						}
						else {
							CParty.add(122 * MemberSlotNo + 1965).writeU8(0);
						}
						CParty.add(122 * MemberSlotNo + 1966).writeU8(ItemType); //背包索引
						CParty.add(122 * MemberSlotNo + 1967).writeU32(Item_id); //道具代码
						CParty.add(122 * MemberSlotNo + 1972).writeU32(get_rand_int(0)); //道具数量
						CParty.add(122 * MemberSlotNo + 1976).writeU16(durability); //耐久度
					}
				}
			}
		});
}

function Hook_CParty_makeRewardItemInfo() {
	Interceptor.attach(ptr(0x85AD0BE),
		{
			onEnter: function (args) {
				var callerAddress = this.returnAddress; //调用地址
				var Inven_Item = args[2];
				//使用原生判断，当得到物品才会进行自定义道具的获取
				if (Inven_Item.add(63).readS8() > 0) {
					var CParty = args[0];
					var user = args[1];
					var Dungeon_ID = CDungeon_get_index(CParty.add(812 * 4)); //取队伍副本ID
					//普通卡片
					if (callerAddress == 0x85b0a05 && (privilege_PlainCardItemlist.hasOwnProperty(Dungeon_ID) || PlainCardItemlist.hasOwnProperty(Dungeon_ID))) {

						var flag = false;
						var Itemlist = [];
						//查询当前人物是否存在指定契约
						var acctount_id = CUser_get_acc_id(user);
						api_MySQL_exec(mysql_taiwan_login, "select event_id, pre_type,server_id,m_id,service_start,service_end from member_premium  where m_id ='" + acctount_id + "' and pre_type = 79 ;");
						if (MySQL_get_n_rows(mysql_taiwan_login) == 1) {
							flag = true;
						}
						if (flag) {
							Itemlist = privilege_PlainCardItemlist[Dungeon_ID][get_rand_int(PlainCardItemlist[Dungeon_ID].length)];
						} else {
							Itemlist = PlainCardItemlist[Dungeon_ID][get_rand_int(PlainCardItemlist[Dungeon_ID].length)];

						}

						var Item_id = Itemlist[0];
						var Item_cnt = Itemlist[1];
						var CurCharacInvenR = CUserCharacInfo_getCurCharacInvenR(user);
						var ItemType = CInventory_GetItemType(CurCharacInvenR, Item_id); //道具类型
						//消耗品 材料 副职业材料
						if (ItemType == 2 || ItemType == 3 || ItemType == 12) {
							Inven_Item.add(61).writeU8(0);
							Inven_Item.add(62).writeU8(ItemType); //背包索引
							Inven_Item.add(63).writeU32(Item_id); //道具代码
							if (Item_cnt === 0) {
								Inven_Item.add(68).writeU32(1);
							}
							Inven_Item.add(68).writeU32(Item_cnt); //道具数量
							console.log(Inven_Item.add(61).readByteArray(61));
						}
						else {
							var Citem = CDataManager_find_item(G_CDataManager(), Item_id); //获取道具在pvf文件内容
							var durability = CEquipItem_get_endurance(Citem); //装备耐久度
							var AttachType = CItem_getAttachType(Citem); //交易类型
							if (AttachType === 3) {
								Inven_Item.add(61).writeU8(1);
							}
							else {
								Inven_Item.add(61).writeU8(0);
							}
							Inven_Item.add(62).writeU8(ItemType); //背包索引
							Inven_Item.add(63).writeU32(Item_id); //道具代码
							Inven_Item.add(68).writeU32(get_rand_int(0)); //道具数量
							Inven_Item.add(72).writeU16(durability); //耐久度
						}

					}
					//黑钻卡牌
					if (callerAddress == 0x85b0b48 && VipCardItemlist.hasOwnProperty(Dungeon_ID)) {

						var Itemlist = VipCardItemlist[Dungeon_ID][get_rand_int(VipCardItemlist[Dungeon_ID].length)];
						var Item_id = Itemlist[0];
						var Item_cnt = Itemlist[1];
						var CurCharacInvenR = CUserCharacInfo_getCurCharacInvenR(user);
						var ItemType = CInventory_GetItemType(CurCharacInvenR, Item_id); //道具类型
						//消耗品 材料 副职业材料
						if (ItemType == 2 || ItemType == 3 || ItemType == 12) {
							Inven_Item.add(61).writeU8(0);
							Inven_Item.add(62).writeU8(ItemType); //背包索引
							Inven_Item.add(63).writeU32(Item_id); //道具代码
							if (Item_cnt === 0) {
								Inven_Item.add(68).writeU32(1);
							}
							Inven_Item.add(68).writeU32(Item_cnt); //道具数量
						}
						else {
							var Citem = CDataManager_find_item(G_CDataManager(), Item_id); //获取道具在pvf文件内容
							var durability = CEquipItem_get_endurance(Citem); //装备耐久度
							var AttachType = CItem_getAttachType(Citem); //交易类型
							if (AttachType === 3) {
								Inven_Item.add(61).writeU8(1);
							}
							else {
								Inven_Item.add(61).writeU8(0);
							}
							Inven_Item.add(62).writeU8(ItemType); //背包索引
							Inven_Item.add(63).writeU32(Item_id); //道具代码
							Inven_Item.add(68).writeU32(get_rand_int(0)); //道具数量
							Inven_Item.add(72).writeU16(durability); //耐久度
						}
					}
				}
			}
		});
}

/**********************************自定义翻牌奖励业务逻辑结束********************************************/


/**********************************商店限购********************************************/
var item_restr_list = {
	107: [
		// [3037,2,0,1,1],//[id,个数,月,周,天] //刷新方式为 下个月的1号 下周的周一 第二天的六点 以第一个1为准  哪种方式则将那个改为1
		[2122115612, 1, 0, 0, 1]
	],
	966: [
		// [3037,2,0,1,1],//[id,个数,月,周,天] //刷新方式为 下个月的1号 下周的周一 第二天的六点 以第一个1为准  哪种方式则将那个改为1
		[2132112083, 1, 0, 0, 1]
	],
	15: [
		// [3037,2,0,1,1],//[id,个数,月,周,天] //刷新方式为 下个月的1号 下周的周一 第二天的六点 以第一个1为准  哪种方式则将那个改为1
		[3037, 1, 0, 0, 1]
	]
};

/**
 * 按照指定设置进行商店购买限制
 */
function Hook_DisPatcher_BuyItem_process() {

	var is_buy = false;
	Interceptor.attach(ptr(0x081BE46A),
		{
			onEnter: function (args) {
				is_buy = false;
				var DisPatcher_BuyItem = args[0];
				var user = args[1];
				var msg_base = args[2];
				var item_id = msg_base.add(0xd).readU32();//道具id
				console.log(item_id);
				var item_shop = msg_base.add(0x15).readU32();//商店id
				console.log(item_shop);
				var charac_no = CUserCharacInfo_getCurCharacNo(user);
				//获取下次刷新时间
				var date = new Date();
				date = new Date(date.setHours(date.getHours() + 0)); //转换到本地时间
				//判断当前商店是否存在列表中
				if (item_restr_list.hasOwnProperty(item_shop)) {
					var items_list = item_restr_list[item_shop];
					for (var i = 0; i < items_list.length; i++) {
						var item_info = items_list[i];
						//列表中的物品id
						var item_index = item_info[0];
						var item_count = item_info[1];
						if (item_index == item_id) {
							var refresh_time_month = item_info[2];
							var refresh_time_weeks = item_info[3];
							var refresh_time_days = item_info[4];
							//判断当前物品是否有购买记录
							if (api_MySQL_exec(mysql_frida, "SELECT id,charac_no,item_id,buy_count,item_shop,refresh_time FROM frida.restrict_npc_shop_buy WHERE charac_no = '" + charac_no + "' AND item_id = '" + item_id + "' AND item_shop = '" + item_shop + "';")) {
								//没有记录说明目前是第一次购买

								if (MySQL_get_n_rows(mysql_frida) == 0) {

									//添加记录
									api_CUser_SendNotiPacketMessage(user, '     您购买道具[' + api_CItem_GetItemName(item_id) + ']', 1);
									if (refresh_time_month == 1) {
										date = getFirstOfNextMonth(date);
									} else if (refresh_time_weeks == 1) {
										date = getNextMonday(date);
									} else if (refresh_time_days == 1) {
										date = getSixAMNextDay(date);
									}

									console.log("insert into restrict_npc_shop_buy (charac_no,item_id,buy_count,item_shop,refresh_time) values (" + charac_no + "," + item_id + "," + item_shop + ", '" + date.getTime() + "');")
									api_MySQL_exec(mysql_frida, "insert into restrict_npc_shop_buy (charac_no,item_id,buy_count,item_shop,refresh_time) values (" + charac_no + "," + item_id + ",1," + item_shop + ", '" + date.getTime() + "');");


								} else if (MySQL_get_n_rows(mysql_frida) == 1) {
									//当前已经买过一次 或者 第二轮购买
									//需要判断当前日期是否大于刷新日期  购买数量小于限制数量
									MySQL_fetch(mysql_frida);
									//id,charac_no,item_id,item_shop,refresh_time FROM frida.restrict_npc_shop_buy
									var id = api_MySQL_get_int(mysql_frida, 0);
									var buy_count = api_MySQL_get_int(mysql_frida, 3);
									var refresh_time = api_MySQL_get_str(mysql_frida, 5);
									var refrish_date = new Date(parseInt(refresh_time));
									console.log(refrish_date);
									//判断当前时间是否
									console.log(date);
									if (date >= refrish_date) {
										//因为当前时间已经过了刷新时间 所以需要重置购买物品的记录

										if (refresh_time_month == 1) {
											date = getFirstOfNextMonth(date);
										} else if (refresh_time_weeks == 1) {
											date = getNextMonday(date);
										} else if (refresh_time_days == 1) {
											date = getSixAMNextDay(date);
										}
										api_MySQL_exec(mysql_frida, "update  restrict_npc_shop_buy set buy_count = 1,refresh_time = '" + date.getTime() + "' where charac_no = " + charac_no + " and item_id = " + item_id + " and item_shop = " + item_shop + ";");
									} else {
										//当前日期小于 刷新日期 判断数量是否
										if ((buy_count + 1) > item_count) {
											is_buy = true;
											api_CUser_SendNotiPacketMessage(user, '    您已达到购买限制', 1);
											CUser_SendCmdErrorPacket(user, 21, 114);
											// 计算日期差异

											var diffInMs = refrish_date - date;
											var diffInMinutes = Math.floor(diffInMs / (1000 * 60));
											var diffInHours = Math.floor(diffInMinutes / 60);
											var diffInDays = Math.floor(diffInHours / 24);
											var diffInMonths = Math.floor(diffInDays / 30);  // 粗略计算月份差异

											// 计算剩余的分钟、小时和天数
											var remainingMinutes = diffInMinutes % 60;
											var remainingHours = diffInHours % 24;
											var remainingDays = diffInDays % 30;  // 粗略计算天数

											// 输出结果
											api_CUser_SendNotiPacketMessage(user, "当前道具距离下次可购买时间还剩 " + (diffInMonths > 0 ? diffInMonths + " 月, " : "") + (remainingDays > 0 ? remainingDays + " 天, " : "") + (remainingHours > 0 ? remainingHours + " 小时, " : "") + remainingMinutes + " 分钟", 1)
											// return -1;
										} else {
											api_CUser_SendNotiPacketMessage(user, '     您购买道具[' + api_CItem_GetItemName(item_id) + ']', 1);
											//修改数据库记录
											api_MySQL_exec(mysql_frida, "update  restrict_npc_shop_buy set buy_count = " + (buy_count + 1) + " where charac_no = " + charac_no + " and item_id = " + item_id + " and item_shop = " + item_shop + ";");
										}

									}

								}
							}
							break;
						}
					}

				}


			},
			onLeave: function (retval) {
				console.log(is_buy);
				if (is_buy) {
					retval.replace(19);

				} else {
					retval.replace("0x0");
				}
			}
		});

}

// 定义一个函数来计算下个月的1号
function getFirstOfNextMonth(date) {
	var d = new Date(date);
	d.setMonth(d.getMonth() + 1);
	d.setDate(1);
	d.setHours(6, 0, 0, 0); // 设置为早上六点
	return d;
}

// 定义一个函数来计算下周的周一
function getNextMonday(date) {
	var d = new Date(date);
	var day = d.getDay();
	var diff = (day === 0 ? 1 : 8 - day); // 如果是周日，计算到下周一的天数
	d.setDate(d.getDate() + diff);
	d.setHours(6, 0, 0, 0); // 设置为早上六点
	return d;
}

// 定义一个函数来计算第二天的六点
function getSixAMNextDay(date) {
	var d = new Date(date);
	d.setDate(d.getDate() + 1);
	d.setHours(6, 0, 0, 0); // 设置为早上六点
	return d;
}
/**********************************商店限购********************************************/


//➢随机附魔---------------------------------------------------------------------------------------------------**/

var all_monster_card = {
	"10002604": [193003102, 193003104, 193003106, 193003108, 193003110, 193003112, 193003114, 193003116, 193003118, 193003120, 193003122, 193003124, 193003126, 193003128, 193003130, 193003132, 193003134],
	"10002603": [193003202, 193003204, 193003206, 193003208, 193003210, 193003212, 193003214, 193003216, 193003218, 193003220, 193003222, 193003224, 193003226, 193003228, 193003230, 193003232, 193003302, 193003304, 193003306, 193003308, 193003310, 193003312, 193003314, 193003316, 193003318, 193003320, 193003322, 193003324, 193003326, 193003328, 193003330, 193003332, 193003402, 193003404, 193003406, 193003408, 193003410, 193003412, 193003414, 193003416, 193003418, 193003420, 193003422, 193003424, 193003426, 193003428, 193003430, 193003432, 193003502, 193003504, 193003506, 193003508, 193003510, 193003512, 193003514, 193003516, 193003518, 193003520, 193003522, 193003524, 193003526, 193003528, 193003530, 193003532, 193003602, 193003604, 193003606, 193003608, 193003610, 193003612, 193003614, 193003616, 193003618, 193003620, 193003622, 193003624, 193003626, 193003628, 193003630, 193003632, 193003702, 193003704, 193003706, 193003708, 193003710, 193003712, 193003714, 193003716, 193003718, 193003720, 193003722, 193003724, 193003726, 193003728, 193003730, 193003732, 193003802, 193003804, 193003806, 193003808, 193003810, 193003812, 193003814, 193003816, 193003818, 193003820, 193003822, 193003824, 193003826, 193003828, 193003830, 193003832, 193003902, 193003904, 193003906, 193003908, 193003910, 193003912, 193003914, 193003916, 193003918, 193003920, 193003922, 193003924, 193003926, 193003928, 193003930, 193003932, 193004002, 193004004, 193004006, 193004008, 193004010, 193004012, 193004014, 193004016, 193004018, 193004020, 193004022, 193004024, 193004026, 193004028, 193004030, 193004032, 193004102, 193004104, 193004106, 193004108, 193004110, 193004112, 193004114, 193004116, 193004118, 193004120, 193004122, 193004124, 193004126, 193004128, 193004130, 193004132, 193004202, 193004204, 193004206, 193004208, 193004210, 193004212, 193004214, 193004216, 193004218, 193004220, 193004222, 193004224, 193004226, 193004228, 193004230, 193004232, 193004302, 193004304, 193004306, 193004308, 193004310, 193004312, 193004314, 193004316, 193004318, 193004320, 193004322, 193004324, 193004326, 193004328, 193004330, 193004332, 193004402, 193004404, 193004406, 193004408, 193004410, 193004412, 193004414, 193004416, 193004418, 193004420, 193004422, 193004424, 193004426, 193004428, 193004430, 193004432, 193004502, 193004504, 193004506, 193004508, 193004510, 193004512, 193004514, 193004516, 193004518, 193004520, 193004522, 193004524, 193004526, 193004528, 193004530, 193004532, 193004602, 193004604, 193004606, 193004608, 193004610, 193004612, 193004614, 193004616, 193004618, 193004620, 193004622, 193004624, 193004626, 193004628, 193004630, 193004632, 193004702, 193004704, 193004706, 193004708, 193004710, 193004712, 193004714, 193004716, 193004718, 193004720, 193004722, 193004724, 193004726, 193004728, 193004730, 193004732],
	"10002605": [193004802, 193004804, 193004806, 193004808, 193004810, 193004812, 193004814, 193004816, 193004818, 193004820, 193004822, 193004824, 193004826, 193004828, 193004830, 193004902, 193004904, 193004906, 193004908, 193004910, 193004912, 193004914, 193004916, 193004918, 193004920, 193004922, 193004924, 193004926, 193004928, 193004930, 193005002, 193005004, 193005006, 193005008, 193005010, 193005012, 193005014, 193005016, 193005018, 193005020, 193005022, 193005024, 193005026, 193005028, 193005030, 193005102, 193005104, 193005106, 193005108, 193005110, 193005112, 193005114, 193005116, 193005118, 193005120, 193005122, 193005124, 193005126, 193005128, 193005130, 193005202, 193005204, 193005206, 193005208, 193005210, 193005212, 193005214, 193005216, 193005218, 193005220, 193005222, 193005224, 193005226, 193005228, 193005230, 193005302, 193005304, 193005306, 193005308, 193005310, 193005312, 193005314, 193005316, 193005318, 193005320, 193005322, 193005324, 193005326, 193005328, 193005330, 193005402, 193005404, 193005406, 193005408, 193005410, 193005412, 193005414, 193005416, 193005418, 193005420, 193005422, 193005424, 193005426, 193005428, 193005430, 193005502, 193005504, 193005506, 193005508, 193005510, 193005514, 193005516, 193005518, 193005520, 193005522, 193005524, 193005526, 193005528, 193005530, 193005602, 193005604, 193005606, 193005608, 193005610, 193005612, 193005614, 193005616, 193005618, 193005620, 193005622, 193005624, 193005626, 193005628, 193005630, 193005702, 193005704, 193005706, 193005708, 193005710, 193005712, 193005714, 193005716, 193005718, 193005720, 193005722, 193005724, 193005726, 193005728, 193005730, 193005802, 193005804, 193005806, 193005808, 193005810, 193005812, 193005814, 193005816, 193005818, 193005820, 193005822, 193005824, 193005826, 193005830, 193005902, 193005904, 193005906, 193005908, 193005910, 193005912, 193005914, 193005916, 193005918, 193005920, 193005922, 193005924, 193005926, 193005928, 193005930, 193006002, 193006004, 193006006, 193006008, 193006010, 193006012, 193006014, 193006016, 193006018, 193006020, 193006022, 193006024, 193006026, 193006028, 193006030, 193006102, 193006104, 193006106, 193006108, 193006110, 193006112, 193006114, 193006116, 193006118, 193006120, 193006122, 193006124, 193006126, 193006128, 193006130, 193006202, 193006204, 193006206, 193006208, 193006210, 193006212, 193006214, 193006216, 193006218, 193006220, 193006222, 193006224, 193006226, 193006228, 193006230, 193006302, 193006304, 193006306, 193006308, 193006310, 193006312, 193006314, 193006316, 193006318, 193006320, 193006322, 193006324, 193006326, 193006328, 193006330],
	"202404149": [402330246, 402330303, 402330304, 402330314, 402330302, 402330280, 402330291, 402330301, 402330292, 402330278, 402330300, 402330227, 402330234, 402330230, 402330241, 402330252, 402329739, 402329740, 402329752, 402329727, 402329728, 402329715, 402329737, 402329736, 402329710, 402329711, 402329716, 402329644, 402329675, 402329658, 402329651, 402329667, 402329668, 402339378, 402329388, 402329389, 402329391, 402329400, 402329385, 402329346, 402329361, 402329362, 402329387, 402329377, 402329360, 402329376, 402329386, 402339361, 402339353, 402339371, 402339370, 402329078, 402329144, 402329145, 402329146, 402329159, 402329132, 402329142, 402329143, 402329133, 402329121, 402329120, 402329115, 402329112, 402329047, 402329141, 402329071, 402329070, 402329054, 402329061, 402329959, 402329968, 402329952, 402329969, 402329976, 402330034, 402330035, 402330037, 402330047, 402330012, 402330008, 402330032, 402330023, 402329944, 402330033, 402330024],
	"202404148": [402328283, 402328309, 402328310, 402328320, 402328296, 402328297, 402328307, 402328255, 402328279, 402328306, 402328248, 402328308, 402328282, 402328243, 402328232, 402328236, 402328240, 402328228, 402327975, 402328036, 402328037, 402328046, 402327945, 402328025, 402328026, 402328035, 402328034, 402328009, 402328011, 402327958, 402327951, 402327968, 402327967, 402327351, 402327592, 402327593, 402327595, 402327564, 402327570, 402327591, 402327590, 402327566, 402327568, 402327565, 402327581, 402327500, 402327344, 402327582, 402327531, 402327519, 402327514, 402327528, 402327510, 402327741, 402327742, 402327744, 402327754, 402327740, 402327729, 402327645, 402327738, 402327739, 402327712, 402327709, 402327716, 402327730, 402327710, 402327675, 402327651, 402327667, 402327658, 402327668, 402327046, 402327076, 402327069, 402327052, 402327059, 402327068, 402327141, 402327142, 402327144, 402327154, 402327130, 402327131, 402327115, 402327112, 402327140, 402327139, 402327111, 402327116],
	"202404150": [402331435, 402331436, 402331444, 402331425, 402331408, 402331424, 402331344, 402331434, 402331412, 402331409, 402331375, 402331368, 402331367, 402331351, 402331358, 402331732, 402331733, 402331742, 402331707, 402331731, 402331708, 402331706, 402331730, 402331722, 402331644, 402331710, 402331721, 402331672, 402331650, 402331667, 402331657, 402331666, 402332336, 402332337, 402332339, 402332324, 402332335, 402332307, 402332334, 402332244, 402332305, 402332323, 402332306, 402332274, 402332250, 402332257, 402332266, 402332267, 402331973, 402332029, 402332030, 402332038, 402332027, 402332003, 402332007, 402332018, 402332019, 402331945, 402332028, 402332005, 402331962, 402331951, 402331958, 402331968, 402331966, 402331967, 402331053, 402331065, 402331060, 402331070, 402331142, 402331143, 402331154, 402331128, 402331112, 402331141, 402331140, 402331127, 402331139, 402331115, 402331046, 402331077],
	"202404151": [402334282, 402334283, 402334285, 402334294, 402334255, 402334281, 402334256, 402334270, 402334259, 402334250, 402334258, 402334257, 402334271, 402334279, 402334280, 402334253, 402333330, 402333324, 402333385, 402333384, 402333407, 402333408, 402333418, 402333405, 402333406, 402333378, 402333342, 402333396, 402333336, 402333335, 402333327, 402333627, 402333635, 402333673, 402333677, 402333630, 402333703, 402333704, 402333714, 402333642, 402333691, 402333672, 402333692, 402333701, 402333700, 402333702, 402333624, 402333636, 402333027, 402333024, 402333036, 402333075, 402333080, 402333077, 402333030, 402333042, 402333103, 402333104, 402333113, 402333101, 402333102, 402333074, 402333092, 402333091, 402333072, 402333100, 402333035, 402333937, 402333936, 402333928, 402333978, 402333925, 402333931, 402333943, 402334001, 402334002, 402334003, 402333999, 402333975, 402333991, 402333990, 402334000],
	"202404152": [402336297, 402336298, 402336309, 402336285, 402336236, 402336271, 402336296, 402336239, 402336233, 402336284, 402336294, 402336266, 402336295, 402336230, 402336267, 402336272, 402335100, 402335101, 402335103, 402335113, 402335031, 402335040, 402335071, 402335098, 402335089, 402335034, 402335099, 402335088, 402335072, 402335037, 402335097, 402335077, 402335076, 402335372, 402335394, 402335395, 402335405, 402335384, 402335383, 402335333, 402335330, 402335336, 402335393, 402335367, 402335339, 402335392, 402335991, 402335992, 402336001, 402335939, 402335936, 402335930, 402335980, 402335990, 402335933, 402335989, 402335968, 402335964, 402335981, 402335674, 402335697, 402335698, 402335707, 402335639, 402335633, 402335686, 402335695, 402335685, 402335696, 402335636, 402335694, 402335630, 402335669],
	"202404153": [402337095, 402337096, 402337109, 402337092, 402337093, 402337039, 402337047, 402337041, 402337048, 402337038, 402337094, 402337040, 402337043, 402337042, 402337037, 402337081, 402337080, 402337385, 402337386, 402337387, 402337397, 402337375, 402337335, 402337336, 402337374, 402337338, 402337345, 402337337, 402337341, 402337384, 402337339, 402337340, 402337383, 402337346, 402337687, 402337688, 402337698, 402337641, 402337636, 402337676, 402337685, 402337645, 402337646, 402337639, 402337637, 402337635, 402337640, 402337675, 402337686, 402337684],
};

/*卡片业务逻辑开始*/
function random_monster_card(user, equ_id, monster_card_id, old_monster_card_id) {
	var arr = all_monster_card[monster_card_id];

	// 创建一个排除当前怪物卡片ID的新数组
	var filteredArr = arr.filter(function (cardId) {
		return cardId !== parseInt(monster_card_id);
	});
	var bz_list = [10002603, 10002604, 10002605, 202404149, 202404148, 202404150, 202404151, 1202404152, 1202404153];
	var inven = CUserCharacInfo_getCurCharacInvenW(user);
	for (var i = 9; i <= 58; i++) {
		var equ = CInventory_GetInvenRef(inven, INVENTORY_TYPE_ITEM, i);
		var item_id = Inven_Item_getKey(equ);
		if (item_id && item_id == equ_id) {
			var kp = equ.add(13).readU32();
			if (bz_list.indexOf(kp) != -1) {
				if (filteredArr.length === 0) {
					api_CUser_SendNotiPacketMessage(user, '没有找到可用附魔', 14);
				} else {
					var monster_card = filteredArr[get_random_int(0, filteredArr.length)];
					equ.add(13).writeU32(monster_card);
				}
				CUser_send_itemspace(user, ENUM_ITEMSPACE_INVENTORY);
				return;
			}
		}
	}
	api_CUser_SendNotiPacketMessage(user, '没有找到可用装备', 14);
}
/**---------------------------------------------------------------------------------------------------**/


//加载主功能
function start() {
	console.log('[' + get_timestamp() + '] [frida] [info] --------------------------- set function ----------------------------');

	log('DP无脑一键端');
	//加载本地配置文件
	load_config('/dp2/frida/frida_config.json');
	//初始化数据库
	api_scheduleOnMainThread(init_db, null);
	//挂接消息分发线程 执行需要在主线程运行的代码
	hook_TimerDispatcher_dispatch();
	//开启怪物攻城活动
	//api_scheduleOnMainThread(start_event_villageattack, null);
	fix_TOD(false); //绝望之塔金币修复
	//fix_use_emblem(); //时装镶嵌配合0725exe
	//InterSelectMobileAuthReward(); //取消新账号送成长契约
	//start_event_lucky_online_user(); //开启抽取幸运在线玩家活动
	hook_user_inout_game_world(); //角色登入和登出，Hello提示
	//vip_Login();//vip等级判定,需要自行改任务代码-旧版可忽略
	enable_online_reward(); //在线奖励
	//change_random_option_inherit(); //魔法封印属性转换时可以继承(配合魔法封印改的装备镶嵌用)
	//auto_unseal_random_option_equipment(); //魔法封印自动解封(配合魔法封印改的装备镶嵌用)
	//enable_drop_use_luck_piont(); //使用角色幸运值加成装备爆率
	disable_check_create_character_limit(); //解除每日创建角色数量限制
	//setMaxCAccountCargoSolt(120);//金库扩容，设置账号金库格子数量，修改pvf可实现最多120，搜索金库扩容，角色离线处也有个开关！和跨界冲突！开了就别用跨界石。
	//HookDsSwordman_SkillSlot();//黑暗武士技能拖动
	api_scheduleOnMainThread_delay(SendRandMsg, null, 30000);//定时公告
	//api_scheduleOnMainThread_delay(startOnlineGifts, null, 1000);//6点删除剩余红包
	//api_scheduleOnMainThread_delay(startOnlineGifts_new, null, 1000);  //处理在线玩家心悦等级相关
	hook_history_log();//自动修理 装备播报 等等功能
	//hook_characterMessageLog();		//加载消息类型口令码和抢口令红包
	//reward_config = load_json('/dp2/frida/reward_config.json');	//加载口令红包配置
	increase_status();  //技能书返还必须
	//BanEnterDungeon() //特殊抗魔足够才能进副本
	EpicPotion();   //2600010史诗药剂
	hook_encrypt();
	startEquNew();//+13以上的券无需重选角色或整理装备
	//cancel_epic_ok();     //取消史诗确认框
	//share_seria_room();    //允许赛利亚房间的人互相可见
	hook_gm_command();//GM模式 

	//enhanced_Equip();	    //副本增强 GM模式下手动输入命令开启   //zt 查看状态   //zq开启增强  //sj随机刷新怪物  //zb开启拾取装备增强   再输一次命令为关闭
	//enhanced_Dungeon();	    //副本增强

	Privatestore_IgnoreNearDungeon();    //忽略副本门口禁止摆摊

	//积分商城<配合dll使用>
	//Hook_Arad_MileageProcess_BuySuccess();
	//FixCeraPointADD();
	//练习模式修复<配合dll使用>
	//FixPracticemode();	
	zhen14();   //真14键配合登录器
	andonglishanbai_Equipment_inlay();//装备时装镶嵌配合登录器
	disable_redeem_item();	//NPC回购关闭，装备时装镶嵌必开

	//api_scheduleOnMainThread_delay(start_events, null, 10000)//每日深渊活动(史诗大比拼)
	//api_scheduleOnMainThread_delay(send_dungeon_luck_reward, null, 3000);//进入指定副本参与抽奖
	//init_chouj_db();//初始化幸运魔盒抽奖数据 
	//start_hidden_option();//装扮潜能
	//HOOK_CParty_SetCardNumber();//自定义副本翻牌(金币)
	//Hook_CParty_makeRewardItemInfo();//自定义副本翻牌(普通和黑钻)
	//Hook_DisPatcher_BuyItem_process();//挂载商店购买限制
	console.log('[' + get_timestamp() + '] [frida] [info] ----------------------- set function success ------------------------');
}
