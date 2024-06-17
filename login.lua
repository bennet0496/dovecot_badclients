-- MIT License
--
-- Copyright (c) 2024 Bennet Becker <dev@bennet.cc>
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.
--
package.path = package.path .. ";/etc/dovecot/lua/?.lua"

local list_path = "./lists"
local asn_script_path = "./client_networks.py"
local disabled_services = {}
local ignore_networks = {}
local maxmind = false
local log_local = false
local process_unknown = false
local result_success = dovecot.auth.PASSDB_RESULT_NEXT
local result_block = dovecot.auth.PASSDB_RESULT_USER_DISABLED

local ISO_COUNTRY = {
    ["AF"] = "AFGHANISTAN",                                  ["AX"] = "ALAND ISLANDS",                          ["AL"] = "ALBANIA",
    ["DZ"] = "ALGERIA",                                      ["AS"] = "AMERICAN SAMOA",                         ["AD"] = "ANDORRA",
    ["AO"] = "ANGOLA",                                       ["AI"] = "ANGUILLA",                               ["AQ"] = "ANTARCTICA",
    ["AG"] = "ANTIGUA & BARBUDA",                            ["AR"] = "ARGENTINA",                              ["AM"] = "ARMENIA",
    ["AW"] = "ARUBA",                                        ["AU"] = "AUSTRALIA",                              ["AT"] = "AUSTRIA",
    ["AZ"] = "AZERBAIJAN",                                   ["BS"] = "BAHAMAS",                                ["BH"] = "BAHRAIN",
    ["BD"] = "BANGLADESH",                                   ["BB"] = "BARBADOS",                               ["BY"] = "BELARUS",
    ["BE"] = "BELGIUM",                                      ["BZ"] = "BELIZE",                                 ["BJ"] = "BENIN",
    ["BM"] = "BERMUDA",                                      ["BT"] = "BHUTAN",                                 ["BO"] = "BOLIVIA",
    ["BA"] = "BOSNIA & HERZEGOVINA",                         ["BW"] = "BOTSWANA",                               ["BV"] = "BOUVET ISLAND",
    ["BR"] = "BRAZIL",                                       ["IO"] = "BRITISH INDIAN OCEAN TERRITORY",         ["BN"] = "BRUNEI DARUSSALAM",
    ["BG"] = "BULGARIA",                                     ["BF"] = "BURKINA FASO",                           ["BI"] = "BURUNDI",
    ["KH"] = "CAMBODIA",                                     ["CM"] = "CAMEROON",                               ["CA"] = "CANADA",
    ["CV"] = "CAPE VERDE",                                   ["KY"] = "CAYMAN ISLANDS",                         ["CF"] = "CENTRAL AFRICAN REPUBLIC",
    ["TD"] = "CHAD",                                         ["CL"] = "CHILE",                                  ["CN"] = "CHINA",
    ["CX"] = "CHRISTMAS ISLAND",                             ["CC"] = "COCOS (KEELING) ISLANDS",                ["CO"] = "COLOMBIA",
    ["KM"] = "COMOROS",                                      ["CG"] = "CONGO",                                  ["CD"] = "CONGO, DEMOCRATIC REPUBLIC OF THE",
    ["CK"] = "COOK ISLANDS",                                 ["CR"] = "COSTA RICA",                             ["CI"] = "COTE D’IVOIRE",
    ["HR"] = "CROATIA (Hrvatska)",                           ["CU"] = "CUBA",                                   ["CY"] = "CYPRUS",
    ["CZ"] = "CZECH REPUBLIC",                               ["DK"] = "DENMARK",                                ["DJ"] = "DJIBOUTI",
    ["DM"] = "DOMINICA",                                     ["DO"] = "DOMINICAN REPUBLIC",                     ["EC"] = "ECUADOR",
    ["EG"] = "EGYPT",                                        ["SV"] = "EL SALVADOR",                            ["GQ"] = "EQUATORIAL GUINEA",
    ["ER"] = "ERITREA",                                      ["EE"] = "ESTONIA",                                ["ET"] = "ETHIOPIA",
    ["FK"] = "FALKLAND ISLANDS (MALVINAS)",                  ["FO"] = "FAROE ISLANDS",                          ["FJ"] = "FIJI",
    ["FI"] = "FINLAND",                                      ["FR"] = "FRANCE",                                 ["GF"] = "FRENCH GUIANA",
    ["PF"] = "FRENCH POLYNESIA",                             ["TF"] = "FRENCH SOUTHERN TERRITORIES",            ["GA"] = "GABON",
    ["GM"] = "GAMBIA",                                       ["GE"] = "GEORGIA",                                ["DE"] = "GERMANY",
    ["GH"] = "GHANA",                                        ["GI"] = "GIBRALTAR",                              ["GR"] = "GREECE",
    ["GL"] = "GREENLAND",                                    ["GD"] = "GRENADA",                                ["GP"] = "GUADELOUPE",
    ["GU"] = "GUAM",                                         ["GT"] = "GUATEMALA",                              ["GG"] = "GUERNSEY",
    ["GN"] = "GUINEA",                                       ["GW"] = "GUINEA-BISSAU",                          ["GY"] = "GUYANA",
    ["HT"] = "HAITI",                                        ["HM"] = "HEARD & MC DONALD ISLANDS",              ["VA"] = "HOLY SEE (VATICAN CITY STATE)",
    ["HN"] = "HONDURAS",                                     ["HK"] = "HONG KONG",                              ["HU"] = "HUNGARY",
    ["IS"] = "ICELAND",                                      ["IN"] = "INDIA",                                  ["ID"] = "INDONESIA",
    ["IR"] = "IRAN (ISLAMIC REPUBLIC OF)",                   ["IQ"] = "IRAQ",                                   ["IE"] = "IRELAND",
    ["IM"] = "ISLE OF MAN",                                  ["IL"] = "ISRAEL",                                 ["IT"] = "ITALY",
    ["JM"] = "JAMAICA",                                      ["JP"] = "JAPAN",                                  ["JE"] = "JERSEY",
    ["JO"] = "JORDAN",                                       ["KZ"] = "KAZAKHSTAN",                             ["KE"] = "KENYA",
    ["KI"] = "KIRIBATI",                                     ["KP"] = "KOREA, DEMOCRATIC PEOPLE’S REPUBLIC OF", ["KR"] = "KOREA, REPUBLIC OF",
    ["KW"] = "KUWAIT",                                       ["KG"] = "KYRGYZSTAN",                             ["LA"] = "LAO PEOPLE’S DEMOCRATIC REPUBLIC",
    ["LV"] = "LATVIA",                                       ["LB"] = "LEBANON",                                ["LS"] = "LESOTHO",
    ["LR"] = "LIBERIA",                                      ["LY"] = "LIBYAN ARAB JAMAHIRIYA",                 ["LI"] = "LIECHTENSTEIN",
    ["LT"] = "LITHUANIA",                                    ["LU"] = "LUXEMBOURG",                             ["MO"] = "MACAU",
    ["MK"] = "MACEDONIA, THE FORMER YUGOSLAV REPUBLIC OF",   ["MG"] =  "MADAGASCAR",                            ["MW"] = "MALAWI",
    ["MY"] = "MALAYSIA",                                     ["MV"] = "MALDIVES",                               ["ML"] = "MALI",
    ["MT"] = "MALTA",                                        ["MH"] = "MARSHALL ISLANDS",                       ["MQ"] = "MARTINIQUE",
    ["MR"] = "MAURITANIA",                                   ["MU"] = "MAURITIUS",                              ["YT"] = "MAYOTTE",
    ["MX"] = "MEXICO",                                       ["FM"] = "MICRONESIA, FEDERATED STATES OF",        ["MD"] = "MOLDOVA, REPUBLIC OF",
    ["MC"] = "MONACO",                                       ["MN"] = "MONGOLIA",                               ["ME"] = "MONTENEGRO",
    ["MS"] = "MONTSERRAT",                                   ["MA"] = "MOROCCO",                                ["MZ"] = "MOZAMBIQUE",
    ["MM"] = "MYANMAR",                                      ["NA"] = "NAMIBIA",                                ["NR"] = "NAURU",
    ["NP"] = "NEPAL",                                        ["NL"] = "NETHERLANDS",                            ["AN"] = "NETHERLANDS ANTILLES",
    ["NC"] = "NEW CALEDONIA",                                ["NZ"] = "NEW ZEALAND",                            ["NI"] = "NICARAGUA",
    ["NE"] = "NIGER",                                        ["NG"] = "NIGERIA",                                ["NU"] = "NIUE",
    ["NF"] = "NORFOLK ISLAND",                               ["MP"] = "NORTHERN MARIANA ISLANDS",               ["NO"] = "NORWAY",
    ["OM"] = "OMAN",                                         ["PK"] = "PAKISTAN",                               ["PW"] = "PALAU",
    ["PS"] = "PALESTINIAN TERRITORY",                        ["PA"] = "PANAMA",                                 ["PG"] = "PAPUA NEW GUINEA",
    ["PY"] = "PARAGUAY",                                     ["PE"] = "PERU",                                   ["PH"] = "PHILIPPINES",
    ["PN"] = "PITCAIRN",                                     ["PL"] = "POLAND",                                 ["PT"] = "PORTUGAL",
    ["PR"] = "PUERTO RICO",                                  ["QA"] = "QATAR",                                  ["RE"] = "REUNION",
    ["RO"] = "ROMANIA",                                      ["RU"] = "RUSSIAN FEDERATION",                     ["RW"] = "RWANDA",
    ["KN"] = "SAINT KITTS & NEVIS",                          ["SH"] = "ST. HELENA",                             ["LC"] = "SAINT LUCIA",
    ["MF"] = "SAINT MARTIN",                                 ["PM"] = "ST. PIERRE & MIQUELON",                  ["VC"] = "SAINT VINCENT & THE GRENADINES",
    ["WS"] = "SAMOA",                                        ["SM"] = "SAN MARINO",                             ["ST"] = "SAO TOME & PRINCIPE",
    ["SA"] = "SAUDI ARABIA",                                 ["SN"] = "SENEGAL",                                ["RS"] = "SERBIA",
    ["SC"] = "SEYCHELLES",                                   ["SL"] = "SIERRA LEONE",                           ["SG"] = "SINGAPORE",
    ["SK"] = "SLOVAKIA (Slovak Republic)",                   ["SI"] = "SLOVENIA",                               ["SB"] = "SOLOMON ISLANDS",
    ["SO"] = "SOMALIA",                                      ["ZA"] = "SOUTH AFRICA",                           ["GS"] = "SOUTH GEORGIA & THE SOUTH SANDWICH ISLANDS",
    ["ES"] = "SPAIN",                                        ["LK"] = "SRI LANKA",                              ["SD"] = "SUDAN",
    ["SR"] = "SURINAME",                                     ["SJ"] = "SVALBARD & JAN MAYEN ISLANDS",           ["SZ"] = "SWAZILAND",
    ["SE"] = "SWEDEN",                                       ["CH"] = "SWITZERLAND",                            ["SY"] = "SYRIAN ARAB REPUBLIC",
    ["TW"] = "TAIWAN",                                       ["TJ"] = "TAJIKISTAN",                             ["TZ"] = "TANZANIA, UNITED REPUBLIC OF",
    ["TH"] = "THAILAND",                                     ["TL"] = "TIMOR-LESTE",                            ["TG"] = "TOGO",
    ["TK"] = "TOKELAU",                                      ["TO"] = "TONGA",                                  ["TT"] = "TRINIDAD & TOBAGO",
    ["TN"] = "TUNISIA",                                      ["TR"] = "TURKEY",                                 ["TM"] = "TURKMENISTAN",
    ["TC"] = "TURKS & CAICOS ISLANDS",                       ["TV"] = "TUVALU",                                 ["UG"] = "UGANDA",
    ["UA"] = "UKRAINE",                                      ["AE"] = "UNITED ARAB EMIRATES",                   ["GB"] = "UNITED KINGDOM",
    ["US"] = "UNITED STATES",                                ["UM"] = "UNITED STATES MINOR OUTLYING ISLANDS",   ["UY"] = "URUGUAY",
    ["UZ"] = "UZBEKISTAN",                                   ["VU"] = "VANUATU",                                ["VE"] = "VENEZUELA, BOLIVARIAN REPUBLIC OF",
    ["VN"] = "VIET NAM",                                     ["VG"] = "VIRGIN ISLANDS (BRITISH)",               ["VI"] = "VIRGIN ISLANDS (U.S.)",
    ["WF"] = "WALLIS & FUTUNA ISLANDS",                      ["EH"] = "WESTERN SAHARA",                         ["YE"] = "YEMEN",
    ["ZM"] = "ZAMBIA",                                       ["ZW"] = "ZIMBABWE",
    ["ZZ"] = "LOCAL COUNTRY",                                   ["None"] = "UNKOWN COUNTRY"
}

function success(req)
	if result_success == dovecot.auth.PASSDB_RESULT_NEXT or result_success == dovecot.auth.PASSDB_RESULT_USER_UNKNOWN or req.skip_password_check then
		return result_success
	else
	    return dovecot.auth.PASSDB_RESULT_USER_UNKNOWN
	end
end

function non_empty(line)
    return line:match("^%s*[#;].*$") == nil -- lines starting with # or ; (or only spaces before that)
            and line:match("^%s*%-%-.*") == nil -- lines starting with -- (or only spaces before that)
            and line:match("^%s*$") == nil -- lines with only spaces
end

function iter_file(base_name)
    local f = io.open(list_path .. "/" .. base_name, "rb")
    if f then
        return f:lines()
    else
        return pairs({})
    end
end

-- https://stackoverflow.com/a/4991602
function file_exists(name)
   local f=io.open(name,"r")
   if f~=nil then io.close(f) return true else return false end
end

-- https://stackoverflow.com/a/17878208
function prequire(m)
  local ok, err = pcall(require, m)
  if not ok then return nil, err end
  return err
end

function check_regexpfile(filename, data)
    local i = 0
    for line in iter_file(filename) do
        i = i+1
        if non_empty(line) then
            if line:sub(1,1) == "'" then -- Lines with ' are case-insensitve literals
                if line:sub(2):lower() == data:lower() then
                    return result_block,
                    "not allowed to authenticate from " .. data
                end
            elseif line:sub(1,1) == "\"" then -- Lines with " are case-sensitve literals
                if line:sub(2) == data then
                    return result_block,
                    "not allowed to authenticate from " .. data
                end
            else
                -- catch errror
                local success, result = pcall(string.match, data, line)
                if success and result == data then
                    return result_block,
                        "not allowed to authenticate from " .. data
                elseif not success then
                    dovecot.i_error("syntax error in " .. list_path .. "/" .. filename .. " line "..i)
                    --return dovecot.auth.PASSDB_RESULT_INTERNAL_FAILURE, "config error"
                end
            end
        end
    end

    return nil, nil
end

function check_simplefile(filename, data, block_specifier)
    local i = 0
    for line in iter_file(filename) do
        if non_empty(line) and line:lower() == tostring(data):lower() then
            return result_block,
            "not allowed to authenticate from " .. (block_specifier or data)
        end
    end

    return nil, nil
end

function check_ccfile(filename, cc)
    local i = 0
    for line in iter_file(filename)
    do
        i = i + 1
        if non_empty(line) then
            -- check that country code is valid
            if ISO_COUNTRY[line:match("%a+")] == nil then
                dovecot.i_warning("Invalid CC " .. line:match("%a+") .. " in " .. list_path .. "/" .. filename .. " line " .. i)
            end
            -- truncate any non letter symbols (like spaces) from CCs
            if cc ~= nil and line:match("%a+") == cc:match("%a+") then
                return result_block,
                    "not allowed to authenticate from " .. ISO_COUNTRY[cc]
            end
        end
    end
    return nil, nil
end

function in_network(ip, network)
    -- Parse CIDR entry from file
    local sno1,sno2,sno3,sno4,smask = network:match("(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)/(%d%d?)")
    local sio1,sio2,sio3,sio4 = ip:match("(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)")

    if sio1 == nil or sio2 ==nil or sio3 == nil or sio4 == nil then
        dovecot.i_error("error parsing IP. IPv6 is currently unsupported")
        return nil
    end

    local no1,no2,no3,no4,mask = tonumber(sno1),tonumber(sno2),tonumber(sno3),tonumber(sno4),tonumber(smask)
    local io1,io2,io3,io4 = tonumber(sio1),tonumber(sio2),tonumber(sio3),tonumber(sio4)

    if type(io1) ~= "number" or type(io2) ~= "number" or type(io3) ~= "number" or type(io4) ~= "number" or
        io1 > 255 or io2 > 255 or io3 > 255 or io4 > 255 then
        dovecot.i_error(ip .. " is not valid ip expression")
        return nil
    end

    if type(no1) ~= "number" or type(no2) ~= "number" or type(no3) ~= "number" or type(no4) ~= "number" or type(mask) ~= "number" or
        no1 > 255 or no2 > 255 or no3 > 255 or no4 > 255 or mask > 32 then
        dovecot.i_error(network .. " is not valid network expression")
        return nil
    end

    local net_num = (no1 << 24) | (no2 << 16) | (no3 << 8) | no4
    local ip_num = (io1 << 24) | (io2 << 16) | (io3 << 8) | io4

    if net_num & (0xffffffff << (32-mask)) ~= net_num then
        dovecot.i_warning(string.format("%s has hostbits set", network))
    end

    -- after applying the mask, the network addresses are the same
    -- 1111 1111.1111 1111.1111 1111.1111 1111 << (32 - mask)
    return net_num & (0xffffffff << (32-mask)) == ip_num & (0xffffffff << (32-mask))
end

function script_init()
    local inifile = prequire('inifile')
    if not inifile then
    	dovecot.i_error('failed loading inifile')
    	return -1
    end
    local conf
    if file_exists("/etc/dovecot/bad_clients.conf.ext") then
        conf = inifile.parse("/etc/dovecot/bad_clients.conf.ext")
    elseif file_exists("/usr/local/etc/dovecot/bad_clients.conf.ext") then
        conf = inifile.parse("/etc/dovecot/bad_clients.conf.ext")
    elseif file_exists("/usr/local/dovecot/bad_clients.conf.ext") then
        conf = inifile.parse("/etc/dovecot/bad_clients.conf.ext")
    elseif file_exists("bad_clients.conf.ext") then
        conf = inifile.parse("./bad_clients.conf.ext")
    end
    if conf["general"]["list_path"] ~= nil then
    	list_path = conf["general"]["list_path"]
    end
    if conf["general"]["asn_script_path"] ~= nil then
    	asn_script_path = conf["general"]["asn_script_path"]
    end

    if conf["general"]["log_local"] ~= nil and (conf["general"]["log_local"]:lower() == "yes" or conf["general"]["log_local"]:lower() == "true") then
    	log_local = true
    end

    if conf["general"]["result_success"] ~= nil then
        local val = conf["general"]["result_success"]:lower()
        if val == "next" then
    	    result_success = dovecot.auth.PASSDB_RESULT_NEXT
    	elseif val == "unknown" then
    	    result_success = dovecot.auth.PASSDB_RESULT_USER_UNKNOWN
    	elseif val == "ok" then
    	    result_success = dovecot.auth.PASSDB_RESULT_OK
    	end
    end

    if conf["general"]["result_block"] ~= nil then
        local val = conf["general"]["result_block"]:lower()
        if val == "disabled" then
    	    result_block = dovecot.auth.PASSDB_RESULT_USER_DISABLED
        elseif val == "expired" then
            result_block = dovecot.auth.PASSDB_RESULT_PASS_EXPIRED
        elseif val == "missmatch" then
            result_block = dovecot.auth.PASSDB_RESULT_PASSWORD_MISMATCH
        end
    end

    if conf["general"]["process_unknown"] ~= nil and (conf["general"]["process_unknown"]:lower() == "yes" or conf["general"]["process_unknown"]:lower() == "true") then
    	process_unknown = true
    end

    if conf["general"]["disabled_services"] ~= nil then
    	for match in (conf["general"]["disabled_services"]..","):gmatch("(.-),") do
            local ins = match:match("^%s*(.-)%s*$")
            table.insert(disabled_services, ins or match)
            dovecot.i_info("will always deny for " .. (ins or match))
        end
    end

    if conf["general"]["ignore_networks"] ~= nil then
    	for match in (conf["general"]["ignore_networks"]..","):gmatch("(.-),") do
            local ins = match:match("^%s*(.-)%s*$")
            table.insert(ignore_networks, ins or match)
        end
    end

    if conf["general"]["enable_maxmind"] ~= nil and (conf["general"]["enable_maxmind"]:lower() == "yes" or conf["general"]["enable_maxmind"]:lower() == "true") then
    	maxmind = true
    end

    return 0
end

function script_deinit()
end

function auth_passdb_lookup(req)
    local socket = prequire("socket")
    local json = prequire("json") or prequire("cjson")

    if not json or not socket then
        dovecot.i_error("lua libraries missing! aborting!")
    	return dovecot.auth.PASSDB_RESULT_INTERNAL_FAILURE, "missing libaries"
    end

    -- ignore unauthenticated requests
    if req.passdbs_seen_user_unknown and not process_unknown then
        return dovecot.auth.PASSDB_RESULT_USER_UNKNOWN, ""
    end

    local dns, _ = socket.dns.tohostname(req.remote_ip)
    if dns == nil then
        dns = "<>"
    end

    local handle = nil
    if file_exists(asn_script_path)
    then
        handle = io.popen(asn_script_path .. " " .. req.remote_ip)
    end
    -- reads command output.
    if handle ~= nil
    then
    	local output = handle:read('*a')
        local data = json.decode(output)
        if output == nil or data == nil or data.error ~= nil
        then
            dovecot.i_error(string.format("failed to execute %s or lookup was empty. error=%s", asn_script_path, data and data.error or nil))
            return dovecot.auth.PASSDB_RESULT_INTERNAL_FAILURE, "lookup empty"
        end

        -- line counter
        local i = 0
        -- return values
        local dovret, strret, matched

        for _, srv in ipairs(disabled_services) do
        	if srv:lower() == req.service:lower() then
                dovret = result_block
                strret = srv:upper().." is disabled"
                matched = "service"
                goto log_and_return
        	end
        end

        -- local adresses can never be blocked
        if data.reserved then
            if log_local then
                dovret = success(req)
                strret = ""
                matched = ""
                goto log_and_return
            end
        	return success(req), ""
        end

        -- ignore configured networks
        for _, net in ipairs(ignore_networks) do
        	if in_network(req.remote_ip, net) then
                return success(req), ""
        	end
        end

        -- Check CIDR IP Networks
        for line in iter_file("ip_net.deny.lst")
        do
            i = i + 1
            if non_empty(line) then
                if in_network(req.remote_ip, line) then
                    dovret = result_block
                    strret = "not allowed to authenticate from " .. line
                    matched = "ip_net"
                    goto log_and_return
                end
            end
        end
        -- Check DNS name Regexes
        -- https://www.lua.org/pil/20.2.html
        dovret, strret = check_regexpfile("rev_host.deny.lst", dns)
        if dovret ~= nil and strret ~= nil then
            matched = "rev_host"
            goto log_and_return
        end
        -- Check AS numbers
        i = 0
        for line in iter_file("asn.deny.lst")
        do
        i = i + 1
            -- skip comments and empty lines
            if non_empty(line) then
                if line:match("AS%d+") == data.asn:match("AS%d+") or
                    (data.maxmind ~= nil and line:match("AS%d+") == data.maxmind.asn:match("AS%d+")) then
                    dovret = result_block
                    strret = "not allowed to authenticate from " .. data.asn
                    matched = "asn"
                    goto log_and_return
                elseif line:match("AS%d+") == nil then
                    dovecot.i_error("syntax error in "..list_path.."/asn_num.deny.lst line "..i)
                    goto continue_next_as
                end
            end
            ::continue_next_as::
        end
        -- Check AS Registration Countries
        dovret, strret = check_ccfile("as_cc.deny.lst", data.asn_country_code)
        if dovret ~= nil and strret ~= nil then
            matched = "as_cc"
            goto log_and_return
        end
        -- Check AS Descriptions/Human-readable names
        -- https://www.lua.org/pil/20.2.html
        dovret, strret = check_regexpfile("as_dscr.deny.lst", data.as_dscr)
        if dovret ~= nil and strret ~= nil then
            matched = "as_dscr"
            goto log_and_return
        end
        -- Check Network Country Code
        dovret, strret = check_ccfile("net_cc.deny.lst", data.net_country_code)
        if dovret ~= nil and strret ~= nil then
            matched = "net_cc"
            goto log_and_return
        end
        -- Check Provider Network Name
        -- This is independet of other factors, which may leed to unforseen overlaps
        -- https://www.lua.org/pil/20.2.html
        dovret, strret = check_regexpfile("net_name.deny.lst", data.net_name)
        if dovret ~= nil and strret ~= nil then
            matched = "net_name"
            goto log_and_return
        end
        -- Check list of related entities
        -- These should be unique tags-names assigned by the RIR, to identify owners, admins, tech-cs
        if data.entities ~= nil then
            for line in iter_file("entity.deny.lst") do
                if non_empty(line) then
                    for _, ent in ipairs(data.entities) do
                        if line:lower() == ent:lower() then -- equalsIgnoreCase
                            dovret = result_block
                            strret = "not allowed to authenticate from network with related entity " .. ent
                            matched = "entity:" .. ent
                            goto log_and_return
                        end
                    end
                end
            end
        end
        -- MaxMind Data processing
        if data.maxmind ~= nil then
            -- MaxMind AS Organization
            dovret, strret = check_regexpfile("maxmind/as_org.deny.lst", data.maxmind.as_org)
            if dovret ~= nil and strret ~= nil then
            	--return dovret, strret
            	matched = "maxmind:as_org"
                goto log_and_return
            end
            -- MaxMind City
            if data.maxmind.city ~= nil then
                dovret, strret = check_simplefile("maxmind/geo_loc.deny.lst", data.maxmind.city.geoname_id,
                        data.maxmind.city.names.en .. ", " .. data.maxmind.country.names.en)
                if dovret ~= nil and strret ~= nil then
                    --return dovret, strret
                    matched = "maxmind:geoloc_city"
                    goto log_and_return
                end
            end
            -- MaxMind Subdivision
            if data.maxmind.subdivisions ~= nil then
                for _, subdiv in ipairs(data.maxmind.subdivisions) do
                    --print(subdiv.geoname_id, subdiv.names.en .. ", " .. data.maxmind.country.names.en)
                    dovret, strret = check_simplefile("maxmind/geo_loc.deny.lst",
                        subdiv.geoname_id, subdiv.names.en .. ", " .. data.maxmind.country.names.en)
                    if dovret ~= nil and strret ~= nil then
                        --return dovret, strret
                        matched = "maxmind:geoloc_subdiv"
                        goto log_and_return
                    end
                end
            end
            -- MaxMind Country
            if data.maxmind.country ~= nil then
                dovret, strret = check_simplefile("maxmind/geo_loc.deny.lst", data.maxmind.country.geoname_id, data.maxmind.country.names.en)
                if dovret ~= nil and strret ~= nil then
                    --return dovret, strret
                    matched = "maxmind:geoloc_country"
                    goto log_and_return
                end
            end
            if data.maxmind.location.latitude ~= nil and
                data.maxmind.location.longitude ~= nil and
                data.maxmind.location.accuracy_radius ~= nil then
            	i = 0
                for line in iter_file("maxmind/coords.deny.lst")
                do
                i = i + 1
                    -- skip comments and empty lines
                    if non_empty(line) then
                        local lat,lon,rad, rad_overlap = line:match("%s*(%-?%d+%.?%d*)%s*,%s*(%-?%d+%.?%d*)%s*,%s*(%d+)%s*,%s*(%d.%d+)")
                        local function torad(deg)
                        	return (math.pi / 180.0) * tonumber(deg)
                        end
                        -- https://en.wikipedia.org/wiki/Geographical_distance
                        local dlat = torad(data.maxmind.location.latitude) - torad(lat)
                        local mlat = (data.maxmind.location.latitude + lat) / 2
                        local dlon = torad(data.maxmind.location.longitude) - torad(lon)
                        local s = 6371.009 * math.sqrt(dlat^2 + (math.cos(mlat) * dlon)^2)
                        --print(lat,lon,rad,data.maxmind.location.latitude,data.maxmind.location.longitude,data.maxmind.location.accuracy_radius,dlat,dlon,s)
                        if s < data.maxmind.location.accuracy_radius + rad then -- radii intersect
                            overlap = data.maxmind.location.accuracy_radius + rad - s
                            --print(overlap, overlap/data.maxmind.location.accuracy_radius)
                            if overlap/data.maxmind.location.accuracy_radius > tonumber(rad_overlap) then
                                dovecot.i_info(data.maxmind.location.latitude .. "," .. data.maxmind.location.longitude .. " is close to " .. lat .. "," .. lon)
                            	--return dovecot.auth.PASSDB_RESULT_USER_DISABLED,
                                --    "not allowed to authenticate close to forbidden location"
                                matched = string.format("maxmind:geoloc:%f,%f,%d,%f", lat, lon, rad, rad_overlap)
                                goto log_and_return
                            end
                        end
                    end
                end
            end
        end

        ::log_and_return::
        local es = table.concat(data.entities, ", entity=")

        local audit = string.format("mail-audit: user=<%s>, service=%s, ip=%s, host=%s, asn=%s, as_cc=%s, as_desc=<%s>, net_name=<%s>, net_cc=%s, entity=%s",
            req.user, req.service, req.remote_ip, dns, data.asn, data.asn_country_code, data.asn_description, data.net_name, data.net_country_code, es
        )

        if dovret == result_block then
        	dovecot.i_info(audit .. string.format(", blocked=True, matched=%s", matched))
        else
            dovecot.i_info(audit)
        end

        if maxmind and data.maxmind ~= nil then
            --print(dump(data.maxmind))
            local city = data.maxmind.city and string.format("%s/%d", data.maxmind.city.names.en, data.maxmind.city.geoname_id) or ""
            local country = data.maxmind.country and string.format("%s/%d", data.maxmind.country.iso_code, data.maxmind.country.geoname_id) or ""
            local continent = data.maxmind.continent and string.format("%s/%d", data.maxmind.continent.code, data.maxmind.continent.geoname_id) or ""
            local registered_country = data.maxmind.registered_country and string.format("%s/%d", data.maxmind.registered_country.iso_code, data.maxmind.registered_country.geoname_id) or ""

            --print(req.user, req.remote_ip, data.maxmind.asn, data.maxmind.as_org, city)
            local logstr = string.format("mail-audit-maxmind: user=<%s>, service=%s, ip=%s, asn=%s, as_org=<%s>, city=<%s>",
                req.user, req.service, req.remote_ip, data.maxmind.asn, data.maxmind.as_org, city
            )
            if data.maxmind.subdivisions ~= nil then
                for i, subdiv in ipairs(data.maxmind.subdivisions) do
                    logstr = logstr .. string.format(", subdivision[%d]=<%s/%d>", i - 1, subdiv.names.en, subdiv.geoname_id)
                end
            end
            logstr = logstr .. string.format(", country=<%s>, continent=<%s>, registered_country=<%s>",
                country, continent, registered_country
            )
            if data.maxmind.represented_country ~= nil then
                	logstr = logstr .. string.format(", represented_country=<%s/%d>", data.maxmind.represented_country.iso_code, data.maxmind.represented_country.geoname_id)
            end
            logstr = logstr .. string.format(", lat=%f, lon=%f, rad=%dkm", data.maxmind.location.latitude, data.maxmind.location.longitude, data.maxmind.location.accuracy_radius)

        	dovecot.i_info(logstr)
        end

        if dovret ~= nil and strret ~= nil then
            return dovret, strret
        end
    else
        dovecot.i_error(string.format("failed to execute %s", asn_script_path))
        -- could not execute client_networks.py
        return dovecot.auth.PASSDB_RESULT_INTERNAL_FAILURE, "lookup failed"
    end

    -- nothing found. login ok
    return success(req), ""
end