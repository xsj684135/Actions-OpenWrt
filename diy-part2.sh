#!/bin/bash
#
# https://github.com/P3TERX/Actions-OpenWrt
# File name: diy-part2.sh
# Description: OpenWrt DIY script part 2 (After Update feeds)
#
# Copyright (c) 2019-2024 P3TERX <https://p3terx.com>
#
# This is free software, licensed under the MIT License.
# See /LICENSE for more information.
#

# Beware! This script will be in /rom/etc/uci-defaults/ as part of the image.
# Uncomment lines to apply:

# 设备首次安装需要，更新请注释
#wlan_name="OpenWrt"
#wlan_password=""
#root_password="322ybs"
#lan_ip_address="192.168.31.1"

# log potential errors
exec >/tmp/setup.log 2>&1

if [ -n "$root_password" ]; then
  (echo "$root_password"; sleep 1; echo "$root_password") | passwd > /dev/null
fi

# Configure LAN
# More options: https://openwrt.org/docs/guide-user/base-system/basic-networking
if [ -n "$lan_ip_address" ]; then
  uci set network.lan.ipaddr="$lan_ip_address"
  uci commit network
fi

# Configure WLAN
# More options: https://openwrt.org/docs/guide-user/network/wifi/basic#wi-fi_interfaces
if [ -n "$wlan_name" -a -n "$wlan_password" -a ${#wlan_password} -ge 8 ]; then
  uci set wireless.@wifi-device[0].disabled='0'
  uci set wireless.@wifi-iface[0].disabled='0'
  uci set wireless.@wifi-iface[0].encryption='psk2'
  uci set wireless.@wifi-iface[0].ssid="$wlan_name"
  uci set wireless.@wifi-iface[0].key="$wlan_password"
  uci commit wireless
fi

#!/bin/bash

# 替换index.html
modify_index_html() {
	local file_path="/www/index.html"
	cat > "$file_path" <<'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>设备绑定</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100vh;
        }
        .container {
            width: 80%;
            padding: 20px;
            background-color: #fff;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            margin: 20px;
            min-height: 200px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }
        h1 {
            color: #4CAF50;
            margin: 0 0 10px 0;
        }
        p {
            color: #333;
            font-size: 18px;
            margin: 0;
        }
        .button-container {
            margin-top: 20px;
        }
        button {
            background-color: #4CAF50;
            border: none;
            color: white;
            padding: 15px 32px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            cursor: pointer;
            border-radius: 10px;
        }
    </style>
</head>
<body>
<div class="container">
    <h1>欢迎使用</h1>
    <p>通过小程序扫码绑定设备</p>
    <div class="svg-container">
        <img src="qrcode.svg" alt="QRCode" style="width: 150px; height: 150px; margin-top: 20px;">
        <img src="mac_text.svg" alt="MAC Address">
    </div>
    <div class="button-container">
        <button onclick="redirectToLogin()">后台登陆</button>
    </div>
</div>
<script>
    function redirectToLogin() {
        window.location.href = '/cgi-bin/luci/';
    }
</script>
</body>
</html>
EOF
}

# 注释uhttpd
modify_uhttpd() {
sed -i '/list index_page/ s/^/#&/' /etc/config/uhttpd
}

# 清空 links.htm 文件
clear_links_html() {
    local file_path="/usr/lib/lua/luci/view/admin_status/index/links.htm"
    echo "" > "$file_path"
}

# 修改 /etc/openwrt_release 中的描述
modify_openwrt_release() {
    local file_path="/etc/openwrt_release"
    local new_description='DISTRIB_DESCRIPTION="OpenWrt v1.0.0 By Gulang"'
    sed -i "s/^DISTRIB_DESCRIPTION=.*/$new_description/" "$file_path"
}

# 修改 /etc/banner 中的内容
modify_banner() {
    local file_path="/etc/banner"
    local new_banner="---------------------------------------------------------------------------- 
             
                         
			上传脚本到指定位置并安装程序包

			OpenWrt v1.0.0 By Gulang
                
                
----------------------------------------------------------------------------"
    echo "$new_banner" > "$file_path"
}

# 修改 /www/luci-static/resources/view/wizard/initsetup.js 文件
modify_initsetup_js() {
    local file_path="/www/luci-static/resources/view/wizard/initsetup.js"
    cat > "$file_path" <<'EOF'
'use strict';
'require view';
'require dom';
'require poll';
'require uci';
'require rpc';
'require form';
'require fs';
return view.extend({
    load: function() {
        return Promise.all([fs.exec('/etc/init.d/wizard', ['reconfig']), uci.changes(), uci.load('wizard')]);
    },
    render: function(data) {
        var m, s, o;
        var has_wifi = false;
        if (uci.sections('wireless', 'wifi-device').length > 0) {
            has_wifi = true;
        }
        m = new form.Map('wizard', [_('上网设置')], _('快速设置上网方式'));
        s = m.section(form.NamedSection, 'default', 'wizard');
        s.addremove = false;
        s.tab('netsetup', _('Net Settings'), _('Three different ways to access the Internet, please choose according to your own situation.'));
        o = s.taboption('netsetup', form.ListValue, 'wan_proto', _('Protocol'));
        o.rmempty = false;
        o.value('dhcp', _('DHCP client'));
        o.value('pppoe', _('PPPoE'));
        o = s.taboption('netsetup', form.Value, 'wan_pppoe_user', _('PAP/CHAP username'));
        o.depends('wan_proto', 'pppoe');
        o = s.taboption('netsetup', form.Value, 'wan_pppoe_pass', _('PAP/CHAP password'));
        o.depends('wan_proto', 'pppoe');
        o.password = true;
        o = s.taboption('netsetup', form.Value, 'lan_ipaddr', _('IPv4 address'));
        o.description = _('网关地址 默认为192.168.31.1');
        o.datatype = 'ip4addr';
        o = s.taboption('netsetup', form.Value, 'lan_netmask', _('IPv4 netmask'));
        o.datatype = 'ip4addr';
        o.value('255.255.255.0');
        o.value('255.255.0.0');
        o.value('255.0.0.0');
        o.default = '255.255.255.0';
        o = s.taboption('netsetup', form.DynamicList, 'lan_dns', _('Use custom DNS servers'), _('Leave empty to use ISP DNS'));
        o.datatype = 'ip4addr';
        o = s.taboption('netsetup', form.Value, 'lan_gateway', _('IPv4 gateway'));
        o.depends('siderouter', '1');
        o.datatype = 'ip4addr';
        o.placeholder = _('Enter the main router IP');
        o.rmempty = false;
        o = s.taboption('netsetup', form.Flag, 'dhcp', _('DHCP Server'), _('To turn on this DHCP, you need to turn off the DHCP of the main router, and to turn off this DHCP, you need to manually change the gateway and DNS of all Internet devices to the IP of this bypass router'));
        o.depends('siderouter', '1');
        o.default = o.enabled;
        o = s.taboption('netsetup', form.Flag, 'ipv6', _('Enable IPv6'), _('Enable/Disable IPv6'));
        o.default = o.enabled;
        setTimeout("document.getElementsByClassName('cbi-button-apply')[0].children[3].children[0].value='1'", 1000);
        return m.render();
    }
});
EOF
}

#修改 默认WIFI
modify_wifi() {
# 默认设置所有接口为未知频段
radio0="Unknown"
radio1="Unknown"

# 获取 wireless.radio0.band 的值
band0=$(uci get wireless.radio0.band)

# 获取 wireless.radio1.band 的值
band1=$(uci get wireless.radio1.band)

# 判断 radio0 的频段
if [ "$band0" = "2g" ]; then
    radio0="2.4G"
elif [ "$band0" = "5g" ]; then
    radio0="5G"
fi

# 判断 radio1 的频段
if [ "$band1" = "2g" ]; then
    radio1="2.4G"
elif [ "$band1" = "5g" ]; then
    radio1="5G"
fi

echo "Radio 0 is $radio0"
echo "Radio 1 is $radio1"

# 设置 2.4G WiFi
if [ "$radio0" = "2.4G" ]; then
    # 设置 2.4G WiFi 的名称和密码
    uci set wireless.@wifi-iface[0].ssid="IOTRouter_2.4G"
    uci set wireless.@wifi-iface[0].encryption="none"
    uci set wireless.radio0.country='US'
    uci set wireless.radio0.htmode='HT40'
    uci set wireless.radio0.mu_beamformer='1'
    uci set wireless.radio0.cell_density='3'
    uci set wireless.radio0.frag='2346'
    uci set wireless.radio0.rts='2347'
    uci set wireless.radio0.vendor_vht='1'
	uci set wireless.radio0.noscan='1'
	uci set wireless.@wifi-device[0].disabled='0'
    echo "2.4G WiFi 设置完成"
elif [ "$radio0" = "5G" ]; then
    # 设置 5G WiFi 的名称和密码
    uci set wireless.@wifi-iface[0].ssid="IOTRouter_5G"
    uci set wireless.@wifi-iface[0].encryption="none"
	uci set wireless.radio0.country='US'
    uci set wireless.radio0.channel='36'
    uci set wireless.radio0.htmode='VHT80'
    uci set wireless.radio0.rts='2347'
    uci set wireless.radio0.frag='2346'
    uci set wireless.radio0.cell_density='3'
    uci set wireless.radio0.mu_beamformer='1'
	uci set wireless.@wifi-device[0].disabled='0'
    echo "5G WiFi 设置完成"
fi

# 设置 5G WiFi
if [ "$radio1" = "2.4G" ]; then
    # 设置 5G WiFi 的名称和密码
    uci set wireless.@wifi-iface[1].ssid="IOTRouter_2.4G"
    uci set wireless.@wifi-iface[1].encryption="none"
    uci set wireless.radio1.country='US'
    uci set wireless.radio1.htmode='HT40'
    uci set wireless.radio1.mu_beamformer='1'
    uci set wireless.radio1.cell_density='3'
    uci set wireless.radio1.frag='2346'
    uci set wireless.radio1.rts='2347'
    uci set wireless.radio1.vendor_vht='1'
	uci set wireless.radio1.noscan='1'
	uci set wireless.@wifi-device[1].disabled='0'
    echo "5G WiFi 设置完成"
elif [ "$radio1" = "5G" ]; then
    # 设置 2.4G WiFi 的名称和密码
    uci set wireless.@wifi-iface[1].ssid="IOTRouter_5G"
    uci set wireless.@wifi-iface[1].encryption="none"
	uci set wireless.radio1.country='US'
    uci set wireless.radio1.channel='36'
    uci set wireless.radio1.htmode='VHT80'
    uci set wireless.radio1.rts='2347'
    uci set wireless.radio1.frag='2346'
    uci set wireless.radio1.cell_density='3'
    uci set wireless.radio1.mu_beamformer='1'
    echo "2.4G WiFi 设置完成"
	uci set wireless.@wifi-device[1].disabled='0'
fi

# 应用更改
uci commit wireless
wifi reload
}

# 修改 opkg源
modify_opkg() {
sed -i 's_downloads.openwrt.org_mirrors.aliyun.com/openwrt_' /etc/opkg/distfeeds.conf
}

# 修改 /etc/config
modify_etc_config() {
	# 生成UUID
	uuid=$(cat /proc/sys/kernel/random/uuid)
	local file_path="/etc/config/upnpd"
{
	echo
    echo "config upnpd 'config'"
    echo "	option enabled '1'"
    echo "	option enable_natpmp '1'"
    echo "	option enable_upnp '1'"
    echo "	option secure_mode '1'"
    echo "	option log_output '0'"
    echo "	option download '1024'"
    echo "	option upload '512'"
    echo "	option internal_iface 'lan'"
    echo "	option port '5000'"
    echo "	option upnp_lease_file '/var/run/miniupnpd.leases'"
    echo "	option igdv1 '1'"
    echo "	option uuid '$uuid'"
    echo
    echo "config perm_rule"
    echo "	option action 'allow'"
    echo "	option ext_ports '1024-65535'"
    echo "	option int_addr '0.0.0.0/0'"
    echo "	option int_ports '1024-65535'"
    echo "	option comment 'Allow high ports'"
} > "$file_path"

	local file_path="/etc/config/firewall"
	cat > "$file_path" <<'EOF'

config defaults
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'
	option synflood_protect '1'
	option flow_offloading '1'
	option flow_offloading_hw '1'

config zone
	option name 'lan'
	list network 'lan'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'

config zone
	option name 'wan'
	list network 'wan'
	list network 'wan6'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'
	option masq '1'
	option mtu_fix '1'

config forwarding
	option src 'lan'
	option dest 'wan'

config rule
	option name 'Allow-DHCP-Renew'
	option src 'wan'
	option proto 'udp'
	option dest_port '68'
	option target 'ACCEPT'
	option family 'ipv4'

config rule
	option name 'Allow-Ping'
	option src 'wan'
	option proto 'icmp'
	option icmp_type 'echo-request'
	option family 'ipv4'
	option target 'ACCEPT'

config rule
	option name 'Allow-IGMP'
	option src 'wan'
	option proto 'igmp'
	option family 'ipv4'
	option target 'ACCEPT'

config rule
	option name 'Allow-DHCPv6'
	option src 'wan'
	option proto 'udp'
	option dest_port '546'
	option family 'ipv6'
	option target 'ACCEPT'

config rule
	option name 'Allow-MLD'
	option src 'wan'
	option proto 'icmp'
	option src_ip 'fe80::/10'
	list icmp_type '130/0'
	list icmp_type '131/0'
	list icmp_type '132/0'
	list icmp_type '143/0'
	option family 'ipv6'
	option target 'ACCEPT'

config rule
	option name 'Allow-ICMPv6-Input'
	option src 'wan'
	option proto 'icmp'
	list icmp_type 'echo-request'
	list icmp_type 'echo-reply'
	list icmp_type 'destination-unreachable'
	list icmp_type 'packet-too-big'
	list icmp_type 'time-exceeded'
	list icmp_type 'bad-header'
	list icmp_type 'unknown-header-type'
	list icmp_type 'router-solicitation'
	list icmp_type 'neighbour-solicitation'
	list icmp_type 'router-advertisement'
	list icmp_type 'neighbour-advertisement'
	option limit '1000/sec'
	option family 'ipv6'
	option target 'ACCEPT'

config rule
	option name 'Allow-ICMPv6-Forward'
	option src 'wan'
	option dest '*'
	option proto 'icmp'
	list icmp_type 'echo-request'
	list icmp_type 'echo-reply'
	list icmp_type 'destination-unreachable'
	list icmp_type 'packet-too-big'
	list icmp_type 'time-exceeded'
	list icmp_type 'bad-header'
	list icmp_type 'unknown-header-type'
	option limit '1000/sec'
	option family 'ipv6'
	option target 'ACCEPT'

config rule
	option name 'Allow-IPSec-ESP'
	option src 'wan'
	option dest 'lan'
	option proto 'esp'
	option target 'ACCEPT'

config rule
	option name 'Allow-ISAKMP'
	option src 'wan'
	option dest 'lan'
	option dest_port '500'
	option proto 'udp'
	option target 'ACCEPT'

config rule
	option name 'Support-UDP-Traceroute'
	option src 'wan'
	option dest_port '33434:33689'
	option proto 'udp'
	option family 'ipv4'
	option target 'REJECT'
	option enabled 'false'

config include
	option path '/etc/firewall.user'


EOF
}

# 修改时区和Zram设置
modify_time_ZRam() {
uci set system.@system[0].zonename='Asia/Shanghai'
uci set system.@system[0].conloglevel='4'
uci set system.@system[0].cronloglevel='8'
uci set system.@system[0].zram_size_mb='38'
uci set system.@system[0].zram_comp_algo='zstd'
uci commit system
}

# 屏蔽reset
modify_reset() {
    local file_path="/etc/rc.button/reset"
    echo "" > "$file_path"
}

# 安装 mqtt.lua
install_mqtt_lua(){
	local file_path="/usr/lib/lua/luci/controller/mqtt.lua"
	mkdir -p /usr/lib/lua/luci/controller/
	touch $file_path
	cat > "$file_path" <<'EOF'
module("luci.controller.mqtt", package.seeall)  

function index()  
    -- 在 "系统" 菜单下添加新菜单项  
    entry({"admin", "system", "mqtt"}, cbi("mqtt"), _("MQTT设置"), 1).leaf = true  
end  
EOF

	local file_path="/usr/lib/lua/luci/model/cbi/mqtt.lua" 
	mkdir -p /usr/lib/lua/luci/model/cbi/
	touch $file_path
	cat > "$file_path" <<'EOF'
local fs = require "nixio.fs"
local sys = require "luci.sys"

m = Map("mqtt", translate("MQTT配置"), translate("用于配置MQTT连接相关项"))
s = m:section(TypedSection, "mqtt")
s.anonymous=true
-- 创建标签页：配置文件
s:tab("config_file", translate("配置文件"), translate("保存后重启生效，非不必要不建议随意更改！首选建议使用MQTT协议进行配置"))
-- 显示和编辑配置文件内容
config_text = s:taboption("config_file", TextValue, "_settings", translate("配置文件内容"))
config_text.rmempty = false
config_text.rows = 30  -- 设置编辑框的行数，增加垂直空间
config_text.wrap = "off"  -- 设置编辑框内容不自动换行
function config_text.cfgvalue(self, section)
    return fs.readfile("/root/config.yaml") or ""
end

function config_text.write(self, section, value)
    if value then
        local file_path = "/usr/sbin/mqtt/config.yaml"
        local file = io.open(file_path, "w")
        if file then
            file:write(value)
            file:close()
        else
            luci.sys.exec("echo \"" .. value .. "\" > " .. file_path)
        end
    end
end

return m
EOF

	local file_path="/etc/config/mqtt"
	touch $file_path
	cat > "$file_path" <<'EOF'

config mqtt
EOF

}

# 安装MQTT软件
install_mqtt(){
	mkdir -p /usr/sbin/mqtt/
	local file_path="/usr/sbin/mqtt/config.yaml"
	touch $file_path
	chmod +x $file_path
	cat > "$file_path" <<'EOF'
mqtt:
  broker_address: "ma703931.ala.cn-hangzhou.emqxsl.cn"
  port: 8883
  username: "admin"
  password: "xi962464"
  device_id: ""
  enable_ssl: true  # 是否启用SSL
  qos: 2  # MQTT连接的QoS级别，0：可靠性最低 1：可靠性一般 2：可靠性最高

topics:
  - name: "toServer"
    description: "用于发送消息"
    send_topic: "Router/toServer/"
  - name: "toClient"
    description: "用于接受消息"
    receive_topic: "Router/toClient/"
EOF

	local file_path="/usr/sbin/mqtt/handler_hostapd_cli.sh"
	touch $file_path
	chmod +x $file_path
	cat > "$file_path" <<'EOF'
#!/bin/bash

# global IFNAME=phy1-ap0 <3>AP-STA-DISCONNECTED c8:3c:85:ad:4b:4f

# 获取参数
message="$@"
#echo "$@"
# 提取信息
ifname=$(echo "$message" | awk -F '=' '{print $2}' | awk '{print $1}')
status=$(echo "$message" | awk '{gsub(/<|>|[0-9]/,"",$3); print $3}')
mac_address=$(echo "$message" | awk '{print $4}')

# 查询ESSID
essid=$(iwinfo "$ifname" info | awk -F ': ' '/ESSID/ {gsub(/"/, "", $2); print $2}')

# 构建 JSON 格式数据
json_data=$(cat <<INNER_EOF
{
    "event": "device_change",
    "info": {
        "essid": "$essid",
        "status": "$status",
        "mac_address": "$mac_address"
    }
}
INNER_EOF
)

# 向管道写入 JSON 数据
echo "$json_data" > "/tmp/handler_hostapd_cli_pipe"
EOF

	local file_path="/usr/sbin/mqtt/handler_set_wifi.py"
	touch $file_path
	chmod +x $file_path
	cat > "$file_path" <<'EOF'
import subprocess
import json
import sys

def set_wifi(ssid, password, band):
    if band == "2.4G":
        iface_index = 0
    elif band == "5G":
        iface_index = 1
    else:
        print(f"Unsupported band: {band}")
        return

    try:
        # Set SSID
        ssid_command = f'uci set wireless.@wifi-iface[{iface_index}].ssid="{ssid}"'
        subprocess.run(ssid_command, shell=True, check=True)

        # Set password
        password_command = f'uci set wireless.@wifi-iface[{iface_index}].key="{password}"'
        subprocess.run(password_command, shell=True, check=True)

        # Set encryption
        encryption_command = f'uci set wireless.@wifi-iface[{iface_index}].encryption="psk2+ccmp"'
        subprocess.run(encryption_command, shell=True, check=True)

        # Commit changes and reload WiFi
        subprocess.run('uci commit wireless', shell=True, check=True)
        subprocess.run(['wifi', 'reload'], check=True)

        print(f"Successfully updated {band} WiFi SSID to '{ssid}' and password.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to update {band} WiFi settings: {e}")

def main():
    try:
        message = json.loads(sys.argv[1])
        parameters = message.get('parameters', [])
        for param in parameters:
            for band, data in param.items():
                ssid = data.get('ssid')
                password = data.get('password')
                if ssid and password:
                    set_wifi(ssid, password, band)
                else:
                    print(f"SSID or password not provided for {band} WiFi.")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()

EOF

	local file_path="/usr/sbin/mqtt/handler_system_upgrade.py"
	touch $file_path
	chmod +x $file_path
	cat > "$file_path" <<'EOF'
import sys
import os
import hashlib
import subprocess
import json
import sys

def download_file(url, md5):
    # 使用wget下载文件到当前目录
    command = f"wget {url}"
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"下载失败: {e}")
        return None
    
    # 获取文件名
    file_name = url.split("/")[-1]

    # 计算下载文件的MD5值
    try:
        downloaded_md5 = hashlib.md5(open(file_name, "rb").read()).hexdigest()
    except Exception as e:
        print(f"计算MD5时出错: {e}")
        return None
    
    # 检查MD5值是否匹配
    if downloaded_md5 == md5:
        print("下载成功，并且MD5校验一致")
        return file_name
    else:
        print("MD5校验失败")
        os.remove(file_name)
        sys.exit(1)
        return None

def main():
    # 获取传递给脚本的所有参数
    args = json.loads(sys.argv[1])
    
    # 获取下载地址和MD5值
    download_url = args["parameters"][0]["download_ur"]
    md5 = args["parameters"][0]["md5"]
    
    # 下载文件并进行MD5校验
    downloaded_file = download_file(download_url, md5)
    if downloaded_file:
        try:
            # 执行固件升级操作
            command = f"sysupgrade {downloaded_file}"
            completed_process = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
            print("固件升级成功：", completed_process.stdout)
        except subprocess.CalledProcessError as e:
            print(f"固件升级失败: {e}")
            os.remove(downloaded_file)
            sys.exit(1)
    else:
        print("其他错误")
        os.remove(downloaded_file)
        sys.exit(1)

if __name__ == "__main__":
    main()

EOF

	local file_path="/usr/sbin/mqtt/main.py"
	touch $file_path
	chmod +x $file_path
	cat > "$file_path" <<'EOF'
import yaml
import logging
import paho.mqtt.client as mqtt
import subprocess
import os
import signal
import sys
import json
from typing import Union
from threading import Thread
import time

# 软件版本
software_versions = "1.0"

def process_output(output):
    """
    对输出进行转义处理，并将字节串转换为字符串。

    Args:
        output (Union[str, bytes]): 要处理的输出。

    Returns:
        str: 转义处理后的输出。
    """
    # 如果是字节串，则将其转换为字符串
    if isinstance(output, bytes):
        output = output.decode('utf-8', 'ignore')

    # 替换转义的换行符为真正的换行符
    processed_output = output.replace("\\n", "\n")

    return processed_output

def get_mac_address():
    try:
        # 读取config.yaml文件
        with open("config.yaml", "r") as file:
            config_content = file.read()
            # 获取MAC地址
            mac_address = None
            try:
                with open('/sys/class/net/wan/address', 'r') as addr_file:
                    mac_address = addr_file.readline().strip()
            except FileNotFoundError:
                logging.info("Error: File '/sys/class/net/wan/address' not found.")

            # 如果成功获取到MAC地址，就更新config.yaml文件中的device_id字段
            if mac_address:
                updated_config_content = config_content.replace('device_id: ""', 'device_id: "' + mac_address + '"')
                # 将更新后的内容写入config.yaml文件
                with open("config.yaml", "w") as file:
                    file.write(updated_config_content)
                logging.info("MAC 地址已填入到 device_id 中:%s", mac_address)
            else:
                logging.info("无法获取 MAC 地址")
    except FileNotFoundError:
        logging.info("Error: File 'config.yaml' not found.")

def execute_hostapd_command():
    """
    执行 hostapd_cli 命令的线程函数。
    """
    try:
        hostapd_process = subprocess.Popen(["hostapd_cli", "-i", "global", "-a", "handler_hostapd_cli.sh"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logging.info("hostapd_cli 运行成功：正在监听")
        logging.info("\033[1;31m【启动完成】遇到报错请截图并携带完整日志反馈\033[0m")
        hostapd_process.communicate()  # 等待子进程结束
        logging.info("hostapd_cli 进程结束")
    except Exception as e:
        logging.error("hostapd_cli 运行失败：%s", e)

def start_mqtt(broker_address: str, port: int, username: str, password: str, enable_ssl: bool, device_id: str, receive_topic: str, send_topic: str, qos: int) -> None:
    """
    连接到 MQTT 服务器，并启动 MQTT 客户端。

    Args:
        broker_address (str): MQTT 服务器地址。
        port (int): MQTT 服务器端口。
        username (str): MQTT 用户名。
        password (str): MQTT 密码。
        enable_ssl (bool): 是否启用 SSL 加密连接。
        device_id (str): 设备 ID。
        receive_topic (str): 接收消息的主题。
        send_topic (str): 发送消息的主题。
        qos (int): MQTT 连接的 QoS 级别。

    Returns:
        None
    """
    # 创建 MQTT 客户端
    client = mqtt.Client(client_id=device_id)
    
    # 设置用户名和密码，如果为空则表示匿名连接
    if username and password:
        client.username_pw_set(username, password)
    else:
        logging.warning("用户名或密码为空，将以匿名身份连接到 MQTT 服务器")
    
    # 设置 SSL 连接
    if enable_ssl:
        client.tls_set()
        logging.info("已启用 SSL 加密连接")
    else:
        logging.info("未启用 SSL 加密连接")

    # 定义回调函数处理消息
    def on_message(client, userdata, message):
        """
        处理接收到的 MQTT 消息。

        Args:
            client: MQTT 客户端。
            userdata: 用户数据。
            message: 接收到的消息。
        """
        logging.info("收到 %s 的消息：%s", message.topic, message.payload.decode())
        # 解析接收到的 JSON 格式消息
        try:
            msg_data = json.loads(message.payload.decode())
            task_id = msg_data.get("task_id")
            if "execute_function" in msg_data:
                function_name = msg_data["execute_function"]
                logging.info("开始执行函数：%s", function_name)
                #执行函数需要传递参数
                result, original_output = execute_function(function_name, message.payload.decode())
                reply = {
                    "task_id": task_id,
                    "result_function": "success" if result else "failure",
                    "result_function_original_output": original_output
                }
                # 发送回复消息
                client.publish(send_topic, json.dumps(reply), qos=qos)
            elif "execute_command" in msg_data:
                command = msg_data["execute_command"]
                logging.info("开始执行命令：%s", command)
                result, original_output = execute_command(command)
                reply = {
                    "task_id": task_id,
                    "result_command": "success" if result else "failure",
                    "result_command_original_output": original_output
                }
                # 发送回复消息
                client.publish(send_topic, json.dumps(reply), qos=qos)
            else:
                logging.warning("未知消息格式：%s", msg_data)
        except Exception as e:
            error_message = "处理消息时发生错误：{}".format(e)
            logging.error(error_message)
            client.publish(send_topic, error_message, qos=qos)

    # 定义回调函数处理连接状态
    def on_connect(client, userdata, flags, rc):
        """
        处理 MQTT 连接状态。

        Args:
            client: MQTT 客户端。
            userdata: 用户数据。
            flags: 连接标志。
            rc: 返回代码。
        """
        if rc == 0:
            logging.info("已成功连接到 MQTT 服务器")
            # 订阅接收主题
            logging.info("订阅接收主题：%s", receive_topic)
            client.subscribe(receive_topic, qos=qos)
            # 发送上线消息
            message = {
                "event": "client_status",
                "info": {
                    "software_versions": software_versions,
                    "status": "online",
                    "mac_address": device_id
                }
            }
            logging.info("发送上线消息：%s", message)
            client.publish(send_topic, json.dumps(message), qos=qos)
            # 启动线程执行 hostapd_cli 命令
            hostapd_thread = Thread(target=execute_hostapd_command)
            hostapd_thread.start()
            # 创建管道并启动线程接收 hostapd_cli 消息
            pipe_thread = Thread(target=receive_handler_hostapd_cli_messages, args=(client, send_topic, qos))
            pipe_thread.start()
        else:
            logging.error("连接到 MQTT 服务器失败，错误代码：%s", rc)

    # 设置回调函数
    client.on_message = on_message
    client.on_connect = on_connect

    # 连接到 MQTT 服务器
    while True:
        try:
            logging.info("尝试连接到 MQTT 服务器...")
            client.connect(broker_address, port)
            client.loop_forever()
        except Exception as e:
            logging.error("连接到 MQTT 服务器失败：%s", e)
            logging.info("将在10秒后尝试重新连接...")
            time.sleep(10)

def receive_handler_hostapd_cli_messages(client, send_topic, qos):
    """
    接收 handler_hostapd_cli.sh 发送的消息并通过 MQTT 发布出去。

    Args:
        client: MQTT 客户端。
        send_topic (str): 发送消息的主题。
        qos (int): 发布消息的 QoS 级别。

    Returns:
        None
    """
    # 创建管道
    pipe_path = '/tmp/handler_hostapd_cli_pipe'
    if not os.path.exists(pipe_path):
        os.mkfifo(pipe_path)
        logging.info("已创建管道：%s", pipe_path)
    else:
        logging.info("管道已存在：%s", pipe_path)

    # 循环等待接收消息
    while True:
        with open(pipe_path, 'r') as pipe:
            message = pipe.read().strip()
            if message:
                logging.info("收到 hostapd_cli 的消息：%s", message)
                client.publish(send_topic, message, qos=qos)

def execute_function(function_name: str, message: dict) -> tuple:
    """
    根据接收到的消息内容执行不同的函数，并将结果发送给服务器。

    Args:
        function_name (str): 要执行的函数名。
        message (dict): 从服务器接收到的完整 JSON 消息内容。

    Returns:
        tuple: 执行结果和原始输出。
    """
    try:
        
        if function_name == "set_wifi":
            # 执行 handler_set_wifi.py 脚本，并捕获输出结果
            success, output = subprocess.getstatusoutput(f"python3 handler_set_wifi.py '{message}'")
            result = success == 0  # 如果命令成功执行，结果为True，否则为False
            original_output = output
        elif function_name == "system_upgrade":
            #执行 系统升级
            success, output = subprocess.getstatusoutput(f"python3 handler_system_upgrade.py '{message}'")
            result = success == 0  # 如果命令成功执行，结果为True，否则为False
            original_output = output
        else:
            logging.error("未知函数：%s", function_name)
            result = False  # 执行失败
            original_output = "未知函数"

        # 输出执行结果和原始输出
        if result:
            logging.info("执行函数成功：%s", function_name)
            logging.info("函数输出：%s", original_output)
        else:
            logging.error("执行函数失败：%s", function_name)
            logging.error("错误输出：%s", original_output)

        # 返回执行结果和原始输出
        return result, process_output(original_output)

    except Exception as e:
        logging.error("处理函数时发生错误：%s", e)
        return False, process_output(str(e))

def execute_command(command: str) -> tuple:
    """
    执行命令并将结果发送给服务器。

    Args:
        command (str): 要执行的命令。

    Returns:
        tuple: 执行结果和原始输出。
    """
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True, timeout=60)
        logging.info("执行命令成功：%s", command)
        logging.info("命令输出：%s", result)
        return True, process_output(result)
    except subprocess.CalledProcessError as e:
        logging.error("执行命令失败：%s", command)
        logging.error("错误输出：%s", e.output)
        return False, process_output(e.output)
    except subprocess.TimeoutExpired as e:
        logging.warning("执行命令超时：%s", command)
        timeout_output = e.output
        logging.error("超时输出：%s", timeout_output)
        return False, process_output(timeout_output)
    except Exception as e:
        logging.error("处理命令时发生错误：%s", e)
        return False, process_output(str(e))

def main() -> None:
    """
    主函数，用于启动 MQTT 客户端。

    Returns:
        None
    """

    # 读取配置文件
    with open('config.yaml', 'r') as f:
        config = yaml.safe_load(f)
        logging.info("配置文件已加载")

    # 输出配置信息以便调试
    logging.info("配置信息：\n%s", yaml.dump(config))

    # 获取 MQTT 相关配置信息
    mqtt_config = config['mqtt']
    broker_address = mqtt_config['broker_address']
    port = mqtt_config['port']
    username = mqtt_config['username']
    password = mqtt_config['password']
    device_id = mqtt_config['device_id']
    enable_ssl = mqtt_config['enable_ssl']
    qos = mqtt_config.get('qos', 0)  # 获取QoS级别，默认为0

    # 获取主题信息
    topics = config.get('topics', [])
    receive_topic = None
    send_topic = None
    for topic in topics:
        if 'receive_topic' in topic and topic['name'] == 'toClient':
            receive_topic = topic['receive_topic'] + device_id
        elif 'send_topic' in topic and topic['name'] == 'toServer':
            send_topic = topic['send_topic'] + device_id

    if not receive_topic or not send_topic:
        logging.error("接收主题或发送主题未配置，请检查配置文件")
        return

    # 启动 MQTT 客户端
    start_mqtt(broker_address, port, username, password, enable_ssl, device_id, receive_topic, send_topic, qos)

def signal_handler(sig, frame):
    print('Exiting...')
    # 发送 SIGINT 信号给 hostapd_cli 进程
    subprocess.run(['killall', 'hostapd_cli'])
    # 直接终止整个进程
    os._exit(0)

if __name__ == "__main__":
    # 配置日志处理器
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s:%(name)s - %(message)s')
    # 注册信号处理函数
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    get_mac_address()

    main()

EOF

	local file_path="/usr/sbin/mqtt/MQTT_Service.sh"
	touch $file_path
	chmod +x $file_path
	cat > "$file_path" <<'EOF'
#!/bin/sh

# 进程名字
PROCESS_NAME="python /usr/sbin/mqtt/main.py"

# PID 文件路径
PID_FILE="/var/run/MQTT_Service.pid"

start() {
    # 启动Python程序，并将日志输出到系统日志中
	rm /tmp/handler_hostapd_cli_pipe
	cd /usr/sbin/mqtt/
    $PROCESS_NAME 2>&1 | logger -t MQTT_Service &

    # 等待一段时间确保进程已经启动
    sleep 1

    # 获取Python程序的PID并保存到PID文件中
    PID=$(ps | grep -v grep | grep "$PROCESS_NAME" | awk '{print $1}')
    echo "$PID" > "$PID_FILE"

    # 输出PID
    echo "Started MQTT Service with PID: $PID"
}

stop() {
    # 从PID文件中读取PID
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        # 终止进程
        kill "$PID"
        echo "Stopped MQTT Service with PID: $PID"
        # 删除PID文件
        rm "$PID_FILE"
    else
        echo "PID file not found. Service may not be running."
    fi
}

restart() {
    stop
    start
}

# 根据输入参数执行相应操作
case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        restart
        ;;
    *)
        echo "Usage: $0 {start|stop|restart}"
        exit 1
        ;;
esac

exit 0
EOF
	
	grep -q "/usr/sbin/mqtt/MQTT_Service.sh start" /etc/rc.local || sed -i '/^exit 0/i /usr/sbin/mqtt/MQTT_Service.sh start' /etc/rc.local
}


# 调用函数
#modify_index_html
#modify_uhttpd
#clear_links_html
modify_openwrt_release
modify_banner
#modify_initsetup_js
#modify_wifi
modify_opkg
modify_etc_config
modify_time_ZRam
modify_reset
install_mqtt_lua
install_mqtt

exit 0
