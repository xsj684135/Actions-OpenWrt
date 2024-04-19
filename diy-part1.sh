#!/bin/bash
#
# https://github.com/P3TERX/Actions-OpenWrt
# File name: diy-part1.sh
# Description: OpenWrt DIY script part 1 (Before Update feeds)
#
# Copyright (c) 2019-2024 P3TERX <https://p3terx.com>
#
# This is free software, licensed under the MIT License.
# See /LICENSE for more information.
#

# Uncomment a feed source
#sed -i 's/^#\(.*helloworld\)/\1/' feeds.conf.default

# Add a feed source
#echo 'src-git helloworld https://github.com/fw876/helloworld' >>feeds.conf.default
#echo 'src-git passwall https://github.com/xiaorouji/openwrt-passwall' >>feeds.conf.default
echo 'src-git packages https://git.openwrt.org/feed/packages.git' >>feeds.conf.default
echo 'src-git luci https://git.openwrt.org/project/luci.git'>>feeds.conf.default
echo 'src-git routing https://git.openwrt.org/feed/routing.git'>>feeds.conf.default
echo 'src-git telephony https://git.openwrt.org/feed/telephony.git'>>feeds.conf.default
