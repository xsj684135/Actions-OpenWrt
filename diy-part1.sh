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
echo 'src-git packages https://git.openwrt.org/feed/packages.git^063b2393cbc3e5aab9d2b40b2911cab1c3967c59' >>feeds.conf.default
echo 'src-git luci https://git.openwrt.org/project/luci.git^b07cf9dcfc37e021e5619a41c847e63afbd5d34a'>>feeds.conf.default
echo 'src-git routing https://git.openwrt.org/feed/routing.git^648753932d5a7deff7f2bdb33c000018a709ad84'>>feeds.conf.default
echo 'src-git telephony https://git.openwrt.org/feed/telephony.git^86af194d03592121f5321474ec9918dd109d3057'>>feeds.conf.default
