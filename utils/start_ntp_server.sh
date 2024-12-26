#!/bin/bash

LANG=C
P=$0; [[ $0 = /* ]] && P=${0##*/}
AT=("$@")
switchroot() {
	[[ $(id -u) != 0 ]] && {
		echo -e "{NETNS:WARN} $P need root permission, switch to:\n  sudo $P ${AT[@]}" | GREP_COLORS='ms=1;4' grep --color=always . >&2
		exec sudo $P "${AT[@]}"
	}
}
switchroot;

which chronyd &>/dev/null || yum install -y chrony >/dev/null
systemctl enable chronyd
systemctl start chronyd
