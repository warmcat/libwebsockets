#
# libwebsockets - protocol_lws_dht_dnssec_monitor
#
# Copyright (C) 2026 Andy Green <andy@warmcat.com>
#
#  This library is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation:
#  version 2.1 of the License.
#
#  This library is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public
#  License along with this library; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA  02110-1301  USA

set(SRCS
	protocol_lws_dht_dnssec_monitor.c
)

set(requirements 1)
require_lws_config(LWS_WITH_AUTHORITATIVE_DNS 1 requirements)
require_lws_config(LWS_WITH_JOSE 1 requirements)
require_lws_config(LWS_WITH_SYS_ASYNC_DNS_DNSSEC 1 requirements)
require_lws_config(LWS_WITH_SPAWN 1 requirements)

if (requirements)
	generate_plugin(protocol_lws_dht_dnssec_monitor
			"lws-dht-dnssec-monitor" "protocol_lws_dht_dnssec_monitor.c" "")
endif()
