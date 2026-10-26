# HOME-AX3 watchdog v3. Run as a saved script once per minute.
# Requires existing main-table route 8.8.8.8/32 via wg-awg-proxy-1.
# 8.8.8.8 is a single health target: an ICMP-only outage can cause a restart.
:if ([/system script job print count-only as-value where script=[:jobname]] > 1) do={ :error "watchdog instance already running" }
:global vpnWatchV3Failures
:global vpnWatchV3LastRestart
:global vpnWatchV3State
:global vpnWatchV3Since
:global vpnWatchV3GraceUntil
:local up [/system resource get uptime]
:if ($up < 5m) do={ :return 0 }
:if ([:typeof $vpnWatchV3Failures] != "num") do={ :set vpnWatchV3Failures 0 }
:if ([:typeof $vpnWatchV3State] != "str") do={ :set vpnWatchV3State "init" }
:if ([:typeof $vpnWatchV3Since] != "str") do={ :set vpnWatchV3Since "" }
:if ([:typeof $vpnWatchV3GraceUntil] != "time") do={ :set vpnWatchV3GraceUntil 0s }
:local ct [/container find where name="awg-proxy-arm64"]
:local wg [/interface wireguard find where name="wg-awg-proxy-1"]
:if (([:len $ct] != 1) || ([:len $wg] != 1)) do={ :log error "tunnel-watch: expected container or interface missing/duplicated"; :return 0 }
:if ([/interface wireguard get $wg disabled]) do={ :return 0 }
:local route [/ip route find where dst-address=8.8.8.8/32]
:if ([:len $route] = 0) do={ :log error "tunnel-watch: tunnel probe route missing; refusing recovery"; :return 0 }
:local now ([/system clock get date] . " " . [/system clock get time])
:if ([/ping 8.8.8.8 count=3 interval=500ms] > 0) do={
    :if ($vpnWatchV3State != "up") do={
        :log info ("tunnel-watch: tunnel OK; previous=" . $vpnWatchV3State . "; down since=" . $vpnWatchV3Since)
    }
    :set vpnWatchV3State "up"
    :set vpnWatchV3Failures 0
    :set vpnWatchV3Since ""
    :set vpnWatchV3GraceUntil 0s
    :return 0
}
:if ([:len $vpnWatchV3Since] = 0) do={ :set vpnWatchV3Since $now }
:local wanA [/ping 77.88.8.8 count=3 interval=500ms]
:local wanB [/ping 8.8.4.4 count=3 interval=500ms]
:if (($wanA + $wanB) = 0) do={
    :if ($vpnWatchV3State != "wan-down") do={ :log warning "tunnel-watch: direct probes failed; no restart" }
    :set vpnWatchV3State "wan-down"
    :set vpnWatchV3Failures 0
    :return 0
}
:if ($vpnWatchV3State = "wan-down") do={
    :set vpnWatchV3State "grace"
    :set vpnWatchV3GraceUntil ($up + 2m)
    :set vpnWatchV3Failures 0
    :log info "tunnel-watch: WAN recovered; waiting 2 minutes"
    :return 0
}
:if ($up < $vpnWatchV3GraceUntil) do={ :return 0 }
:set vpnWatchV3Failures ($vpnWatchV3Failures + 1)
:if ($vpnWatchV3State != "vpn-down") do={
    :set vpnWatchV3State "vpn-down"
    :log warning ("tunnel-watch: tunnel probe failed; WAN reachable; since " . $vpnWatchV3Since)
}
:if ($vpnWatchV3Failures < 2) do={ :return 0 }
:if ([:typeof $vpnWatchV3LastRestart] = "time") do={
    :if (($up - $vpnWatchV3LastRestart) < 30m) do={ :return 0 }
}
:set vpnWatchV3LastRestart $up
:log warning "tunnel-watch: restarting AWG container; cooldown 30 minutes"
:do {
    :if ([/container get $ct status] != "stopped") do={ /container stop $ct }
    :local stopped false
    :for i from=1 to=15 do={
        :if (!$stopped) do={
            :if ([/container get $ct status] = "stopped") do={ :set stopped true } else={ :delay 2s }
        }
    }
    :if (!$stopped) do={ :error "container did not stop within 30 seconds" }
    /container start $ct
    :delay 15s
    :if ([/ping 8.8.8.8 count=3 interval=500ms] > 0) do={
        :log info ("tunnel-watch: restored after restart; down since " . $vpnWatchV3Since)
        :set vpnWatchV3State "up"
        :set vpnWatchV3Failures 0
        :set vpnWatchV3Since ""
    } else={ :log warning "tunnel-watch: still unavailable; waiting for next checks" }
} on-error={ :log error "tunnel-watch: container recovery failed; inspect container status/logs" }
