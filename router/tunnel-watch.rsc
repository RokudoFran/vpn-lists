# Скрипт для ax3: System -> Scripts -> tunnel-watch, запускается планировщиком раз в 5 минут:
#   /system scheduler add name=tunnel-watch interval=5m start-time=startup on-event="/system script run tunnel-watch"
# Логи на английском: RouterOS плохо показывает кириллицу.
#
# Туннель проверяется пингом 8.8.8.8: маршрут awg-proxy-1-dns ведёт его через wg-awg-proxy-1,
# так что ответы есть, только пока жив весь путь роутер -> контейнер -> VPS.
# Если туннель молчит, сначала проверяется сам интернет — пингом напрямую 77.88.8.8 и 8.8.4.4:
#   - интернета нет: авария у провайдера, контейнер не трогаем, в лог пишем один раз;
#   - интернет есть: перезапускаем контейнер AmneziaWG — сразу, дальше не чаще раза в 30 минут,
#     пока туннель лежит (если умер сам VPS, частые перезапуски не помогут).
# Когда интернет вернулся, туннелю даётся 5 минут подняться самому.
# При восстановлении в лог пишется, с какого момента был простой.
# Первые 5 минут после загрузки ничего не делает: контейнер ещё поднимается.

:global awgDownRuns
:global awgWanDown
:global awgDownSince
:local ctName "awg-proxy-arm64"
:if ([:typeof $awgDownRuns] != "num") do={ :set awgDownRuns 0 }
:if ([:typeof $awgWanDown] != "bool") do={ :set awgWanDown false }
:if ([:typeof $awgDownSince] != "str") do={ :set awgDownSince "" }

:if ([/system resource get uptime] > 00:05:00) do={
    :local now ([/system clock get date] . " " . [/system clock get time])
    :if ([/ping 8.8.8.8 count=5] > 0) do={
        # туннель жив
        :if ([:len $awgDownSince] > 0) do={ :log warning "tunnel-watch: tunnel is up again (down since $awgDownSince)" }
        :set awgDownRuns 0
        :set awgWanDown false
        :set awgDownSince ""
    } else={
        :if ([:len $awgDownSince] = 0) do={ :set awgDownSince $now }
        :local wan ([/ping 77.88.8.8 count=3] + [/ping 8.8.4.4 count=3])
        :if ($wan = 0) do={
            # интернета нет совсем: перезапуск контейнера не поможет
            :if (!$awgWanDown) do={ :log warning "tunnel-watch: WAN down (no direct ping), not touching the container" }
            :set awgWanDown true
            :set awgDownRuns 0
        } else={
            :if ($awgWanDown) do={
                # интернет только что вернулся: даём туннелю время подняться самому
                :log warning "tunnel-watch: WAN is up again, giving the tunnel 5 minutes"
                :set awgWanDown false
            } else={
                :set awgDownRuns ($awgDownRuns + 1)
                :if ((($awgDownRuns - 1) % 6) = 0) do={
                    :local c [/container find where name=$ctName]
                    :if ([:len $c] = 0) do={
                        :log error "tunnel-watch: container $ctName not found"
                    } else={
                        :log warning "tunnel-watch: tunnel down since $awgDownSince, WAN is up, restarting container $ctName"
                        :do { /container stop $c } on-error={}
                        :delay 10s
                        :local started false
                        :for i from=1 to=6 do={
                            :if (!$started) do={
                                :do {
                                    /container start $c
                                    :set started true
                                } on-error={ :delay 5s }
                            }
                        }
                        :if (!$started) do={ :log error "tunnel-watch: failed to start container $ctName" }
                    }
                }
            }
        }
    }
}
