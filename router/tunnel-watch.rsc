# Скрипт для ax3: System -> Scripts -> tunnel-watch, запускается планировщиком раз в 5 минут:
#   /system scheduler add name=tunnel-watch interval=5m start-time=startup on-event="/system script run tunnel-watch"
# Логи на английском: RouterOS плохо показывает кириллицу.
#
# Проверяет туннель пингом 8.8.8.8: маршрут awg-proxy-1-dns ведёт его через wg-awg-proxy-1,
# так что ответы есть, только пока жив весь путь роутер -> контейнер -> VPS.
# Нет ни одного ответа из пяти — перезапускает контейнер AmneziaWG.
# Первый перезапуск сразу, дальше не чаще раза в 30 минут, пока туннель лежит:
# если умер сам VPS, частые перезапуски не помогут.
# Первые 5 минут после загрузки ничего не делает: контейнер ещё поднимается.

:global awgDownRuns
:local ctName "awg-proxy-arm64"
:if ([:typeof $awgDownRuns] != "num") do={ :set awgDownRuns 0 }

:if ([/system resource get uptime] > 00:05:00) do={
    :local replies [/ping 8.8.8.8 count=5]
    :if ($replies > 0) do={
        :if ($awgDownRuns > 0) do={ :log warning "tunnel-watch: tunnel is up again" }
        :set awgDownRuns 0
    } else={
        :set awgDownRuns ($awgDownRuns + 1)
        :if ((($awgDownRuns - 1) % 6) = 0) do={
            :local c [/container find where name=$ctName]
            :if ([:len $c] = 0) do={
                :log error "tunnel-watch: container $ctName not found"
            } else={
                :log warning "tunnel-watch: tunnel down, restarting container $ctName"
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
