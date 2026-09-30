# Скрипт для ax3: System -> Scripts -> vpn-lists -> Source (заменить всё содержимое).
# Логи на английском: RouterOS плохо показывает кириллицу.
# Качает с GitHub только ДАННЫЕ (адреса и домены), сам проверяет каждую строку
# и обновляет списки без "окна", когда их нет. Код из репо не выполняется.
#
# Списки на роутере:
#   vpn_git  — подсети с GitHub (статические)
#   vpn_dns  — IP, которые роутер сам ловит по доменам (динамические)
#   no_vpn   — российские сервисы, всегда напрямую
#
# Защита от кривых списков:
#   - каждая строка проверяется: IP с маской /8../32, домен строчной латиницей;
#   - минимум 50 подсетей, 20 VPN-доменов и 5 direct-доменов;
#   - новый список не меньше 3/4 того, что уже стоит (подсети и оба списка доменов отдельно);
#   - старые записи удаляются, только если новых реально легло не меньше 90%.
# Если список уменьшился осознанно (выключил сервис), один раз в терминале:
#   :global vpnListsForce true; /system script run vpn-lists
#
# Требуется RouterOS 7.13+ и доверенные корневые сертификаты:
#   /certificate settings set builtin-trust-store=all

:global vpnListsVer
:global vpnListsForce
:local base "https://raw.githubusercontent.com/RokudoFran/vpn-lists/main/lists"
:local vpnDns "8.8.8.8"
:local directDns "77.88.8.8"
:local files {"vpn_ipv4.txt";"domains_vpn.txt";"domains_direct.txt"}
:local minNets 50
:local minVpnDoms 20
:local minDirectDoms 5
:local force false
:if ([:typeof $vpnListsForce] = "bool") do={ :set force $vpnListsForce }

# Читает файл по кускам и возвращает массив непустых строк (CR в конце строки отрезается)
:local readLines do={
    :local out ({})
    :local size [/file get [find name=$fn] size]
    :local off 0
    :local rest ""
    :while ($off < $size) do={
        :local chunk ([/file read file=$fn offset=$off chunk-size=32000 as-value]->"data")
        :if ([:len $chunk] = 0) do={ :set off $size } else={
            :set off ($off + [:len $chunk])
            :local buf ($rest . $chunk)
            :local pos 0
            :local nl [:find $buf "\n" $pos]
            :while ([:typeof $nl] = "num") do={
                :local line [:pick $buf $pos $nl]
                :if ([:len $line] > 0) do={
                    :if ([:pick $line ([:len $line] - 1)] = "\r") do={ :set line [:pick $line 0 ([:len $line] - 1)] }
                }
                :if ([:len $line] > 0) do={ :set out ($out, $line) }
                :set pos ($nl + 1)
                :set nl [:find $buf "\n" $pos]
            }
            :set rest [:pick $buf $pos [:len $buf]]
        }
    }
    :if ([:len $rest] > 0) do={ :set out ($out, $rest) }
    :return $out
}

# 1. Проверяем версию
:local ver ""
:do {
    :set ver [:pick (([/tool fetch url="$base/version.txt" check-certificate=yes-without-crl output=user as-value])->"data") 0 64]
} on-error={ :log warning "vpn-lists: version.txt fetch failed, keeping current lists" }

:if ([:len $ver] != 64 || $ver = $vpnListsVer) do={
    :if ([:len $ver] = 64) do={ :log debug "vpn-lists: no changes" }
} else={

    # 2. Качаем файлы
    :local ok true
    :foreach f in=$files do={
        :do { /file remove [find name="vpnlists-$f"] } on-error={}
        :do { /tool fetch url="$base/$f" dst-path="vpnlists-$f" check-certificate=yes-without-crl } on-error={ :set ok false }
    }
    :delay 2s
    :if (!$ok) do={ :log warning "vpn-lists: download failed, keeping current lists" }

    # 3. Читаем и проверяем каждую строку
    :local nets ({})
    :local vdoms ({})
    :local ddoms ({})
    :local bad 0
    :if ($ok) do={
        :do {
            :foreach l in=[$readLines fn="vpnlists-vpn_ipv4.txt"] do={
                :local good true
                :local ipPart $l
                :local slash [:find $l "/"]
                :if ([:typeof $slash] = "num") do={
                    :set ipPart [:pick $l 0 $slash]
                    :local m [:tonum [:pick $l ($slash + 1) [:len $l]]]
                    :if ([:typeof $m] = "num") do={
                        :if (($m < 8) || ($m > 32)) do={ :set good false }
                    } else={ :set good false }
                }
                :if ([:typeof [:toip $ipPart]] != "ip") do={ :set good false }
                :if ($good) do={ :set nets ($nets, $l) } else={ :set bad ($bad + 1) }
            }
            :foreach d in=[$readLines fn="vpnlists-domains_vpn.txt"] do={
                :if (([:len $d] <= 253) && ($d ~ "^[a-z0-9-]+([.][a-z0-9-]+)+\$")) do={ :set vdoms ($vdoms, $d) } else={ :set bad ($bad + 1) }
            }
            :foreach d in=[$readLines fn="vpnlists-domains_direct.txt"] do={
                :if (([:len $d] <= 253) && ($d ~ "^[a-z0-9-]+([.][a-z0-9-]+)+\$")) do={ :set ddoms ($ddoms, $d) } else={ :set bad ($bad + 1) }
            }
        } on-error={
            :log warning "vpn-lists: failed to read downloaded files, keeping current lists"
            :set ok false
        }
        :if ($bad > 0) do={ :log warning "vpn-lists: skipped $bad malformed lines" }
    }

    # 4. Размеры: абсолютный минимум и не меньше 3/4 того, что уже стоит
    :if ($ok) do={
        :local n [:len $nets]
        :local v [:len $vdoms]
        :local dd [:len $ddoms]
        :if (($n < $minNets) || ($v < $minVpnDoms) || ($dd < $minDirectDoms)) do={
            :log warning "vpn-lists: lists too small (subnets $n, vpn domains $v, direct domains $dd), not applying"
            :set ok false
        } else={
            :local curN [:len [/ip firewall address-list find where list=vpn_git]]
            :local curV [:len [/ip dns static find where type=FWD comment="git-dns" address-list=vpn_dns]]
            :local curD [:len [/ip dns static find where type=FWD comment="git-dns" address-list=no_vpn]]
            :local shrunk ((($n * 4) < ($curN * 3)) || (($v * 4) < ($curV * 3)) || (($dd * 4) < ($curD * 3)))
            :if ($shrunk && !$force) do={
                :log warning "vpn-lists: new lists shrank by more than 25% (subnets $curN to $n, vpn domains $curV to $v, direct domains $curD to $dd), not applying. If intended: :global vpnListsForce true; /system script run vpn-lists"
                :set ok false
            }
        }
    }

    # 5. Подсети: сначала добавляем/помечаем новые, потом убираем устаревшие — без пустого окна.
    #    Если реально легло меньше 90% новых, старые не трогаем.
    :if ($ok) do={
        /ip firewall address-list {
            :foreach a in=$nets do={
                :local id [find list=vpn_git address=$a]
                :if ([:len $id] > 0) do={ set $id comment=git-new } else={
                    :do { add list=vpn_git address=$a comment=git-new } on-error={}
                }
            }
            :local fresh [:len [find list=vpn_git comment="git-new"]]
            :if (($fresh * 10) < ([:len $nets] * 9)) do={
                :log error "vpn-lists: only $fresh of $[:len $nets] subnets applied, keeping old entries"
                set [find list=vpn_git comment="git-new"] comment=git
                :set ok false
            } else={
                remove [find list=vpn_git comment!="git-new"]
                set [find list=vpn_git comment="git-new"] comment=git
            }
        }
    }

    # 6. Домены: FWD-записи, IP автоматически попадают в address-list.
    #    Та же логика: старые записи удаляются, только если новых легло не меньше 90%.
    :if ($ok) do={
        :local total ([:len $vdoms] + [:len $ddoms])
        /ip dns static {
            :foreach d in=$vdoms do={
                :local id [find name=$d type=FWD]
                :if ([:len $id] > 0) do={
                    set $id forward-to=$vpnDns address-list=vpn_dns match-subdomain=yes comment=git-new
                } else={
                    :do { add name=$d type=FWD forward-to=$vpnDns address-list=vpn_dns match-subdomain=yes comment=git-new } on-error={}
                }
            }
            :foreach d in=$ddoms do={
                :local id [find name=$d type=FWD]
                :if ([:len $id] > 0) do={
                    set $id forward-to=$directDns address-list=no_vpn match-subdomain=yes comment=git-new
                } else={
                    :do { add name=$d type=FWD forward-to=$directDns address-list=no_vpn match-subdomain=yes comment=git-new } on-error={}
                }
            }
            :local freshD [:len [find comment="git-new"]]
            :if (($freshD * 10) < ($total * 9)) do={
                :log error "vpn-lists: only $freshD of $total domains applied, keeping old entries"
                set [find comment="git-new"] comment=git-dns
                :set ok false
            } else={
                remove [find comment="git-dns"]
                set [find comment="git-new"] comment=git-dns
            }
        }
    }

    :if ($ok) do={
        :set vpnListsVer $ver
        :set vpnListsForce false
        :log info "vpn-lists: updated: $[:len $nets] subnets, $[:len $vdoms] vpn domains, $[:len $ddoms] direct domains, ver $[:pick $ver 0 8]"
    }
}
