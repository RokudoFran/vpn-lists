# Восстановление обновлятора на HOME-AX3

Эта процедура восстанавливает скрипт `vpn-lists-v2`, его расписание и управляемые IPv4/DNS-записи. После сброса или замены роутера сначала восстановите из своей защищённой копии LAN, доступ владельца, WAN, ключи и peer WireGuard, DNS, NAT и маршрутизацию. Рабочая конфигурация использует адрес `192.168.13.1` на `bridge`, туннель `wg-vps0`, таблицу `to_vpn` и маршрут к VPN-резолверу `8.8.8.8/32` через WG. Часы и доверенные сертификаты должны позволять HTTPS к raw.githubusercontent.com. Команды ниже рассчитаны на RouterOS 7.25.1.

## Повторить восстановление на чистой CHR

Для проверки одного обновлятора достаточно ПК с Git, Python 3.12, QEMU x86-64 с поддержкой пользовательской сети (SLIRP), 1 ГиБ свободной памяти для гостя и доступом по HTTPS к MikroTik и GitHub. Добавьте `qemu-system-x86_64` в PATH. Для Windows доступны сборки по ссылке с сайта QEMU. [Установка CHR](https://manual.mikrotik.com/docs/getting-started/installation-and-upgrade/install/chr-installation/) · [Загрузка QEMU](https://www.qemu.org/download/)

В PowerShell из новой папки выполните:

```powershell
git clone https://github.com/RokudoFran/vpn-lists.git
cd vpn-lists
python -m venv ../chr-venv
../chr-venv/Scripts/python.exe -m pip install "paramiko==5.1.0"
../chr-venv/Scripts/python.exe tools/rehearse_chr.py ../chr-result
```

На Linux и macOS путь к Python окружения — `../chr-venv/bin/python`. К команде можно добавить `--qemu "путь к исполняемому файлу"` и `--image-zip "путь к chr-7.25.1.img.zip"`. По умолчанию скрипт скачивает официальный x86-64 RAW ZIP версии 7.25.1. В обоих случаях он проверяет SHA-256 архива перед распаковкой. Для каждого прогона укажите новый каталог результата.

[Сценарий проверки CHR](tools/rehearse_chr.py) создаёт одноразовую ВМ с отдельным диском и случайным паролем. Управление доступно с локального ПК через loopback. Внутри гостя скрипт проверяет модель, версию и пустые таблицы, задаёт identity `HOME-AX3` для установщика и адрес `192.168.13.1` на внутреннем bridge. Для HTTPS используется NAT QEMU. Этот стенд проверяет восстановление обновлятора и свойства DNS FWD. Клиентскую маршрутизацию через настоящий WireGuard проверяют отдельно по разделу 5.

1. Из текущего клона собирается комплект. Сценарий передаёт его по SFTP, сверяет пять SHA-512 на CHR и выполняет синтаксический импорт. С выключенным расписанием проходит `dry-lan` и проверяет, что управляемые таблицы по-прежнему пусты.
2. `once-lan` применяется дважды. После каждого применения выполняются независимый `verify-lan.rsc` и построчная сверка на ПК. Учитываются повторы, свойства сетей и DNS, резолверы, адресные списки, охват поддоменов и сохранность контрольной записи `router.lan`.
3. Сценарий устанавливает `hourly-lan`, включает `vpn-lists-hourly` с интервалом `1h` и печатает `next-run`. Оставьте ПК включённым примерно на час. После включения расписания обновлятор запускает сама CHR. Для успеха нужны переход счётчика `0 → 1`, завершённая job, свежая запись `reconciled`, обновлённые LastCheck и LastVerified и пустой LastError.
4. После первого тика обе сверки повторяются. Если за время ожидания опубликован другой пакет, сценарий находит соответствующий SHA-512 в истории `main` и проверяет записи по этому неизменяемому коммиту.

Строка `PASS` и код возврата 0 означают, что проверки завершились. В каталоге результата `before.json` содержит исходное расписание и статус перед первым тиком, `result.json` — коммиты, SHA-512, счётчик, журнал и время наблюдения в UTC. Полные фактические таблицы находятся в `ipv4.tsv` и `dns.tsv`. При ошибке команда возвращает ненулевой код. Для диагностики сохраняются доступные результаты этапов и `qemu.log`. При завершении сценарий останавливает свой процесс QEMU и освобождает временный диск.

### Что подтвердил контрольный прогон 20 ноября 2026 года

На чистой CHR 7.25.1 до установки было 0 скриптов, планировщиков, адресных и статических DNS-записей. В этом прогоне отдельная ВМ служила WireGuard-пиром. Проверена инструкция из `5dc49c40` и пакет данных из [коммита 48776515](https://github.com/RokudoFran/vpn-lists/commit/48776515a376e2cdb9f706a7a2e28e059fc21401). Оба применения дали одинаковый состав. После первого часового запуска счётчик вырос с 0 до 1, LastError остался пустым.

| После первого запуска по расписанию | В Git | В CHR | Расхождения |
|---|---:|---:|---:|
| IPv4-сети `vpn_git` | 867 | 867 | 0 |
| DNS FWD через VPN | 137 | 137 | 0 |
| DNS FWD напрямую | 34 | 34 | 0 |

По часам гостя LastCheck был `2026-11-19 23:09:53 UTC`, LastVerified — `23:10:38 UTC`. ПК уходил в сон и подтвердил результат после пробуждения, 20 ноября в 19:19 МСК. У следующих коммитов количества могут отличаться.

## 1. Собрать и проверить комплект на ПК

В PowerShell с Git и Python 3.12 выполните команды в новой папке. Для виртуального окружения и комплекта используются соседние каталоги.

```powershell
git clone https://github.com/RokudoFran/vpn-lists.git
cd vpn-lists
python -m venv ../vpn-lists-venv
../vpn-lists-venv/Scripts/python.exe -m pip install -r requirements.txt
../vpn-lists-venv/Scripts/python.exe collector.py --check
../vpn-lists-venv/Scripts/python.exe -m unittest discover -s tests -v
../vpn-lists-venv/Scripts/python.exe tools/verify_bundle.py
../vpn-lists-venv/Scripts/python.exe tools/prepare_restore.py ../vpn-lists-restore
Get-Content ../vpn-lists-restore/RELEASE.txt
Get-Content ../vpn-lists-restore/SHA512SUMS.txt | ForEach-Object {
    $expected, $name = $_ -split '  ', 2
    $actual = (Get-FileHash -Algorithm SHA512 -LiteralPath (Join-Path ../vpn-lists-restore $name)).Hash
    if ($actual -ne $expected) { throw "SHA-512 mismatch: $name" }
}
```

В Linux и macOS интерпретатор окружения находится в `../vpn-lists-venv/bin/python`. Генератор выбирает последний коммит, менявший `lists/` в текущем checkout. Для конкретной опубликованной версии укажите `--ref <полный-SHA-коммита>` и новую выходную папку. Генератор читает данные из Git-объектов и создаёт комплект только после проверки всего пакета. Исторический контрольный коммит — `48776515a376e2cdb9f706a7a2e28e059fc21401`. Для него начало SHA-512 пакета — `d188b9a4436f`. Штатный часовой Source на HOME-AX3 имеет следующий SHA-512.

```text
445b66443cb56235bdd23c08d89dae6fbcaabdd95b7808be0ae7ec71e4193c8355e5e838d0f06ee81b6dc9e0f146919843ba9a42c929200bd66ffd69bd054af2
```

## 2. Зафиксировать исходное состояние

В локальном WinBox проверьте identity, расписание, скрипты, активные jobs и состояние туннеля. Запишите `disabled`, `on-event`, `interval`, `run-count`, `next-run` и хеш существующего Source. При наличии прежнего комплекта сохраните его `RELEASE.txt` и запустите его проверяющий скрипт, чтобы определить версию для отката. Снимите также фактические данные, включая ручные DNS-записи.

```routeros
/system identity print
/system resource print
:foreach sid in=[/system script find] do={:put ([/system script get $sid name] . " owner=" . [/system script get $sid owner] . " policy=" . [/system script get $sid policy])}
/system scheduler print detail without-paging
/system script job print
:foreach wid in=[/interface wireguard find] do={:put ([/interface wireguard get $wid name] . " running=" . [/interface wireguard get $wid running] . " mtu=" . [/interface wireguard get $wid mtu])}
/ip route print detail where routing-table=to_vpn
```

Для существующего скрипта прочитайте контрольную сумму.

```routeros
:put [:convert [/system script get [find where name="vpn-lists-v2"] source] from=raw to=hex transform=sha512]
```

Выберите свободные имена файлов в Files и скачайте экспорты на ПК. Ниже приведён пример для первой копии.

```routeros
/system script export file=restore-before-scripts
/system scheduler export file=restore-before-scheduler
/ip firewall address-list export file=restore-before-addresses
/ip dns static export file=restore-before-dns
```

Сохраните экспорты локально. Учитывайте, что Source других скриптов может содержать чувствительные строки. Если требуется только подтвердить исправную установку, переходите к проверке `verify-lan.rsc` из следующего раздела и к просмотру планового запуска из раздела 5.

## 3. Проверить файлы на роутере и подготовить расписание

Передайте в корень Files пять файлов из одного комплекта — `stage-lan.rsc`, `verify-lan.rsc`, `v2-dry-lan.txt`, `v2-once-lan.txt`, `v2-hourly-lan.txt`. Если в Files есть комплект предыдущей версии, сохраните его на ПК. Сравните все пять полных сумм со своим `SHA512SUMS.txt` перед первым импортом.

```routeros
:foreach f in={"stage-lan.rsc";"verify-lan.rsc";"v2-dry-lan.txt";"v2-once-lan.txt";"v2-hourly-lan.txt"} do={:put ($f . " " . [:convert [/file get $f contents] from=raw to=hex transform=sha512])}
/import file-name=stage-lan.rsc verbose=yes dry-run
/import file-name=verify-lan.rsc verbose=yes dry-run
:put [:typeof [:parse [/file get v2-dry-lan.txt contents]]]
```

Ожидаются успешный синтаксический разбор и `code`. Для проверки уже работающего устройства выполните `/import file-name=verify-lan.rsc`. Он сравнит полный состав сетей и DNS, тип FWD, резолвер, список, включённое состояние, охват поддоменов и комментарии с коммитом из `RELEASE.txt`. На пустом устройстве совпадение ожидается после первого применения.

Для восстановления остановите существующий `vpn-lists-hourly` на время работ. Если планировщик отсутствует, создайте его выключенным. Существующий объект с другим событием или интервалом сначала сопоставьте с сохранённой конфигурацией. Команды ниже сохраняют его свойства и права.

```routeros
{ :local s [/system scheduler find where name="vpn-lists-hourly"]; :if ([:len $s]=0) do={ /system scheduler add name=vpn-lists-hourly disabled=yes start-time=startup interval=1h on-event="/system script run vpn-lists-v2" policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon } else={ :if ([:len $s]!=1) do={:error "ambiguous scheduler"}; :if (([/system scheduler get $s on-event]!="/system script run vpn-lists-v2") || ([/system scheduler get $s interval]!=1h)) do={:error "review scheduler"}; /system scheduler disable $s } }
/system script job print
```

Дождитесь завершения текущей job обновлятора. Проверьте, что других активных обработчиков, меняющих эти же таблицы, нет. При первой установке используйте учётную запись владельца. Политики новых объектов соответствуют проверенному профилю HOME-AX3.

## 4. Пройти пробный запуск, применение и независимую сверку

Выполняйте стадии отдельно. После каждого импорта установщика дождитесь `Installed Source stage=...`. Он проверяет имя устройства, выключенное расписание, отсутствие активного обновлятора, SHA-512 и синтаксис загруженного Source, затем перечитывает установленное значение. Если скрипт отсутствует, стадия `dry-lan` создаёт его. При неизвестном Source установка останавливается для сверки с резервной копией.

```routeros
:global vlAuditStage "dry-lan"
/import file-name=stage-lan.rsc
/system script run vpn-lists-v2
/log print where message~"vpn-lists-v2:"
```

Найдите свежую строку `dry-run OK`, сравните три количества и начало SHA-512 с `RELEASE.txt`. Пробный запуск проверяет пакет и конфликты владения до записи. При успехе установите закреплённый профиль применения.

```routeros
:global vlAuditStage "once-lan"
/import file-name=stage-lan.rsc
/system script run vpn-lists-v2
/log print where message~"vpn-lists-v2:"
/import file-name=verify-lan.rsc
:global vpnListsV2Version; :put $vpnListsV2Version
:global vpnListsV2LastVerified; :put $vpnListsV2LastVerified
:global vpnListsV2LastError; :put $vpnListsV2LastError
```

Ожидаются свежая запись `reconciled`, `MATCH` с нужным commit и полным SHA-512, новый LastVerified, пустой LastError и Version из `RELEASE.txt`. Повторите запуск того же `once-lan` и проверку. Состав должен остаться тем же, время подтверждения обновится. При конфликте с ручной записью или смене политики домена разберите конкретное имя до следующего применения.

## 5. Вернуть часовую работу

```routeros
:global vlAuditStage "hourly-lan"
/import file-name=stage-lan.rsc
:put [:convert [/system script get [find where name="vpn-lists-v2"] source] from=raw to=hex transform=sha512]
```

Сверьте хеш с `v2-hourly-lan.txt` в `SHA512SUMS.txt`. Для рабочего ежечасного режима включите планировщик и запишите его счётчик и следующий запуск. При восстановлении намеренно приостановленного обслуживания сохраните согласованное состояние расписания.

```routeros
/system scheduler enable [find where name="vpn-lists-hourly"]
/system scheduler print detail where name="vpn-lists-hourly"
```

Дождитесь следующего естественного запуска без ручного вызова. Проверьте прирост run-count, свежую строку `reconciled`, LastCheck, LastVerified, LastError и Version. Снова выполните `verify-lan.rsc`. Если за это время `main` получила другой пакет, обновите чистый клон через `git pull --ff-only`, подготовьте новый комплект и передайте только новый проверяющий файл после сверки SHA-512. Итоговые ожидания возьмите из нового `RELEASE.txt`.

Клиентская проверка с LAN охватывает A-запросы к `router.lan` и публичному имени по UDP и TCP через `192.168.13.1`, `1.1.1.1` и `8.8.8.8`. Для Autodesk проверьте новый HTTPS-сеанс к `efulfillment.autodesk.com`, метку `to_vpn` и двусторонний трафик того же соединения на `wg-vps0`. Приложение может отдельно требовать действительную ссылку на файл.

## Если проверка не прошла

Оставьте планировщик выключенным, зафиксируйте фазу в журнале, LastError и состояние job. До изменения таблиц достаточно восстановить прежний проверенный Source и состояние расписания. После изменения данных сравните обе таблицы с исходными экспортами и закреплённым пакетом. Скрипт выполняет компенсирующие операции при ошибке; прерывание питания и сообщение `ROLLBACK INCOMPLETE` требуют проверки фактического состояния.

Для возврата данных подготовьте отдельный комплект с `--ref` исходного опубликованного коммита. Если в скрипте остался закреплённый профиль нового комплекта, сначала верните им известный обоим комплектам `hourly-lan` при выключенном scheduler, без запуска. Затем загрузите старый комплект, сверьте суммы и пройдите dry, once и verify. Включайте часовой профиль, когда актуальный пакет в `main` снова пригоден для применения. Экспорт с командами `add` поверх заполненных таблиц может создавать дубликаты. Неизвестный Source, ручные записи и незавершённый откат сверяйте по сохранённым объектам.
