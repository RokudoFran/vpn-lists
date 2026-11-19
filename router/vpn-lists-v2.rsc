
# HOME-AX3 updater 2.0.3 with exact legacy job guard; saved name vpn-lists-v2.
# Requires sha512 :convert and JSON :deserialize. Preflight fails before mutations.
# applyChanges controls network writes. See the deployment procedure for this build.
:local applyChanges true
:local bundleUrl "https://raw.githubusercontent.com/RokudoFran/vpn-lists/main/lists/bundle.json"
:local vpnResolver "8.8.8.8"
:local directResolver "77.88.8.8"
:if ([/system script job print count-only as-value where script=[:jobname]] > 1) do={ :return 0 }
:global vpnListsV2AllowShrink
:global vpnListsV2Version
:global vpnListsV2LastCheck
:global vpnListsV2LastVerified
:global vpnListsV2LastError
:local allowShrink false
:set vpnListsV2LastCheck ([/system clock get date] . " " . [/system clock get time])
:local phase "guard"
:local currentItem ""
:local currentId ""
:local currentProperty ""
:local mutated false
:local rollbackOK true
:local previousNets ({})
:local previousDns ({})
:local newNetIds ({})
:local newDnsIds ({})
:local removedNets ({})
:local removedDns ({})
:onerror updateError in={
    :local ownName [:tostr [:jobname]]
    :local ownSeen false
    :foreach jobRow in=[/system script job print as-value] do={
        :local listedName [:tostr ($jobRow->"script")]
        :if ($listedName = "vpn-lists") do={ :error "legacy updater is running" }
        :if ($listedName = $ownName) do={ :set ownSeen true }
    }
    :if (($ownName = "") || (!$ownSeen)) do={ :error "cannot verify current job name" }
    :local legacyScheduler [/system scheduler find where name="vpn-lists"]
    :foreach sid in=$legacyScheduler do={
        :if (([/system scheduler get $sid disabled] != true) && ([/system scheduler get $sid on-event] != "/system script run vpn-lists-v2")) do={ :error "disable legacy vpn-lists scheduler before applying v2" }
    }
    :if ($applyChanges) do={
        :set allowShrink ($vpnListsV2AllowShrink = true)
        :set vpnListsV2AllowShrink false
    }
    :set phase "download"
    # One HTTPS response: no independently changing files. output=user is bounded by RouterOS.
    :local download [/tool fetch url=$bundleUrl src-address=192.168.13.1 check-certificate=yes-without-crl output=user as-value]
    :if (($download->"status") != "finished") do={ :error "bundle download incomplete" }
    :local raw ($download->"data")
    :if (([:len $raw] < 100) || ([:len $raw] > 60000)) do={ :error "bundle size outside bounds" }
    :set phase "validate"
    :local envelope [:deserialize from=json value=$raw options=json.no-string-conversion]
    :if (($envelope->"schema") != 1) do={ :error "unsupported bundle schema" }
    :local payload ($envelope->"payload")
    :local digest ($envelope->"sha512")
    :if (([:typeof $payload] != "str") || ([:typeof $digest] != "str") || ([:len $digest] != 128)) do={ :error "invalid payload or digest" }
    :local actualDigest [:convert $payload from=raw to=hex transform=sha512]
    :if ($actualDigest != $digest) do={ :error "bundle SHA-512 mismatch" }
    :local package [:deserialize from=json value=$payload options=json.no-string-conversion]
    :if ([:len $package] != 3) do={ :error "unexpected payload fields" }
    :local nets ($package->"vpn_ipv4.txt")
    :local vdoms ($package->"domains_vpn.txt")
    :local ddoms ($package->"domains_direct.txt")
    :if (([:typeof $nets] != "array") || ([:typeof $vdoms] != "array") || ([:typeof $ddoms] != "array")) do={ :error "payload arrays missing" }
    :if (([:len $nets] < 50) || ([:len $nets] > 5000) || ([:len $vdoms] < 20) || ([:len $vdoms] > 1000) || ([:len $ddoms] < 5) || ([:len $ddoms] > 1000)) do={ :error "list counts outside bounds" }
    :local netSet ({})
    :local desiredDns ({})
    :local addressVolume 0
    :local previousEnd -1
    :local forbiddenRanges {{"lo"=0;"hi"=16777215};{"lo"=167772160;"hi"=184549375};{"lo"=1681915904;"hi"=1686110207};{"lo"=2130706432;"hi"=2147483647};{"lo"=2851995648;"hi"=2852061183};{"lo"=2886729728;"hi"=2887778303};{"lo"=3221225472;"hi"=3221225727};{"lo"=3221225984;"hi"=3221226239};{"lo"=3232235520;"hi"=3232301055};{"lo"=3323068416;"hi"=3323199487};{"lo"=3325256704;"hi"=3325256959};{"lo"=3405803776;"hi"=3405804031};{"lo"=3758096384;"hi"=4294967295}}
    :foreach netText in=$nets do={
        :if ([:typeof $netText] != "str") do={ :error "network must be text" }
        :if (([:typeof ($netSet->$netText)] != "nil") && ([:typeof ($netSet->$netText)] != "nothing")) do={ :error ("duplicate network " . $netText) }
        :local slash [:find $netText "/"]
        :local hostText $netText
        :local mask 32
        :if ([:typeof $slash] = "num") do={
            :set hostText [:pick $netText 0 $slash]
            :set mask [:tonum [:pick $netText ($slash + 1) [:len $netText]]]
        }
        :if ([:typeof $mask] != "num") do={ :error "invalid prefix length" }
        :if (($mask < 8) || ($mask > 32)) do={ :error "prefix length outside bounds" }
        :local ipValue [:toip $hostText]
        :if ([:typeof $ipValue] != "ip") do={ :error "invalid IPv4" }
        :if ([:tostr $ipValue] != $hostText) do={ :error "noncanonical IPv4" }
        :if (($ipValue in 0.0.0.0/8) || ($ipValue in 10.0.0.0/8) || ($ipValue in 100.64.0.0/10) || ($ipValue in 127.0.0.0/8) || ($ipValue in 169.254.0.0/16) || ($ipValue in 172.16.0.0/12) || ($ipValue in 192.168.0.0/16) || ($ipValue in 192.0.0.0/24) || ($ipValue in 192.0.2.0/24) || ($ipValue in 198.18.0.0/15) || ($ipValue in 198.51.100.0/24) || ($ipValue in 203.0.113.0/24) || ($ipValue in 224.0.0.0/3)) do={ :error "nonpublic IPv4 rejected" }
        :local blockSize 1
        :if ($mask < 32) do={
            :for bit from=1 to=(32 - $mask) do={ :set blockSize ($blockSize * 2) }
        }
        :local ipNumber 0
        :local octetStart 0
        :for offset from=0 to=[:len $hostText] do={
            :if (($offset = [:len $hostText]) || ([:pick $hostText $offset ($offset + 1)] = ".")) do={
                :set ipNumber (($ipNumber * 256) + [:tonum [:pick $hostText $octetStart $offset]])
                :set octetStart ($offset + 1)
            }
        }
        :if (($ipNumber % $blockSize) != 0) do={ :error "network host bits must be zero" }
        :if (([:typeof $slash] = "num") && ($mask = 32)) do={ :error "hosts must omit /32" }
        :local lastAddress ($ipNumber + $blockSize - 1)
        :if ($ipNumber <= $previousEnd) do={ :error "networks must be sorted and nonoverlapping" }
        :set previousEnd $lastAddress
        :foreach forbidden in=$forbiddenRanges do={
            :if (($ipNumber <= ($forbidden->"hi")) && ($lastAddress >= ($forbidden->"lo"))) do={ :error "network overlaps nonpublic range" }
        }
        :set addressVolume ($addressVolume + $blockSize)
        :if ($addressVolume > 50000000) do={ :error "address volume exceeds 50 million" }
        :set ($netSet->$netText) true
    }
    :foreach listKind in={"vpn";"direct"} do={
        :local domains $vdoms
        :local listName "vpn_dns"
        :local resolver $vpnResolver
        :if ($listKind = "direct") do={ :set domains $ddoms; :set listName "no_vpn"; :set resolver $directResolver }
        :foreach domainName in=$domains do={
            :if ([:typeof $domainName] != "str") do={ :error "domain must be text" }
            :if (([:len $domainName] < 3) || ([:len $domainName] > 253)) do={ :error "domain size invalid" }
            :if (!($domainName ~ "^[a-z0-9-]+([.][a-z0-9-]+)+\$")) do={ :error ("invalid domain " . $domainName) }
            :if (([:typeof ($desiredDns->$domainName)] != "nil") && ([:typeof ($desiredDns->$domainName)] != "nothing")) do={ :error ("duplicate/conflicting domain " . $domainName) }
            :local labelStart 0
            :for offset from=0 to=[:len $domainName] do={
                :if (($offset = [:len $domainName]) || ([:pick $domainName $offset ($offset + 1)] = ".")) do={
                    :local label [:pick $domainName $labelStart $offset]
                    :if (([:len $label] < 1) || ([:len $label] > 63) || ([:pick $label 0 1] = "-") || ([:pick $label ([:len $label] - 1)] = "-")) do={ :error "invalid domain label" }
                    :set labelStart ($offset + 1)
                }
            }
            :set ($desiredDns->$domainName) {"list"=$listName;"resolver"=$resolver}
        }
    }
    :foreach domainName,domainSpec in=$desiredDns do={
        :local dot [:find $domainName "."]
        :while ([:typeof $dot] = "num") do={
            :local parentName [:pick $domainName ($dot + 1) [:len $domainName]]
            :if (([:typeof ($desiredDns->$parentName)] != "nil") && ([:typeof ($desiredDns->$parentName)] != "nothing")) do={ :error ("nested policy conflict: " . $domainName) }
            :set dot [:find $domainName "." ($dot + 1)]
        }
    }
    :set phase "preflight"
    # Complete ownership check before mutations; no adoption of manual records.
    :foreach rid in=[/ip firewall address-list find where list="vpn_git"] do={
        :if (([/ip firewall address-list get $rid comment] != "git") || ([/ip firewall address-list get $rid dynamic] = true) || ([/ip firewall address-list get $rid disabled] = true)) do={ :error "vpn_git contains foreign, dynamic or disabled entries" }
        :local entry [:tostr [/ip firewall address-list get $rid address]]
        :if (([:typeof ($previousNets->$entry)] != "nil") && ([:typeof ($previousNets->$entry)] != "nothing")) do={ :error "duplicate installed network" }
        :set ($previousNets->$entry) $rid
    }
    :foreach rid in=[/ip dns static find where comment="git-dns"] do={
        :if (([/ip dns static get $rid type] != "FWD") || ([/ip dns static get $rid disabled] = true) || ([/ip dns static get $rid match-subdomain] != true)) do={ :error "managed DNS record has unexpected state" }
        :local domainName [/ip dns static get $rid name]
        :if (([:typeof ($previousDns->$domainName)] != "nil") && ([:typeof ($previousDns->$domainName)] != "nothing")) do={ :error "duplicate installed domain" }
        :set ($previousDns->$domainName) {"id"=$rid;"list"=[/ip dns static get $rid address-list];"resolver"=[:tostr [/ip dns static get $rid forward-to]]}
    }
    :foreach domainName,domainSpec in=$desiredDns do={
        :local matches [/ip dns static find where name=$domainName]
        :local oldSpec ($previousDns->$domainName)
        :if (([:typeof $oldSpec] = "nil") || ([:typeof $oldSpec] = "nothing")) do={
            :if ([:len $matches] > 0) do={ :error ("foreign DNS conflict: " . $domainName) }
        } else={
            :if ([:len $matches] != 1) do={ :error ("ambiguous DNS name: " . $domainName) }
            :if ((($oldSpec->"list") != ($domainSpec->"list")) || (($oldSpec->"resolver") != ($domainSpec->"resolver"))) do={ :error ("DNS policy change requires reviewed migration: " . $domainName) }
        }
    }
    :local oldVpnCount 0
    :local oldDirectCount 0
    :foreach domainName,domainSpec in=$previousDns do={
        :if (($domainSpec->"list") = "vpn_dns") do={ :set oldVpnCount ($oldVpnCount + 1) } else={
            :if (($domainSpec->"list") = "no_vpn") do={ :set oldDirectCount ($oldDirectCount + 1) } else={ :error "unexpected managed DNS list" }
        }
    }
    :if (!$allowShrink) do={
        :if ((([:len $nets] * 4) < ([:len $previousNets] * 3)) || (([:len $vdoms] * 4) < ($oldVpnCount * 3)) || (([:len $ddoms] * 4) < ($oldDirectCount * 3))) do={ :error "shrink exceeds 25%; explicit one-shot allowance required" }
    }
    :if (!$applyChanges) do={
        :log info ("vpn-lists-v2: dry-run OK; subnets=" . [:len $nets] . "; vpn=" . [:len $vdoms] . "; direct=" . [:len $ddoms] . "; sha512=" . [:pick $digest 0 12])
        :return 0
    }
    :set phase "add"
    :set mutated true
    :foreach entry in=$nets do={
        :if (([:typeof ($previousNets->$entry)] = "nil") || ([:typeof ($previousNets->$entry)] = "nothing")) do={
            :set currentItem $entry
            :set currentId ""
            :set currentProperty "add-network"
            :local createdId [/ip firewall address-list add list=vpn_git address=$entry comment=git]
            :set newNetIds ($newNetIds, $createdId)
            :set currentId [:tostr $createdId]
            :if ([:typeof $createdId] != "id") do={ :error "network add did not return an ID" }
            :set currentProperty "read-added-network"
            :if ([:tostr [/ip firewall address-list get $createdId address]] != $entry) do={ :error "network add address mismatch" }
        }
    }
    :foreach domainName,domainSpec in=$desiredDns do={
        :if (([:typeof ($previousDns->$domainName)] = "nil") || ([:typeof ($previousDns->$domainName)] = "nothing")) do={
            :set currentItem $domainName
            :set currentId ""
            :set currentProperty "add-dns"
            :local createdId [/ip dns static add name=$domainName type=FWD forward-to=($domainSpec->"resolver") address-list=($domainSpec->"list") match-subdomain=yes disabled=no comment=git-dns]
            :set newDnsIds ($newDnsIds, $createdId)
            :set currentId [:tostr $createdId]
            :if ([:typeof $createdId] != "id") do={ :error "DNS add did not return an ID" }
            :local ids [/ip dns static find where name=$domainName comment="git-dns"]
            :if ([:len $ids] != 1) do={ :error "DNS add verification failed" }
        }
    }
    :set phase "verify-before-cleanup"
    # Re-read actual entries once; do not query typed address fields using text.
    :local verifiedNets ({})
    :set currentItem "vpn_git"
    :set currentId ""
    :set currentProperty "enumerate-networks"
    :foreach verifyId in=[/ip firewall address-list find where list="vpn_git"] do={
        :set currentId [:tostr $verifyId]
        :set currentProperty "address"
        :local verifyAddress [:tostr [/ip firewall address-list get $verifyId address]]
        :set currentItem $verifyAddress
        :set currentProperty "comment"
        :if ([/ip firewall address-list get $verifyId comment] != "git") do={ :error "foreign network before cleanup" }
        :set currentProperty "dynamic"
        :if ([/ip firewall address-list get $verifyId dynamic] = true) do={ :error "dynamic network before cleanup" }
        :set currentProperty "disabled"
        :if ([/ip firewall address-list get $verifyId disabled] = true) do={ :error "disabled network before cleanup" }
        :if (([:typeof ($verifiedNets->$verifyAddress)] != "nil") && ([:typeof ($verifiedNets->$verifyAddress)] != "nothing")) do={ :error "duplicate network before cleanup" }
        :set ($verifiedNets->$verifyAddress) true
    }
    :foreach entry in=$nets do={
        :set currentItem $entry
        :set currentId ""
        :set currentProperty "verify-network-membership"
        :if (($verifiedNets->$entry) != true) do={ :error "expected network missing before cleanup" }
    }
    :foreach domainName,domainSpec in=$desiredDns do={
        :set currentItem $domainName
        :set currentId ""
        :set currentProperty "find-dns"
        :local ids [/ip dns static find where name=$domainName type=FWD comment="git-dns"]
        :if ([:len $ids] != 1) do={ :error "expected domain missing before cleanup" }
        :local recordId [:pick $ids 0]
        :set currentId [:tostr $recordId]
        :set currentProperty "name"
        :if ([/ip dns static get $recordId name] != $domainName) do={ :error "DNS name mismatch" }
        :set currentProperty "disabled"
        :if ([/ip dns static get $recordId disabled] = true) do={ :error "DNS entry is disabled" }
        :set currentProperty "match-subdomain"
        :if ([/ip dns static get $recordId match-subdomain] != true) do={ :error "DNS match-subdomain mismatch" }
        :set currentProperty "address-list"
        :if ([/ip dns static get $recordId address-list] != ($domainSpec->"list")) do={ :error "DNS address-list mismatch" }
        :set currentProperty "forward-to"
        :if ([:tostr [/ip dns static get $recordId forward-to]] != ($domainSpec->"resolver")) do={ :error "DNS resolver mismatch" }
    }
    :set currentItem ""
    :set currentId ""
    :set currentProperty ""
    :set phase "cleanup"
    :foreach entry,rid in=$previousNets do={
        :if (([:typeof ($netSet->$entry)] = "nil") || ([:typeof ($netSet->$entry)] = "nothing")) do={
            /ip firewall address-list remove $rid
            :set removedNets ($removedNets, $entry)
        }
    }
    :foreach domainName,domainSpec in=$previousDns do={
        :if (([:typeof ($desiredDns->$domainName)] = "nil") || ([:typeof ($desiredDns->$domainName)] = "nothing")) do={
            /ip dns static remove ($domainSpec->"id")
            :set removedDns ($removedDns, $domainName)
        }
    }
    :set phase "verify-final"
    :if ([:len [/ip firewall address-list find where list="vpn_git"]] != [:len $nets]) do={ :error "final network count mismatch" }
    :if ([:len [/ip dns static find where comment="git-dns"]] != ([:len $vdoms] + [:len $ddoms])) do={ :error "final DNS count mismatch" }
    :set vpnListsV2Version $digest
    :set vpnListsV2LastVerified ([/system clock get date] . " " . [/system clock get time])
    :set vpnListsV2LastError ""
    :log info ("vpn-lists-v2: reconciled; subnets=" . [:len $nets] . "; vpn=" . [:len $vdoms] . "; direct=" . [:len $ddoms] . "; sha512=" . [:pick $digest 0 12])
} do={
    :set vpnListsV2LastError ("phase=" . $phase . "; item=" . $currentItem . "; id=" . $currentId . "; property=" . $currentProperty . "; " . $updateError)
    :log error ("vpn-lists-v2: " . $vpnListsV2LastError)
    :if ($mutated) do={
        # Compensate ordinary runtime errors. Power loss cannot be rolled back in RAM.
        :foreach entry in=$removedNets do={
            :onerror rollbackError in={ /ip firewall address-list add list=vpn_git address=$entry comment=git } do={ :set rollbackOK false; :log error ("vpn-lists-v2: rollback network: " . $rollbackError) }
        }
        :foreach domainName in=$removedDns do={
            :local domainSpec ($previousDns->$domainName)
            :onerror rollbackError in={ /ip dns static add name=$domainName type=FWD forward-to=($domainSpec->"resolver") address-list=($domainSpec->"list") match-subdomain=yes disabled=no comment=git-dns } do={ :set rollbackOK false; :log error ("vpn-lists-v2: rollback DNS: " . $rollbackError) }
        }
        :foreach rid in=$newDnsIds do={
            :onerror rollbackError in={ /ip dns static remove $rid } do={ :set rollbackOK false; :log error ("vpn-lists-v2: rollback added DNS: " . $rollbackError) }
        }
        :foreach rid in=$newNetIds do={
            :onerror rollbackError in={ /ip firewall address-list remove $rid } do={ :set rollbackOK false; :log error ("vpn-lists-v2: rollback added network: " . $rollbackError) }
        }
        :if ($rollbackOK) do={ :log warning "vpn-lists-v2: rollback commands completed; inspect state before retry" } else={ :log error "vpn-lists-v2: ROLLBACK INCOMPLETE; manual inspection required" }
    }
    :error $vpnListsV2LastError
}

