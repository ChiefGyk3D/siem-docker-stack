<?php
// ONE-TIME change note kept in git for a rebuild, NOT part of the alert deploy and
// not run automatically. It edits the firewall configuration: read it and run it
// by hand on the firewall only if the same two feeds are broken again.
//
// Two pfBlockerNG DNSBL feed fixes (investigation: pfsense-siem-stack#66, tracked in #67).
//  1. AZORult_BD: the source site is dead (origin down): set the row to Disabled.
//  2. urlhause_abuse_malicious: the keyless abuse.ch URL returns 410 Gone: use the
//     keyless malware-filter mirror of the same data.
// Changes only these two rows. Prints plain status words, never a full URL with a key.
require_once("config.inc");
global $config;

$new_url = "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt";
$old_url = "https://urlhaus.abuse.ch/downloads/hostfile/";
$done = array();

$groups = $config["installedpackages"]["pfblockerngdnsbl"]["config"];
foreach (array_keys($groups) as $gi) {
    $alias = $groups[$gi]["aliasname"];
    foreach (array_keys((array)$groups[$gi]["row"]) as $ri) {
        $row = $groups[$gi]["row"][$ri];
        if ($alias === "Malicious2" && $row["header"] === "AZORult_BD"
            && strpos($row["url"], "azorult-tracker.net") !== false) {
            $config["installedpackages"]["pfblockerngdnsbl"]["config"][$gi]["row"][$ri]["state"] = "Disabled";
            $done[] = "AZORult_BD set to Disabled";
        }
        if ($alias === "Firebog_Malicious" && $row["header"] === "urlhause_abuse_malicious"
            && $row["url"] === $old_url) {
            $config["installedpackages"]["pfblockerngdnsbl"]["config"][$gi]["row"][$ri]["url"] = $new_url;
            $done[] = "urlhause_abuse_malicious URL replaced";
        }
    }
}

if (count($done) !== 2) {
    echo "unexpected state, nothing written: " . implode("; ", $done) . "\n";
    exit(1);
}
write_config("pfBlockerNG: disable dead AZORult_BD feed and move the URLhaus feed to a working mirror (fixes 2 failing downloads)");
echo implode("; ", $done) . "\n";
