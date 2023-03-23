rule redline_stealer {
  meta:
    description = "Detects Redline Stealer malware"
    author = "Fevar54"
    reference = "https://www.openanalysis.net/2020/02/19/malware-analysis-redline-stealer/"
  strings:
    $str1 = "RedLineStealer" nocase
    $str2 = "RLST" nocase
  condition:
    any of them
}
