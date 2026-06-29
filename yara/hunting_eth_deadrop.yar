rule Hunting_ETH_Deadrop_C2
{
  meta:
      author = "@iossefy"
      date = "2026-06-18"
      description = "Low-confidence hunt for potential Ethereum dead-drop C2 activity"
      confidence  = "low"
      reference = "https://github.com/iossefy/signatures"

  strings:
      $jsonrpc = "\"jsonrpc\"" ascii wide
      $method  = "\"method\":\"eth_call\"" ascii wide
      $params  = "\"params\""  ascii wide
      $to      = "\"to\":"     ascii wide
      $data    = "\"data\":\"0x" ascii wide

  condition:
      all of them
}
