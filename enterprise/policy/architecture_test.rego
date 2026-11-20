package main

test_safe_topology if {
  cfg := parse_config_file("json", "enterprise/architecture.json")
  count(deny with input as cfg) == 0
}

test_denied_topology if {
  cfg := parse_config_file("json", "enterprise/fixtures/architecture-denied.json")
  count(deny with input as cfg) >= 4
}
