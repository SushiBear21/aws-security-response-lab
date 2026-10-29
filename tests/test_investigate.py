import unittest

from app.investigate import public_ssh_rules


def rule(protocol="tcp", start=22, end=22, **changes):
    result = {
        "IsEgress": False,
        "IpProtocol": protocol,
        "FromPort": start,
        "ToPort": end,
        "CidrIpv4": "0.0.0.0/0",
    }
    result.update(changes)
    return result


class InvestigationTests(unittest.TestCase):
    def test_public_ssh_matches(self):
        self.assertEqual(len(public_ssh_rules([rule()])), 1)

    def test_private_ssh_does_not_match(self):
        self.assertEqual(
            public_ssh_rules([rule(CidrIpv4="10.77.0.0/24")]), []
        )

    def test_public_https_does_not_match(self):
        self.assertEqual(public_ssh_rules([rule(start=443, end=443)]), [])

    def test_port_range_including_ssh_matches(self):
        self.assertEqual(
            len(public_ssh_rules([rule(start=20, end=25)])), 1
        )

    def test_ipv6_all_protocols_matches(self):
        value = rule(
            protocol="-1",
            CidrIpv4=None,
            CidrIpv6="::/0",
        )
        self.assertEqual(len(public_ssh_rules([value])), 1)

    def test_egress_does_not_match(self):
        self.assertEqual(public_ssh_rules([rule(IsEgress=True)]), [])


if __name__ == "__main__":
    unittest.main()