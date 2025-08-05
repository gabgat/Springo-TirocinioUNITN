import os
import json
from execute_command import execute_command


class Dig:
    def __init__(self, ip, port, tools_dir, timestamp):
        self.ip = ip
        self.port = port
        self.tools_dir = tools_dir
        self.timestamp = timestamp
        self.output_file = os.path.join(tools_dir, f"dig_{self.port}_{self.timestamp}.json")

    def run_dig(self):
        """Execute all DNS vulnerability tests and return only vulnerable results"""
        vulnerable_results = []

        # Run all tests and collect only vulnerable results
        tests = [
            self.version_disclosure,
            self.hostname_disclosure,
            self.server_id_disclosure,
            self.authors_disclosure,
            self.test_recursion_google,
            #self.test_recursion_cloudflare,
            self.test_amplification_any,
            self.test_amplification_txt,
            self.test_dnssec_amplification,
            self.test_mx_records,
            self.test_zone_transfer_root,
            self.test_zone_transfer_local,
            self.test_zone_transfer_internal,
            self.test_zone_transfer_corp,
            self.test_tcp_fallback,
            self.test_edns_support,
            self.test_edns_disable,
            self.test_reverse_lookup,
            self.test_wildcard_query,
            self.test_ns_records,
            self.test_soa_records,
            self.test_ipv6_query,
            self.test_malformed_query,
            self.test_long_domain_query,
            self.test_unusual_flags,
            self.test_cache_poisoning,
            self.test_subdomain_enumeration,
            self.test_dns_tunneling,
            self.test_rate_limiting,
        ]

        for test_func in tests:
            try:
                result = test_func()
                if result is not None:
                    vulnerable_results.append(result)
            except Exception as e:
                print(f"Error running {test_func.__name__}: {e}")

        # Write only the vulnerable results to the output file
        try:
            with open(self.output_file, 'w') as f:
                json.dump(vulnerable_results, f, indent=2)
        except Exception as e:
            print(f"Error writing results to {self.output_file}: {e}")

        return vulnerable_results

    def version_disclosure(self):
        """Test for version information disclosure via CHAOS class queries"""
        cmd = f"dig @{self.ip} -c CHAOS -t TXT version.bind"
        result = execute_command(cmd, "Dig Version", self.output_file, self.ip)

        if not result.get("success", False):
            # Check for NOTIMP responses as they indicate protocol handling issues
            output = result.get("output", "").lower()
            if "notimp" in output or "missing question section" in output:
                result["vulnerability_type"] = "protocol_issue"
                result["severity"] = "medium"
                result["description"] = "DNS server shows protocol implementation issues with CHAOS queries"
                return result
            return None

        output = result.get("output", "").lower()

        # Check for actual version disclosure (like "ZyWALL DNS")
        if ('"' in output and
                "unknown" not in output and
                "refused" not in output and
                "notimp" not in output and
                "answer: 1" in output):
            result["vulnerability_type"] = "information_disclosure"
            result["severity"] = "low"
            result["description"] = "DNS server discloses version information via CHAOS queries"
            return result

        return None

    def hostname_disclosure(self):
        """Test for hostname information disclosure"""
        cmd = f"dig @{self.ip} -c CHAOS -t TXT hostname.bind"
        result = execute_command(cmd, "Dig Hostname", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        if ('"' in output and
                "unknown" not in output and
                "refused" not in output and
                "notimp" not in output and
                "answer: 1" in output):
            result["vulnerability_type"] = "information_disclosure"
            result["severity"] = "low"
            result["description"] = "DNS server discloses hostname information"
            return result
        return None

    def server_id_disclosure(self):
        """Test for server ID information disclosure"""
        cmd = f"dig @{self.ip} -c CHAOS -t TXT id.server"
        result = execute_command(cmd, "Dig Server ID", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        if ('"' in output and
                "unknown" not in output and
                "refused" not in output and
                "notimp" not in output and
                "answer: 1" in output):
            result["vulnerability_type"] = "information_disclosure"
            result["severity"] = "low"
            result["description"] = "DNS server discloses server ID information"
            return result
        return None

    def authors_disclosure(self):
        """Test for authors information disclosure"""
        cmd = f"dig @{self.ip} -c CHAOS -t TXT authors.bind"
        result = execute_command(cmd, "Dig Authors", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        if ('"' in output and
                "unknown" not in output and
                "refused" not in output and
                "notimp" not in output and
                "answer: 1" in output):
            result["vulnerability_type"] = "information_disclosure"
            result["severity"] = "low"
            result["description"] = "DNS server discloses authors information"
            return result
        return None

    def test_recursion_google(self):
        """Test if server acts as open resolver with Google DNS"""
        cmd = f"dig @{self.ip} google.com A"
        result = execute_command(cmd, "Dig Recursion Google", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        if ("answer:" in output and
                not "answer: 0" in output and
                "noerror" in output and
                "recursion requested but not available" not in output):
            result["vulnerability_type"] = "open_resolver"
            result["severity"] = "high"
            result["description"] = "DNS server acts as open resolver - can be used for DDoS amplification"
            return result
        return None

    # def test_recursion_cloudflare(self):
    #     """Test if server acts as open resolver with Cloudflare"""
    #     cmd = f"dig @{self.ip} cloudflare.com A"
    #     result = execute_command(cmd, "Dig Recursion CF", self.output_file, self.ip)
    #
    #     if not result.get("success", False):
    #         return None
    #
    #     output = result.get("output", "").lower()
    #
    #     if ("answer:" in output and
    #             not "answer: 0" in output and
    #             "noerror" in output and
    #             "recursion requested but not available" not in output):
    #         result["vulnerability_type"] = "open_resolver"
    #         result["severity"] = "high"
    #         result["description"] = "DNS server acts as open resolver - can be used for DDoS amplification"
    #         return result
    #     return None

    def test_amplification_any(self):
        """Test for DNS amplification potential with ANY query"""
        cmd = f"dig @{self.ip} google.com ANY"
        result = execute_command(cmd, "Dig Amplification ANY", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        # Check for large responses or multiple answers
        if (("answer:" in output and not "answer: 0" in output) or
                any(size in output for size in ["1024", "2048", "4096", "8192"])):
            result["vulnerability_type"] = "amplification"
            result["severity"] = "high"
            result["description"] = "DNS server vulnerable to amplification attacks via ANY queries"
            return result
        return None

    def test_amplification_txt(self):
        """Test for DNS amplification with large TXT records"""
        cmd = f"dig @{self.ip} google.com TXT"
        result = execute_command(cmd, "Dig Amplification TXT", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        if (("answer:" in output and not "answer: 0" in output) or
                any(size in output for size in ["1024", "2048", "4096", "8192"])):
            result["vulnerability_type"] = "amplification"
            result["severity"] = "medium"
            result["description"] = "DNS server may be vulnerable to amplification attacks via TXT queries"
            return result
        return None

    def test_dnssec_amplification(self):
        """Test for DNSSEC-related amplification"""
        cmd = f"dig @{self.ip} +dnssec google.com A"
        result = execute_command(cmd, "Dig DNSSEC Amp", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        if (("answer:" in output and not "answer: 0" in output) or
                any(size in output for size in ["2048", "4096", "8192"])):
            result["vulnerability_type"] = "amplification"
            result["severity"] = "high"
            result["description"] = "DNS server vulnerable to DNSSEC amplification attacks"
            return result
        return None

    def test_zone_transfer_root(self):
        """Attempt zone transfer on root zone"""
        cmd = f"dig @{self.ip} . AXFR"
        result = execute_command(cmd, "Dig AXFR Root", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        if ("transfer failed" not in output and
                "refused" not in output and
                "answer:" in output and not "answer: 0" in output):
            result["vulnerability_type"] = "zone_transfer"
            result["severity"] = "critical"
            result["description"] = "DNS server allows unauthorized zone transfers"
            return result
        return None

    def test_zone_transfer_local(self):
        """Attempt zone transfer on common local domains"""
        cmd = f"dig @{self.ip} local AXFR"
        result = execute_command(cmd, "Dig AXFR Local", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        if ("transfer failed" not in output and
                "refused" not in output and
                "answer:" in output and not "answer: 0" in output):
            result["vulnerability_type"] = "zone_transfer"
            result["severity"] = "critical"
            result["description"] = "DNS server allows unauthorized zone transfers for local domain"
            return result
        return None

    def test_zone_transfer_internal(self):
        """Attempt zone transfer on internal domain"""
        cmd = f"dig @{self.ip} internal AXFR"
        result = execute_command(cmd, "Dig AXFR Internal", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        if ("transfer failed" not in output and
                "refused" not in output and
                "answer:" in output and not "answer: 0" in output):
            result["vulnerability_type"] = "zone_transfer"
            result["severity"] = "critical"
            result["description"] = "DNS server allows unauthorized zone transfers for internal domain"
            return result
        return None

    def test_zone_transfer_corp(self):
        """Attempt zone transfer on corp domain"""
        cmd = f"dig @{self.ip} corp AXFR"
        result = execute_command(cmd, "Dig AXFR Corp", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        if ("transfer failed" not in output and
                "refused" not in output and
                "answer:" in output and not "answer: 0" in output):
            result["vulnerability_type"] = "zone_transfer"
            result["severity"] = "critical"
            result["description"] = "DNS server allows unauthorized zone transfers for corp domain"
            return result
        return None

    def test_tcp_fallback(self):
        """Test TCP fallback behavior"""
        cmd = f"dig @{self.ip} +tcp google.com A"
        result = execute_command(cmd, "Dig TCP Fallback", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        if "refused" not in output and "answer:" in output and not "answer: 0" in output:
            result["vulnerability_type"] = "open_resolver"
            result["severity"] = "medium"
            result["description"] = "DNS server accepts TCP queries and may act as open resolver"
            return result
        return None

    def test_edns_support(self):
        """Test EDNS support and buffer size"""
        cmd = f"dig @{self.ip} +edns=0 +bufsize=4096 google.com A"
        result = execute_command(cmd, "Dig EDNS Support", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        if "refused" not in output and "answer:" in output and not "answer: 0" in output:
            result["vulnerability_type"] = "amplification"
            result["severity"] = "medium"
            result["description"] = "DNS server supports large EDNS buffer sizes - potential for amplification"
            return result
        return None

    def test_edns_disable(self):
        """Test behavior with EDNS disabled"""
        cmd = f"dig @{self.ip} +noedns google.com A"
        result = execute_command(cmd, "Dig No EDNS", self.output_file, self.ip)

        # Check for failed commands or protocol issues
        if not result.get("success", False) or result.get("return_code", 0) != 0:
            output = result.get("output", "").lower()
            if ("notimp" in output or
                    "formerr" in output or
                    "missing question section" in output):
                result["vulnerability_type"] = "protocol_issue"
                result["severity"] = "medium"
                result["description"] = "DNS server has protocol implementation issues with EDNS disabled"
                return result

        return None

    def test_reverse_lookup(self):
        """Test reverse DNS lookup capabilities"""
        cmd = f"dig @{self.ip} -x 8.8.8.8"
        result = execute_command(cmd, "Dig Reverse Lookup", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        if "refused" not in output and "answer:" in output and not "answer: 0" in output:
            result["vulnerability_type"] = "open_resolver"
            result["severity"] = "medium"
            result["description"] = "DNS server performs reverse lookups for external IPs"
            return result
        return None

    def test_wildcard_query(self):
        """Test wildcard domain responses"""
        cmd = f"dig @{self.ip} nonexistent.google.com A"
        result = execute_command(cmd, "Dig Wildcard", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        if "refused" not in output and "answer:" in output and not "answer: 0" in output:
            result["vulnerability_type"] = "wildcard_misconfiguration"
            result["severity"] = "medium"
            result["description"] = "DNS server returns answers for non-existent domains (wildcard misconfiguration)"
            return result
        return None

    def test_mx_records(self):
        """Test MX record queries for amplification potential"""
        cmd = f"dig @{self.ip} google.com MX"
        result = execute_command(cmd, "Dig MX Records", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        if (("answer:" in output and not "answer: 0" in output) or
                any(size in output for size in ["1024", "2048", "4096"])):
            result["vulnerability_type"] = "amplification"
            result["severity"] = "medium"
            result["description"] = "DNS server may be vulnerable to amplification via MX queries"
            return result
        return None

    def test_ns_records(self):
        """Test NS record queries"""
        cmd = f"dig @{self.ip} google.com NS"
        result = execute_command(cmd, "Dig NS Records", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        if "refused" not in output and "answer:" in output and not "answer: 0" in output:
            result["vulnerability_type"] = "open_resolver"
            result["severity"] = "medium"
            result["description"] = "DNS server resolves NS records for external domains"
            return result
        return None

    def test_soa_records(self):
        """Test SOA record queries"""
        cmd = f"dig @{self.ip} google.com SOA"
        result = execute_command(cmd, "Dig SOA Records", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        if "refused" not in output and "answer:" in output and not "answer: 0" in output:
            result["vulnerability_type"] = "open_resolver"
            result["severity"] = "medium"
            result["description"] = "DNS server resolves SOA records for external domains"
            return result
        return None

    def test_ipv6_query(self):
        """Test IPv6 AAAA record queries"""
        cmd = f"dig @{self.ip} google.com AAAA"
        result = execute_command(cmd, "Dig IPv6 Query", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        if "refused" not in output and "answer:" in output and not "answer: 0" in output:
            result["vulnerability_type"] = "open_resolver"
            result["severity"] = "medium"
            result["description"] = "DNS server resolves IPv6 records for external domains"
            return result
        return None

    def test_malformed_query(self):
        """Test with intentionally malformed query"""
        cmd = f"dig @{self.ip} invalid..domain.com A"
        result = execute_command(cmd, "Dig Malformed", self.output_file, self.ip)

        # Check for protocol issues
        if not result.get("success", False) or result.get("return_code", 0) != 0:
            output = result.get("output", "").lower()
            if ("notimp" in output or
                    "formerr" in output or
                    "missing question section" in output):
                result["vulnerability_type"] = "protocol_issue"
                result["severity"] = "medium"
                result["description"] = "DNS server has issues handling malformed queries"
                return result

        return None

    def test_long_domain_query(self):
        """Test with very long domain name"""
        long_domain = "a" * 60 + ".com"
        cmd = f"dig @{self.ip} {long_domain} A"
        result = execute_command(cmd, "Dig Long Domain", self.output_file, self.ip)

        # Check for protocol issues
        if not result.get("success", False) or result.get("return_code", 0) != 0:
            output = result.get("output", "").lower()
            if ("notimp" in output or
                    "formerr" in output or
                    "missing question section" in output):
                result["vulnerability_type"] = "protocol_issue"
                result["severity"] = "medium"
                result["description"] = "DNS server has issues handling long domain queries"
                return result

        return None

    def test_unusual_flags(self):
        """Test with unusual DNS flags"""
        cmd = f"dig @{self.ip} +norecurse +noadd google.com A"
        result = execute_command(cmd, "Dig Unusual Flags", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        if "refused" not in output and "answer:" in output and not "answer: 0" in output:
            result["vulnerability_type"] = "open_resolver"
            result["severity"] = "low"
            result["description"] = "DNS server responds to queries with unusual flags"
            return result
        return None

    def test_cache_poisoning(self):
        """Test for potential cache poisoning vulnerabilities"""
        cmd = f"dig @{self.ip} +norecurse example.com A"
        result = execute_command(cmd, "Dig Cache Poisoning", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        # Check if server provides answers when recursion is disabled but still resolves
        if ("refused" not in output and "answer:" in output and not "answer: 0" in output and
                "recursion requested but not available" not in output):
            result["vulnerability_type"] = "cache_poisoning"
            result["severity"] = "medium"
            result["description"] = "DNS server may be vulnerable to cache poisoning attacks"
            return result
        return None

    def test_subdomain_enumeration(self):
        """Test for subdomain enumeration potential"""
        cmd = f"dig @{self.ip} www.google.com A"
        result = execute_command(cmd, "Dig Subdomain Enum", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        if "refused" not in output and "answer:" in output and not "answer: 0" in output:
            result["vulnerability_type"] = "subdomain_enumeration"
            result["severity"] = "low"
            result["description"] = "DNS server allows subdomain enumeration"
            return result
        return None

    def test_dns_tunneling(self):
        """Test for DNS tunneling detection"""
        cmd = f"dig @{self.ip} TXT test.example.com"
        result = execute_command(cmd, "Dig DNS Tunneling", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        if "refused" not in output and ("answer:" in output and not "answer: 0" in output):
            result["vulnerability_type"] = "dns_tunneling"
            result["severity"] = "medium"
            result["description"] = "DNS server may allow DNS tunneling via TXT records"
            return result
        return None

    def test_rate_limiting(self):
        """Test for rate limiting implementation"""
        cmd = f"dig @{self.ip} google.com A"
        result = execute_command(cmd, "Dig Rate Limiting", self.output_file, self.ip)

        if not result.get("success", False):
            return None

        output = result.get("output", "").lower()

        # If server responds normally without rate limiting indicators
        if ("refused" not in output and "answer:" in output and
                "rate limit" not in output and "too many queries" not in output):
            result["vulnerability_type"] = "no_rate_limiting"
            result["severity"] = "low"
            result["description"] = "DNS server does not appear to implement rate limiting"
            return result
        return None