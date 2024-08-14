from collections import defaultdict, deque
from hhh import RHHH
import pandas as pd

class DNSProtection:
    def __init__(self, threshold_nxd_ratio, hierarchy_levels, k, list_expiry_limit):
        self.threshold_nxd_ratio = threshold_nxd_ratio
        self.list_expiry_limit = list_expiry_limit
        self.legitimate_traffic = defaultdict(int)
        self.blacklist = defaultdict(int)
        self.whitelist = defaultdict(int)
        self.rh_legit = RHHH(hierarchy_levels, k)
        self.rh_attack = RHHH(hierarchy_levels, k)
        self.total_queries = 0
        self.queries = 0
        self.total_nxd = 0
        self.nxd = 0
        self.tp = 0
        self.fp = 0
        self.tn = 0
        self.fn = 0
        self.debug_log = []

    def log_normal_traffic(self, packet):
        source = packet['Source']
        # self.legitimate_traffic[source] += 1
        self.rh_legit.update(source, legitimate=True)

    def packet_allowed(self, packet):
        source = packet['Source']
        
        # Clean up expired entries from blacklist and whitelist
        self.cleanup_lists()

        if source in self.blacklist:
            self.blacklist[source] += 1
            self.debug_log.append((packet, "Block", "Blacklisted"))
            return "Block"
        if source in self.whitelist:
            self.whitelist[source] += 1
            self.debug_log.append((packet, "Allow", "Whitelisted"))
            return "Allow"

        if self.is_under_attack():
            if self.should_block(source):
                self.blacklist[source] = 1  # Add to blacklist with initial count
                self.debug_log.append((packet, "Block", "Attack detected"))
                return "Block"
            else:
                self.whitelist[source] = 1  # Add to whitelist with initial count
                self.debug_log.append((packet, "Allow", "Attack not detected"))
                return "Allow"
        else:
            self.debug_log.append((packet, "Allow", "Normal traffic"))
            return "Allow"

    def process_packet(self, packet):
        alowed = self.packet_allowed(packet)
        source = packet['Source']

        self.total_queries += 1
        self.queries += 1

        nxd_flg = self.is_nxd(packet)
        if nxd_flg:
            self.total_nxd += 1
            self.nxd += 1
            self.rh_attack.update(source)
        else:
            self.log_normal_traffic(packet)

        if alowed == 'Allow':
            if not nxd_flg:
                self.tp += 1
            if nxd_flg:
                self.fp += 1
        if alowed == 'Block':
            if nxd_flg:
                self.tn += 1
            if not nxd_flg:
                self.fn += 1

        return alowed

    def is_nxd(self, packet):
        return packet['Legitimate'] == 'False' or packet['Legitimate'] == False

    def is_under_attack(self):
        # if self.total_queries == 0:
        if self.queries == 0:
            return False
        # current_nxd_ratio = self.total_nxd / self.total_queries
        current_nxd_ratio = self.nxd / self.queries
        return current_nxd_ratio > self.threshold_nxd_ratio

    def should_block(self, source):
        legit_freq = self.rh_legit.func(source)
        attack_freq = self.rh_attack.func(source)

        # Compare adjusted conditioned frequencies
        return attack_freq > legit_freq

    def cleanup_lists(self):
        # Remove expired entries from blacklist
        if self.total_queries % self.list_expiry_limit == 0:
            self.queries = self.queries // 2
            self.nxd = self.nxd // 2
            for source, count in self.blacklist.items():
                self.blacklist[source] = count // 2

        expired_blacklist = [source for source, count in self.blacklist.items() if count == 0 or not self.should_block(source)]
        for source in expired_blacklist:
            del self.blacklist[source]

        # Remove expired entries from whitelist
        if self.total_queries % self.list_expiry_limit == 0:
            for source, count in self.whitelist.items():
                self.whitelist[source] = count // 2

        expired_whitelist = [source for source, count in self.whitelist.items() if count == 0 or self.should_block(source)]
        for source in expired_whitelist:
            del self.whitelist[source]

def simulate_attack(hierarchy_levels, threshold_nxd_ratio, list_expiry_limit, k, packets):
    dns_protection = DNSProtection(
        threshold_nxd_ratio=threshold_nxd_ratio, 
        hierarchy_levels=hierarchy_levels, 
        k=k, 
        list_expiry_limit=list_expiry_limit  
    )

    for packet in packets:
        _ = dns_protection.process_packet(packet)
    return dns_protection
