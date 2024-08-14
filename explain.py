import streamlit as st

def page_hhh_explanation():
    st.title('HHH and DNS Protection Explanation')

    st.write("""
        ## Hierarchical Heavy Hitters (HHH)
        The Hierarchical Heavy Hitters (HHH) algorithm is designed to identify aggregates of network traffic 
        that share common IP prefixes and are responsible for a significant portion of the traffic. The hierarchy 
        is determined by the structure of the IP addresses.

        ### Key Concepts:
        - **Heavy Hitters (HH)**: In network monitoring, a heavy hitter is an entity (like an IP address) that contributes a large portion of the traffic.
        - **Hierarchical Structure**: IP addresses can be viewed in a hierarchy based on their prefixes (e.g., 192.168.*.*). The HHH algorithm identifies heavy hitters at various levels of this hierarchy.
        - **Space-Saving Algorithm**: A core component of the HHH algorithm is the use of a space-saving technique, which efficiently tracks the most frequent items (or prefixes) in the data stream.

        ### RHHH (Randomized HHH)
        The RHHH is a variant of the HHH algorithm that introduces randomness to reduce computational overhead. Instead of updating every level in the hierarchy for each incoming packet, RHHH randomly selects a level to update. 
        This approach ensures that the algorithm runs in constant time while maintaining probabilistic guarantees on accuracy and coverage.

        ### How It Works:
        - **Initialization**: The algorithm initializes a heavy-hitters detection instance for each level of the hierarchy.
        - **Update**: For each packet, a random level in the hierarchy is selected, and the relevant heavy-hitter algorithm at that level is updated with the packet’s prefix.
        - **Output**: The algorithm periodically aggregates results from all levels to produce a set of hierarchical heavy hitters.

        ## NXD (Non-Existent Domain) Detection and DNS Protection
        NXD detection is crucial in identifying DNS-based attacks, such as DDoS (Distributed Denial of Service) attacks, where attackers flood a DNS server with requests for non-existent domains.

        ### NXD Detection
        In this project, we implements a DNS protection mechanism that monitors the ratio of NXD responses to legitimate DNS queries. A high NXD ratio may indicate an ongoing attack.
        - The algorithm logs normal traffic patterns and uses this baseline to detect anomalies. When the NXD ratio exceeds a predefined threshold, the system considers it a potential attack.

        ## DNS Protection Mechanism
        The DNS protection mechanism in this project is designed to safeguard DNS servers from DDoS attacks, particularly those involving Non-Existent Domain (NXD) queries.

        ### Blacklist and Whitelist
        - **Dynamic Lists**: The algorithm uses two lists: a blacklist and a whitelist. The blacklist contains IP addresses that are suspected of being involved in an attack, while the whitelist contains IP addresses identified as legitimate.
        - **Use of RHHH (Randomized Hierarchical Heavy Hitters)**: The algorithm leverages the RHHH technique to maintain and update these lists. It tracks the hierarchical heavy hitters separately for legitimate traffic and suspected attack traffic.
        - **List Management**: The algorithm dynamically updates these lists as it monitors incoming DNS queries. IP addresses can be added to or removed from these lists based on their behavior over time.

        ### How the Algorithm Works:
        1. **Monitoring Traffic with RHHH**:
           - The algorithm uses two instances of the RHHH algorithm: one for tracking legitimate traffic and another for tracking potential attack traffic.
           - For each incoming DNS query, the algorithm updates the relevant RHHH instance based on whether the traffic is identified as legitimate or suspicious.
           - This allows the algorithm to maintain a hierarchical view of both types of traffic, ensuring that it can effectively distinguish between normal and attack patterns.

        2. **NXD Detection**:
           - The algorithm tracks the ratio of Non-Existent Domain (NXD) responses to the total number of queries from each IP address.
           - A high NXD ratio may indicate that the IP is generating malicious traffic, possibly part of a DDoS attack.
           - The RHHH algorithm helps aggregate and identify IP prefixes that are generating a significant number of NXD responses, which can then be flagged as suspicious.

        3. **Deciding on Blocking or Allowing Traffic**:
           - **Normal Conditions**: Under normal conditions, the algorithm primarily monitors and logs traffic, updating the blacklist and whitelist using the insights provided by the RHHH algorithm.
           - **During an Attack**:
             - If the NXD ratio for a given IP exceeds a predefined threshold, the algorithm considers this IP to be part of a potential attack.
             - The IP address is then added to the blacklist, and all future queries from this IP are blocked. The decision is based on the hierarchical analysis performed by the RHHH.
             - Conversely, if the NXD ratio remains low, the IP may be added to or maintained on the whitelist, ensuring its queries are allowed.

        4. **Handling Expired or Stale Entries**:
           - To prevent the blacklist and whitelist from becoming outdated, the algorithm periodically reviews and cleans up these lists.
           - IP addresses that have not been active for a certain period or whose behavior has normalized may be removed from the blacklist.
           - The whitelist is also periodically reviewed to ensure that it only contains currently active and legitimate IP addresses.

        ### Attack Response
        - **Selective Blocking with RHHH**: When an attack is detected, the algorithm selectively blocks traffic based on the blacklist, minimizing disruption to legitimate users. The use of RHHH ensures that only significant attack sources are targeted.
        - **Protection Against Collateral Damage**: The whitelist, maintained with the help of RHHH, ensures that legitimate traffic continues to flow, even during an attack, reducing the risk of collateral damage.
        - **Adaptation to Traffic Patterns**: As traffic patterns evolve, the algorithm adapts by dynamically updating the blacklist and whitelist using RHHH, ensuring ongoing protection against both known and emerging threats.

        The overall goal of this DNS protection mechanism is to efficiently block malicious traffic while allowing legitimate queries to pass through, maintaining the availability and integrity of the DNS service even under attack conditions.
    
        ## Implementation in This Project
        ### Simulation of DDoS Attacks
        - We simulate NXD attacks by generating DNS traffic traces, including legitimate and malicious requests. 
          The attack simulation allows you to test the effectiveness of the RHHH algorithm and the DNS protection mechanism.
        - Parameters such as the number of packets, botnets, shared subnet levels, and NXD volume can be adjusted to simulate different attack scenarios.

        ### Visualization and Analysis
        - This project provides visualizations for the distribution of packets over time, the performance of the detection algorithm (TP, FP, TN, FN), and a comparison of legitimate versus attack traffic.
        - The top 5 IPs by traffic volume are also displayed to help identify the most significant sources of traffic during the simulation.

        ## Related Concepts from the Paper
        The paper on HHH highlights the challenges of real-time network monitoring, especially in detecting anomalies like DDoS attacks. 
        The proposed RHHH algorithm improves upon previous HHH approaches by offering faster update times and maintaining accuracy with fewer computational resources. 
        This project implementation of this algorithm demonstrates its practical application in DNS attack detection and mitigation.
    """)
