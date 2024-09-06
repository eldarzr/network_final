import streamlit as st

def algo_explain():
    # Initialization
    st.write("### 1. Initialization")
    st.write("""
    When the server starts, it initializes several components:
    - **Legitimate traffic tracker**: Tracks legitimate DNS requests using RHHH.
    - **Attack tracker**: Tracks suspicious or malicious DNS requests using RHHH.
    - **Counters**: The algorithm uses counters to track how many packets have been processed so far and how many of them were identified as attacks.
    - **Thresholds**: Various thresholds are set, such as the ratio of non-existent domain (NXD) queries that might indicate an attack.
    """)

    # Cleanup and Aging
    st.write("### 2. Cleanup and Aging")
    st.write("""
    After each period of packet processing (defined by the user), the algorithm decreases all the counters and trackers by the aging factor (also provided by the user).
    """)

    # Attack Detection
    st.write("### 3. Attack Detection")
    st.write("""
    The algorithm continuously monitors the ratio of NXD queries compared to the total number of queries:
    - **Under Attack**: If this ratio exceeds the `upper_threshold_nxd_ratio`, the algorithm enters the "under attack" state.
    - **No Attack**: If this ratio falls below the `lower_threshold_nxd_ratio`, the algorithm exits the "under attack" state.
    """)

    # Decision on Each Packet
    st.write("### 4. Decision on Each Packet")
    st.write("""
    - **Legitimate vs Malicious**:
      The algorithm compares how frequently a source appears in the legitimate traffic tracker versus the attack tracker.
      - If the algorithm is in the "under attack" state, it checks if the ratio between the attack tracker of the source and the legitimate tracker is greater than the `lower_attack_threshold_ratio` (defined by the user).
      - If the algorithm is not in the "under attack" state, it checks if the ratio between the attack tracker of the source and the legitimate tracker is greater than the `upper_attack_threshold_ratio` (defined by the user).
    - **Block or Allow**: Based on the analysis, the packet is either blocked or allowed to reach the DNS server.
    """)

    # Processing Each Packet
    st.write("### 5. Processing Each Packet")
    st.write("""
    For every DNS packet received:
    1. **Check legitimacy**: If the algorithm decides to allow the packet, it is forwarded to the DNS resolver, which returns the decision on whether the packet is legitimate or a potential NXD attack.
    2. **Update trackers**: 
       - If legitimate, the packet’s source is logged in the legitimate traffic tracker.
       - If malicious (NXD), the source is added to the attack tracker.
    3. **Update Ccunters**: Our algorithm updates internal counters such as the total number of queries and NXDs.
    """)
