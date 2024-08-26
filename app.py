import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from hhh import RHHH
from attack_traces import *
import nxd_detecter as nxd
from explain import page_hhh_explanation 

def simulate_ddos_attack(hierarchy_levels, upper_threshold_nxd_ratio, lower_threshold_nxd_ratio,
                    upper_attack_threshold_ratio, lower_attack_threshold_ratio, list_expiry_limit,
                    aging, k, dataset):

    list_of_dicts = [row.to_dict() for index, row in dataset.iterrows()]
    nxd_sim = nxd.simulate_attack(hierarchy_levels, upper_threshold_nxd_ratio, lower_threshold_nxd_ratio,
                    upper_attack_threshold_ratio, lower_attack_threshold_ratio, list_expiry_limit, aging, k, list_of_dicts)
    return nxd_sim, list_of_dicts

def colored_ip_line(part1, part2):
    return f"<span style='color: red;'>{part1}</span>.<span style='color: blue;'>{part2}</span>"

def plot_statistics(packets, tp, fp, tn, fn):
    packet_times = {}
    packet_sources = {}
    for packet in packets:
        time = round(packet['Time'], 2)
        if time not in packet_times:
            packet_times[time] = 0
        if packet['Source'] not in packet_sources:
            packet_sources[packet['Source']] = 0
        packet_times[time] += 1
        packet_sources[packet['Source']] += 1

    # Packet Distribution over Time
    plt.figure(figsize=(10, 6))
    plt.plot(list(packet_times.keys()), list(packet_times.values()), color='blue')
    plt.title('Packet Distribution Over Time')
    plt.xlabel('Time')
    plt.ylabel('Frequency')
    plt.grid(True)
    st.pyplot(plt.gcf())  # Use st.pyplot to display the plot in Streamlit

    # Detection Performance with values
    plt.figure(figsize=(6, 4))
    performance_labels = ['TP', 'FP', 'TN', 'FN']
    performance_values = [tp, fp, tn, fn]
    plt.bar(performance_labels, performance_values, color=['green', 'red', 'green', 'red'])
    for i, v in enumerate(performance_values):
        plt.text(i, v + max(performance_values) * 0.01, str(v), ha='center')
    plt.title('Detection Performance')
    plt.ylabel('Count')
    st.pyplot(plt.gcf())

    # Legitimate vs Attack Traffic
    legitimate_traffic = [p for p in packets if p['Legitimate']]
    attack_traffic = [p for p in packets if not p['Legitimate']]  # Adjusted this line
    plt.figure(figsize=(6, 4))
    plt.bar(['Legitimate Traffic', 'Attack Traffic'], [len(legitimate_traffic), len(attack_traffic)], color=['blue', 'orange'])
    plt.title('Legitimate vs Attack Traffic')
    plt.ylabel('Count')
    st.pyplot(plt.gcf())

    # Additional Information (shared subnet)
    subnet = st.session_state['subnet']
    st.write("### Shared Subnet:")
    st.write(subnet)

    # Additional Information (botnets)
    botnets = st.session_state['botnets']
    st.write("### Botnets:")
    splited_ip = [(subnet, ip[len(subnet)+1:]) for ip in botnets if ip.startswith(subnet)]
    for part1, part2 in splited_ip:
        st.markdown(colored_ip_line(part1, part2), unsafe_allow_html=True)

    # Additional Information (Top 5 IPs by Traffic)
    top_ips = dict(sorted(packet_sources.items(), key=lambda item: item[1], reverse=True)[:min(5, len(packet_sources))])
    st.write("### Top 5 IPs by Traffic:")
    for ip, traffic_count in top_ips.items():
        st.write(f"{ip}: {traffic_count}")

def page_attack_simulation():
    st.title('Attack Simulation')

    with st.expander("Create Traces"):
        packets_num = st.slider(
            'Num of original packets', 
            min_value=100, max_value=10000, value=10000,
            help="The total number of legitimate packets generated for the simulation"
        )
        botnet_num = st.slider(
            'Num of botnets', 
            min_value=1, max_value=10, value=2,
            help="The number of botnets participating in the attack. Each botnet is a group of compromised devices sending malicious traffic."
        )
        shared_subnet = st.slider(
            'Shared subnet level', 
            min_value=0, max_value=4, value=2,
            help="Defines how much of the network prefix is shared among the attacking botnets. A higher value means more shared prefixes."
        )
        attacke_packets_num = st.slider(
            'Attack volume', 
            min_value=0.0, max_value=10.0, value=3.0, step=0.1,
            help="This parameter determines how much the original data is multiplied to generate the attack data. Higher values mean a more intense attack."
        )
        legit_volume = st.slider(
            'When to start the attack', 
            min_value=0.0, max_value=1.0, value=0.1, step=0.01,
            help="Determines the point in time when the attack starts, as a fraction of the total simulation time."
        )
        nxd_num = st.slider(
            'Num of NXD', 
            min_value=1, max_value=10, value=2,
            help="The number of Non-Existent Domain (NXD) queries generated during the simulation. These simulate malicious DNS queries."
        )
        if st.button('Create'):
            with st.spinner('Processing...'):
                attack_dataset, botnets, subnet = create_attack_dataset(packets_num, botnet_num, shared_subnet, attacke_packets_num, nxd_num, legit_volume)
                st.session_state['attack_dataset'] = attack_dataset
                st.session_state['botnets'] = botnets
                st.session_state['subnet'] = subnet
                st.success('Done!')

    if 'attack_dataset' in st.session_state:
        with st.expander("Simulate attack"):
            hierarchy_levels = st.slider(
                'Hierarchy Levels', 
                min_value=1, max_value=4, value=2,
                help="Specifies the number of levels in the IP prefix hierarchy that the RHHH algorithm uses to analyze and track traffic patterns."
            )
            k = st.slider(
                'Space Saving Parameter k', 
                min_value=1, max_value=20, value=10,
                help="Controls the space-saving algorithm in RHHH. A higher value allows the algorithm to track a greater number of heavy hitters, which are significant traffic sources."
            )
            upper_threshold_nxd_ratio = st.slider(
                'Upper Threshold NXD Ratio', 
                min_value=0.01, max_value=1.0, value=0.1,
                help="Defines the overall ratio of NXD responses to all packets processed so far. If this ratio exceeds the threshold, the traffic is flagged as suspicious."
            )
            lower_threshold_nxd_ratio = st.slider(
                'Lower Threshold NXD Ratio', 
                min_value=0.01, max_value=1.0, value=0.05,
                help="Defines the overall ratio of NXD responses to all packets processed so far. If this ratio is below the threshold, the traffic is considered legitimate."
            )
            upper_attack_threshold_ratio = st.slider(
                'Upper Threshold NXD Ratio per IP', 
                min_value=0.01, max_value=1.0, value=0.6,
                help="Sets the ratio of NXD responses to total packets for each IP. If the ratio for an IP exceeds this threshold and an attack is suspected, the IP will be blocked."
            )
            lower_attack_threshold_ratio = st.slider(
                'Lower Threshold NXD Ratio per IP', 
                min_value=0.01, max_value=1.0, value=0.3,
                help="Sets the ratio of NXD responses to total packets for each IP. If the ratio for an IP is below this threshold and no attack is suspected, the IP will be allowed."
            )
            list_expiry_limit = st.slider(
                'Expiry Limit', 
                min_value=10, max_value=500, value=150,
                help="Determines the number of queries after which entries in the blacklist or whitelist are re-evaluated and possibly removed."
            )
            aging = st.slider(
                'Aging', 
                min_value=0.01, max_value=1.0, value=0.5,
                help="Specifies the factor by which the historical data is multiplied to reduce its influence over time."
            )

            if st.button('Simulate Attack'):
                with st.spinner('Processing...'):
                    dns_protection, packets = simulate_ddos_attack(hierarchy_levels, upper_threshold_nxd_ratio, lower_threshold_nxd_ratio,
                    upper_attack_threshold_ratio, lower_attack_threshold_ratio, list_expiry_limit, aging, k, st.session_state['attack_dataset'])
                    plot_statistics(packets, dns_protection.tp, dns_protection.fp, dns_protection.tn, dns_protection.fn)
                    st.success('Done!')


# Main function to control the page navigation
def main():
    st.sidebar.title('Navigation')
    page = st.sidebar.radio('Go to', ['Attack Simulation', 'Explanations'])

    if page == 'Attack Simulation':
        page_attack_simulation()
    elif page == 'Explanations':
        page_hhh_explanation()

if __name__ == "__main__":
    main()