import streamlit as st
from attack_traces import *
import nxd_detecter as nxd
from explain import page_hhh_explanation 
from plot_statistics import plot_statistics
from algo_explain import algo_explain

def simulate_ddos_attack(hierarchy_levels, upper_threshold_nxd_ratio, lower_threshold_nxd_ratio,
                    upper_attack_threshold_ratio, lower_attack_threshold_ratio, list_expiry_limit,
                    aging, k, dataset):

    list_of_dicts = [row.to_dict() for index, row in dataset.iterrows()]
    nxd_sim = nxd.simulate_attack(hierarchy_levels, upper_threshold_nxd_ratio, lower_threshold_nxd_ratio,
                    upper_attack_threshold_ratio, lower_attack_threshold_ratio, list_expiry_limit, aging, k, list_of_dicts)
    return nxd_sim, list_of_dicts

def page_attack_simulation():
    st.title('Attack Simulation')

    with st.expander("How our algorithm works"):
        algo_explain()

    with st.expander("Create Traces"):
        packets_num = st.slider(
            'Num of original packets', 
            min_value=100, max_value=10000, value=10000,
            help="The total number of legitimate packets generated for the simulation"
        )
        botnet_num = st.number_input(
            'Num of botnets', 
            min_value=1, max_value=10, value=2,
            help="The number of botnets participating in the attack per subnet. Each botnet is a group of compromised devices sending malicious traffic."
        )
        shared_subnet = st.slider(
            'Shared subnet level', 
            min_value=0, max_value=4, value=2,
            help="Defines how much of the network prefix is shared among the attacking botnets. A higher value means more shared prefixes."
        )
        subnet_num = st.number_input(
            'Number of shared subnet', 
            value=2,
            help="Defines how much different network prefix will be."
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
        nxd_num = st.number_input(
            'Num of NXD', 
            value=2,
            help="The number of Non-Existent Domain (NXD) queries generated during the simulation. These simulate malicious DNS queries."
        )
        if st.button('Create'):
            with st.spinner('Processing...'):
                attack_dataset, botnets, subnet = create_attack_dataset(packets_num, botnet_num, shared_subnet, subnet_num, attacke_packets_num, nxd_num, legit_volume)
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
            k = st.number_input(
                'Space Saving Parameter k', 
                value=10,
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
                help="Sets the ratio of NXD responses to total packets for each IP. If the ratio for an IP is below this threshold and no attack is suspected, the IP will be allowed."
            )
            lower_attack_threshold_ratio = st.slider(
                'Lower Threshold NXD Ratio per IP', 
                min_value=0.01, max_value=1.0, value=0.3,
                help="Sets the ratio of NXD responses to total packets for each IP. If the ratio for an IP exceeds this threshold and an attack is suspected, the IP will be blocked."
            )
            list_expiry_limit = st.slider(
                'Expiry Limit', 
                min_value=10, max_value=500, value=150,
                help="Determines the number of queries after which historical data will age."
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