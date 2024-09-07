import streamlit as st
import matplotlib.pyplot as plt
import numpy as np

def colored_ip_line(ip, sub_len):
    part1 = '' if sub_len == 0 else '.'.join(ip.split('.')[:sub_len])
    part2 = '' if sub_len == 4 else '.'.join(ip.split('.')[sub_len:])
    # splited_ip = [('.'.join(ip.split('.')[:subnet_len]), '.'.join(ip.split('.')[subnet_len:])) for ip in botnets]
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
    plt.bar(list(packet_times.keys()), list(packet_times.values()), color='blue')
    plt.title('Packet Distribution Over Time')
    plt.xlabel('Time')
    plt.ylabel('Frequency')
    plt.grid(True)
    st.pyplot(plt.gcf())  # Use st.pyplot to display the plot in Streamlit

    # Detection Performance with values
    confusion_matrix = np.array([[tp, fp], 
                                [fn, tn]])

    # Labels for the matrix
    labels = np.array([[f'{tp}\nTP', f'{fp}\nFP'], 
                                [f'{fn}\nFN', f'{tn}\nTN']])

    # Create the plot
    fig, ax = plt.subplots()
    cax = ax.matshow(confusion_matrix, cmap=plt.cm.Blues)

    # Add color bar
    plt.colorbar(cax)

    # Add text annotations for the values in the matrix
    for i in range(confusion_matrix.shape[0]):
        for j in range(confusion_matrix.shape[1]):
            ax.text(j, i, labels[i, j], ha='center', va='center')

    # Set axis labels
    ax.set_xticklabels([''] + ['Legitimate', 'Malicious'])
    ax.set_yticklabels([''] + ['Alow', 'Block'])

    # Show the plot
    plt.title('Detection Performance')
    st.pyplot(plt.gcf())

    accuracy = (tp + tn) / (tp + tn + fp + fn)
    precision = tp / (tp + fp)
    recall = tp / (tp + fn)
    f1_score = 2 * (precision * recall) / (precision + recall)
    specificity = tn / (tn + fp)
    type_1_error = fp / (tn + fp)
    type_2_error = fn / (tp + fn)

    # Overall Results Summary
    st.write("## Overall Results Summary")

    st.write(f"Our algorithm correctly classifies **{(accuracy * 100):.2f}%** of all traffic, both legitimate and malicious-related.")
    st.write(f"Out of all the traffic flagged as an malicious, **{(precision * 100):.2f}%** was indeed malicious, showing the accuracy of the algorithm in detecting malicious.")
    st.write(f"Our algorithm captures **{(recall * 100):.2f}%** of all malicious traffic, ensuring most malicious packets are successfully identified.")
    st.write(f"Our algorithm correctly identifies **{(specificity * 100):.2f}%** of legitimate traffic, ensuring that real users are not mistakenly blocked.")
    st.write(f"Our algorithm incorrectly blocks **{(type_1_error * 100):.2f}%** of legitimate traffic, flagging it as an malicious by mistake.")
    st.write(f"Our algorithm fails to block **{(type_2_error * 100):.2f}%** of malicious traffic, allowing some malicious requests to pass through.")

    # Metric Breakdown
    st.write("## Metric Breakdown")

    st.write("TP - Number of legitimate packets sent to the DNS resolver.")
    st.write("TN- Number of malicious packets that were blocked.")
    st.write("FP- Number of malicious packets sent to the DNS resolver.")
    st.write("FN- Number of legitimate packets that were blocked.")

    # 1. Accuracy
    st.write(f"### Accuracy: **{accuracy:.4f}**")
    st.write("""
    **Explanation:**  
    Accuracy measures the overall correctness of the algorithm.  
    It is the ratio of correctly classified packages (both allow and block) to the total packages.
    """)
    st.write("**Formula:** $\\text{Accuracy} = \\frac{TP + TN}{TP + TN + FP + FN}$")

    # 2. Precision
    st.write(f"### Precision: **{precision:.4f}**")
    st.write("""
    **Explanation:**  
    Precision evaluates the accuracy of legitimate packages classification made by the algorithm.  
    It is the ratio of legitimate packages that the algorithm allowed to the total packages the algorithm allowed.
    """)
    st.write("**Formula:** $\\text{Precision} = \\frac{TP}{TP + FP}$")

    # 3. Recall
    st.write(f"### Recall: **{recall:.4f}**")
    st.write("""
    **Explanation:**  
    Recall measures the ability of the algorithm to identify all relevant legitimate packages.  
    It is the ratio of legitimate packages that the algorithm allowed to the sum of all actual legitimate packages.
    """)
    st.write("**Formula:** $\\text{Recall} = \\frac{TP}{TP + FN}$")

    # 4. F1-Score
    st.write(f"### F1-Score: **{f1_score:.4f}**")
    st.write("""
    **Explanation:**  
    The F1-Score provides a balanced measure of the algorithm's accuracy, combining precision and recall.  
    It is the harmonic mean of precision and recall.
    """)
    st.write("**Formula:** $\\text{F1-Score} = 2 \\times \\frac{\\text{Precision} \\times \\text{Recall}}{\\text{Precision} + \\text{Recall}}$")

    # 5. Specificity
    st.write(f"### Specificity: **{specificity:.4f}**")
    st.write("""
    **Explanation:**  
    Specificity, or the non-legitimate blocking rate, assesses the algorithm's ability to correctly identify non-legitimate packages.  
    It is the ratio of the non-legitimate packages the algorithm blocked to the total number of actual non-legitimate packages.
    """)
    st.write("**Formula:** $\\text{Specificity} = \\frac{TN}{TN + FP}$")

    # 6. Type 1 and Type 2 Errors

    # Type 1 Error (False Positive Rate)
    st.write(f"### Type 1 Error (False Positive Rate): **{type_1_error:.4f}**")
    st.write("""
    **Explanation:**  
    Type 1 Error occurs when the algorithm incorrectly allows a non-legitimate package.
    """)
    st.write("**Formula:** $\\text{Type 1 Error} = \\frac{FP}{TN + FP}$")

    # Type 2 Error (False Negative Rate)
    st.write(f"### Type 2 Error (False Negative Rate): **{type_2_error:.4f}**")
    st.write("""
    **Explanation:**  
    Type 2 Error occurs when the algorithm incorrectly blocks a legitimate package.
    """)
    st.write("**Formula:** $\\text{Type 2 Error} = \\frac{FN}{TP + FN}$")

    # Legitimate vs Attack Traffic
    legitimate_traffic = [p for p in packets if p['Legitimate']]
    attack_traffic = [p for p in packets if not p['Legitimate']]  # Adjusted this line
    plt.figure(figsize=(6, 4))
    plt.bar(['Legitimate Traffic', 'Attack Traffic'], [len(legitimate_traffic), len(attack_traffic)], color=['blue', 'orange'])
    plt.title('Legitimate vs Attack Traffic')
    plt.ylabel('Count')
    st.pyplot(plt.gcf())

    # Additional Information (shared subnet)
    subnets = st.session_state['subnet']
    st.write("### Shared Subnet:")
    for ip in subnets:
        st.write(ip)

    # Additional Information (botnets)
    botnets = st.session_state['botnets']
    st.write("### Botnets:")
    subnet_len = 0 if len(subnets) == 0 or len(subnets[0]) == 0 else len(subnets[0].split('.'))
    # splited_ip = [('.'.join(ip.split('.')[:subnet_len]), '.'.join(ip.split('.')[subnet_len:])) for ip in botnets]
    for ip in botnets:
        st.markdown(colored_ip_line(ip, subnet_len), unsafe_allow_html=True)

    # Additional Information (Top 5 IPs by Traffic)
    top_ips = dict(sorted(packet_sources.items(), key=lambda item: item[1], reverse=True)[:min(5, len(packet_sources))])
    st.write("### Top 5 IPs by Traffic:")
    for ip, traffic_count in top_ips.items():
        st.write(f"{ip}: {traffic_count}")
