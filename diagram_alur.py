import matplotlib.pyplot as plt
import seaborn as sns
import networkx as nx
import random

# Define steps of your program flow
steps = [
    "Input XPDL File",
    "Parse and Extract Data",
    "Convert to Neo4j Graph",
    "Detect Deadlocks",
    "Save Deadlocks to Neo4j",
    "Visualize and Report"
]

# Create a directed graph
G = nx.DiGraph()

# Add edges between the steps
for i in range(len(steps) - 1):
    G.add_edge(steps[i], steps[i + 1])

# Set up plot
plt.figure(figsize=(14, 6))
sns.set_style("white")

# Position nodes horizontally and slightly adjust y-axis for clean arrows
pos = {step: (i * 2, 0) for i, step in enumerate(steps)}

# Assign different colors to each node
colors = sns.color_palette("hls", len(steps))
node_colors = {step: colors[i] for i, step in enumerate(steps)}

# Draw nodes with different colors
for node, (x, y) in pos.items():
    plt.scatter(x, y, s=3000, color=node_colors[node], zorder=3)
    plt.text(x, y, node, horizontalalignment='center', verticalalignment='center', fontsize=10, fontweight='bold', color='black', zorder=4)

# Draw edges manually
for start, end in G.edges():
    start_pos = pos[start]
    end_pos = pos[end]
    plt.annotate(
        '',
        xy=end_pos,
        xytext=start_pos,
        arrowprops=dict(arrowstyle='->', lw=2, color='gray', shrinkA=30, shrinkB=30),
        zorder=2
    )

# Hide axis
plt.axis('off')

# Set title outside the nodes
plt.title("Program Flow Diagram: XPDL to Neo4j & Deadlock Detection", fontsize=16, pad=20)

# Show plot
plt.tight_layout()
plt.show()
