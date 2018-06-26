# -*- coding: utf-8 -*-

import networkx as nx
import matplotlib.pyplot as plt
from networkx.drawing.nx_agraph import graphviz_layout

from search import find_violation


def system_graph(infile):
    """This function takes as input a GraphML file
       and produces a networkx graph definition.
       Formally, this function produces the system graph, Σ.
    """
    sigma = nx.read_graphml(infile)
    return sigma


def attack_surface_coloring(graph, attack_surface):
    """This function takes as input a system topology
       (including the parts that are in its attack surface)
       and its corresponding attack surface
       and produces a color map for the nodes
       based on if they are in the attack surface
       or not.
    """
    color = []

    # takes a two-dimensional list
    # and produces a one-dimensional list
    # so we can check if each node is
    # in the attack surface
    flatten = lambda l: [item for sublist in l for item in sublist]
    flat_attack_surface = flatten(attack_surface)

    for node in graph:
        if node in flat_attack_surface:
            color.append('red')
        else:
            color.append('grey')
    return color


def exploit_chain_coloring(graph, exploit_chain):
    """This function takes as input a system topology
       (including the parts that are in its attack surface)
       and its corresponding exploit chain
       and produces a color map for the nodes
       based on if they are in the exploit chain
       or not.
    """
    node_color = []
    edge_color = []

    for node in graph:
        if node in exploit_chain:
            node_color.append('red')
        else:
            node_color.append('grey')

    for edge in graph.edges:
        control = False
        # checks if in exploit chain or not
        for i in range(len(exploit_chain)-1):
            if edge[0]==exploit_chain[i] and edge[1]==exploit_chain[i+1]:
                edge_color.append('red')
                control = True
            elif edge[1]==exploit_chain[i] and edge[0]==exploit_chain[i+1]:
                edge_color.append('red')
                control = True

        if control == False:
            edge_color.append('grey')

    return node_color, edge_color


def plot_system_topology(graph):
    """This function takes as input a graph
       and plots it using networkx and matplotlib.
    """

    plt.figure(figsize=(10,8))
    plt.title('System Topology')
    nx.draw(graph,
            pos=graphviz_layout(graph),
            node_size = [16 * graph.degree(n) for n in graph],
            with_labels = True,
            node_color = 'grey',
            font_size = 10,
            alpha = 0.5
    )


def attack_surface_graph(graph, attack_surface):
    """Takes as input the system graph
       and produces a new attack surface graph.
    """
    # adds nodes from the results
    # of the vulnerability analysis
    for violated_component in attack_surface:
        graph.add_edge(violated_component[1], violated_component[0])

    return(graph)


def plot_attack_surface(graph, attack_surface):
    """Takes as input a networkx graph
       and a list of violated components
       at the `entry point`
       to produce a visualization
       of the attack surface elements
       using a different colour.
    """
    plt.figure(figsize=(10,8))
    plt.title('System Attack Surface')
    nx.draw(graph,
            pos=graphviz_layout(graph),
            node_size = [16 * graph.degree(n) for n in graph],
            with_labels = True,
            node_color = attack_surface_coloring(graph, attack_surface),
            font_size = 10,
            alpha = 0.5,
    )

    return graph


def validate_edges(attack_surface_graph, admissible_path, starting_points):
    """Checks that all edges in a graph are attackable,
       otherwise it is not a valid path.
    """
    for i in range(len(admissible_path)-1):
        for edge in attack_surface_graph.edges(data=True):
            if edge[0] == admissible_path[i] and edge[1] == admissible_path[i+1]:
                descriptors = edge[2]
                if find_violation(descriptors) == [] and edge[0] not in starting_points:
                    return False
    return True


def find_exploit_chains(attack_surface_graph, attack_surface, violated_components, target):
    """ Takes as input a networkx graph,
        the attack surface
        and the connected components that are violated
        from each node in the attack surface
        to produce potential exploit chains.
    """
    starting_points = []
    admissible_components = []
    admissible_paths = []

    for violated_component in attack_surface:
        starting_points.append(violated_component[1])

    # removing duplicates
    for violated_component in violated_components:
        admissible_components.append(violated_component[0])

    admissible_components = set(admissible_components + starting_points)

    for starting_point in starting_points:
        for path in nx.all_simple_paths(attack_surface_graph, source=starting_point, target=target):
            # path - admissible components should result in an empty set
            # because all elements in path need to be in admissible components.
            if not (set(path) - admissible_components):
                if validate_edges(attack_surface_graph, path, starting_points):
                    admissible_paths.append(path)

    # remove duplicate paths
    admissible_paths_set = set(tuple(x) for x in admissible_paths)
    admissible_paths = [list(x) for x in admissible_paths_set]

    return admissible_paths


def plot_exploit_chain(exploit_chain, attack_surface_graph):
    """This function takes as input an exploit chain
       and the attack surface graph
       to produce a visual coloring the exploit chain path
       on the graph.
    """

    node_color, edge_color = exploit_chain_coloring(attack_surface_graph, exploit_chain)

    nx.draw(attack_surface_graph,
            pos=graphviz_layout(attack_surface_graph),
            node_size = [16 * attack_surface_graph.degree(n) for n in attack_surface_graph],
            with_labels = True,
            node_color = node_color,
            edge_color = edge_color,
            font_size = 10,
            alpha = 0.5,
    )

    return attack_surface_graph


def plot_exploit_chains(exploit_chains, attack_surface_graph, target):
    plt.subplots(figsize=(10,8))

    for exploit_chain in exploit_chains:
        plt.title('System Exploit Chains\nfor %s' % target)
        plot_exploit_chain(exploit_chain, attack_surface_graph)
        plt.pause(2.5)
        plt.cla()


def filter_targets(related, database_name):
    remove_na = list(filter(lambda x: x != "N/A", related))
    filtered_targets = list(map((lambda x: database_name + x), remove_na))

    return filtered_targets


def attack_vector_graph(violated_components):
    """Takes as input a result set
       and produces the attack vector graph.
    """
    attack_vector_graph = nx.Graph()
    admissible_vertices = []
    for violated_component in violated_components:
        for attack_vector in violated_component[1]:
            vertex = attack_vector.db_name + "-" + attack_vector.db_id
            attack_vector_graph.add_node(vertex)
            admissible_vertices.append(vertex)

            capec_filtered_targets = filter_targets(attack_vector.related_attack_pattern, "CAPEC-")
            for capec_filtered_target in capec_filtered_targets:
                if capec_filtered_target in admissible_vertices:
                    attack_vector_graph.add_edge(vertex, capec_filtered_target)

            cwe_filtered_targets = filter_targets(attack_vector.related_weakness, "CWE-")
            for cwe_filtered_target in cwe_filtered_targets:
                if cwe_filtered_target in admissible_vertices:
                    attack_vector_graph.add_edge(vertex, cwe_filtered_target)

            cve_filtered_targets = filter_targets(attack_vector.related_vulnerability, "")
            for cve_filtered_target in cve_filtered_targets:
                if cve_filtered_target in admissible_vertices:
                    attack_vector_graph.add_edge(vertex, cve_filtered_target)

    return attack_vector_graph
