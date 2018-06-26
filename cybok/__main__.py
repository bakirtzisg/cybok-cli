#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import matplotlib.pyplot as plt
import copy
import networkx as nx
import csv

from update import update_capec, update_cwe, update_cve
from extractor import attack_vector_cross
from search import create_index, search, find_attack_surface, find_violated_components
from graphs import system_graph, plot_system_topology, plot_attack_surface, find_exploit_chains, attack_surface_graph, plot_exploit_chains, attack_vector_graph
from pprinting import pprint_component, pprint_attack_vector


from ranking import rank_results


def main(args):
    """Parses arguments and runs the correct command.
    """
    parser = argparse.ArgumentParser(
        description="""CYBOK: The Cyber Security Body of Knowledge
                       for Model-Based Vulnerability Assessment"""
    )

    parser.add_argument("-s", "--search",
                        help="search attack vectors from database")
    parser.add_argument("-r", "--rank",
                        help="ranks results based on how many times they match",
                        action="store_true")
    parser.add_argument("-a", "--abstract",
                        help="abstracts from CVE to CWE and CAPEC",
                        action="store_true")
    parser.add_argument("-i", "--input",
                        help="inputs system model from graphml file")
    parser.add_argument("-u", "--update",
                        help="updates CAPEC, CWE, CVE data files",
                        action="store_true")
    parser.add_argument("-v", "--visualize",
                        help="plots the graph of attack vectors",
                        action="store_true")
    parser.add_argument("-t", "--target",
                        help="inputs target to find exploit chains based on evidence")
    parser.add_argument("-o", "--output",
                        help="outputs the results of -s or -i to csv and graphml files")

    args = parser.parse_args(args)


    if args.search:
        matched_attack_vectors = search(args.search)

        ranked_attack_vectors = rank_results(matched_attack_vectors)

        if args.output:
            with open(args.output + '_' + args.search + ".csv", "w") as results_file:
                writer = csv.writer(results_file)
                writer.writerow(('Hits', 'Attack Vector', 'Database', 'Related CWE',
                                 'Related CAPEC', 'Related CVE', 'Contents'))

                for ranked_attack_vector in ranked_attack_vectors:
                    writer.writerow((ranked_attack_vector[1],
                                     ranked_attack_vector[0].name,
                                     ranked_attack_vector[0].db_name,
                                     ranked_attack_vector[0].related_weakness,
                                     ranked_attack_vector[0].related_attack_pattern,
                                     ranked_attack_vector[0].related_vulnerability,
                                     ranked_attack_vector[0].contents))
        else:
            for ranked_attack_vector in ranked_attack_vectors:
                pprint_attack_vector(ranked_attack_vector[0], str(ranked_attack_vector[1]))


    if args.input:
        sigma = system_graph(args.input)

        violated_components = find_violated_components(sigma)

        if args.output:
            print("Exporting system topology")
            nx.write_graphml(sigma, args.output + "_system_topology.graphml")

            print("Exporting attack vector graph")
            av_graph = attack_vector_graph(violated_components)

            nx.write_graphml(av_graph, args.output + "_attack_vector_graph.graphml")

            print("Exporting full vulnerability analysis")
            with open(args.output + '_' + "full_analysis.csv", "w") as results_file:
                writer = csv.writer(results_file)
                writer.writerow(('Violated Component', 'Hits for Component', 'Attack Vector', 'Database', 'ID',
                                 'Related CWE', 'Related CAPEC', 'Related CVE', 'Contents'))

                for violated_component in violated_components:
                    violated_component[1] = rank_results(violated_component[1])
                    for piece in violated_component[1]:
                        writer.writerow((violated_component[0],
                                         piece[1],
                                         piece[0].name,
                                         piece[0].db_name,
                                         piece[0].db_id,
                                         piece[0].related_weakness,
                                         piece[0].related_attack_pattern,
                                         piece[0].related_vulnerability,
                                         piece[0].contents))

            as_sigma = copy.deepcopy(sigma)
            attack_surface, evidence = find_attack_surface(as_sigma)
            as_graph = attack_surface_graph(as_sigma, attack_surface)

            if attack_surface == []:
                print("I could not find any entry points in the system. This does not mean there are not any.")
            else:
                print("Exporting attack surface")
                nx.write_graphml(as_graph, args.output + "_attack_surface_graph.graphml")

                with open(args.output + '_' + "_attack_surface_evidence.csv", "w") as results_file:
                    writer = csv.writer(results_file)
                    writer.writerow(('Attack Surface Source', 'Attack Surface Target',
                                     'Attack Vector', 'Database', 'ID', 'Related CWE',
                                     'Related CAPEC', 'Related CVE', 'Contents'))

                    for violated_component in attack_surface:
                        for piece in evidence:
                            if piece[0] == violated_component[0]:
                                writer.writerow((violated_component[1],
                                                 violated_component[0],
                                                 piece[1].name,
                                                 piece[1].db_name,
                                                 piece[1].db_id,
                                                 piece[1].related_weakness,
                                                 piece[1].related_attack_pattern,
                                                 piece[1].related_vulnerability,
                                                 piece[1].contents))
        else:
            # searches each component's descriptors for vulnerabilities
            print("\n\rFull system analysis")
            print("====================")

            for violated_component in violated_components:
                pprint_component(violated_component[0])
                violated_component[1] = rank_results(violated_component[1])
                for piece in violated_component[1]:
                    if args.abstract:
                        if piece.db_name == "CVE":
                            continue
                        else:
                            pprint_attack_vector(piece)
                    else:
                        pprint_attack_vector(piece[0], str(piece[1]))

            # finds the attack surface
            print("\n\rAttack surface analysis")
            print("=======================")

            # we deepcopy sigma as not modify the initial graph object needed
            # for the system topology graph visualization
            as_sigma = copy.deepcopy(sigma)

            attack_surface, evidence = find_attack_surface(as_sigma)
            as_graph = attack_surface_graph(as_sigma, attack_surface)


            if attack_surface == []:
                print("I could not find any entry points in the system. This does not mean there are not any.")
            else:
                for violated_component in attack_surface:
                    pprint_component(violated_component[1] + " ↦ " + violated_component[0])
                    for piece in evidence:
                        if piece[0] == violated_component[0]:
                            if args.abstract:
                                if piece[1].db_name == "CVE":
                                    continue
                                else:
                                    pprint_attack_vector(piece[1])
                            else:
                                pprint_attack_vector(piece[1])


            # find exploit chains
            if args.target:
                exploit_chains = find_exploit_chains(as_graph, attack_surface, violated_components, args.target)
                print("\n\rExploit chain analysis")
                print("======================\n\r")

                chain = ""
                for exploit_chain in exploit_chains:
                    first = True
                    for element in exploit_chain:
                        if first:
                            chain += str(element)
                            first = False
                        else:
                            chain +=  " ↦ " + str(element)
                        print(chain)
                        chain = ""


            if args.visualize:
                print(sigma)
                plot_system_topology(sigma)
                plot_attack_surface(as_graph, attack_surface)
                if args.target:
                    plot_exploit_chains(exploit_chains, as_graph, args.target)
                plt.show()


    if args.update:
        print("Updating MITRE CAPEC")
        update_capec()
        print("Updated MITRE CAPEC")

        print("Updating MITRE CWE")
        update_cwe()
        print("Updated MITRE CWE")

        print("Updating NVD CVE")
        update_cve()
        print("Updated NVD CVE\n\r")

        print("Parsing attack vectors")
        attack_vectors = attack_vector_cross()
        print("I found %d attack vectors.\n\r" % len(attack_vectors))

        print("Creating search index, this might take a while")
        create_index(attack_vectors)
        print("Created search index")


if __name__ == "__main__":
    main(sys.argv[1:])
