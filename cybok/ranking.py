# -*- coding: utf-8 -*-

from itertools import groupby


def rank_results(matched_attack_vectors):
    """Takes as input a list
       of attack vector results
       and shorts them based
       on how many times the entry
       was returned for a given element.
    """

    grouped_results = []

    grouped_matched_attack_vectors = groupby(sorted(matched_attack_vectors))

    for grouped_matched_attack_vector in grouped_matched_attack_vectors:
        grouped_results.append([grouped_matched_attack_vector[0], len(list(grouped_matched_attack_vector[1]))])

    ranked_results = sorted(grouped_results, key=lambda x: x[1], reverse=True)

    return ranked_results
