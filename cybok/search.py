# -*- coding: utf-8 -*-

import os, os.path
from extractor import AttackVector
from whoosh import index
from whoosh.qparser import *
from whoosh.fields import Schema, TEXT, ID, STORED, KEYWORD
from whoosh.analysis import CompoundWordFilter,  RegexTokenizer #, NgramFilter
from whoosh.lang.porter import stem


def create_index(entries):
    """Takes as input the extracted entries
       from extractor.py and produces a search index.
    """
    if not os.path.exists("indexdir"):
        os.mkdir("indexdir")

    schema = Schema(db_id=ID(stored=True),
                    db_name=ID(stored=True),
                    name=ID(stored=True),
                    related_weakness=ID(stored=True),
                    related_attack_pattern=ID(stored=True),
                    related_vulnerability=ID(stored=True),
                    contents=TEXT(stored=True))

    ix = index.create_in("indexdir", schema)
    ix = index.open_dir("indexdir")
    writer = ix.writer()

    for entry in entries:
        writer.add_document(db_id=entry.db_id,
                            db_name=entry.db_name,
                            name=entry.name,
                            related_weakness=entry.related_weakness,
                            related_attack_pattern=entry.related_attack_pattern,
                            related_vulnerability=entry.related_vulnerability,
                            contents=entry.contents)

    writer.commit()
    ix.close()


def search(query):
    """Takes as input a query string, creates a parser object
       from that query string and matches entries
       to that query string from the constructed index.
    """

    matched_attack_vectors = []
    # stems the query but it does not seem
    # to produce better results (to the contrary)
    # stemmed_query = stem(query)

    # n-gram filtering---if needed
    # my_analyzer = StandardAnalyzer() | NgramFilter(minsize=2, maxsize=4)
    # n_gram_query = [token.text for token in my_analyzer(query)]

    # compound word filter takes a query string
    # and produces a list of individual words to check
    cwf = CompoundWordFilter(query, keep_compound=True)
    analyzer = RegexTokenizer(r"\S+") | cwf
    cwf_query = [t.text for t in analyzer(query)]


    ix = index.open_dir("indexdir")

    schema = ix.schema

    query_parser = MultifieldParser(schema.names(), schema)

    with ix.searcher() as searcher:
        for instance in cwf_query:
            parse_query = query_parser.parse(instance)
            results = searcher.search(parse_query, limit=100000)
            for result in results:
                # transform results back to attack vector definition
                matched_attack_vectors.append(AttackVector(db_id=result['db_id'],
                                                           db_name=result['db_name'],
                                                           name=result['name'],
                                                           related_weakness=result['related_weakness'],
                                                           related_vulnerability=result['related_vulnerability'],
                                                           related_attack_pattern=result['related_attack_pattern'],
                                                           contents=result['contents']))

    return matched_attack_vectors


def find_attack_surface(sigma):
    """This function takes as input a system graph
       and searches to find which parts
       of the system compose the attack surface.
    """
    attack_surface = []
    entry_points = []
    evidence = []

    for node in sigma.nodes(data=True):
        entry_points = (node[1]["Entry Points"].split(", "))

        for entry_point in entry_points:
            if entry_point == "N/A":
                continue
            else:
                matched_attack_vectors = search(entry_point)

                if matched_attack_vectors == []:
                    continue
                else:
                    for matched_attack_vector in matched_attack_vectors:
                        evidence.append([node[0], matched_attack_vector])

                    if matched_attack_vectors:
                        attack_surface.append([node[0], entry_point])

                matched_attack_vectors = []

    return attack_surface, evidence


def find_violation(descriptors):
    """Finds evidence for an individual node.
    """
    matched_attack_vectors = []

    for category, descriptor in descriptors.items():
        descriptor = descriptor.split(", ")

        for value in descriptor:
            if value == "N/A":
                continue
            else:
                query_value = search(value)

                for result in query_value:
                    matched_attack_vectors.append(result)

    return matched_attack_vectors


def find_violated_components(sigma):
    """Iterates through all the nodes in a graph
       and matches potential attack vectors
       from the search index.
    """
    violated_components = []

    for node in sigma.nodes(data=True):
        matched_attack_vectors = find_violation(node[1])

        if matched_attack_vectors == []:
            continue
        else:
            violated_components.append([node[0], matched_attack_vectors])

    return violated_components



