# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
from typing import NamedTuple
import json

class AttackVector(NamedTuple):
    """Generic data structure
       to hold the minimum amount
       of data necessary
       for creating the attack vector graph
       and accessing the rest
       of the text for NLP.
    """
    db_id: str
    db_name: str
    name: str
    related_weakness: list
    related_attack_pattern: list
    related_vulnerability: list
    contents: str


def extract_contents(entry):
    """For a given entry it removes unwanted tags
       and returns only the text.
    """
    unwanted_tags = ["Code", "Example_Code", "Content_History"]

    for tag in entry:
        if tag.name in unwanted_tags:
            tag.extract()

    return " ".join([s for s in entry.stripped_strings])


def cwe_related_attack_patterns(entry):
    """Takes as input a single weakness entry
       and finds all related attack paterns
       (CWE to CAPEC, therefore, inter-related
       connections).
    """
    related_capec = []
    if entry.Related_Attack_Patterns:
        instance = entry.Related_Attack_Patterns.Related_Attack_Pattern
        while instance is not None:
            related_capec.append(instance["CAPEC_ID"])
            instance = instance.find_next_sibling()
    else:
        related_capec.append("N/A")

    return related_capec


def cwe_related_weaknesses(entry):
    """Takes as input a single weakness or category entry
       and finds all the related weaknesses  (CWE to CWE,
       therefore, intra-related connections).
    """
    related_cwe = []
    # parses weakness relationships
    if entry.Related_Weaknesses:
        instance = entry.Related_Weaknesses.Related_Weakness
        while instance is not None:
            related_cwe.append(instance["CWE_ID"])
            instance = instance.find_next_sibling()
    # parses category relationships
    elif entry.Relationships:
        instance = entry.Relationships.Has_Member
        while instance is not None:
            related_cwe.append(instance["CWE_ID"])
            instance = instance.find_next_sibling()
    else:
        related_cwe.append("N/A")

    return related_cwe


def cwe_related_vulnerabilities(entry):
    """Takes as input a single weakness entry
       and finds all related vulnerabilities
       (CWE to CVE, therefore, inter-related
       connections).
    """
    related_cve = []
    if entry.Observed_Examples:
        instance = entry.Observed_Examples.Observed_Example
        while instance is not None:
            related_cve.append(instance.Reference.text)
            instance = instance.find_next_sibling()
    else:
        related_cve.append("N/A")

    return related_cve


def extract_cwe():
    """Extracts CWE entries (weaknesses
       and categories) and produces a list
       of attack vectors. Formally,
       extract_cwe constructs the set W
       of all weaknesses.
    """
    with open("./data/CWE.xml", encoding='utf8') as infile:
        soup = BeautifulSoup(infile, "xml")

    weaknesses = soup.Weaknesses.find_all("Weakness")
    weaknesses_lst = []

    for entry in weaknesses:
        if entry["Status"] == "Deprecated":
            continue
        else:
            weaknesses_lst.append(AttackVector(db_id=entry["ID"],
                                               db_name="CWE",
                                               name=entry["Name"],
                                               related_weakness=cwe_related_weaknesses(entry),
                                               related_attack_pattern=cwe_related_attack_patterns(entry),
                                               related_vulnerability=cwe_related_vulnerabilities(entry),
                                               contents=extract_contents(entry)))

    categories = soup.Categories.find_all("Category")

    for entry in categories:
        if entry["Status"] == "Deprecated":
            continue
        else:
            weaknesses_lst.append(AttackVector(db_id=entry["ID"],
                                               db_name="CWE",
                                               name=entry["Name"],
                                               related_weakness=cwe_related_weaknesses(entry),
                                               related_attack_pattern=cwe_related_attack_patterns(entry),
                                               related_vulnerability=cwe_related_vulnerabilities(entry),
                                               contents=extract_contents(entry)))

    return weaknesses_lst


def capec_related_attack_patterns(entry):
    """Takes as input a single attack pattern entry
       and finds all related attack paterns
       (CWE to CAPEC, therefore, inter-related
       connections).
    """
    related_capec = []
    if entry.find("capec:Related_Attack_Patterns"):
        instance = entry.find("capec:Related_Attack_Patterns").find("capec:Related_Attack_Pattern")
        while instance is not None:
            related_capec.append(instance.find("capec:Relationship_Target_ID").text)
            instance = instance.find_next_sibling()
    else:
        related_capec.append("N/A")

    return related_capec


def capec_related_weaknesses(entry):
    """Takes as input a single attack pattern
       and finds all the related weaknesses  (CAPEC to CWE,
       therefore, inter-related connections).
    """
    related_cwe = []
    if entry.find("capec:Related_Weaknesses"):
        instance = entry.find("capec:Related_Weaknesses").find("capec:Related_Weakness")
        while instance is not None:
            related_cwe.append(instance.find("capec:CWE_ID").text)
            instance = instance.find_next_sibling()
    else:
        related_cwe.append("N/A")

    return related_cwe


def extract_capec():
    """Extracts CAPEC entries
       and produces a list
       of attack vectors.
       Formally, extract_capec
       constructs the set A,
       of all attack patterns.
    """
    with open("./data/CAPEC.xml", encoding='utf8') as infile:
        soup = BeautifulSoup(infile, "xml")

    attack_patterns = soup.Attack_Patterns.find_all("Attack_Pattern")
    attack_pattern_lst = []

    for entry in attack_patterns:
        if entry["Status"] == "Deprecated":
            continue
        else:
            attack_pattern_lst.append(AttackVector(db_id=entry["ID"],
                                                   db_name="CAPEC",
                                                   name=entry["Name"],
                                                   related_weakness=capec_related_weaknesses(entry),
                                                   related_attack_pattern=capec_related_attack_patterns(entry),
                                                   related_vulnerability=["N/A"],
                                                   contents=extract_contents(entry)))

    return attack_pattern_lst


def get_cve_entries(cve_json):
    try:
        with open(cve_json, "r") as cve:
            cve_data = json.load(cve)
            return cve_data["CVE_Items"]
    except:
        return []

def parse_cve_relationships(problemtype_data):
    cwes = []
    for ptdata in problemtype_data:
        if "description" in ptdata:
            #if isinstance(item, str):
            #    print(problemtype_data)
            #    continue
            for desc in ptdata["description"]:
                cwes.append(desc["value"])
    return cwes

def parse_desc_data(desc_data):
    ds = ""
    for desc in desc_data:
        ds += desc["value"]
    return ds

def extract_cve():
    """Extract CVE entries
       and produces a list
       of attack vectors.
       Formally, extract_cve
       constructs the set V,
       of all vulnerabilities.
    """
    cve_data = ['CVE-Modified.json', 'CVE-Recent.json',
                'CVE-2002.json', 'CVE-2003.json',
                'CVE-2004.json', 'CVE-2005.json',
                'CVE-2006.json', 'CVE-2007.json',
                'CVE-2008.json', 'CVE-2009.json',
                'CVE-2010.json', 'CVE-2011.json',
                'CVE-2012.json', 'CVE-2013.json',
                'CVE-2014.json', 'CVE-2015.json',
                'CVE-2016.json', 'CVE-2017.json',
                'CVE-2018.json']

    vulnerability_lst = []
    for cve_datum in cve_data:
        entries = get_cve_entries("./data/"+cve_datum)
        
        for entry in entries:
            vulnerability_lst.append(AttackVector(db_id=entry["cve"]["CVE_data_meta"]["ID"][4:],
                                                  db_name="CVE",
                                                  name=entry["cve"]["CVE_data_meta"]["ID"],
                                                  related_weakness=parse_cve_relationships(entry["cve"]["problemtype"]["problemtype_data"]),
                                                  related_attack_pattern=["N/A"],
                                                  related_vulnerability=["N/A"],
                                                  contents=parse_desc_data(entry["cve"]["description"]["description_data"])))

    return vulnerability_lst


def attack_vector_cross():
    """It takes a number
       of lists to produce
       their cross. Formally,
       for the current data,
       it constructs A × W × V.
    """

    print("Extract CAPEC\n", flush = True)
    # Constructs set of attack patterns, A
    A = extract_capec()

    print("Extract CWE\n", flush = True)
    # Constructs set of weaknesses, W
    W = extract_cwe()
    
    print("Extract CVE\n", flush = True)
    # Constructs set of vulnerabilities, V
    V = extract_cve()

    # Returns their concatination
    return A + W + V
