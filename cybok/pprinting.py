# -*- coding: utf-8 -*-

from sty import fg, rs

def pprint_attack_vector(attack_vector, hits = ''):
    """Fancy Printing based on `db_name`,
       Takes as input the results
       and using the `db_name` colour codes the output.
    """
    if attack_vector.db_name == 'CVE':
        cve_result = fg.yellow + attack_vector.name + rs.all + " " + hits
        print(cve_result)
    elif attack_vector.db_name == 'CWE':
        print(fg.blue + attack_vector.db_name, attack_vector.db_id, attack_vector.name + rs.all + " " + hits)
    elif attack_vector.db_name == 'CAPEC':
        print(fg.red + attack_vector.db_name, attack_vector.db_id, attack_vector.name + rs.all + " " + hits)


def pprint_component(node):
    print("\n\r")
    print(node)
    print("----------\n\r")
