# -*- coding: utf-8 -*-

import zipfile
import gzip
import io
import shutil
import requests
import os


def download_and_unzip(url):
    """Downloads and unzips a file.

       Keyword Args:
         link to zipped xml file.

       Returns:
         unzipped data file in the current directory.
    """
    r = requests.get(url)
    z = zipfile.ZipFile(io.BytesIO(r.content))
    return z.extractall()


def update_capec():
    """Gets latest CAPEC.xml file and moves it to ../data.
    """
    capec_url = "https://capec.mitre.org/data/xml/views/1000.xml.zip"
    download_and_unzip(capec_url)
    shutil.move("1000.xml", "./data/CAPEC.xml")


def update_cwe():
    """Gets latest CWE.xml file and moves it to ../data.
    """
    cwe_url = "https://cwe.mitre.org/data/xml/views/2000.xml.zip"
    download_and_unzip(cwe_url)
    shutil.move("2000.xml", "./data/CWE.xml")


def update_cve():
    """Gets latest CVE.xml file and moves it to ../data.
       This is handled differently than CAPEC
       and CWE because the file is not available
       in zip.
    """
    cve_links = {
        'CVE-Modified': 'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-modified.xml.gz',
        'CVE-Recent': 'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-recent.xml.gz',
        'CVE-2002': 'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2002.xml.gz',
        'CVE-2003': 'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2003.xml.gz',
        'CVE-2004': 'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2004.xml.gz',
        'CVE-2005': 'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2005.xml.gz',
        'CVE-2006': 'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2006.xml.gz',
        'CVE-2007': 'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2007.xml.gz',
        'CVE-2008': 'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2008.xml.gz',
        'CVE-2009': 'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2009.xml.gz',
        'CVE-2010': 'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2010.xml.gz',
        'CVE-2011': 'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2011.xml.gz',
        'CVE-2012': 'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2012.xml.gz',
        'CVE-2013': 'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2013.xml.gz',
        'CVE-2014': 'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2014.xml.gz',
        'CVE-2015': 'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2015.xml.gz',
        'CVE-2016': 'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2016.xml.gz',
        'CVE-2017': 'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2017.xml.gz',
        'CVE-2018': 'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2018.xml.gz'
    }

    for name, url in cve_links.items():
        with open('./data/%s.gz' % name, 'wb') as f:
            f.write(requests.get(url).content)

        with gzip.open('./data/%s.gz' % name, 'rb') as f:
            xml_content = f.read()

        with open('./data/%s' % name + '.xml', 'wb') as f:
            f.write(xml_content)

    try:
        for name, url in cve_links.items():
            os.remove('./data/%s.gz' % name)
    except:
        print("Files do not exist and therefore cannot be removed")
