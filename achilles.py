#!/usr/bin/env python3

#this tool analyze vulnerabilities from web based on its html, config file and requests, then generate a report to a file


import argparse

from yaml import parse
import validators
import requests
import yaml
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from bs4 import Comment

parser = argparse.ArgumentParser(description='The Achilles HTML Vulnerability Analyzer v.1.0')
parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
parser.add_argument('url', type=str, help="The URL of the HTML to analyze")
parser.add_argument('--config', help='Path to configuration')
parser.add_argument('-o', '--output', help='Generate output file')

args = parser.parse_args()

config={'forms': True, 'comments': True, 'passwords': True}
if(args.config):
    print('Using config file:' + args.config)
    config_file = open(args.config, 'r')
    config_from_file = yaml.safe_load(config_file)
    if(config_from_file):
        config = {**config, **config_from_file}
        print(config)

report = ''
url = args.url

if(validators.url(url)):
    result_html = requests.get(url).text
    parsed_html = BeautifulSoup(result_html, "html.parser")

    forms           = parsed_html.find_all('form')
    comments        = parsed_html.find_all(string=lambda text:isinstance(text,Comment))
    password_inputs = parsed_html.find_all('input', {'name' : 'password'})

    if(config['forms']):
        for form in forms:
            if(form.get('action').find('https') < 0 and (urlparse(url).scheme != 'https')):
                report += 'Form Issue: Insecured form action ' +form.get('action')+' found in HTML\n'

    if(config['comments']):
        for comment in comments:
            if(comment.find('key:') > -1):
                report += 'Comment Issue: Comment contains sensitive issue, key found\n'

    if(config['passwords']):
        for password_input in password_inputs:
            if(password_input.get('type') != 'password'):
                report += 'Input issue: password is plain text\n'

else:
    print("Invalid URL, please include the whole scheme")

if(report == ''):
    report += 'Nice Job! your HTML doc is secured'
else:
    header = 'Vulnerabilities Found!\n'
    header += '======================\n\n'
    report = header + report
    
   


if(args.output):
    f = open(args.output, 'w')
    f.write(report)
    f.close
    print('Saved to output provided')