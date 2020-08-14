import yaml
import dns.resolver
import csv


def check_spf(domain):
    spf = None
    try:
        for r in dns.resolver.resolve(domain, 'TXT'):
            # convert object to string and strip '"'
            rtext = r.to_text().lstrip('"').rstrip('"')
            # extract only spf records
            if rtext.startswith('v=spf'):
                spf = rtext
    except dns.resolver.NoAnswer as e:
        spf = None
    return spf

def check_dmarc(domain):
    dmarc = None
    p_policy = None
    dmarc_domain = '_dmarc.' + domain
    try:
        for r in dns.resolver.resolve(dmarc_domain, 'TXT'):
            # convert object to string and strip '"'
            rtext = r.to_text().lstrip('"').rstrip('"')
            # extract only dmarc records
            if rtext.startswith('v=DMARC'):
                dmarc = rtext
                p_policy = get_dmarc_policy(dmarc)
    except dns.resolver.NXDOMAIN:
        dmarc = None
    except dns.resolver.NoAnswer:
        dmarc = None
    return dmarc, p_policy

def get_dmarc_policy(dmarc):
    try:
        # split tags into list
        dmarc = dmarc.split(';')
        # extract p tag 
        dmarc_p_policy = dmarc[1].split('=')[1]
    except:
        dmarc_p_policy = None
    return dmarc_p_policy

with open('domains.yaml', encoding='utf-8') as f:
    result = []
    data = yaml.load(f, Loader=yaml.FullLoader)
    for k, v in data.items():
        print('Analysing %s' % (v))
        spf = check_spf(v)
        if spf:
            has_spf = 'Yes'
        else:
            has_spf = 'No'
        dmarc = check_dmarc(v)[0]
        if dmarc:
            has_dmarc = 'Yes'
        else:
            has_dmarc = 'No'
        dmarc_p_policy = check_dmarc(v)[1]
        result.append((k,v,has_spf,has_dmarc,dmarc_p_policy,spf,dmarc))

#write result to csv file
with open('result.csv', 'w', newline = '', encoding = 'utf-8') as f:
    writer = csv.writer(f, delimiter = ',')
    writer.writerow(('Entity', 'Domain', 'Has SPF', 'Has DMARC', 'DMARC p Policy', 'SPF record', 'DMARC record'))
    for d in result:
        writer.writerow(d)
