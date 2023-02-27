import whois
import logging
import json
import dns.resolver

unique_domains = ['youtu.be']


def get_nslookup(domain):

    # records = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT']
    records = {
        'A': [],
        'AAAA': [],
        'CNAME': [],
        'MX': [],
        'NS': [],
        'SOA': [],
        'TXT': []
    }
    for record in records.keys():
        try:
            nslookup = dns.resolver.query(domain, record)
            # print('nslookup:', nslookup)
            for server in nslookup:
                # print(record + ': ' + str(server))
                records[record].append(str(server))
        except Exception as e:
            print(e)
            # submitError(link=link)
    logging.info("NS Lookup fetched... ✅")
    print("NS Lookup: " + json.dumps(records, indent=4, sort_keys=True))
    return records


def getWhois(parsed_url):
    try:
        whois_data = whois.whois(parsed_url['domain'])

        if ('domain_name' in whois_data.keys()):
            domain_name = whois_data['domain_name'][0] if type(
                whois_data['domain_name']) is list else whois_data['domain_name']

        else:
            if (parsed_url['domain'] in unique_domains):
                domain_name = parsed_url['domain']
            else:
                # print('domain_name not found')
                logging.error("domain_name not found... 👻")

                return

        # convert domain_name to lowercase
        domain_name = domain_name.lower()

        # print('domain_name: ', domain_name)

        if ('registrar' in whois_data.keys()):
            registrar = whois_data['registrar']
        else:
            registrar = None

        whoisServer = whois_data['whois_server'] if 'whois_server' in whois_data.keys(
        ) else None

        if 'updatedDate' in whois_data.keys():
            updatedDate = whois_data['updated_date'] if type(
                whois_data['updated_date']) is list else [whois_data['updated_date']]
        else:
            updatedDate = None

        if 'creation_date' in whois_data.keys():
            creationDate = whois_data['creation_date'][0] if type(
                whois_data['creation_date']) is list else whois_data['creation_date']
        else:
            creationDate = None

        if 'expiration_date' in whois_data.keys():
            expirationDate = whois_data['expiration_date'][0] if type(
                whois_data['expiration_date']) is list else whois_data['expiration_date']
        else:
            expirationDate = None

        if 'name_servers' in whois_data.keys():
            nameServers = whois_data['name_servers']
        else:
            nameServers = None

        if 'status' in whois_data.keys():
            status = whois_data['status'] if type(whois_data['status']) is list else [
                whois_data['status']]
        else:
            status = None

        if 'emails' in whois_data.keys():
            emails = whois_data['emails'] if type(whois_data['emails']) is list else [
                whois_data['emails']]
        else:
            emails = None

        if 'dnssec' in whois_data.keys():
            dnssec = whois_data['dnssec'] if type(whois_data['dnssec']) is list else [
                whois_data['dnssec']]
        else:
            dnssec = None

        if 'name' in whois_data.keys():
            name = whois_data['name'] if whois_data['name'] else None
        else:
            name = None

        if 'org' in whois_data.keys():
            org = whois_data['org'] if whois_data['org'] else None
        else:
            org = None

        if 'address' in whois_data.keys():
            address = whois_data['address'] if whois_data['address'] else None
        else:
            address = None

        if 'city' in whois_data.keys():
            city = whois_data['city'] if whois_data['city'] else None
        else:
            city = None

        if 'country' in whois_data.keys():
            country = whois_data['country'] if whois_data['country'] else None
        else:
            country = None

        if 'state' in whois_data.keys():
            state = whois_data['state'] if whois_data['state'] else None
        else:
            state = None

        if 'address' in whois_data.keys():
            address = address if type(address) is list else [address]
        else:
            address = None

        if address and address[0] is None:
            address = None
        if updatedDate and updatedDate[0] is None:
            updatedDate = None
        if status and status[0] is None:
            status = None
        if emails and emails[0] is None:
            emails = None
        if dnssec and dnssec[0] is None:
            dnssec = None

        logging.info("whois data collected... 📝")

        print(
            'domain:', domain_name,
            '\nregistrar:', registrar,
            '\nwhoisServer:', whoisServer,
            '\nupdatedDate:', updatedDate,
            '\ncreationDate:', creationDate,
            '\nexpirationDate:', expirationDate,
            '\nnameServers:', nameServers,
            '\nstatus:', status,
            '\nemails:', emails,
            '\ndnssec:', dnssec,
            '\nname:', name,
            '\norg:', org,
            '\naddress:', address,
            '\ncity:', city,
            '\ncountry:', country,
            '\nstate:', state
        )

    except Exception as e:
        print(e)
        # submitError(link=link)


if __name__ == '__main__':
    getWhois({'domain': 'google.com'})
    get_nslookup('google.com')
