import socket
import requests
import argparse
import time

def test_tcp_port(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


record={'FTP-Data-20': 0, 'FTP-Control-21': 0, 'SSH-22': 0, 'Telnet-23': 0, 'SMTP-25': 0, 
        'DNS-53': 0, 'DHCP-Server-67': 0, 'DHCP-Client-68': 0, 'TFTP-69': 0, 'HTTP-80': 0, 
        'POP3-110': 0, 'RPCbind-111': 0, 'NTP-123': 0, 'Microsoft-RPC-135': 0, 'NetBIOS-Name-137': 0, 
        'NetBIOS-Datagram-138': 0, 'NetBIOS-Session-139': 0, 'IMAP-143': 0, 'SNMP-161': 0, 'SNMP-Trap-162': 0, 
        'BGP-179': 0, 'LDAP-389': 0, 'HTTPS-443': 0, 'SMB-445': 0, 'SMTPS-465': 0, 'Syslog-514': 0, 
        'Mail-Submission-587': 0, 'IPP-Printing-631': 0, 'IMAPS-993': 0, 'POP3S-995': 0, 'SOCKS-Proxy-1080': 0, 
        'MS-SQL-Server-1433': 0, 'Oracle-DB-1521': 0, 'PPTP-VPN-1723': 0, 'NFS-2049': 0, 'cPanel-2082': 0, 
        'cPanel-SSL-2083': 0, 'MySQL-3306': 0, 'RDP-3389': 0, 'PostgreSQL-5432': 0, 'VNC-5900': 0, 'HTTP-Alt-8080': 0, 
        'HTTPS-Alt-8443': 0, 'MongoDB-27017': 0, 'Redis-6379': 0, 'Elasticsearch-9200': 0, 'Cassandra-9042': 0, 
        'Memcached-11211': 0, 'Zookeeper-2181': 0, 'model': 0}

services={'NFS-2049': 2049, 'RDP-3389': 3389, 'NTP-123': 123, 'cPanel-2082': 2082,
          'FTP-Data-20': 20, 'Zookeeper-2181': 2181, 'Telnet-23': 23, 'Oracle-DB-1521': 1521,
          'Microsoft-RPC-135': 135, 'HTTPS-Alt-8443': 8443, 'HTTP-80': 80,
          'MongoDB-27017': 27017, 'LDAP-389': 389, 'Memcached-11211': 11211,
          'IMAPS-993': 993, 'SMB-445': 445, 'SNMP-161': 161, 'DNS-53': 53,
          'MS-SQL-Server-1433': 1433, 'RPCbind-111': 111, 'PostgreSQL-5432': 5432,
          'VNC-5900': 5900, 'HTTPS-443': 443, 'IMAP-143': 143, 'SMTPS-465': 465,
          'PPTP-VPN-1723': 1723, 'SSH-22': 22, 'FTP-Control-21': 21, 'POP3-110': 110,
          'SMTP-25': 25, 'DHCP-Server-67': 67, 'DHCP-Client-68': 68, 'TFTP-69': 69,
          'NetBIOS-Session-139': 139, 'NetBIOS-Datagram-138': 138, 'NetBIOS-Name-137': 137,
          'Mail-Submission-587': 587, 'Syslog-514': 514, 'SNMP-Trap-162': 162,
          'BGP-179': 179, 'IPP-Printing-631': 631, 'POP3S-995': 995,
          'SOCKS-Proxy-1080': 1080, 'MySQL-3306': 3306, 'cPanel-SSL-2083': 2083,
          'Redis-6379': 6379, 'HTTP-Alt-8080': 8080, 'Cassandra-9042': 9042,
          'Elasticsearch-9200': 9200}



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Honeybear Client")
    parser.add_argument("host", help="IP address of the host to scan")
    parser.add_argument("model", help="Options: logreg, randforest, ada, anomaly")

    args = parser.parse_args()

    print("Scanning:")
    print("host:", args.host)
    print("model:", args.model)

    host=args.host
    record['model']=args.model

    for service in services:  
        # Example usage
        port=services[service]
        if test_tcp_port(host, port):
            print(f"Port {port} on {host} is open")
            record[service]=1
        else:
            print(f"Port {port} on {host} is closed")
            record[service]=0  
        response = requests.post('http://127.0.0.1:4001/api/data', json=record)
        output=response.json()
        if args.model=='anomaly':
            print("Clssification:", output['label'])
            print("Anomaly Score:", output['Score'])
        else:
            print("Clssification:", output['label'])
            print("Probability it is a Honeypot:", output['Probability'])
        print("--------------------------------------------")
        time.sleep(1)




