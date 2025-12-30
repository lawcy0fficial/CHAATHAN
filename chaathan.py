#!/usr/bin/env python3
"""
CHAATHAN v4.0 Enterprise - Advanced Subdomain Takeover Detection
Professional-grade tool with modern architecture detection capabilities
"""
import os,sys,json,time,sqlite3,subprocess,argparse,re,socket,ssl,hashlib,base64
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
from urllib.parse import urlparse
import threading

VERSION="4.0-Enterprise"
BANNER="""
   ██████╗██╗  ██╗ █████╗  █████╗ ████████╗██╗  ██╗ █████╗ ███╗   ██╗
  ██╔════╝██║  ██║██╔══██╗██╔══██╗╚══██╔══╝██║  ██║██╔══██╗████╗  ██║
  ██║     ███████║███████║███████║   ██║   ███████║███████║██╔██╗ ██║
  ██║     ██╔══██║██╔══██║██╔══██║   ██║   ██╔══██║██╔══██║██║╚██╗██║
  ╚██████╗██║  ██║██║  ██║██║  ██║   ██║   ██║  ██║██║  ██║██║ ╚████║
   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
       Advanced Subdomain Takeover Detection Framework v{ 1 }
          Enterprise Edition with Modern Architecture Detection
          BY LAWCY SCHOOL OF HACKERS ( YT : LAWCY ) 
"""
class C:
    R='\033[91m';G='\033[92m';Y='\033[93m';B='\033[94m';M='\033[95m'
    C='\033[96m';W='\033[97m';N='\033[0m';BOLD='\033[1m';DIM='\033[2m'

SIGNATURES={
    's3.amazonaws.com':['NoSuchBucket','does not exist','404'],
    'cloudfront.net':['Bad request','ERROR: The request could not be satisfied','ViewerCertificateException'],
    'elasticbeanstalk.com':['404 Not Found'],
    'amazonaws':['NoSuchBucket','AccessDenied'],
    'azurewebsites.net':['404 Web Site not found','Error 404'],
    'azurefd.net':['Our services aren\'t available','AFDVERIFY','404'],
    'azure-api.net':['API Management service is not available'],
    'azurecontainer.io':['not found','404'],
    'blob.core.windows.net':['The specified container does not exist'],
    'github.io':['There isn\'t a GitHub Pages site here','404','For root URLs'],
    'gitlab.io':['The page you\'re looking for could not be found'],
    'bitbucket.io':['Repository not found','404'],
    'herokuapp.com':['No such app','There\'s nothing here','herokucdn.com/error-pages'],
    'netlify.app':['Not Found - Request ID','Page not found','netlify'],
    'netlify.com':['Not Found - Request ID'],
    'vercel.app':['The deployment could not be found','404: NOT_FOUND','DEPLOYMENT_NOT_FOUND'],
    'now.sh':['deployment could not be found'],
    'render.com':['Service Unavailable','404 Not Found'],
    'fly.io':['404 - Not Found','fly.io'],
    'railway.app':['404 - Page Not Found','Project not found'],
    'surge.sh':['project not found','There isn\'t anything here'],
    'replit.app':['Application not found','404'],
    'pantheonsite.io':['404 error unknown site','The gods are wise'],
    'wordpress.com':['Do you want to register','WordPress.com'],
    'ghost.io':['The thing you were looking for is no longer here'],
    'medium.com':['404 - Page Not Found'],
    'tumblr.com':['Whatever you were looking for','There\'s nothing here'],
    'hubspot.net':['The site you\'re looking for could not be found'],
    'squarespace.com':['No Such Account','There isn\'t a Squarespace page here'],
    'shopify.com':['Sorry, this shop is currently unavailable','Only one step left'],
    'bigcartel.com':['Oops! We couldn\'t find that page'],
    'myshopify.com':['Sorry, this shop is currently unavailable'],
    'readme.io':['Project doesnt exist','You tried to access a project'],
    'helpjuice.com':['We could not find what you\'re looking for'],
    'helpscoutdocs.com':['No settings were found'],
    'zendesk.com':['Help Center Closed','Oops, this help center no longer exists'],
    'uservoice.com':['This UserVoice instance does not exist'],
    'intercom.io':['Uh oh. That page doesn\'t exist','This page is reserved'],
    'cargo.site':['404 Not Found','If you\'re moving your domain'],
    'statuspage.io':['You are being redirected','Status page'],
    'fastly.net':['Fastly error: unknown domain'],
    'strikingly.com':['But if you\'re looking to build your own website'],
    'webflow.io':['The page you are looking for doesn\'t exist'],
    'storage.googleapis.com':['NoSuchBucket','The specified bucket does not exist'],
    'c.storage.googleapis.com':['NoSuchBucket'],
    'digitaloceanspaces.com':['The specified bucket does not exist'],
    'cloudflareapp.com':['This site can\'t be reached'],
    'workers.dev':['Error 1016','404 Not Found']
}
WORDLIST=['www','mail','ftp','localhost','webmail','smtp','pop','ns1','webdisk','ns2','cpanel',
'whm','autodiscover','autoconfig','m','imap','test','ns','blog','pop3','dev','www2','admin',
'forum','news','vpn','ns3','mail2','new','mysql','old','lists','support','mobile','mx','static',
'docs','beta','shop','sql','secure','demo','cp','calendar','wiki','web','media','email','images',
'img','www1','intranet','portal','video','sip','dns2','api','cdn','stats','dns1','ns4','www3',
'dns','search','staging','server','mx1','chat','wap','my','svn','mail1','sites','proxy','ads',
'host','crm','cms','backup','mx2','lyncdiscover','info','apps','download','remote','db','forums',
'store','relay','files','newsletter','app','live','owa','en','start','sms','office','exchange',
'ipv4','dashboard','git','help','s','webmail','bbs','monitoring','eshop','stage','redirect',
'moodle','erp','webcam','elearning','payments','preprod','preview','cloud','test1','test2','dev1',
'dev2','staging1','staging2','api1','api2','auth','sso','oauth','ldap','vpn1','vpn2','gateway',
'firewall','router','switch','ap','wifi','wireless','radius','tacacs','ntp','dns-server','dhcp',
'tftp','ftp-server','sftp','ftps','ssh','telnet','rdp','vnc','citrix','terminal','desktop','vm',
'hypervisor','esxi','vcenter','vcloud','vmware','hyper-v','kvm','xen','openstack','kubernetes',
'k8s','docker','swarm','mesos','rancher','openshift','jenkins','gitlab-ci','travis','circleci',
'bamboo','teamcity','artifactory','nexus','registry','harbor','quay','elastic','kibana','logstash',
'grafana','prometheus','nagios','zabbix','cacti','observium','influxdb','graphite','datadog',
'splunk','elk','graylog','fluentd','kafka','rabbitmq','redis','memcached','mongodb','cassandra',
'elasticsearch','solr','neo4j','couchdb','rethinkdb','dynamodb','aurora','rds','postgres','mysql',
'mariadb','mssql','oracle','db2','sqlite','cockroachdb','s3','cloudfront','lambda','ecs','eks']

class EnterpriseScanner:
    def __init__(self,domain,output_dir,timeout=5,threads=50):
        self.domain=domain;self.output_dir=output_dir;self.timeout=timeout;self.threads=threads
        self.subdomains=set();self.active=[];self.vulnerable=[];self.cnames={};self.lock=threading.Lock()
        self.tech_stack={};self.ssl_info={};self.cloud_resources=[];self.security_headers={}
        Path(output_dir).mkdir(parents=True,exist_ok=True)
        self.db_file=f"{output_dir}/chaathan.db";self.init_db()
    
    def init_db(self):
        conn=sqlite3.connect(self.db_file);c=conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS scan_info(id INTEGER PRIMARY KEY,domain TEXT,
                     date TEXT,total INT,active INT,vulnerable INT,duration INT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities(id INTEGER PRIMARY KEY,subdomain TEXT,
                     cname TEXT,service TEXT,severity TEXT,cvss REAL,details TEXT,exploitable INT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS subdomains(id INTEGER PRIMARY KEY,subdomain TEXT,
                     ip TEXT,cname TEXT,http INT,https INT,tech TEXT,ssl_valid INT,cloud TEXT)''')
        conn.commit();conn.close()
    
    def log(self,level,msg):
        colors={'INFO':C.B,'SUCCESS':C.G,'ERROR':C.R,'WARN':C.Y}
        symbols={'INFO':'[*]','SUCCESS':'[✓]','ERROR':'[!]','WARN':'[!]'}
        print(f"{colors.get(level,'')}{symbols.get(level,'')}{C.N} {msg}")
    
    def cmd(self,c,t=10):
        try:return subprocess.run(c,shell=True,capture_output=True,text=True,timeout=t).stdout
        except:return ""
    
    def enum_crtsh(self):
        self.log('INFO','CT Logs: crt.sh')
        o=self.cmd(f"curl -s 'https://crt.sh/?q=%25.{self.domain}&output=json'|grep -oP '\"name_value\":\"\\K[^\"]+' |sed 's/\\*\\.//g;s/\\\\n/\\n/g'|sort -u",30)
        for l in o.split('\n'):
            if l and self.domain in l:self.subdomains.add(l.strip())
    
    def enum_certspotter(self):
        self.log('INFO','CT Logs: CertSpotter')
        o=self.cmd(f"curl -s 'https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names'|grep -oE '[a-zA-Z0-9._-]+\\.{self.domain}'|sort -u",25)
        for l in o.split('\n'):
            if l:self.subdomains.add(l.strip())
    
    def enum_hackertarget(self):
        self.log('INFO','Passive DNS: HackerTarget')
        o=self.cmd(f"curl -s 'https://api.hackertarget.com/hostsearch/?q={self.domain}'|awk -F',' '{{print $1}}'|grep '\\.{self.domain}'",20)
        for l in o.split('\n'):
            if l:self.subdomains.add(l.strip())
    
    def enum_threatcrowd(self):
        self.log('INFO','Threat Intel: ThreatCrowd')
        o=self.cmd(f"curl -s 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}'|grep -oE '[a-zA-Z0-9.-]+\\.{self.domain}'|sort -u",20)
        for l in o.split('\n'):
            if l:self.subdomains.add(l.strip())
    
    def enum_alienvault(self):
        self.log('INFO','Threat Intel: AlienVault OTX')
        o=self.cmd(f"curl -s 'https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns'|grep -oE '[a-zA-Z0-9.-]+\\.{self.domain}'|sort -u",20)
        for l in o.split('\n'):
            if l:self.subdomains.add(l.strip())
    
    def enum_urlscan(self):
        self.log('INFO','Web Archive: URLScan.io')
        o=self.cmd(f"curl -s 'https://urlscan.io/api/v1/search/?q=domain:{self.domain}'|grep -oE '[a-zA-Z0-9.-]+\\.{self.domain}'|sort -u",20)
        for l in o.split('\n'):
            if l:self.subdomains.add(l.strip())
    
    def enum_rapiddns(self):
        self.log('INFO','DNS Database: RapidDNS')
        o=self.cmd(f"curl -s 'https://rapiddns.io/subdomain/{self.domain}'|grep -oE '[a-zA-Z0-9._-]+\\.{self.domain}'|sort -u",20)
        for l in o.split('\n'):
            if l:self.subdomains.add(l.strip())
    
    def enum_bufferover(self):
        self.log('INFO','DNS Database: BufferOver')
        o=self.cmd(f"curl -s 'https://dns.bufferover.run/dns?q=.{self.domain}'|grep -oE '[a-zA-Z0-9._-]+\\.{self.domain}'",20)
        for l in o.split('\n'):
            if l:self.subdomains.add(l.strip())
        o=self.cmd(f"curl -s 'https://tls.bufferover.run/dns?q=.{self.domain}'|grep -oE '[a-zA-Z0-9._-]+\\.{self.domain}'",20)
        for l in o.split('\n'):
            if l:self.subdomains.add(l.strip())
    
    def enum_anubis(self):
        self.log('INFO','DNS Database: Anubis')
        o=self.cmd(f"curl -s 'https://jldc.me/anubis/subdomains/{self.domain}'|grep -oE '[a-zA-Z0-9._-]+\\.{self.domain}'",20)
        for l in o.split('\n'):
            if l:self.subdomains.add(l.strip())
    
    def enum_wayback(self):
        self.log('INFO','Web Archive: Wayback Machine')
        o=self.cmd(f"curl -s 'http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=txt&fl=original&collapse=urlkey'|grep -oE '[a-zA-Z0-9._-]+\\.{self.domain}'|sort -u",25)
        for l in o.split('\n'):
            if l:self.subdomains.add(l.strip())
    
    def enum_virustotal(self):
        self.log('INFO','Threat Intel: VirusTotal')
        o=self.cmd(f"curl -s 'https://www.virustotal.com/ui/domains/{self.domain}/subdomains?limit=40'|grep -oE '[a-zA-Z0-9._-]+\\.{self.domain}'|sort -u",20)
        for l in o.split('\n'):
            if l:self.subdomains.add(l.strip())
    
    def enum_dns_zone(self):
        self.log('INFO','DNS Zone Transfer')
        ns=self.cmd(f"dig +short NS {self.domain}",10).strip().split('\n')
        for n in ns:
            if n:
                n=n.rstrip('.')
                o=self.cmd(f"dig AXFR @{n} {self.domain}|grep -oE '[a-zA-Z0-9.-]+\\.{self.domain}'|sort -u",15)
                for l in o.split('\n'):
                    if l:self.subdomains.add(l.strip())
    
    def enum_dns_bruteforce(self):
        self.log('INFO',f'DNS Bruteforce ({len(WORDLIST)} words)')
        for w in WORDLIST:self.subdomains.add(f"{w}.{self.domain}")
    
    def enum_permutations(self):
        self.log('INFO','Generating permutations')
        base=self.domain.split('.')[0]
        prefixes=['dev','staging','test','prod','api','admin','www','uat','qa','preprod']
        suffixes=['prod','test','dev','staging','backup','new','old','1','2','v1','v2']
        for p in prefixes:
            self.subdomains.add(f"{p}.{self.domain}");self.subdomains.add(f"{p}-{base}.{'.'.join(self.domain.split('.')[1:])}")
        for s in suffixes:self.subdomains.add(f"{base}-{s}.{'.'.join(self.domain.split('.')[1:])}")
    
    def check_ssl(self,subdomain):
        try:
            ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
            with socket.create_connection((subdomain,443),timeout=3) as sock:
                with ctx.wrap_socket(sock,server_hostname=subdomain) as ssock:
                    cert=ssock.getpeercert()
                    return {'valid':True,'issuer':str(cert.get('issuer','')),'subject':str(cert.get('subject',''))}
        except:return {'valid':False}
    
    def detect_tech(self,subdomain,response,headers):
        tech=[]
        patterns={'WordPress':'wp-content|wp-includes','Drupal':'sites/default|drupal','Joomla':'com_content|joomla',
                 'React':'react|__NEXT_DATA__|_next','Vue.js':'vue|__NUXT__|nuxt','Angular':'ng-version|angular',
                 'Django':'__debug__|csrfmiddlewaretoken|django','Laravel':'laravel_session|laravel',
                 'Node.js':'X-Powered-By: Express','PHP':'X-Powered-By: PHP','ASP.NET':'__VIEWSTATE|asp.net'}
        for t,p in patterns.items():
            if any(x in response.lower() or x in str(headers).lower() for x in p.split('|')):tech.append(t)
        return ','.join(tech) if tech else 'Unknown'
    
    def detect_cloud(self,subdomain,cname):
        if not cname:return 'None'
        providers={'AWS':['amazonaws','cloudfront','elasticbeanstalk','s3-website','awsglobalaccelerator'],
                  'Azure':['azure','azurewebsites','azurefd','blob.core.windows','trafficmanager'],
                  'GCP':['googleapis','appspot','cloud.google','cloudfunctions'],
                  'Cloudflare':['cloudflare','workers.dev'],
                  'DigitalOcean':['digitalocean'],
                  'Heroku':['herokuapp'],
                  'Netlify':['netlify'],
                  'Vercel':['vercel','now.sh'],
                  'Fastly':['fastly'],
                  'Akamai':['akamai','akamaiedge']}
        for provider,keywords in providers.items():
            if any(k in cname.lower() for k in keywords):return provider
        return 'Other'
    
    def check_security_headers(self,subdomain):
        try:
            headers_cmd=f"curl -sI --max-time {self.timeout} https://{subdomain} 2>/dev/null"
            headers_out=self.cmd(headers_cmd,self.timeout+2)
            security={'csp':False,'hsts':False,'xframe':False,'xcontent':False}
            if 'content-security-policy' in headers_out.lower():security['csp']=True
            if 'strict-transport-security' in headers_out.lower():security['hsts']=True
            if 'x-frame-options' in headers_out.lower():security['xframe']=True
            if 'x-content-type-options' in headers_out.lower():security['xcontent']=True
            return security
        except:return {}
    
    def check_active(self,subdomain):
        ip=self.cmd(f"dig +short A {subdomain}|head -1|grep -E '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'",5).strip()
        cname=self.cmd(f"dig +short CNAME {subdomain}|head -1|sed 's/\\.$//'",5).strip()
        if ip or cname:
            http=self.cmd(f"curl -s -o /dev/null -w '%{{http_code}}' -L --max-time {self.timeout} http://{subdomain}",self.timeout+2).strip()
            https=self.cmd(f"curl -s -o /dev/null -w '%{{http_code}}' -L --max-time {self.timeout} -k https://{subdomain}",self.timeout+2).strip()
            if http and http!='000' and http!='':
                resp=self.cmd(f"curl -sL --max-time {self.timeout} http://{subdomain}",self.timeout+2)
                headers=self.cmd(f"curl -sI --max-time {self.timeout} http://{subdomain}",self.timeout+2)
                tech=self.detect_tech(subdomain,resp,headers)
                ssl=self.check_ssl(subdomain) if https and https!='000' else {'valid':False}
                cloud=self.detect_cloud(subdomain,cname)
                sec_headers=self.check_security_headers(subdomain)
                with self.lock:
                    self.active.append({'sub':subdomain,'ip':ip,'cname':cname,'http':http,'https':https,
                                      'tech':tech,'ssl':ssl['valid'],'cloud':cloud,'response':resp,'headers':headers})
                    if cname:self.cnames[subdomain]=cname
                    self.tech_stack[subdomain]=tech;self.ssl_info[subdomain]=ssl
                    self.security_headers[subdomain]=sec_headers
                    if cloud!='None':self.cloud_resources.append({'sub':subdomain,'provider':cloud,'cname':cname})
                return True
        return False
    
    def detect_takeover(self,item):
        subdomain,cname=item['sub'],item.get('cname','')
        if not cname:return False
        if not self.cmd(f"host {cname}",5).strip():
            with self.lock:
                self.vulnerable.append({'sub':subdomain,'cname':cname,'service':'DANGLING_DNS',
                    'severity':'CRITICAL','cvss':8.5,'details':f'CNAME {cname} does not resolve - DNS dangling','exploitable':1})
            return True
        response=item.get('response','')
        for service,patterns in SIGNATURES.items():
            if service.lower() in cname.lower():
                for pattern in patterns:
                    if pattern.lower() in response.lower():
                        with self.lock:
                            self.vulnerable.append({'sub':subdomain,'cname':cname,'service':service.upper(),
                                'severity':'CRITICAL','cvss':9.0,'details':f'Pattern matched: {pattern}','exploitable':1})
                        return True
        if 's3' in cname.lower() and 'amazonaws' in cname.lower():
            if any(x in response.lower() for x in ['nosuchbucket','does not exist','404']):
                with self.lock:
                    self.vulnerable.append({'sub':subdomain,'cname':cname,'service':'AWS_S3',
                        'severity':'CRITICAL','cvss':9.2,'details':'S3 bucket takeover - bucket does not exist','exploitable':1})
                return True
        if 'github.io' in cname.lower():
            if "there isn't a github pages site here" in response.lower():
                with self.lock:
                    self.vulnerable.append({'sub':subdomain,'cname':cname,'service':'GITHUB_PAGES',
                        'severity':'CRITICAL','cvss':8.8,'details':'GitHub Pages takeover - repository unclaimed','exploitable':1})
                return True
        if 'herokuapp.com' in cname.lower():
            if any(x in response.lower() for x in ['no such app','heroku']):
                with self.lock:
                    self.vulnerable.append({'sub':subdomain,'cname':cname,'service':'HEROKU',
                        'severity':'CRITICAL','cvss':8.7,'details':'Heroku app takeover - app does not exist','exploitable':1})
                return True
        if 'azurewebsites' in cname.lower() or 'azurefd' in cname.lower():
            if any(x in response.lower() for x in ['404','not found','error 404']):
                with self.lock:
                    self.vulnerable.append({'sub':subdomain,'cname':cname,'service':'AZURE',
                        'severity':'CRITICAL','cvss':8.9,'details':'Azure service takeover - resource not found','exploitable':1})
                return True
        if 'storage.googleapis.com' in cname.lower() or 'c.storage.googleapis' in cname.lower():
            if any(x in response.lower() for x in ['nosuchbucket','does not exist']):
                with self.lock:
                    self.vulnerable.append({'sub':subdomain,'cname':cname,'service':'GCP_STORAGE',
                        'severity':'CRITICAL','cvss':9.1,'details':'GCP bucket takeover - bucket does not exist','exploitable':1})
                return True
        if 'netlify' in cname.lower():
            if any(x in response.lower() for x in ['not found','page not found']):
                with self.lock:
                    self.vulnerable.append({'sub':subdomain,'cname':cname,'service':'NETLIFY',
                        'severity':'CRITICAL','cvss':8.6,'details':'Netlify site takeover - site not configured','exploitable':1})
                return True
        if 'vercel' in cname.lower() or 'now.sh' in cname.lower():
            if any(x in response.lower() for x in ['404: not_found','deployment_not_found']):
                with self.lock:
                    self.vulnerable.append({'sub':subdomain,'cname':cname,'service':'VERCEL',
                        'severity':'CRITICAL','cvss':8.6,'details':'Vercel deployment takeover - deployment not found','exploitable':1})
                return True
        return False
    
    def save_results(self,duration):
        conn=sqlite3.connect(self.db_file);c=conn.cursor()
        c.execute("INSERT INTO scan_info VALUES(NULL,?,?,?,?,?,?)",
                 (self.domain,datetime.now().isoformat(),len(self.subdomains),len(self.active),len(self.vulnerable),duration))
        for v in self.vulnerable:
            c.execute("INSERT INTO vulnerabilities VALUES(NULL,?,?,?,?,?,?,?)",
                     (v['sub'],v['cname'],v['service'],v['severity'],v['cvss'],v['details'],v['exploitable']))
        for a in self.active:
            c.execute("INSERT INTO subdomains VALUES(NULL,?,?,?,?,?,?,?,?)",
                     (a['sub'],a['ip'],a['cname'],a['http'],a['https'],a['tech'],a['ssl'],a['cloud']))
        conn.commit();conn.close()
        with open(f"{self.output_dir}/all_subdomains.txt",'w') as f:f.write('\n'.join(sorted(self.subdomains)))
        with open(f"{self.output_dir}/active_subdomains.txt",'w') as f:
            for a in self.active:f.write(f"{a['sub']}|{a['ip']}|{a['cname']}|{a['http']}|{a['https']}|{a['tech']}|{a['cloud']}\n")
        with open(f"{self.output_dir}/vulnerabilities.txt",'w') as f:
            for v in self.vulnerable:f.write(f"{v['severity']}|{v['sub']}|{v['cname']}|{v['service']}|CVSS:{v['cvss']}|{v['details']}\n")
        with open(f"{self.output_dir}/cloud_resources.json",'w') as f:json.dump(self.cloud_resources,f,indent=2)
        with open(f"{self.output_dir}/tech_stack.json",'w') as f:json.dump(self.tech_stack,f,indent=2)
        with open(f"{self.output_dir}/security_headers.json",'w') as f:json.dump(self.security_headers,f,indent=2)
    
    def generate_report(self):
        critical=sum(1 for v in self.vulnerable if v['severity']=='CRITICAL')
        cloud_stats={};[cloud_stats.update({c['provider']:cloud_stats.get(c['provider'],0)+1}) for c in self.cloud_resources]
        tech_stats={};[tech_stats.update({t:tech_stats.get(t,0)+1}) for t in self.tech_stack.values() if t!='Unknown']
        html=f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>CHAATHAN Enterprise Report</title>
<style>*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:'Segoe UI',Arial,sans-serif;background:#0a0e27;color:#fff}}
.container{{max-width:1400px;margin:0 auto;padding:20px}}.header{{background:linear-gradient(135deg,#667eea,#764ba2);
padding:30px;border-radius:10px;margin-bottom:20px;box-shadow:0 10px 30px rgba(0,0,0,0.3)}}.header h1{{font-size:32px;margin-bottom:10px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin:20px 0}}
.card{{background:#1a1f3a;padding:20px;border-radius:8px;border-left:4px solid #667eea;box-shadow:0 4px 15px rgba(0,0,0,0.2)}}
.card.critical{{border-left-color:#e74c3c}}.card .label{{font-size:12px;color:#8b92b0;text-transform:uppercase;margin-bottom:8px}}
.card .value{{font-size:28px;font-weight:bold}}.section{{background:#1a1f3a;padding:20px;border-radius:8px;margin:15px 0;box-shadow:0 4px 15px rgba(0,0,0,0.2)}}
.section h2{{color:#667eea;margin-bottom:15px;border-bottom:2px solid #2c3354;padding-bottom:10px}}
.vuln{{background:#2c1a1a;padding:15px;margin:10px 0;border-left:5px solid #e74c3c;border-radius:5px}}
.vuln h3{{color:#ff6b6b;margin-bottom:8px;font-size:18px}}.vuln p{{margin:5px 0;font-size:14px;color:#ccc}}
table{{width:100%;border-collapse:collapse;margin-top:10px}}th{{background:#667eea;padding:12px;text-align:left}}
td{{padding:10px;border-bottom:1px solid #2c3354}}.badge{{display:inline-block;padding:4px 12px;border-radius:12px;
font-size:11px;font-weight:bold;margin:0 5px}}.badge.critical{{background:#e74c3c}}.badge.high{{background:#f39c12}}
.chart{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:15px;margin-top:15px}}
.chart-item{{background:#2c3354;padding:15px;border-radius:8px}}.chart-item h4{{margin-bottom:10px;color:#8b92b0;font-size:14px}}
.bar{{background:#667eea;height:25px;border-radius:4px;margin:8px 0;position:relative;animation:grow 0.5s ease-out}}
.bar span{{position:absolute;right:10px;line-height:25px;font-weight:bold;font-size:12px}}
@keyframes grow{{from{{width:0}}to{{width:100%}}}}.footer{{text-align:center;padding:20px;color:#8b92b0;margin-top:30px}}</style></head><body>
<div class="container"><div class="header"><h1>🔒 CHAATHAN Enterprise Security Report</h1>
<p><strong>Domain:</strong> {self.domain}</p><p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p><strong>Framework:</strong> v{VERSION}</p></div><div class="stats">
<div class="card"><div class="label">Total Subdomains</div><div class="value">{len(self.subdomains)}</div></div>
<div class="card"><div class="label">Active Subdomains</div><div class="value" style="color:#2ecc71">{len(self.active)}</div></div>
<div class="card critical"><div class="label">Vulnerabilities</div><div class="value" style="color:#e74c3c">{len(self.vulnerable)}</div></div>
<div class="card"><div class="label">Critical Issues</div><div class="value" style="color:#e74c3c">{critical}</div></div>
<div class="card"><div class="label">Cloud Resources</div><div class="value" style="color:#3498db">{len(self.cloud_resources)}</div></div>
<div class="card"><div class="label">SSL Enabled</div><div class="value" style="color:#2ecc71">{sum(1 for a in self.active if a['ssl'])}</div></div>
</div><div class="section"><h2>🚨 Critical Vulnerabilities</h2>"""
        if self.vulnerable:
            for v in self.vulnerable:
                html+=f"""<div class="vuln"><h3>{v['sub']} <span class="badge critical">{v['severity']}</span> 
<span class="badge high">CVSS: {v['cvss']}</span></h3><p><strong>Service:</strong> {v['service']}</p>
<p><strong>CNAME:</strong> {v['cname']}</p><p><strong>Details:</strong> {v['details']}</p>
<p><strong>Exploitable:</strong> {'Yes - Immediate Action Required' if v['exploitable'] else 'No'}</p></div>"""
        else:
            html+="<p style='color:#2ecc71;font-size:16px'>✓ No vulnerabilities detected</p>"
        html+="</div>"
        if cloud_stats:
            html+="<div class='section'><h2>☁️ Cloud Infrastructure Distribution</h2><div class='chart'>"
            max_val=max(cloud_stats.values()) if cloud_stats else 1
            for provider,count in sorted(cloud_stats.items(),key=lambda x:x[1],reverse=True):
                width=int((count/max_val)*100)
                html+=f"<div class='chart-item'><h4>{provider}</h4><div class='bar' style='width:{width}%'><span>{count}</span></div></div>"
            html+="</div></div>"
        if tech_stats:
            html+="<div class='section'><h2>🛠️ Technology Stack Detection</h2><div class='chart'>"
            max_val=max(tech_stats.values()) if tech_stats else 1
            for tech,count in sorted(tech_stats.items(),key=lambda x:x[1],reverse=True)[:10]:
                width=int((count/max_val)*100)
                html+=f"<div class='chart-item'><h4>{tech}</h4><div class='bar' style='width:{width}%'><span>{count}</span></div></div>"
            html+="</div></div>"
        html+="<div class='section'><h2>📊 Active Subdomains</h2><table><thead><tr>"
        html+="<th>Subdomain</th><th>IP</th><th>CNAME</th><th>HTTP</th><th>HTTPS</th><th>Technology</th><th>Cloud</th></tr></thead><tbody>"
        for a in self.active[:100]:
            html+=f"<tr><td>{a['sub']}</td><td>{a['ip'] or '-'}</td><td>{a['cname'] or '-'}</td><td>{a['http']}</td><td>{a['https']}</td><td>{a['tech']}</td><td>{a['cloud']}</td></tr>"
        html+="</tbody></table></div>"
        ssl_insecure=sum(1 for a in self.active if not a['ssl'] and a['https']!='000')
        if ssl_insecure>0:
            html+=f"<div class='section'><h2>⚠️ Security Findings</h2><p style='color:#f39c12'>• {ssl_insecure} subdomains with SSL/TLS issues</p>"
            no_sec_headers=sum(1 for sh in self.security_headers.values() if not any(sh.values()))
            if no_sec_headers>0:
                html+=f"<p style='color:#f39c12'>• {no_sec_headers} subdomains missing security headers</p>"
            html+="</div>"
        html+=f"""<div class='footer'><p>Generated by CHAATHAN v{VERSION} - Enterprise Subdomain Takeover Detection Framework</p>
<p>Red Team Edition | © 2024</p></div></div></body></html>"""
        with open(f"{self.output_dir}/report.html",'w') as f:f.write(html)
    
    def display_results(self):
        print(f"\n{C.Y}{'='*80}{C.N}")
        print(f"{C.C}{C.BOLD}{'ENTERPRISE SCAN RESULTS':^80}{C.N}")
        print(f"{C.Y}{'='*80}{C.N}\n")
        print(f"Domain: {C.C}{C.BOLD}{self.domain}{C.N}")
        print(f"Total Subdomains: {C.C}{len(self.subdomains)}{C.N}")
        print(f"Active Subdomains: {C.G}{len(self.active)}{C.N}")
        print(f"Vulnerable: {C.R}{C.BOLD}{len(self.vulnerable)}{C.N}")
        print(f"Cloud Resources: {C.B}{len(self.cloud_resources)}{C.N}\n")
        if self.vulnerable:
            print(f"{C.R}{C.BOLD}CRITICAL VULNERABILITIES DETECTED:{C.N}\n")
            for i,v in enumerate(self.vulnerable,1):
                print(f"{C.R}[{i}] {v['severity']} - CVSS {v['cvss']}{C.N}")
                print(f"  Subdomain: {C.C}{v['sub']}{C.N}")
                print(f"  Service: {C.M}{v['service']}{C.N}")
                print(f"  CNAME: {v['cname']}")
                print(f"  Details: {v['details']}")
                print(f"  Exploitable: {C.R}YES{C.N}\n" if v['exploitable'] else f"  Exploitable: {C.Y}NO{C.N}\n")
        else:
            print(f"{C.G}{C.BOLD}✓ No subdomain takeover vulnerabilities detected{C.N}\n")
        if self.cloud_resources:
            print(f"{C.B}CLOUD INFRASTRUCTURE:{C.N}")
            cloud_summary={}
            for c in self.cloud_resources:
                cloud_summary[c['provider']]=cloud_summary.get(c['provider'],0)+1
            for provider,count in sorted(cloud_summary.items(),key=lambda x:x[1],reverse=True):
                print(f"  {provider}: {C.C}{count}{C.N} resources")
            print()
        print(f"{C.Y}{'='*80}{C.N}\n")
        print(f"{C.G}OUTPUT FILES:{C.N}")
        print(f"  📁 {self.output_dir}/")
        print(f"     ├─ all_subdomains.txt ({len(self.subdomains)} subdomains)")
        print(f"     ├─ active_subdomains.txt ({len(self.active)} active)")
        print(f"     ├─ vulnerabilities.txt ({len(self.vulnerable)} vulnerabilities)")
        print(f"     ├─ report.html (Interactive report)")
        print(f"     ├─ cloud_resources.json")
        print(f"     ├─ tech_stack.json")
        print(f"     ├─ security_headers.json")
        print(f"     └─ chaathan.db (SQLite database)\n")
    
    def run(self):
        print(f"{C.C}{BANNER.format(VERSION=VERSION)}{C.N}")
        start=time.time()
        self.log('INFO',f'Target: {C.BOLD}{self.domain}{C.N}')
        self.log('INFO',f'Threads: {self.threads} | Timeout: {self.timeout}s')
        print(f"\n{C.Y}{'='*80}{C.N}")
        print(f"{C.B}{C.BOLD}PHASE 1: SUBDOMAIN ENUMERATION{C.N}\n")
        with ThreadPoolExecutor(max_workers=12) as executor:
            futures=[
                executor.submit(self.enum_crtsh),
                executor.submit(self.enum_certspotter),
                executor.submit(self.enum_hackertarget),
                executor.submit(self.enum_threatcrowd),
                executor.submit(self.enum_alienvault),
                executor.submit(self.enum_urlscan),
                executor.submit(self.enum_rapiddns),
                executor.submit(self.enum_bufferover),
                executor.submit(self.enum_anubis),
                executor.submit(self.enum_wayback),
                executor.submit(self.enum_virustotal),
                executor.submit(self.enum_dns_zone)
            ]
            for f in as_completed(futures):
                try:f.result()
                except Exception as e:self.log('WARN',f'Source error: {str(e)[:50]}')
        self.enum_dns_bruteforce()
        self.enum_permutations()
        self.log('SUCCESS',f'Found {C.BOLD}{len(self.subdomains)}{C.N} unique subdomains\n')
        print(f"{C.Y}{'='*80}{C.N}")
        print(f"{C.B}{C.BOLD}PHASE 2: ACTIVE VERIFICATION & FINGERPRINTING{C.N}\n")
        count=0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures={executor.submit(self.check_active,sub):sub for sub in self.subdomains}
            for future in as_completed(futures):
                count+=1
                if count%20==0:
                    print(f"\r{C.Y}[*]{C.N} Progress: {count}/{len(self.subdomains)} | Active: {C.G}{len(self.active)}{C.N} | Cloud: {C.B}{len(self.cloud_resources)}{C.N}    ",end='',flush=True)
        print(f"\n{C.G}[✓]{C.N} Found {C.BOLD}{len(self.active)}{C.N} active subdomains\n")
        print(f"{C.Y}{'='*80}{C.N}")
        print(f"{C.B}{C.BOLD}PHASE 3: SUBDOMAIN TAKEOVER DETECTION{C.N}\n")
        count=0
        for item in self.active:
            count+=1
            self.detect_takeover(item)
            if count%10==0:
                print(f"\r{C.Y}[*]{C.N} Scanning: {count}/{len(self.active)} | Vulnerable: {C.R}{len(self.vulnerable)}{C.N}    ",end='',flush=True)
        print(f"\n{C.G}[✓]{C.N} Detection complete - Found {C.R}{C.BOLD}{len(self.vulnerable)}{C.N} vulnerabilities\n")
        duration=int(time.time()-start)
        self.log('INFO',f'Scan duration: {C.BOLD}{duration}s{C.N} ({duration//60}m {duration%60}s)')
        self.save_results(duration)
        self.generate_report()
        self.display_results()

def main():
    parser=argparse.ArgumentParser(description='CHAATHAN v4.0 - Enterprise Subdomain Takeover Detection',
                                   formatter_class=argparse.RawDescriptionHelpFormatter,
                                   epilog='''Examples:
  ./chaathan.py -d example.com
  ./chaathan.py -d example.com -o results -t 10 -T 100
  ./chaathan.py -d example.com --fast
  
Red Team Edition - Use Responsibly''')
    parser.add_argument('-d','--domain',required=True,help='Target domain')
    parser.add_argument('-o','--output',help='Output directory (default: chaathan_DOMAIN_TIMESTAMP)')
    parser.add_argument('-t','--timeout',type=int,default=5,help='HTTP timeout in seconds (default: 5)')
    parser.add_argument('-T','--threads',type=int,default=50,help='Number of threads (default: 50)')
    parser.add_argument('--fast',action='store_true',help='Fast mode: 100 threads, 3s timeout')
    args=parser.parse_args()
    if args.fast:
        args.threads=100;args.timeout=3
    output_dir=args.output or f"chaathan_{args.domain.replace('.','-')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    scanner=EnterpriseScanner(args.domain,output_dir,args.timeout,args.threads)
    try:
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n\n{C.Y}[!]{C.N} Scan interrupted by user")
        print(f"{C.Y}[*]{C.N} Partial results saved to: {output_dir}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{C.R}[!]{C.N} Fatal error: {e}")
        import traceback;traceback.print_exc()
        sys.exit(1)

if __name__=='__main__':
    main()
