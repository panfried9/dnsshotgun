import dns.message, dns.query, dns.rdatatype, dns.inet, dns.name 
import re
import sys
from multiprocessing.pool import ThreadPool 


from flask import Flask, render_template
from flask_wtf import FlaskForm
from wtforms import BooleanField, StringField, SelectField, SubmitField 
from wtforms.validators import DataRequired, ValidationError
from flask_wtf.csrf import CSRFProtect


csrf = CSRFProtect()  

app = Flask(__name__)
app.config['SECRET_KEY'] = 'INSERT RANDOM STRING HERE'
csrf.init_app(app)

def valid_domain(form, field):
   # from_text is going to raise an exception if this is not a valid hostname 
   try:
      dns.name.from_text(form.hostname.data)
   except:
      print("in except")
      raise ValidationError('Input is not a valid domain')


class DigForm(FlaskForm):
    hostname = StringField('Hostname', validators=[DataRequired(), valid_domain])
    qtype = SelectField('Type', choices=[ ('A','A'),('AAAA','AAAA'),('ANY','ANY'), ('CNAME','CNAME'), ('DNAME','DNAME'), 
                        ('DNSKEY','DNSKEY'), ('DS','DS'), ('NAPTR','NAPTR'), ('NSEC','NSEC'), ('NSEC3','NSEC3'), ('PTR','PTR'), 
                        ('RRSIG','RRSIG'), ('TXT','TXT'), 
                        ('MX','MX'),('NS','NS'),  ('SOA','SOA') ] )
    authdig   = BooleanField('Query Authoritative Servers')
    dnssecdig = BooleanField('Request DNSSEC') 
    compare   = BooleanField('Red border on results that are different from majority', default=True) 
    proto   = SelectField('Protocol', choices=[ ('UDPFB', 'UDP with TCP fallback'), ('TCP','TCP'), ('UDP','UDP') ] ) 

def name2logo(n):
###########################################
# return logo                             #
###########################################
 name = str(n).lower() 
 if( re.search( "azure-dns.com.$|azure-dns.net.$|azure-dns.org.$|azure-dns.info.$|msft.net.$|o365filtering.com.$", name)):
  return(("microsoft.png","Microsoft"))
 elif( re.search( "google$|google6$|google.com.$", name)):
  return(("google.ico","Google"))
 elif( re.search( "dnsmadeeasy.com.$", name )):
   return(("dnsmadeeasy.ico","DNSmadeeasy"))
 elif( re.search( "dynect.net.$", name )):
   return(("dynect.ico","Dyn/Oracle"))
 elif( re.search( "awsdns-\d\d\.[org|net|co\.uk|com].$", name )):
   return(("aws.png","Amazon"))
 elif( re.search( "domaincontrol.com.$|godaddy.com.$", name )):
   return(("godaddy.png","Godaddy"))
 elif( re.search( "akam.net.$", name )):
   return(("akamai.png","Akamai"))
 elif( re.search( "nsone.net.$", name )):
   return(("ns1.ico","NS1"))
 elif( re.search( "cloudflare$|cloudflare.com.$", name )):
   return(("cloudflare.ico","Cloudflare"))
 elif( re.search( "quad9$", name )):
   return(("quad9.png","Quad9"))
 elif( re.search( "opendns$", name)): 
   return(("opendns.ico","OpenDNS"))
 elif( re.search( "verisign$|nstld.com.$|gtld-servers.net.$|gov-servers.net.$", name )):
   return(("verisign.ico","Verisign"))
 else:
   return(("",""))



def query_server(args):
  to = 2 # Timeout

  domain = args[3]
  type = args[4]
  server = args[0] 
  proto  = args[5] 
  dnssecdig = args[6]
  try: 
   q = dns.message.make_query(domain,type, want_dnssec=dnssecdig )
   if proto == "UDPFB":  
     a = dns.query.udp_with_fallback(q, server, timeout=to)[0]
   elif proto == "TCP": 
     a = dns.query.tcp(q, server, timeout=to ) 
   else: 
     a = dns.query.udp(q, server, timeout=to ) 
  # FIXME we should dig deeper into what error is coming back
  except: 
     print("error came back")
     a = None

  return a

def matches(left, right):
  # corner case where one or both are none
  if left == None and right == None :
    return 1 
  if left == None and right != None : 
    return 0  
  if left != None and right == None :
    return 0 
 
  if left.answer != right.answer : 
    return 0
  return 1 

####################################################################################
# Find the most popular answer so that we can highlight answers that are different #
####################################################################################
def findwinner( results ):
  j = 0
  counter = 0  
  winner = 0 
  maxcounter = 0 
  for result in results:
    for current in results: 
      if matches(result, current): 
         counter += 1
    if counter > maxcounter : 
         winner = j 
    counter = 0  
    j += 1 
  return winner       

###############################################################################################
# Find authoritative servers so that we can add them to the the list of servers to be queried #
###############################################################################################
def find_auth(domain):
    return_providers = [] 
    auth = query_server(["8.8.8.8","authcheck","Recurse", domain, "NS", "UDPFB" , False])
    if auth != None:
      for rdata in auth.answer:
       for r in rdata:
         # make sure this is an NS record, if not check the next
         if( r.rdtype != dns.rdatatype.from_text("NS")) :
           continue
         autha = query_server(["8.8.8.8","google","Recurse", r.target, "A", "UDPFB", False] )
         if autha != None: 
           for ra in autha.answer[0]:
             # make sure we got an A record back, not CNAME
             if ra.rdtype == dns.rdatatype.from_text("A") :
               return_providers.append(( ra.address, r.target ))
             else:
               print("got CNAME or something back, should not happen")
      return return_providers


@app.route('/dig', methods=('GET', 'POST'))
def dig():
  form = DigForm() 
  resarray = [] 
  providers = []
  compare = False 
  winner =  [] 
  error = ""
  if form.validate_on_submit():
    compare = form.compare.data
    
    try:
       domain = dns.name.from_text(form.hostname.data)
    except:
       return render_template("show3.html", form=form, resarray=resarray, providers=providers, compare = compare, name2logo=name2logo, matches=matches, winner=winner,error="invalid domain name")
 
    type =  dns.rdatatype.from_text(form.qtype.data)
    proto = form.proto.data
    dnssec = form.dnssecdig.data

    providers = \
    [ ["8.8.8.8","Google","Recurse", domain, type, proto, dnssec] , 
    ["1.1.1.1","Cloudflare","Recurse", domain, type, proto, dnssec] , 
    ["9.9.9.9","Quad9","Recurse", domain, type, proto, dnssec],
    ["64.6.64.6","Verisign", "Recurse", domain, type, proto, dnssec],
    ["208.67.222.222","OpenDNS", "Recurse", domain, type, proto, dnssec],
#    ["7.9.120.3","Broken", "Recurse", domain, type, proto, dnssec ] 
    ]

    # this section is for the auth checking 
    if form.authdig.data == True: 
      auths = find_auth( domain)
      # If empty, then check parent (for example somebody submits www.google.com, then we check google.com)
      if auths == [] :
        auths = find_auth( domain.parent())
      for auth in auths:
        providers.append([ auth[0], auth[1], "Auth", domain, type, proto, dnssec ] )

    with ThreadPool(5) as p:
      resarray = p.map(query_server, providers)
    winnerpos = findwinner( resarray )
    winner = resarray[winnerpos]  
    #print("most hit is position:" + str( findwinner( resarray) ))  
  return render_template("show3.html", form=form, resarray=resarray, providers=providers, compare = compare, name2logo=name2logo, matches=matches, winner=winner, error=error)
