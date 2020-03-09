#! /usr/bin/python3
# 
# USAGE
# $ python3 ad-manager.py 
#
# Author: hgalvani


# import class and constants
from ldap3 import Server, Connection, ALL, NTLM, Tls, SUBTREE, core, extend, MODIFY_REPLACE
import sys
import argparse
import ssl

# Variables
AD_SERVER = '192.168.0.104'
# AD_SERVER = 'srv-dc01.anterverse.com'
AD_DOMAIN = 'ANTEVERSE'
AD_BIND_USER = AD_DOMAIN + "\\ad-manager" # Use join
AD_BIND_PWD = 'P@ssword123'

AD_BASEDN = 'DC=anteverse,DC=com'
AD_USER_BASEDN = 'OU=SiteA,DC=anteverse,DC=com'
AD_USER_FILTER = '(&(objectClass=USER)(sAMAccountName={username}))'
AD_USER_FILTER2 = '(&(objectClass=USER)(dn={userdn}))'
AD_GROUP_FILTER = '(&(objectClass=GROUP)(cn={group_name}))'


# AD connection uncrypted, prefer ad_auth_ntlm_ssl()
def ad_auth_ntlm(username=AD_BIND_USER, password=AD_BIND_PWD, address=AD_SERVER):
  s = Server(address, use_ssl=False, get_info=ALL)
  c = Connection(s, user=username, password=password, raise_exceptions=True, authentication=NTLM)

  # perform the Bind operation
  try:
    if not c.bind():
      print('error in bind', c.result)
  
  except core.exceptions.LDAPBindError:
      print("Failed to bind connection")
      sys.exit(1)
  except core.exceptions.LDAPSocketOpenError:
      print("unable to open socket : Is Server up ?")
      sys.exit(1)   
  except core.exceptions.LDAPExceptionError:
      print("LDAP Exception Error")
      sys.exit(1)

  # VERBOSE message if True
  if VERBOSE:
    print ("Succesfully authenticated", c.result)
    # print(c)
    # print(s.info)    

  # Return connection
  return c     

# AD SSL connection
def ad_auth_ntlm_ssl(username=AD_BIND_USER, password=AD_BIND_PWD, address=AD_SERVER):
  s = Server(address, port = 636, use_ssl = True, get_info=ALL)
  c = Connection(s, user=username, password=password, raise_exceptions=True, authentication=NTLM)
  c.start_tls()

  # perform the Bind operation
  try:
    if not c.bind():
      print('Error in bind', c.result)
  except core.exceptions.LDAPBindError:
      print("Failed to bind connection")
      sys.exit(1)
  except core.exceptions.LDAPSocketOpenError:
      print("Unable to open socket : Is Server up ?", c.result)
      sys.exit(1)   
  except core.exceptions.LDAPExceptionError:
      print("LDAP Exception Error")
      sys.exit(1)

  # VERBOSE message if True
  if VERBOSE:
    print ("Succesfully authenticated", c.result)
    print(c)
    # print(s.info)    

  # Return connection
  return c     

# Check if user exist
def isExist(connexion, username):
  
  search_base = AD_BASEDN
  search_filter = '(&(objectclass=person)(name={}))'.format(username)
  
  # attributes=['sAMAccountName', 'cn', 'givenname']

  # Get connection
  c = connexion

  try:
    # Perform the search
    c.search(search_base, search_filter, attributes=['cn'])
  except core.exceptions.LDAPInvalidFilterError:
    print("Invalid filter: {}".format(username_cn))
    #sys.exit(1)  

  # VERBOSE messages
  if VERBOSE:
    print(c.entries)

  # Return True if search succed  
  return c.entries


# Modify password
# You *must* use encrypted connection (i.e. LDAPS or StartSSL).
# AD doesn’t allow changing password via unencrypted connection.
def ad_modify_password(connexion, username, password):
  # Get connection
  c = connexion
  if isExist(c,username):
    # Get connection
    c = connexion
    dn = 'CN={},OU=SiteA,DC=anteverse,DC=com'.format(username)

    try:
      r = c.extend.microsoft.modify_password(dn, old_password=None, new_password=password)
      print(r)
    except core.exceptions.LDAPNoSuchObjectResult:
      print("Failed to find user with dn {}".format(dn))
      #sys.exit(1)
    except core.exceptions.LDAPUnwillingToPerformResult:
      print("Unwilling to perform result : Is user dn {} validate ?".format(dn))
      #sys.exit(1)  

# Add User
def add_user_account(connexion, firstname, lastname, sitename, teamname):
  
  # lastname.upper()

  username = firstname.title() + ' ' + lastname.upper()
  user_dn = 'CN={},OU={},OU={},{}'.format(username, teamname, sitename, AD_BASEDN)
  user_object_class = ['OrganizationalPerson', 'person', 'top', 'user']
  user_attributes = {\
  'cn': '{}'.format(username), \
  'displayName': '{}'.format(username), \
  'givenName': '{}'.format(firstname.title()), \
  'sn': '{}'.format(lastname.upper()), \
  'mail': '{}.{}@anteverse.com'.format(firstname.lower(),lastname.lower()), \
  # 'userPrincipalName ': 'a.{}anteverse.com'.format(lastname.lower()), \
  'sAMAccountName': '{}.{}'.format(firstname.lower(),lastname.lower())}
  # attributes=['sAMAccountName', 'cn', 'givenname']

  # Get connection
  c = connexion

  try:
    # Perform the Add operation
    c.add(user_dn, user_object_class, user_attributes)
  except core.exceptions.LDAPEntryAlreadyExistsResult:
    print("Entry Already Exists")
    #sys.exit(1)
  except core.exceptions.LDAPNoSuchAttributeResult:
    print("Error in attribute conversion operation : One or more attributes are incorrect")
    #sys.exit(1)   

  # VERBOSE messages
  if VERBOSE:
    print(c.entries)

  # Return True if search succed  
  return c.entries

# Unlock user account
def ad_unlock_user_account(connexion, username):
  c = connexion
  if isExist(c,username):
    user_dn = 'CN={},OU=SiteA,DC=anteverse,DC=com'.format(username)
    try:
      c.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, ['512'])]})
      print(c.result)
    except core.exceptions.LDAPNoSuchObjectResult:
      print("Failed to find user with dn {}".format(user_dn))
      #sys.exit(1)
    except core.exceptions.LDAPInvalidValueError:
      print("Non valid attribute value set. Please recheck expected type")
      #sys.exit(1)
    except core.exceptions.LDAPUnwillingToPerformResult:
      print("Unwilling to perform result : Have set user password first ?")
      #sys.exit(1)  
  else:
    print("{} does not exist".format(username))

# Main
if __name__ == "__main__":


  parser = argparse.ArgumentParser(description='Manage user in AD.',
                                   epilog="Ex : python3 ad-manager.py --create-user --firstname Agnes --lastname DUPONTEL --sitename SiteA --teamname Direction")
  parser.add_argument('-v', '--verbose', action='store_true',
                       help='Activate verbose messages')
  parser.add_argument('-cu', '--create-user', dest='add_user_account', action='store_const',
                    const=add_user_account, help='Create user')
  parser.add_argument('-f', '--firstname', type=str, help='User Firstname')
  parser.add_argument('-l', '--lastname', type=str, help='User Lastname')
  parser.add_argument('-s', '--sitename', type=str, help='Site name')
  parser.add_argument('-t', '--teamname', type=str, help='Team name')
  
  args = parser.parse_args()

  # Set verbosity
  VERBOSE = True if args.verbose else False

  # Get connection
  c = ad_auth_ntlm_ssl()

  # Create and activate user
  args.add_user_account(c, args.firstname, args.lastname, args.sitename, args.teamname)
  # ad_modify_password(c, 'Agnes DUPONTEL', 'AliceDupond2')
  # ad_unlock_user_account(c,'Agnes DUPONTEL')