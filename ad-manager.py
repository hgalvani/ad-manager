#! /usr/bin/python3
# 
# Author: Harold GALVANI
#
# Copyright 2020 Harold GALVANI
#
# This file is part of ad-manager.
# ad-manager is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ad-manager is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with ad-manager in the COPYING file.
# If not, see <http://www.gnu.org/licenses/>.


# import class
from ldap3 import Server, Connection, ALL, NTLM, Tls, SUBTREE, core, extend, MODIFY_REPLACE
import sys
import argparse
import ssl
import random
import string


# Constants
AD_SERVER = '192.168.0.104'
AD_DOMAIN = 'ANTEVERSE'
AD_BIND_USER = AD_DOMAIN + "\\ad-manager"
AD_BIND_PWD = 'P@ssword123'
AD_DNS = 'anteverse.com'
AD_BASEDN = 'DC=anteverse,DC=com'
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
  
  classic_attributes = ['distinguishedName','sAMAccountName', 'cn', 'sn', 'givenname']

  # Get connection
  c = connexion

  try:
    # Perform the search
    c.search(search_base, search_filter, attributes=classic_attributes)
  except core.exceptions.LDAPInvalidFilterError:
    print("Invalid filter: {}".format(username_cn))
    #sys.exit(1)
  except core.exceptions.LDAPAttributeError:
    print("Invalid attribute")
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
  user = isExist(c,username)

  if user:
    # Get user dn and cast it to string
    userdn = str(user[0].distinguishedName)

    try:
      r = c.extend.microsoft.modify_password(userdn, old_password=None, new_password=password)
    except core.exceptions.LDAPNoSuchObjectResult:
      print("Failed to find user with dn {}".format(userdn))
    except core.exceptions.LDAPUnwillingToPerformResult:
      print("Unwilling to perform result : Is user dn {} validate ?".format(userdn))

  # VERBOSE messages
  if VERBOSE:
    print(r)
  
  # Display set password
  print("Password set is : {}".format(password))

  # Return True if operation succesful
  return r

# Add User
def add_user_account(connexion, firstname, lastname, sitename, teamname):
  
  # Set user qttributes
  username = firstname.title() + ' ' + lastname.upper()
  user_dn = 'CN={},OU={},OU={},{}'.format(username, teamname, sitename, AD_BASEDN)
  user_object_class = ['OrganizationalPerson', 'person', 'top', 'user']
  user_attributes = {\
  'cn': '{}'.format(username), \
  'displayName': '{}'.format(username), \
  'givenName': '{}'.format(firstname.title()), \
  'sn': '{}'.format(lastname.upper()), \
  'mail': '{}.{}@{}'.format(firstname.lower(),lastname.lower(),AD_DNS), \
  'sAMAccountName': '{}.{}'.format(firstname.lower(),lastname.lower())}
  
  # Get connection
  c = connexion

  try:
    # Perform the Add operation
    c.add(user_dn, user_object_class, user_attributes)
    c.modify(user_dn, {'userPrincipalName': [(MODIFY_REPLACE, ['{}.{}@{}'.format(firstname.lower(),lastname.lower(),AD_DNS)])]})
  except core.exceptions.LDAPEntryAlreadyExistsResult:
    print("Entry Already Exists")
    #sys.exit(1)
  except core.exceptions.LDAPNoSuchAttributeResult:
    print("Error in attribute conversion operation : One or more attributes are incorrect")
    #sys.exit(1)   

  # VERBOSE messages
  if VERBOSE:
    print(c.entries)

  # Display set password
  if isExist(c,username):
    print('User {} has been created '.format(username))  

  # Return True if search succed  
  return c.entries

# Unlock user account
def ad_unlock_user_account(connexion, username):
  c = connexion
  user = isExist(c,username)

  if user:
    # Get user dn and cast it to string
    user_dn = str(user[0].distinguishedName)

    try:
      c.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, ['512'])]})
    except core.exceptions.LDAPNoSuchObjectResult:
      print('Failed to find user with dn {}'.format(user_dn))
      #sys.exit(1)
    except core.exceptions.LDAPInvalidValueError:
      print('Non valid attribute value set. Please recheck expected type')
      #sys.exit(1)
    except core.exceptions.LDAPUnwillingToPerformResult:
      print('Unwilling to perform result : Have set user password first ?')
      #sys.exit(1)  
  else:
    print('{} does not exist'.format(username))

  # VERBOSE messages
  if VERBOSE:
    print(c.result)

  # Return True if search succed  
  return c.result 

# Generate a random string of letters, digits and punctuation
def generatepaswd(stringLength=8):
    password_characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(password_characters) for i in range(stringLength))


# Main
if __name__ == "__main__":

  # Manage Option command line
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

  # Create user account, change password and unlock it 
  args.add_user_account(c, args.firstname.title(), args.lastname.upper(), args.sitename, args.teamname.title())
  username = args.firstname.title() + ' ' + args.lastname.upper()
  ad_modify_password(c, username, generatepaswd())
  ad_unlock_user_account(c, username)

  # close the connection
  c.unbind()
