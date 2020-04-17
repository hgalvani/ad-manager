AD-MANAGER
==========

Description
-----------
This project aims to more easily manage some common actions in Active Directory like create a user.

Licence
-------
The ad-manager project is open source software released under the GPL v3 license. Copyright 2020 Harold GALVANI
* Quick Guide : https://www.gnu.org/licenses/quick-guide-gplv3.html

Installation
-------------
ad-manager is based on ldap3 library.
Once you have cloned this repo, you can simply install it with
```python
pip3 install -r  requirements.txt
```

Configuration
-------------
Modify those constants to match your settings
```python
AD_SERVER = '192.168.0.104'
AD_DOMAIN = 'ANTEVERSE'
AD_BIND_USER = AD_DOMAIN + "\\ad-manager"
AD_BIND_PWD = 'P@ssword123'
AD_DNS = 'anteverse.com'
AD_BASEDN = 'DC=anteverse,DC=com'
```

Usage
-----
```
usage: ad-manager.py [-h] [-v] [-cu] [-f FIRSTNAME] [-l LASTNAME]
                     [-s SITENAME] [-t TEAMNAME]

Manage user in AD.

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Activate verbose messages
  -cu, --create-user    Create user
  -f FIRSTNAME, --firstname FIRSTNAME
                        User Firstname
  -l LASTNAME, --lastname LASTNAME
                        User Lastname
  -s SITENAME, --sitename SITENAME
                        Site name
  -t TEAMNAME, --teamname TEAMNAME
                        Team name

Ex : python3 ad-manager.py --create-user --firstname Agnes --lastname DUPONTEL --sitename SiteA --teamname Direction
```

LDAP3
-----
ldap3 is a strictly RFC 4510 conforming LDAP V3 pure Python client library. The same codebase runs in Python 2, Python 3, PyPy and PyPy3.

* Sources : https://github.com/cannatag/ldap3
* Documentation : http://ldap3.readthedocs.io