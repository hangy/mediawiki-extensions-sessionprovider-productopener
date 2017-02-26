# AuthRemoteuser: A MediaWiki Extension

Based on AuthRemoteuser, this extension allows integration with the ProductOpener
authentication system via it's session cookie. If an account with that name does
not exist yet, one is created.

## Installation
First, add this to your `LocalSettings.php`:

    ####################################################
    # Extension: AuthProductOpener
    wfLoadExtension( 'AuthProductOpener' );
    $wgAuthProductOpenerDomain = 'world.openfoodfacts.org';
    
    # If you want the extension to autocreate users not existing you have to add 
    $wgGroupPermissions['*']['autocreateaccount'] = true;
    
    # Settings: AuthRemoteuser
    $wgGroupPermissions['*']['createaccount']   = false;
    $wgGroupPermissions['*']['read']            = false;
    $wgGroupPermissions['*']['edit']            = false;
    ####################################################

# Original version

The original version of this fork can be found on [GitHub]
(https://github.com/noris-network/mediawiki-extensions-sessionprovider-remoteuser).

# License (GPLv2)

    Use web server authentication (REMOTE_USER) in MediaWiki.
    Copyright 2006 Otheus Shelling
	Copyright 2007 Rusty Burchfield
	Copyright 2009 James Kinsman
	Copyright 2010 Daniel Thomas
	Copyright 2010 Ian Ward Comfort
	Copyright 2014 Mark A. Hershberger
	Copyright 2015 Jonas Gröger
	Copyright 2016 Andreas Fink, hangy

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
