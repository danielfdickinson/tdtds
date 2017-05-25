#!/usr/bin/perl -w
#
#     The Dance That Doesn't Suck: Vote on songs for your dance
#     $Id: Auth.pm,v 1.9 2006/12/04 11:16:50 mornir Exp $
#     Copyright (C) 2006 Daniel Dickinson <cshore@wightman.ca>

#     This program is free software; you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation; either version 2 of the License, or
#     (at your option) any later version.

#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.

#     You should have received a copy of the GNU General Public License
#     along with this program; if not, write to the Free Software
#     Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

package Tdtds::Auth;

use strict;
use warnings;

use CGI;
use CGI::Carp;
use IO::File;

use Tdtds::Common;
use Tdtds::Database;

BEGIN {
    use Exporter();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);
            # set the version for version checking
    $VERSION = sprintf "%d.%03d", q$Revision: 1.9 $ =~ /(\d+)/g;

    @ISA         = qw(Exporter);
    @EXPORT      = qw(AUTH_OK AUTH_EXPIRED AUTH_NO_COOKIE AUTH_DB_ERROR
		      AUTH_NO_DB_COOKIE AUTH_LOGGED_OUT $auth_cookie
		      &is_authenticated &create_auth_cookie &remove_cookie
		      );
    %EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

        # exported package globals go here,
        # as well as any optionally exported functions
    @EXPORT_OK   = qw();

}

our @EXPORT_OK;

use constant AUTH_OK => 0;
use constant AUTH_EXPIRED => 1;
use constant AUTH_NO_COOKIE => 2;
use constant AUTH_DB_ERROR => 3;
use constant AUTH_NO_DB_COOKIE => 4;
use constant AUTH_LOGGED_OUT => 5;

# package globals go here

# initialize package globals


# continue intializing package globals

# all file-scoped lexicals must be created before
# the functions below that use them.

# file-private lexicals go here
# my $priv_var    = '';
# my %secret_hash = ();

# here's a file-private function as a closure,
# callable as &$priv_func;  it cannot be prototyped.
# my $priv_func = sub {
        # stuff goes here.
#};

 sub create_auth_cookie {
     my $email = shift;
     my $uuid_gen = new Data::UUID;
     my $auth_cookie_value = $uuid_gen->create_str();
     my $expiry_time = time() + AUTH_COOKIE_EXPIRY;
     my $error = ERROR_OK;
     my $db_value;

     {
	 $db_value = pack('l a*', $expiry_time, $email);
	 $error = db_set("cookie.db", $auth_cookie_value, $db_value);

	 if ($error) {	     
	     last;
	 }

	 $auth_cookie = $http_transaction->cookie(-name=>'auth_cookie',
						  -value=>trim($auth_cookie_value),
						  -path=>SCRIPT_PATH,
						  -expires=>'+8h',
						  -secure=>0);
     }
     return $error;
 }


sub is_authenticated {
    my $auth_cookie_value = trim($http_transaction->cookie('auth_cookie'));
    my $db_value;
    my $expiry;
    my $email = undef;
    $error_number = AUTH_OK;

    {
	if (!defined $auth_cookie_value) {
	    $error_number = AUTH_NO_COOKIE;
	    last;
	}
	if ($auth_cookie_value eq 'logged_out') {
	    $error_number = AUTH_LOGGED_OUT;
	    last;
	}

	$db_value = db_get('cookie.db', $auth_cookie_value);

	if ($error_number) {
	    $error_number = AUTH_DB_ERROR;
	    last;
	}

	if (!defined $db_value) {
	    $error_number = AUTH_NO_DB_COOKIE;
	    last;
	}
	
	($expiry, $email) = unpack('l a*', $db_value);

	if ((!defined $expiry) || (!defined $email)) {
	    croak 'The cookie database has been corrupted.';
	}

	if (time() >= $expiry) {
	    if (DEBUG_LEVEL >= DEBUG_MEDIUM) {
		carp 'expiry ' . $expiry . ', time ' . time();
	    }
	    $error_number = AUTH_EXPIRED;	    
	    $email = undef;
	    db_delete('cookie.db', $auth_cookie_value);
	}
        
	return $email;
    }
    return $email;
}

sub remove_cookie {
    my $auth_cookie_value = $http_transaction->cookie('auth_cookie');
    my $db_value;
    my $expiry;
    $error_number = AUTH_LOGGED_OUT;
    my $error;

    {
	if (!defined $auth_cookie_value) {
	    # no cookie so we don't need to remove it
	    last;
	}
	$error = db_delete('cookie.db', $auth_cookie_value);

	if ($error) {
	    $error_number = AUTH_DB_ERROR;
	    last;
	}
	

	$auth_cookie = $http_transaction->cookie({-name=>'auth_cookie',
						  -value=>'logged_out',
						  -path=>SCRIPT_PATH,
						  -expires=>'-1h',
						  -secure=>0});

    }
    return $error_number;
}


END { }

1;
