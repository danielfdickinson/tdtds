#!/usr/bin/perl -w
#
#     The Dance That Doesn't Suck: Vote on songs for your dance
#     $Id: Database.pm,v 1.9 2006/12/04 11:15:17 mornir Exp $
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

package Tdtds::Database;

use strict;
use warnings;

use Tdtds::Common;
use CGI::Carp;

use IO::File;
use DB_File;

BEGIN {
    use Exporter();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);
            # set the version for version checking
    $VERSION = sprintf "%d.%03d", q$Revision: 1.9 $ =~ /(\d+)/g;

    @ISA         = qw(Exporter);
    @EXPORT      = qw(		      
		      &db_lock &db_open_hash &db_close 
		      &db_get &db_set &db_delete
		      );
    %EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

        # exported package globals go here,
        # as well as any optionally exported functions
    @EXPORT_OK   = qw();

}

our @EXPORT_OK;


# package globals go here
use constant LOCK_SH => 1;
use constant LOCK_EX => 2;
use constant LOCK_NB => 4;
use constant LOCK_UN => 8;

use constant ERROR_DATABASE_OPEN_BUT_NO_HASH => 6;
use constant ERROR_DATABASE_WRITE => 3;
use constant ERROR_DATABASE_SYNC => 4;
use constant ERROR_DATABASE_DELETE => 5;

use constant DB_READ_LOCK_TIMEOUT => 60 * 2; # 2 minutes = 2 * 60 seconds
use constant DB_WRITE_LOCK_TIMEOUT => 60 * 3; # 3 minutes = 3 * 60 seconds


# initialize package globals

# initialize values for CGI

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


sub db_lock {
    my $db_fh = shift;
    my $db_mode = shift;
    my $db_timeout = shift;
    my $start_time = time();
    my $elapsed_time = 0;
    my $error = ERROR_OK;

    while (!(flock ($db_fh, $db_mode))) {
	$elapsed_time = time() - $start_time;
	if ($elapsed_time >= $db_timeout) {
	    last;
	}	    
    }
    if ($elapsed_time >= $db_timeout) {	    
	$error = ERROR_DATABASE_TIMEOUT;	
    } 
    return $error;
}

sub db_open_hash {
    my $db_name = shift;
    my $for_write = shift;
    my $dbref = shift;
    my $dbref_hash = shift;
    my $dbref_fh = shift;
    my $is_btree = shift;
    my $error = ERROR_OK;

    if ((!defined $db_name) || ($db_name eq '')) {
	croak 'No database name given';
    }
    if (!defined $dbref) {
	croak 'No reference for database variable given';
    }
    if (!defined $dbref_hash) {
	croak 'No reference for database hash given';
    }
    if (!defined $dbref_fh) {
	croak 'No reference for database filehandle given';
    }

    if ((!defined $is_btree) || ($is_btree == FALSE) ) 
    {
	$$dbref = tie(%{$dbref_hash}, 'DB_File', DB_PATH . $db_name, 
		      O_CREAT|O_RDWR, 0664, $DB_HASH);
    } else {
	$$dbref = tie(%{$dbref_hash}, 'DB_File', DB_PATH . $db_name, 
		      O_CREAT|O_RDWR, 0664, $DB_BTREE);
    }

    if ($$dbref) {

	my $fd = $$dbref->fd;

	$$dbref_fh = new IO::File;

	if (${$dbref_fh}->open("+<&=$fd")) {
	    if (!$for_write) {
		$error = db_lock($$dbref_fh, LOCK_SH | LOCK_NB, DB_READ_LOCK_TIMEOUT);
		if ($error) {
		    flock($$dbref_fh, LOCK_UN);
		    undef $$dbref;
		    untie %{$dbref_hash};
		    close $$dbref_fh;
		}
	    } else {
		db_lock($$dbref_fh, LOCK_EX | LOCK_NB, DB_WRITE_LOCK_TIMEOUT);
    
		if ($error) {
		    flock($dbref_fh, LOCK_UN);
		    undef $$dbref;
		    untie %{$dbref_hash};
		    close $$dbref_fh;
		}
	    }	    
	} else {
	    croak 'Couldn\'t open database file descriptor';
	    
	    undef $$dbref;
	    untie %{$dbref_hash};
	    close $$dbref_fh;
	}
	
    } else {
	croak 'Unable to associate database with variable';
    }
    return $error;
}
    
sub db_close {
    my $dbref = shift;
    my $dbref_hash = shift;
    my $dbref_fh = shift;
    if (defined $$dbref_fh) {
	flock($$dbref_fh, LOCK_UN) || 
	    carp('unable to remove lock on database');
    }
    undef $$dbref;
    defined $dbref_hash && untie %{$dbref_hash};
    defined $$dbref_fh && close $$dbref_fh;
}

sub db_get {
    my $db_name = shift;
    my $key = shift;
    my $is_btree = shift;
    my $db;
    my %db_hash;
    my $db_fh;
    my $error;
    my $value;
    
    $error_number = ERROR_OK;

    {
	if ((defined $is_btree) && ($is_btree)) {
	    $error = db_open_hash($db_name, FALSE, \$db, \%db_hash, 
				  \$db_fh, TRUE);
	    
	} else {
	    $error = db_open_hash($db_name, FALSE, \$db, \%db_hash, 
				  \$db_fh, FALSE);
	    
	}

	if ($error) {
	    $value = undef;
	    $error_number = $error;
	    last;
	}

	$value = (exists $db_hash{$key})?($db_hash{$key}):undef;       
	db_close(\$db, \%db_hash, \$db_fh);	
    }
    return $value;
}

sub db_set {
    my $db_name = shift;
    my $key = shift;
    my $value = shift;
    my $is_btree = shift;
    my $db;
    my %db_hash;
    my $db_fh;
    my $error;

    $error = ERROR_OK;
    {
	if (!defined $db_name) {
	    croak 'No database name given.';
	}

	if (!defined $key) {
	    croak "Database $db_name, no key specified.";
	}
	
	if (!defined $value) {
	    croak "Database $db_name, no value set for $key";
	}

	if ((defined $is_btree) && ($is_btree)) {
	    $error = db_open_hash($db_name, TRUE, \$db, \%db_hash, 
				  \$db_fh, TRUE);
	} else {
	    $error = db_open_hash($db_name, TRUE, \$db, \%db_hash, 
				  \$db_fh, FALSE);
	}
	if ($error) {
	    last;
	}

	if (!(defined($db_hash{$key} = $value))) {
	    croak "Error writing $key = $value to database";
	}

	if (!(defined($db->sync))) {
	    croak "Error flushing $key = $value to database file";
	}
	sleep 5;
	db_close(\$db, \%db_hash, \$db_fh);	
    }
    return $error;
}

sub db_delete {
    my $db_name = shift;
    my $key = shift;
    my $db;
    my %db_hash;
    my $db_fh;
    my $error;

    $error = ERROR_OK;
    {
	$error = db_open_hash($db_name, TRUE, \$db, \%db_hash, \$db_fh);
	if ($error) {
	    last;
	}

	if (!(defined(delete $db_hash{$key}))) {
	    croak "Error deleting $key from database";
	}
	if (!(defined($db->sync))) {
	    croak "Error sync after deleting $key from database file";
	}
	sleep 5;
	db_close(\$db, \%db_hash, \$db_fh);	
    }
    return $error;
}


END { }

1;
