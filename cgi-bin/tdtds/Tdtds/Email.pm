#!/usr/bin/perl -w
#
#     The Dance That Doesn't Suck (0.8.1): Vote on songs for your dance
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

package Tdtds::Email;

use Tdtds::Common;
use CGI::Carp;
use CGI;
use Digest::MD5 qw(md5_base64);
use Net::SMTP;
use IO::File;
use DB_File;
use URI::Escape;
use Data::UUID;
use strict;
use warnings;

BEGIN {
    use Exporter();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);
            # set the version for version checking
    $VERSION = sprintf "%d.%03d", q$Revision: 1.7 $ =~ /(\d+)/g;

    @ISA         = qw(Exporter);
    @EXPORT      = qw(EMAIL_OK EMAIL_SEND_ERROR EMAIL_BAD_ADDRESS
		      EMAIL_INIT_ERROR EMAIL_DATA_ERROR EMAIL_HEADER_TO_ERROR
		      EMAIL_HEADER_FROM_ERROR EMAIL_HEADER_SUBJECT_ERROR
		      EMAIL_NO_DATA EMAIL_NO_FROM EMAIL_NO_ADDRESS
		      &send_email &send_confirmation
		      );
    %EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

        # exported package globals go here,
        # as well as any optionally exported functions
    @EXPORT_OK   = qw();

}

our @EXPORT_OK;


# package globals go here
# our 

# initialize package globals

# continue intializing package globals
# $http_transaction = new CGI;

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

use constant EMAIL_OK => 0;
use constant EMAIL_SEND_ERROR => 1;
use constant EMAIL_BAD_ADDRESS => 2;
use constant EMAIL_INIT_ERROR => 3;
use constant EMAIL_DATA_ERROR => 4;
use constant EMAIL_HEADER_TO_ERROR => 5;
use constant EMAIL_HEADER_FROM_ERROR => 6;
use constant EMAIL_HEADER_SUBJECT_ERROR => 7;
use constant EMAIL_NO_DATA =>8;
use constant EMAIL_NO_FROM => 9;
use constant EMAIL_NO_ADDRESS => 10;
use constant EMAIL_NO_SUBJECT => 11;
                 
sub send_mail {
    my $email = shift;
    my $from = shift;
    my $subject = shift;
    my $body = shift;
    my $smtp;
    my $email_error = EMAIL_OK;
    my $line;

    $smtp = Net::SMTP->new(SMTP_MAILHOST);   
    while(TRUE) {    
	if (!defined($smtp)) {
	    croak 'There was an error connecting to the mail server.  Unable to send confirmation at this time. (' . SMTP_MAILHOST . ')';	    
	    last;
	}

	if ((!(defined $email)) || ($email eq '')) {
	    $email_error = EMAIL_NO_ADDRESS;
	    last;
	}

	if ((!(defined $from)) || $from eq '') {
	    $email_error = EMAIL_NO_FROM;
	    last;
	}
	    
	if ((!(defined $subject)) || ($subject eq '')) {
	    $email_error = EMAIL_NO_SUBJECT;
	    last;
	}

	if (!(defined $body)) {
	    $email_error = EMAIL_NO_DATA;
	    last;
	}

	if (!($smtp->mail(ADMIN_EMAIL))) {
	    $email_error = EMAIL_INIT_ERROR;
	    last;
	}

	if (!($smtp->to($email))) {
	    $email_error = EMAIL_BAD_ADDRESS;
	    $smtp->quit;
	    last;
	}

	if (!$smtp->data()) {
	    $email_error = EMAIL_DATA_ERROR;
	    $smtp->quit;
	    last;
	}

	if (!$smtp->datasend("To: $email\n")) {
	    $email_error = EMAIL_HEADER_TO_ERROR;
	    $smtp->quit;
	    last;
	}
	   
	if (!($smtp->datasend("From: $from\n"))) {
	    $email_error = EMAIL_HEADER_FROM_ERROR;
	    $smtp->quit;
	    last;
	}

	if (!($smtp->datasend("Subject: $subject\n"))) {
	    $email_error = EMAIL_HEADER_SUBJECT_ERROR;
	    $smtp->quit;
	    last;
	}
	
	if (!($smtp->datasend("\n"))) {
	    $email_error = EMAIL_DATA_ERROR;
	    $smtp->quit;
	    last;
	}

	foreach $line (@{$body}) {
	    if (!($smtp->datasend($line))) {
		$email_error = EMAIL_DATA_ERROR;
		$smtp->quit;
		last;
	    }		
	}

	if ($email_error == EMAIL_DATA_ERROR) {
	    last;
	}
	
	if (!($smtp->dataend())) {
	    $email_error = EMAIL_SEND_ERROR;
	    $smtp->quit;
	    last;
	}

	$email_error = EMAIL_OK;
	$smtp->quit;
	last;
    }
    return($email_error);

}

sub send_confirmation {
    my $email = shift;
    my $confirmation_code = shift;    
    my $email_error;
    my $confirm_file;
    my @body_lines;
    my $from = ADMIN_EMAIL;
    my $subject;

    $email_error = EMAIL_OK;
    {

	$subject = "Confirm registration with " . SITE_NAME;

	$confirm_file = new IO::File TEMPLATE_PATH . "confirmation_email.txt", "r";
	if (!defined($confirm_file)) {
	    croak 'Unable to open confirmation email template.';	    
	    last;
	}
	
	
	while(<$confirm_file>) {
	    s/tdtds_email_address/$email/;
	    s/tdtds_confirmation_code/$confirmation_code/;
	    push @body_lines, $_;	    
	}
	undef $confirm_file;    
	# automatically closes the file
	
	my $email_uri = uri_escape($email);
	if (!defined($email_uri)) {
	    croak 'Something went wrong trying to encode your email address for the link in the confirmation email.';
	}
	
	my $confcode_uri = uri_escape($confirmation_code);
	
	if (!defined($confcode_uri)) {
	    croak "Something went wrong trying to format the confirmation code for the link in the confirmation email.";
	}

	push @body_lines, SCRIPT_BASE_URL . SCRIPT_NAME . '?action=confirm' . '&email=' . $email_uri . '&confcode=' . $confcode_uri;
        
	$email_error = send_mail($email, $from, $subject, \@body_lines);
    }
    return($email_error);
}


END { }

1;
