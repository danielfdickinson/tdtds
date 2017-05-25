#!/usr/bin/perl -w
#
#     The Dance That Doesn't Suck; Vote on songs for your dance
#     Copyright (C) 2006 Daniel Dickinson <cshore@wightman.ca>
#     $Id: tdtds.cgi,v 1.31 2006/12/06 03:44:23 mornir Exp $

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



use CGI;
use CGI::Carp;
use Digest::MD5 qw(md5_base64);
use Net::SMTP;
use IO::File;
use DB_File;
use URI::Escape;
use Data::UUID;
use strict;
use warnings;

use Tdtds::Common;
use Tdtds::Database;
use Tdtds::Email;
use Tdtds::Auth;

use constant CONFIRMATION_CODE_LENGTH => 36;
use constant MAX_EMAIL_ADDRESS_LENGTH => 255;
use constant MIN_EMAIL_ADDRESS_LENGTH => 8; # 3 is a theoretical minimum, but more likely 8 is lower than any real address
use constant MAX_PASSWORD_LENGTH => 255;
use constant MIN_PASSWORD_LENGTH => 8;
use constant MAX_MD5_PASSWORD_LENGTH => 22;

use constant REG_MAX_TRIES_PER_DAY => 3;
use constant REG_WAIT_PERIOD => 5 * 60; # 5 minutes * 60 seconds per minute

use constant REG_SHOULD_WAIT => 1;

use constant USER_OK => 0;
use constant USER_UNKNOWN => 1;
use constant USER_RESET => 2;
use constant USER_DB_ERROR => 3;
use constant USER_RESET_FAILED => 4;

use constant LOGIN_OK => 0;
use constant LOGIN_NOT_REGISTERED => 1;
use constant LOGIN_MISSING_PASSWORD => 2;
use constant LOGIN_BAD_PASSWORD => 3;
use constant LOGIN_MISSING_EMAIL => 4;
use constant LOGIN_UNKNOWN_ERROR => 5;

use constant NUM_VOTES => 5;

use constant ADMIN_HOME => 1;
use constant ADMIN_APPROVE_SONGS =>2;
use constant ADMIN_APPROVE_LINKS =>3;
use constant ADMIN_LINK_APPROVE_PAGE =>4;
use constant ADMIN_MERGE_PAGE => 5;
use constant ADMIN_PERFORM_MERGE => 6;
use constant ADMIN_MISC => 7;
use constant ADMIN_PERFORM_MISC => 8;
use constant ADMIN_END_ROUND => 9;
use constant ADMIN_REMOVE_SONGS => 10;
use constant ADMIN_PERFORM_REMOVE => 11;

page_start();

sub check_registered {
    my $email = shift;
    my $found_user; 
    my $password;
    my $notify;
    my $reset;
    my $db_value;

    $error_number = ERROR_OK;
    {
	$found_user = USER_UNKNOWN;
	$db_value = db_get("login.db", $email);

	if (!(defined $db_value)) {	    
	    last;
	}
	
	($password, $notify, $reset) = unpack("a" . MAX_MD5_PASSWORD_LENGTH . " c c", $db_value);

	if ((!defined $password) || (!defined $notify) || (!defined $reset)) {
	    croak 'Invalid data in database doing registration check.';
	}
	
	if (!$reset) {
	    $found_user = USER_OK;
	} else {
	    $found_user = USER_RESET;
	}
    }
    if ($error_number) {
	$found_user = USER_DB_ERROR;
    }
    return $found_user;
}

sub create_new_user {
    my $email = shift;
    my $password = shift;
    my $notify = shift;
    my $reset = FALSE;
    my $db_value;
    my $error = ERROR_OK;
    {
	if (!(defined ($db_value = pack("a" . MAX_MD5_PASSWORD_LENGTH . " c c", $password, $notify, $reset)))) {
	    croak 'Error packing password and preferences.';
	}

	$error = db_set("login.db", $email, $db_value);
	if ($error) {
	    last;
	}

	$error = db_delete("registration.db", $email);
    }
    return $error;
}

sub set_reg_wait {
    my $email = shift;
    my $conf_code = shift;
    my $password = shift;
    my $notify = shift;
    my $last_try_time;
    my $retry_count = 0;
    my $old_conf_code;
    my $old_password;
    my $old_notify;
    my $md5_password;
    my $reg_value;
    my $error;

    {
	$error = ERROR_OK;

	if ((!defined $email) || (!defined $conf_code) || (!defined $notify)) {
	    croak 'Missing information saving registration.';
	}

	$reg_value = db_get("registration.db", $email);
	if (!defined $reg_value) {
	    if ($error_number) {
		$error = $error_number;
		last;
	    }
	} else {
	    ($last_try_time, $retry_count, $old_conf_code, $old_password, 
	     $old_notify) = \
		 unpack("l c a" . CONFIRMATION_CODE_LENGTH . " a" . 
			MAX_MD5_PASSWORD_LENGTH . " c", $reg_value);
	    
	    if ((!defined $last_try_time) || (!defined $retry_count) || 
		(!defined $old_conf_code) || (!defined $old_password) || 
		(!defined $old_notify)) {
		croak 'Error unpacking registration status';
	    }	

	    if ((time() - DAY_SECONDS) >= $last_try_time) {
		$retry_count = 0;
	    } elsif ((time() - REG_WAIT_PERIOD) < $last_try_time) {
		$error = REG_SHOULD_WAIT
		} elsif ($retry_count < REG_MAX_TRIES_PER_DAY) {
		    $retry_count++;
		} else {
		    $error = REG_SHOULD_WAIT;
		}	  
	}

	if (!$error) {
	    if (!defined ($reg_value = 
			  pack("l c a" . CONFIRMATION_CODE_LENGTH . 
			       " a" . MAX_MD5_PASSWORD_LENGTH . " c", 
			       time(), $retry_count, $conf_code, 
			       $password, $notify))) {
		croak 'Error packing registration status.';
	    } else {
		$error = db_set("registration.db", $email, $reg_value);
	    }
	}
	
	if ($error == REG_SHOULD_WAIT) {
	    croak "The script encountered an error setting time to wait before allowing next attempt at registration.  It appears we have already done this recently, but somehow reached this code anyway.";
	}
    }
    return $error;
}

sub check_last_reg_time {
    my $email = shift;
    my $too_soon = FALSE;
    my $last_try_time;
    my $retry_count;
    my $conf_code;
    my $password;
    my $notify;
    my $db_value;

    $error_number = ERROR_OK;
    {
	if (!defined $email) {
	    croak 'Missing email address.';
	}

	$db_value = db_get("registration.db", $email);
	
	if (!defined $db_value) {    
	    $too_soon = FALSE;
	} else {
	    ($last_try_time, $retry_count, $conf_code, $password, $notify) = 
		unpack("l c a" . CONFIRMATION_CODE_LENGTH . " a" . 
		       MAX_MD5_PASSWORD_LENGTH . " c", $db_value);
	    if ((!defined $last_try_time) || (!defined $retry_count) || 
		(!defined $conf_code) || (!defined $password) || 
		(!defined $notify)) {
		croak 'Error unpacking registration information';
	    }
	    if ((time() - DAY_SECONDS) >= $last_try_time) {
		$too_soon = FALSE;
	    } elsif ((time() - REG_WAIT_PERIOD) < $last_try_time) {
		$too_soon = TRUE;
	    } elsif ($retry_count < REG_MAX_TRIES_PER_DAY) {
		$too_soon = FALSE;
	    } else {
		$too_soon = TRUE;
	    }	  
	}
    }

    return $too_soon;
}

sub set_login_reset {
    my $email = shift;
    my $db_value;
    my $reset_ok = USER_OK;
    my $password;
    my $notify;
    my $reset;
    my $error;

    $error = ERROR_OK;
    {
	$db_value = db_get("login.db", $email);

	if (!defined $db_value) {
	    $reset_ok = USER_UNKNOWN;
	    last;
	}
	
	($password, $notify, $reset) = unpack("a" . MAX_MD5_PASSWORD_LENGTH . " c c", $db_value);

	if ((!defined $password) || (!defined $notify) || (!defined $reset)) {
	    croak 'Invalid data in database doing password reset';
	}

	if (!(defined ($db_value = pack("a" . MAX_MD5_PASSWORD_LENGTH . " c c", $password, $notify, TRUE)))) {
	    croak 'Error packing password and preferences.';
	}

	$error = db_set("login.db", $email, $db_value);
	if ($error) {
	    $reset_ok = USER_RESET_FAILED;
	    last;
	}	
    }
    return $reset_ok;
}

sub do_register {
    my $is_reset = shift;
    my $first_use = shift;
    my $entry_error_message = '';
    my $entry_ok = TRUE;
    my $confirmation_code;
    my $email;
    my $password;
    my $too_soon;
    my $email_error;
    my $notify;
    my $password_confirm;
    my $error;

    {
	if (!$is_reset) {
	    $email = trim($http_transaction->param('registeremail'));
	    $password = trim($http_transaction->param('registerpassword'));
	    $password_confirm = trim($http_transaction->param('registerconfirmpassword'));
	} else {
	    $email = trim($http_transaction->param('resetemail'));
	    $password = trim($http_transaction->param('resetpassword'));
	    $password_confirm = trim($http_transaction->param('resetconfirmpassword'));
	}

	if ((!defined $email) || ($email eq '')){
	    $entry_error_message = "You must enter an email address";
	    $entry_ok = FALSE;
	} elsif ((!defined $password) || ($password eq '')) {
	    $entry_error_message = "You must enter a password";
	    $entry_ok = FALSE;
	} elsif ((!defined $password_confirm) || ($password_confirm eq '')) {
	    $entry_error_message = "You must repeat the password in the 'Confirm password' field.";
	    $entry_ok = FALSE;
	} elsif ((length $email) > MAX_EMAIL_ADDRESS_LENGTH) {
	    $entry_error_message = "The email address you have entered is too long.";
	    $entry_ok = FALSE;
	} elsif ((length $email) < MIN_EMAIL_ADDRESS_LENGTH) {
	    $entry_error_message = "A real email address please.";
	    $entry_ok = FALSE;
	} elsif ((length $password) > MAX_PASSWORD_LENGTH) {
	    $entry_error_message = "The password you have entered is too long.";
	    $entry_ok = FALSE;
	} elsif ((length $password) < MIN_PASSWORD_LENGTH) {
	    $entry_error_message = "The password you have entered is too short.  Passwords must be at least " . MIN_PASSWORD_LENGTH . " characters in length";
	    $entry_ok = FALSE;
	} elsif ($password ne $password_confirm) {
	    $entry_error_message = "The passwords do not match.  Please reenter them.";
	    $entry_ok = FALSE;
	} elsif (index($email, '@') == -1) {
	    $entry_error_message = "An email address must have an &#39;@&#39; symbol.";
	    $entry_ok = FALSE;
	} elsif (index($email, '.') == -1) {
	    # since we're not likely to have users from localhost a domain name
	    # must be specified, which means at least one dot.
	    $entry_error_message = "You must enter your full email address, including domain name.";
	    $entry_ok = FALSE;
	}
	
	if ($entry_ok) {
	    $notify = ((defined $http_transaction->param('registernotify')) ? TRUE : FALSE);

	    my $found_user = USER_UNKNOWN;

	    $found_user = check_registered($email);
	    if ($found_user == USER_DB_ERROR) {
		
		$entry_error_message = generate_message_for_error_number($error_number);
		$entry_ok = FALSE;    
		last;
	    } 

	    if (($found_user == USER_OK) && !$is_reset) {
		$entry_error_message = 'This email address already exists and has a password.  If you have forgotten your password please <a href="' . SCRIPT_BASE_URL . '/account.cgi&action=reset_password">reset your password</a>.';
		$entry_ok = FALSE;
		last;
	    } else {
		$too_soon = check_last_reg_time($email);	    
		if ($too_soon) {
		    $entry_ok = FALSE;
		    $entry_error_message = 
			"You must wait five minutes before trying " . 
			"registration again with at most three tries in a" . 
			" given 24 hour period.";
		    last;
		}
		$entry_error_message = 
		    generate_message_for_error_number($error_number);
		if (defined $entry_error_message) {
		    $entry_ok = FALSE;
		    last;
		}
		
		my $uuid_gen = new Data::UUID;
		$confirmation_code = $uuid_gen->create_str();
		
		my $md5_password = md5_base64($password);
		if (! defined $md5_password) {
		    croak 'There was an error calcuating the md5 hash of ' . 
			'your password.';
		}

		$error = set_reg_wait($email, $confirmation_code, 
				      $md5_password, $notify);

		$entry_error_message = 
		    generate_message_for_error_number($error_number);

		if (defined $entry_error_message) {
		    $entry_ok = FALSE;
		    last;
		}
		
		if ($is_reset) {
		    my $reset_ok = set_login_reset($email);;
		    $entry_ok = TRUE;
		    if ($reset_ok != USER_OK) {
			$entry_error_message = 
			    generate_message_for_error_number($error_number);
			if (defined $entry_error_message) {
			    $entry_ok = FALSE;
			    last;
			} elsif ($reset_ok == USER_RESET_FAILED) {
			    croak 'Error writing reset to database.';
			}
		    }
		}
	    }
	    
	    if ($entry_ok) {
		$email_error = send_confirmation($email, $confirmation_code);
		if ($email_error) {
		    $entry_ok = FALSE;
		    if ($email_error == EMAIL_BAD_ADDRESS) {
			$entry_error_message = "The email address you have entered does not appear to be valid ($email).";
		    } else {
			$entry_error_message = "There was an error ($email_error) sending the confirmation email.  If this error persists, please contact " . ADMIN_EMAIL; 
		    }
		} else {
		    $entry_ok = TRUE;
		    $current_template = 'confirm.tmpl';
		    $current_title = 'Confirm Registration for <BR>' . SITE_NAME;
		    print generate_preauth_page();
		}
	    }
	}
    }

    if (!$is_reset) {
	$current_template = 'register.tmpl';
	$current_title = "Register for <BR>" . SITE_NAME;
    } else {
	$current_template = 'reset_password.tmpl';
	$current_title = 'Reset Password for <BR>' . SITE_NAME;
    }

    if (!$first_use) {
	if (!$entry_ok) {
	    print generate_entry_error_page($entry_error_message, FALSE, 
					    $email);
	}
    } else {
	print generate_preauth_page;
    }
    return;
}


sub do_login {
    my $email = shift;
    my $password = shift;
    my $is_md5_password = shift;
    my $first_use = shift;
    my $login_ok = LOGIN_UNKNOWN_ERROR;
    my $db_password;
    my $db_notify;
    my $db_reset;
    my $db_value;
    my $entry_error_message;
    
    $error_number = ERROR_OK;

    {
	if ((!defined $email) || (!defined $password) || 
	    (!defined $is_md5_password)) {

	    $email = trim($http_transaction->param('loginemail'));
	    $password = trim($http_transaction->param('loginpassword'));

	    if ((!defined $email) || ($email eq '')) {
		$login_ok = LOGIN_MISSING_EMAIL;
		last;
	    }
	    if ((!defined $password) || ($password eq '')) {
		$login_ok = LOGIN_MISSING_PASSWORD;
		last;
	    }
	    if (!defined $is_md5_password) {
		$is_md5_password = FALSE;
	    }
	}

	$db_value = db_get("login.db", $email);
	
	if (!defined $db_value) {    
	    if (!$error_number) {
		$login_ok = LOGIN_NOT_REGISTERED;
		last;
	    } else {
		croak "Error retrieving login information for $email";
	    }
	}
	($db_password, $db_notify, $db_reset) = 
	    unpack("a" . MAX_MD5_PASSWORD_LENGTH . " c c", $db_value);
	if ((!defined $db_password) || (!defined $db_notify) || 
	    (!defined $db_reset)) {
	    croak 'Bad value for password, notify, or reset in login database';
	}
	if ($is_md5_password) {
	    if ($password eq $db_password) {
		$login_ok = LOGIN_OK;
		last;
	    } else {
		$login_ok = LOGIN_BAD_PASSWORD;
	    }
	} else {
	    my $md5_password = md5_base64($password);
	    if (! defined $md5_password) {
		croak 'There was an error calcuating the md5 hash of your ' . 
		    'password.';
	    }
	    if ($md5_password eq $db_password) {
		$login_ok = LOGIN_OK;
	    } else {
		$login_ok = LOGIN_BAD_PASSWORD;
	    }
	}
    }    

    {	
	$current_template = 'login.tmpl';
	$current_title = "Login to <BR>" . SITE_NAME;

	if ($error_number) {
	    $entry_error_message = 
		generate_message_for_error_number($error_number);
	} elsif ($login_ok == LOGIN_OK) {
	    create_auth_cookie($email);
	    do_authhome($email);
	    last;
	} elsif ($login_ok == LOGIN_NOT_REGISTERED) {
	    $entry_error_message = 'This email is not registered';
	} elsif ($login_ok == LOGIN_MISSING_PASSWORD) {
	    $entry_error_message = 'You must enter your password';
	} elsif ($login_ok == LOGIN_BAD_PASSWORD) {
	    $entry_error_message = "Incorrect password";
	} elsif ($login_ok == LOGIN_MISSING_EMAIL) {
	    $entry_error_message = "You must enter your email address";	
	} else {
	    croak 'Unknown login result code';
	}
	
	if (!$first_use) {
	    if (defined $entry_error_message) {	    
		print generate_entry_error_page($entry_error_message, FALSE,
						$email);
	    } else {
		croak 'We had an error but no error message was generated.';
	    }
	} else {
	    print generate_preauth_page();
	}
    }
    return $login_ok;
}

sub do_confirm {
    my $first_use = shift;
    my $email;
    my $confirmation_code;
    my $last_try_time;
    my $retry_count;
    my $conf_code;
    my $password;
    my $notify;
    my $db_value;
    my $entry_error_message = undef;
    my $error;
    
    {
	$email = trim($http_transaction->param('confirmemail'));
	$confirmation_code = trim($http_transaction->param('confirmcode'));
	
	if ((!defined $email) && (!defined $confirmation_code)) {
	    $email = uri_unescape($http_transaction->url_param('email'));
	    $confirmation_code = 
		uri_unescape($http_transaction->url_param('confcode'));
	    if ((!defined $email) || (!defined $confirmation_code)) {
		$entry_error_message = 
		    "There was an error decoding the email or confirmation " . 
		    "code from the link you followed.  Are you sure you " . 
		    "copied it correctly?";
		last;
	    } else {
		if (!defined $email) {
		    $entry_error_message = "Invalid entry for email address." .
			"  Please re-enter";
		    last;
		}
		if (!defined $confirmation_code) {
		    $entry_error_message = 'Invalid entry for confirmation ' .
			'code.  Please re-enter.';
		    last;
		}
	    }
	}

	$db_value = db_get('registration.db', $email);
	
	if (!defined $db_value) {	    
	    my $existing_user = check_registered($email);
	    if ($existing_user == USER_DB_ERROR) {
		$entry_error_message = 
		    generate_message_for_error_number($error_number);
		if (defined $entry_error_message) {
		    last;
		}
	    } elsif ($existing_user == USER_OK) {
		$entry_error_message = 'This user is already registered';
		last;
	    } else {
		$entry_error_message = 
		    "No record of this user (email: $email) in our database";
		last;
	    }
	}
	

	($last_try_time, $retry_count, $conf_code, $password, $notify) = 
	    unpack("l c a" . CONFIRMATION_CODE_LENGTH . " a" . 
		   MAX_MD5_PASSWORD_LENGTH . " c", $db_value);
	
	if ((!defined $last_try_time) || (!defined $retry_count) || 
	    (!defined $conf_code) || (!defined $password) || 
	    (!defined $notify)) {
	    croak 'Error unpacking registration information in confirm';
	}

	if ($conf_code ne $confirmation_code) {
	    $entry_error_message = 
		"The confirmation code in the link you have followed is " .
		"not valid.  Perhaps you attempted to register more than " .
		"once and therefore generated a new confirmation code which " .
		"you should receive (or have already received) in a " . 
		"separate email?";
	    last;
	}
	$error = create_new_user($email, $password, $notify);

	if ($error) {
	    croak 'Error creating new user from registration info and ' .
		'confirmation code.';
	}
    }        

    if (!$first_use) {
	if (!defined $entry_error_message) {
	    do_login($email, $password, TRUE);
	} else {
	    $current_template = 'confirm.tmpl';
	    $current_title = "Confirm Registration with <BR>" . SITE_NAME;
	    print generate_entry_error_page($entry_error_message, FALSE, 
					    $email);
	}
    } else {
	$current_template = 'confirm.tmpl';
	$current_title = "Confirm Registration with <BR>" . SITE_NAME;
	print generate_preauth_page;
    }
    return;
}

sub get_vote_list {
    my $email = shift;
    my $vote_name = 'vote.db';
    my $vote_num;
    my $vote_num_str;
    my $vote_db_filename;
    my $db_value;
    my @vote_list = undef;

    {
	$db_value = db_get($vote_name, $email);
	if (!defined $db_value) {
	    last;
	}

	@vote_list = split /\#song\#/, $db_value;
    }
    return @vote_list;
}

sub calc_avail_votes {
    my $email = shift;
    my @vote_list = get_vote_list($email);
    my $avail_votes = 0; 
    my $vote;

    foreach $vote (@vote_list) {
	if ((defined $vote) && ($vote ne '')) {
	    $avail_votes++;
	}
    }
    return $avail_votes;
}

sub generate_vote_table {
    my $email = shift;
    my $return_to = shift;
    my $table = '';

    my $all_votes = 'tally.db';
    my $all_votedb ;
    my %all_vote_hash;
    my $all_vote_fh;

    my $pending_name = 'pending.db';
    my $pendingdb;
    my %pending_hash;
    my $pending_fh;

    my $error = ERROR_OK;
    my $song;
    my $votes;
    my %vote_hash;
    my @vote_list;
    my @approved_rows;
    my @pending_rows;
    my $vote_action;
    my @html_rows;
    my $pending_count = 0;
    my $approved_count = 0;

    {

	$error = db_open_hash($all_votes, FALSE, \$all_votedb, 
			      \%all_vote_hash, \$all_vote_fh, TRUE);

	if ($error) {
	    last;
	}

	my $voteforsong;
	@vote_list = get_vote_list($email);
	foreach $voteforsong (@vote_list) {
	    $vote_hash{$voteforsong}++;
	}

	while (($song, $votes) = each %all_vote_hash) {

	    my @email_list = split /\s/, $all_vote_hash{$song};

	    if (index($all_vote_hash{$song}, $email) != -1) {

		if (DEBUG_LEVEL >= DEBUG_HIGH) {
		    carp "vote_list for $song is $all_vote_hash{$song}";
		}

		push @approved_rows, 
		$http_transaction->
		    td({class => 'CURRENTVOTEELEMENT'},
		       [ 
			 $#email_list + 1, $song, 
			 generate_song_link_html($email, $song, $return_to) 
			 ]
		       );
	    } else {
		if ($all_vote_hash{$song} ne '0') {
		    $approved_count++;
		}
	    }

	}
	if ($approved_count > 0) {
	    push @approved_rows,
	    $http_transaction->
		td( { class => 'OTHERVOTEELEMENT' }, 
		    $approved_count) .
		    $http_transaction->
		    td( { class => 'OTHERVOTEELEMENT',
			  colspan => 2 },
			' approved from other users.'
			);
	}


	$error = db_open_hash($pending_name, FALSE, \$pendingdb, 
				  \%pending_hash, \$pending_fh, TRUE);
	if ($error) {
	    last;
	}
	    
	if (%pending_hash) {

	    @html_rows = undef;

	    while ( ($song, $votes) = each %pending_hash) {

		my @email_list = split /\s/, $pending_hash{$song};

		if (index($pending_hash{$song}, $email) != -1) {

		    push @pending_rows, 
		    $http_transaction->
			td({class => 'CURRENTVOTEELEMENT'},
			   [ 
			     $#email_list + 1, $song, 
			     generate_song_link_html($email, $song,
						     $return_to) 
			 ]
		       );
		} else {
		    $pending_count++;
		}
	        #}
	    }
	} 
	if ($pending_count > 0) {
	    push @pending_rows,
	    $http_transaction->
		td( { class => 'OTHERPENDINGELEMENT' }, 
		    $pending_count) .
		    $http_transaction->
		    td( { class => 'OTHERPENDINGELEMENT',
			  colspan => 2 },
			' pending for other users.'
			);

	}

	if (%pending_hash) {
	    $table = 
		$http_transaction->
		div( { class => 'VOTETABLE' },
		     $http_transaction->h2('Votes for Approved Songs'),
		     $http_transaction->
		     table({class => "APPROVEDVOTETABLE"},
			   $http_transaction->
			   Tr({class => 'VOTEHEAD'}, 
				 $http_transaction->
				 th( {class => 'VOTEHEADELEMENTS'},
				     [ '# Votes', 'Song and Artist/Group', 
				       'Links for this Song' ]) # , 'Action' ])
				 ),
			   $http_transaction->
			   tbody({class => 'VOTEBODY'},
				 $http_transaction->
				 Tr( { -class => 'CURRENTVOTEROW' },
				     \@approved_rows)
				 )
			   ),
		     $http_transaction->h2('Songs Pending Moderator Approval'),
		     $http_transaction->
		     table({class => "PENDINGVOTETABLE"},
			   $http_transaction->
			   Tr({class => 'VOTEHEAD'}, 
				 $http_transaction->
				 th( { class => 'VOTEHEADELEMENTS' },
				     [ '# Votes', 'Song and Artist/Group', 
				      'Links for this Song' ]) # , 'Action' ])
				 ),
			   $http_transaction->
			   tbody({class => 'VOTEBODY'},
				 $http_transaction->
				 Tr( { -class => 'CURRENTVOTEROW' },
				       \@pending_rows)
				 )
			   ),
		     );
	} else {
	    $table = 
		$http_transaction->
		div( { class => 'VOTETABLE' },
		     $http_transaction->h2('Votes for Approved Songs'),
		     $http_transaction->
		     table({class => "APPROVEDVOTETABLE"},
			   $http_transaction->
			   Tr({class => 'VOTEHEAD'}, 
				 $http_transaction->
				 th( { class => 'VOTEHEADELEMENTS' },
				     [ '# Votes', 'Song and Artist/Group', 
				       'Links for this Song' ]) # , 'Action' ])
				 ),
			   $http_transaction->
			   tbody({class => 'VOTEBODY'},
				 $http_transaction->
				 Tr( { -class => 'CURRENTVOTEROW' },
				     \@approved_rows)
				 )
			   )
		     );
	}
    }
    db_close(\$all_votedb, \%all_vote_hash, \$all_vote_fh);
    db_close(\$pendingdb, \%pending_hash, \$pending_fh);
    if ($error) {
	$table .= $http_transaction->
	    p(generate_message_for_error_number($error));
    }       
    
    return $table;
}

sub generate_homepage {
    my $email = shift;
    my $entry_form_file;
    $current_template = 'homepage.tmpl';
    $current_title = "Welcome to<BR> ". SITE_NAME;
    
    my %substitutes;
    my $vote_table = generate_vote_table($email, 'homepage', FALSE);

    $substitutes{'<!-- script_url -->'} = SCRIPT_BASE_URL . SCRIPT_NAME;
    $substitutes{'<!-- tdtds_heading -->'} = $current_title;
    $substitutes{'<!-- tdtds_vote_table -->'} = $vote_table;
    if (is_admin($email)) {
	$substitutes{'<!-- admin_link -->'} =
	    $http_transaction->
	    a({ href => SCRIPT_BASE_URL . SCRIPT_NAME . '?action=admin' },
	      '[Approve Songs]'
	      );
    }
    return generate_page(TRUE, $email, %substitutes);
}

sub generate_pending_count_html {
    my $email = shift;
    my $pending_name = 'pending.db';
    my $pendingdb;
    my %pending_hash;
    my $pending_fh;
    
    my $error = ERROR_OK;
    my $num_pending = 0;
    my $user_ending = 0;
    my $song;
    my $votes;
    my $html = '';

    {
	$error = db_open_hash($pending_name, FALSE, \$pendingdb, \%pending_hash, \$pending_fh, TRUE);
	if ($error) {
	    last;
	}

	while ( ($song, $votes) = each %pending_hash) {
	    $num_pending++;
	}

	if ($num_pending > 1) {
	    $html .= $http_transaction->p({ class => 'PENDINGCOUNT' }, 
					  "There are also $num_pending " . 
					  "songs waiting for moderator " .
					  "approval.");
	} elsif ($num_pending == 1) {
	    $html .= $http_transaction->p({ class => 'PENDINGCOUNT' },
					  "There is also one song " .
					  "waiting for moderator approval.");
	} else {
	    $html .= $http_transaction->p({ class => 'PENDINGCOUNT' },
					  "There are no songs waiting for " .
					  "moderator approval.");
	}
    }


    db_close(\$pendingdb, \%pending_hash, \$pending_fh);

    
    if ($error) {
	$html .= $http_transaction->
	    p(generate_message_for_error_number($error));
    }

    return $html;
}

sub generate_song_link_html {
    my $email = shift;
    my $song = shift;
    my $return_to = shift;

    my $pending_name = 'pending_url.db';
    my $pendingdb;
    my %pending_hash;
    my $pending_fh; 

    my $url_name = 'url.db';
    my $urldb;
    my %url_hash;
    my $url_fh;

    my @url_list;
    my $url_html = '';
    my $url;

    my @pending_list;
    my $pending_url;
    
    my $pending_url_other_user = 0;
    my $error = ERROR_OK;
    
    {
	$error = db_open_hash($pending_name, FALSE, \$pendingdb, 
			      \%pending_hash, \$pending_fh, TRUE);
	if ($error) {
	    last;
	}
	
	$error = db_open_hash($url_name, FALSE, \$urldb, \%url_hash,
			      \$url_fh, TRUE);

	if (defined $url_hash{$song}) {
	    @url_list = split /\s/, $url_hash{$song};
	}

	foreach $url (@url_list) {
	    if ((defined $url_html) && ($url_html ne '')) {
		$url_html .= ' ';
	    }
	    $url_html .= $http_transaction->a({ href => $url }, $url);
	}	
    }
    
    db_close(\$pendingdb, \%pending_hash, \$pending_fh);
    
    if ($error) {
	$url_html = $http_transaction->
	    p(generate_message_for_error_number($error));
    }       
    return $url_html;

}

sub generate_results_table {
    my $email = shift;
    my $table = '';

    my $vote_name = 'tally.db';
    my $votedb;
    my %vote_hash;
    my $vote_fh;

    my $error = ERROR_OK;
    my $song;
    my @vote_list;
    my @html_rows;

    {
	$error = db_open_hash($vote_name, FALSE, \$votedb, \%vote_hash,
			      \$vote_fh, TRUE);

	if ($error) {
	    last;
	}

	@vote_list = sort { 
	    my @a_list = split /\s/, $vote_hash{$b};
	    my @b_list = split /\s/, $vote_hash{$a};
	    my $a_empty = FALSE;
	    my $b_empty = FALSE;
	    if ((!defined $vote_hash{$b}) || ($vote_hash{$b} eq '') ||
		($vote_hash{$b} eq '0')) {
		$b_empty = TRUE;
	    }
	    
	    if ((!defined $vote_hash{$a}) || ($vote_hash{$a} eq '') ||
		($vote_hash{$a} eq '0')) {
		$a_empty = TRUE;
	    }

	    if ($b_empty) {
		if ($a_empty) {
		    return $a cmp $b;
		} else {
		    return -1;
		}
	    } else {
		if ($a_empty) {
		    return 1;
		} else {
		    $#a_list <=> $#b_list or $a cmp $b;
		}
	    }
	} keys %vote_hash;

	foreach $song (@vote_list) {
	    my @song_list = split /\s/, $vote_hash{$song};
	    if ($vote_hash{$song} eq '0') {
		push @html_rows,
		$http_transaction->
		    td({class => 'CURRENTVOTEELEMENT'},
		       [ '0', $song,
			 generate_song_link_html($email, $song, 'results') ]
		       );
	    } else {
		push @html_rows, 
		$http_transaction->
		    td({class => 'CURRENTVOTEELEMENT'},
		       [ $#song_list + 1, $song, 
			 generate_song_link_html($email, $song, 'results') ]
		       );
	    }
	}

	db_close(\$votedb, \%vote_hash, \$vote_fh);

	$table .= $http_transaction->
	    div({class => 'VOTETABLE'},
		$http_transaction->
		table({class => "CURRENTVOTETABLE"},
		      $http_transaction->
		      thead({class => 'CURRENTVOTEHEAD'}, 
			    $http_transaction->
			    th( { -class => 'CURRENTVOTEHEADELEMENTS' },
				[ '# Votes', 'Song and Artist/Group', 
				 'Links for this Song' ])
			    ),
		      $http_transaction->
		      tbody({class => 'CURRENTVOTEBODY'},
			    $http_transaction->
			    Tr(\@html_rows)
			    )
		      ),
		generate_pending_count_html($email)
		);
    }
    if ($error) {
	$table .= $http_transaction->
	    p(generate_message_for_error_number($error));
	last;
    }

    return $table;
}

sub generate_option_html {
    my $email = shift;
    my $selected_song = shift;
    my $exclude_selected = shift;
    my $include_no_votes = shift;
    my @chosen = $_;
    my $song;
    my $votes_for;
    my $option_html = '';
    my $tally_name = 'tally.db';
    my $tally_db;
    my %tally_hash;
    my $tally_fh;
    my $error;
    my $has_song_match = FALSE;
    my %used;

    if (!defined $include_no_votes) {
	$include_no_votes = TRUE;
    }

    if (!defined $exclude_selected) {
	$exclude_selected = FALSE;
    }

    {
	$error = db_open_hash($tally_name, FALSE, \$tally_db, \%tally_hash,
			      \$tally_fh, TRUE);

	if ($error) {
	    last;
	}

	foreach my $used_song (@chosen) {
	    $used{$used_song}++;	    
	}

	while (($song, $votes_for) = each(%tally_hash)) {   
	    if ((defined $votes_for && $votes_for ne '0' && 
		 trim($votes_for) ne '') || ($include_no_votes)) {
		if (($song eq $selected_song) && ($song ne '')) {
		    if (!$exclude_selected) {
			$option_html .= 
			    '<option class="VOTESONGFIELD" value="' .
			    uri_escape($song) . '" selected="true">' .
			    $song . '</option>';
			if (DEBUG_LEVEL >= DEBUG_NOISE) {
			    carp uri_escape($song) . 
				' should be selected.';
			}
			$has_song_match = TRUE;
		    } elsif (DEBUG_LEVEL >= DEBUG_NOISE) {
			carp uri_escape($song) . ' skipped.';
		    }
		
		} elsif ($song ne '') {
		    $option_html .= 
			'<option class="VOTESONGFIELD" value="' .
			uri_escape($song) . '">' .
			$song . '</option>';	    	        
		}
	    }	    
	}
    
	if (!$has_song_match) {
	    $option_html .= '<option class="VOTESONGFIELD" value="' .
		'== No song selected ==' . '" selected="true">' .
		'== No song selected ==' . '</option>';
	} else {
	    $option_html .= '<option class="VOTESONGFIELD" value="' .
		'== No song selected ==' . '">' .
		'== No song selected ==' . '</option>';
	}

    }

    db_close(\$tally_db, \%tally_hash, \$tally_fh);
    if ($error) {
	$option_html = $http_transaction->
	    p(generate_message_for_error_number($error));
    }       
    return $option_html;
}

sub generate_vote_page {
    my $num_votes = get_num_votes();
    my $vote_boxes = '';
    my $options = '';
    my $song;
    

    my $email = shift;
    my $error_message = shift;
    my $table = '';

    my $vote_name = 'vote.db';
    my $votedb;
    my %vote_hash;
    my $vote_fh;

    my $pending_name = 'pending.db';
    my $pendingdb;
    my %pending_hash;
    my $pending_fh;

    my $error = ERROR_OK;
    my $song_num = 1;
    my $num_votes_for;
    my $option_html = '';
    my $db_value;

    my $page;
    my $tabindex = 1;    

    {
	if (DEBUG_LEVEL >= DEBUG_HIGH) {
	    carp 'generate vote page';
	}
	$error = db_open_hash($vote_name, FALSE, \$votedb, \%vote_hash,
			      \$vote_fh, FALSE);

	if ($error) {
	    carp 'Error opening ' . $vote_name . ' (' . $error . ')';
	    last;
	}

	if (DEBUG_LEVEL >= DEBUG_NOISE) {
	    carp 'opened ' . $vote_name . ' db';
	}
	
	$error = db_open_hash($pending_name, FALSE, \$pendingdb, 
			      \%pending_hash, \$pending_fh, TRUE);

	if ($error) {
	    last;
	}

	if (DEBUG_LEVEL >= DEBUG_NOISE) {
	    carp 'opened ' . $pending_name . ' db';
	}

	if ($error) {
	    last;
	}

	if ($error) {
	    last;
	}

	if (DEBUG_LEVEL >= DEBUG_HIGH) {
	    carp 'generate vote page, opened databases';
	}

	my @vote_list;
	my $song_delimeter = '#song#';
	if (defined $vote_hash{$email}) {
	    @vote_list = split /$song_delimeter/, $vote_hash{$email};
	    if (DEBUG_LEVEL >= DEBUG_HIGH) {
		carp "votes so far: $vote_hash{$email}";
	    }
	}
	if (! @vote_list) {
	    $#vote_list = get_num_votes() - 1;
	}
	if ($#vote_list < get_num_votes() - 1) {
	    $#vote_list = get_num_votes() - 1;
	}

	if ($#vote_list > get_num_votes()) {
	    my @new_list;
	    for (my $i = 0; $i < get_num_votes(); $i++) {
		push @new_list, $vote_list[$i];
	    }
	    @vote_list = @new_list;
	}

	my $vote_song;
	my $entry_box;

	foreach $vote_song (@vote_list) {
	    my $has_value = FALSE;

	    if (is_add_round(get_round())) {
		if ((%pending_hash) && (defined $vote_song) 
		    && (defined $pending_hash{$vote_song})) {
		    
		    $entry_box = $http_transaction->textfield({
			-class => 'VOTESONGFIELD',
			-name => 'entry' . $song_num,
			-size => 26,
			-override => TRUE,
			-value => $vote_song,
			-tabindex => $tabindex + 1 },
							      $vote_song
							      );

		    $has_value = TRUE;

		    if (DEBUG_LEVEL >= DEBUG_HIGH) {
			carp 'entry box ' . $song_num . ' with ' . $vote_song;
		    }
		
		} else {
		    $entry_box = $http_transaction->textfield({		   
			-class => 'VOTESONGFIELD',
			-name => 'entry' . $song_num,
			-size => 26,
			-override => TRUE,
			-value => '',		    
			-tabindex => $tabindex + 1  },
							  ''
							      );
		    if (DEBUG_LEVEL >= DEBUG_HIGH) {
			carp 'entry box ' . $song_num . ' not set';
		    }
		}

	    }

	    if (!defined $vote_song) {
		$vote_song = '';
	    }


	    my $add_box = ''; 

	    if (is_add_round(get_round())) {
		$add_box = $http_transaction->
		    br . 'or&nbsp;add:&nbsp;' . $entry_box;
	    }

	    if (!$has_value) {
		$option_html .=
		    $http_transaction->
		    div( { class => 'VOTEBOX' },			 
			 $http_transaction->
			 div( { class => 'VOTESONGBOX' },
			      'Vote&nbsp;for:&nbsp;<select ' . 
			      'class="VOTESONGFIELD" tabindex="' . 
			      $tabindex . '" name="select' . 
			      $song_num . '">' .			  
			      generate_option_html($email, $vote_song, 
						   @vote_list)
			      . '</select>'. $add_box
			      )
			 ); 
		
	    } else {
		$option_html .=
		    $http_transaction->
		    div( { class => 'VOTEBOX' },
			 $http_transaction->
			 div( { class => 'VOTESONGBOX' },
			      'Vote&nbsp;for:&nbsp;<select ' .
			      'class="VOTESONGFIELD" tabindex"' .
			      $tabindex . '"name="select' .
			      $song_num . '">' .
			      generate_option_html($email, '',
						   \%vote_hash, @vote_list)
			      . '</select>' . $add_box
			      )
			 );
	    }
	    
	    $song_num++;
	    $tabindex += 2;
	}
    }
    db_close(\$votedb, \%vote_hash, \$vote_fh);
    db_close(\$pendingdb, \%pending_hash, \$pending_fh);

    if ($error) {
	$page = generate_error_page($email, 
				  generate_message_for_error_number($error));
    } else {
	$current_template = 'votepage.tmpl';
	$current_title = "Vote for Your Songs";
	
	my %substitutes;

	$substitutes{'<!-- script_url -->'} = SCRIPT_BASE_URL . SCRIPT_NAME;
	$substitutes{'<!-- tdtds_heading -->'} = $current_title;
	$substitutes{'<!-- tdtds_vote_boxes -->'} = $option_html;
	if ((defined $error_message) && ($error_message ne '')) {
	    $substitutes{'<!-- voting_errors -->'} = $error_message;
	}

	if (DEBUG_LEVEL >= DEBUG_HIGH) {
	    carp 'after setting substitutes';
	}
	$page = generate_page(TRUE, $email, %substitutes);
	if (DEBUG_LEVEL >= DEBUG_HIGH) {
	    carp 'generated vote page html';
	}     
    }
    
    return $page;

}

sub generate_url_page {
    my $email = shift;
    my $success_message = shift;
    my $error_message = shift;
    my $entry_box = '';
    my $page;

    my $url_html =
	$http_transaction->
	div( { class => 'URLBOX' },
	     $http_transaction->
	     div( { class => 'URLENTRYBOX' },			 
		  'Add&nbsp;Link&nbsp;for:<select ' . 
		  'class="URLFIELD" tabindex="1"' . 
		  '" name="select1">',
		  generate_option_html($email, ''),		  
		  '</select>'
		  ),
	     'Link&nbsp;is:',
	     $http_transaction->textfield({
		 -class => 'URLFIELD',
		 -name => 'entry1',
		 -size => 26,
		 -override => TRUE,
		 -value => '',
		 -tabindex => 2 },
						       '')
	     );

    $current_template = 'urlpage.tmpl';
    $current_title = "Suggest Links for Songs";
	
    my %substitutes;
    
    $substitutes{'<!-- script_url -->'} = SCRIPT_BASE_URL . SCRIPT_NAME;
    if (defined $success_message && ($success_message ne '')) {
	$substitutes{'<!-- url_success -->'} = $success_message;
    }
    $substitutes{'<!-- tdtds_heading -->'} = $current_title;
    $substitutes{'<!-- tdtds_url_boxes -->'} = $url_html;
    if ((defined $error_message) && ($error_message ne '')) {
	$substitutes{'<!-- url_errors -->'} = $error_message;
    }
    
    if (DEBUG_LEVEL >= DEBUG_NOISE) {
	carp 'after setting substitutes';
    }
    $page = generate_page(TRUE, $email, %substitutes);
    if (DEBUG_LEVEL >= DEBUG_HIGH) {
	carp 'generated vote page html';
    }
    return $page;    
}


sub generate_results {
    my $email = shift;
    my $entry_form_file;
    $current_template = 'results.tmpl';
    $current_title = "Results for<BR> ". SITE_NAME;
    
    my %substitutes;
    my $vote_table = generate_results_table($email);

    $substitutes{'<!-- script_url -->'} = SCRIPT_BASE_URL . SCRIPT_NAME;
    $substitutes{'<!-- tdtds_heading -->'} = $current_title;
    $substitutes{'<!-- tdtds_current_vote_table -->'} = $vote_table;
    if (is_admin($email)) {
	$substitutes{'<!-- admin_link -->'} =
	    $http_transaction->
	    a({ href => SCRIPT_BASE_URL . SCRIPT_NAME . '?action=admin' },
	      '[Approve Songs]'
	      );
    }


    my $page = generate_page(TRUE, $email, %substitutes);

    return $page;
}

sub do_submit_votes {
    my $email = shift;
    my $num_votes = get_num_votes();

    my $pending_name = 'pending.db';
    my $pendingdb;
    my %pending_hash;
    my $pending_fh;

    my $vote_name = 'vote.db';
    my $votedb;
    my %vote_hash;
    my $vote_fh;

    my $tally_name = 'tally.db';
    my $tallydb;
    my %tally_hash;
    my $tally_fh;

    my @vote_list;
    my %num_votes;
    my %old_votes;
    my %new_votes;
    
    my $error = ERROR_OK;
    my $error_message = '';

    {
	if (DEBUG_LEVEL >= DEBUG_HIGH) {
	    carp 'dealing with submission from script';
	}
	$error = db_open_hash($pending_name, TRUE, \$pendingdb, 
			      \%pending_hash, \$pending_fh, TRUE);	

	if ($error) {
	    last;
	}
	
	$error = db_open_hash($vote_name, TRUE, \$votedb,
			      \%vote_hash, \$vote_fh, FALSE);

	if ($error) {
	    last;
	}
	

	$error = db_open_hash($tally_name, TRUE, \$tallydb,
			      \%tally_hash, \$tally_fh, TRUE);

	
	if ($error) {
	    last;
	}

	if (DEBUG_LEVEL >= DEBUG_HIGH) {
	    carp 'after open databases in submit votes';
	}

	my $entry_value = '';
	my $votenum = 1;

	my $old_vote_string = $vote_hash{$email};
	if (defined $old_vote_string && (trim($old_vote_string) ne '')) {
	    @vote_list = split /\#song\#/ , $old_vote_string;
	}

	my $vote;
	foreach $vote (@vote_list) {
	    if ((defined $vote) && (trim($vote) ne '')) {
		$old_votes{$vote}++;
	    }
	}

	my $count;
	while ( ($vote, $count) = each(%old_votes) ) {
	    if (DEBUG_LEVEL >= DEBUG_HIGH) {
		carp 'old vote count is ' . $count .' for ' . $vote;
	    }
	}
  	
	for ($votenum = 1; $votenum <= get_num_votes(); $votenum++) {
	    $entry_value = '';
	    if (is_add_round(get_round())) {
		$entry_value = trim($http_transaction->param('entry' . 
							     $votenum));
		if (DEBUG_LEVEL >= DEBUG_MEDIUM) {
		    carp 'submit: entered value ' . $votenum . 
			' is ' . $entry_value;
		}
	    }
	    if ((!defined $entry_value) || (trim($entry_value) eq '')) {
		$entry_value = 
		    uri_unescape(trim($http_transaction->
				      param('select' . $votenum)));
		# make sure a malicious user can't handcraft a submit form
		# which would bypass the approval process
		if (!defined $tally_hash{$entry_value}) {
		    $entry_value = '';
		}
		if (trim($entry_value) eq '== No song selected ==') {
		    $entry_value = '';
		}

		if (! defined $entry_value) {
		    $entry_value = '';
		}
	    }

	    if (trim($entry_value) ne '') {
		$new_votes{$entry_value}++;
	    }
	}

	if (DEBUG_LEVEL >= DEBUG_HIGH) {
	    carp 'figuring out vote_string';
	}
	
	my $vote_string = '';
	my $add_song_delim = FALSE;
	while ( ($vote, $count) = each(%new_votes) ) {
	    if (DEBUG_LEVEL >= DEBUG_HIGH) {
		carp 'new vote count is ' . $count .' for ' . $vote;
	    }
	    for (my $i = 0; $i < $count; $i++) {
		if (!$add_song_delim) {
		    $vote_string .= $vote;
		} else {
		    $vote_string .= '#song#' . $vote;
		}
		$add_song_delim = TRUE;
	    }
	}

	$vote_hash{$email} = $vote_string;
	if (DEBUG_LEVEL >= DEBUG_HIGH) {
	    carp "vote_string: $vote_string";
	}
    }    

    my $vote;
    my $count;

    # Remove old votes (pending and tally) for this user
    while ( ($vote, $count) = each(%old_votes) ) {
	if (defined $vote && trim($vote) ne '') {
	    my $old_tally = $tally_hash{$vote};
	    if (defined $old_tally) {
		if (DEBUG_LEVEL >= DEBUG_HIGH) {
		    carp "previous votes for $vote: $old_tally";
		}
		$old_tally =~ s/$email//g;
		$old_tally =~ s/  / /g;
		if (trim($old_tally) ne '') {
		    $tally_hash{$vote} = $old_tally;
		} else {
		    $tally_hash{$vote} = '0';
		}
	    } else {
		my $old_pending = $pending_hash{$vote};
		if (defined $old_pending) {
		    if (DEBUG_LEVEL >= DEBUG_HIGH) {
			carp "previous pending votes: $old_pending";
		    }
		    $old_pending =~ s/$email//g;
		    $old_pending =~ s/  / /g;
		    if (trim($old_pending) eq '') {
			delete $pending_hash{$vote};
		    } else {
			$pending_hash{$vote} = $old_pending;		
		    }
		    if (DEBUG_LEVEL >= DEBUG_HIGH) {
			carp "pending votes for $vote, less this user's " . 
			    "votes: $pending_hash{$vote}";
		    }
		}
	    }
	}
    }
    
    # Add current votes for this user
    while ( ($vote, $count) = each(%new_votes) ) {
	my $add_space = FALSE;
	
	# If there is no vote in the tally of approved votes, this is a
	# new vote and therefore pending
	if ((!defined $tally_hash{$vote}) || 
	    (trim($tally_hash{$vote} eq '')))  {
		my $old_pending = $pending_hash{$vote};
		my $new_pending = '';		    
		
		if ((!defined $old_pending) || ($old_pending eq '') || 
		    ($old_pending eq ' ')) {
		    $add_space = FALSE;
		    # no prelude
		} else {
		    $new_pending = $old_pending;
		    $add_space = TRUE;
		}
		my $i;
		for ($i = 0; $i < $count; $i++) {
		    if ($add_space) {
			$new_pending .= ' ' . $email;
		    } else {
			$new_pending .= $email;			    
		    }
		    $add_space = TRUE;
		}					
		if (trim($new_pending) ne '') {
		    $pending_hash{$vote} = $new_pending;
		}

		if (DEBUG_LEVEL >= DEBUG_HIGH) {
		    carp "Pending votes for $vote: $pending_hash{$vote}";
		}
	    } else {
		# There is an approved song of this name, so add this user
		# to the list of users voting for this song
		my $old_tally = $tally_hash{$vote};
		my $new_tally = '';		    
		
		if ((trim($old_tally) eq '') || ($old_tally eq '0')) {
		    $add_space = FALSE;
		    # no prelude
		} else {
		    $new_tally = $old_tally;
		    $add_space = TRUE;
		}
		my $i;
		for ($i = 0; $i < $count; $i++) {
		    if ($add_space) {
			$new_tally .= ' ' . $email;
		    } else {
			$new_tally .= $email;			    
		    }
		    $add_space = TRUE;
		}
		if (trim($new_tally) ne '') {
		    $tally_hash{$vote} = $new_tally;
		} else {
		    $tally_hash{$vote} = '0';
		}
		if (DEBUG_LEVEL >= DEBUG_HIGH) {
		    carp "Votes for $vote: $tally_hash{$vote}";
		}
	    }
	}

    if (!$error) {
	
	if (!(defined($pendingdb->sync))) {
	    croak "Error flushing to pending database file";
	}
	
	if (!(defined($votedb->sync))) {
	    croak "Error flushing votes to database file";
	}

	if (!(defined($tallydb->sync))) {
	    croak "Error flushing tally to database file";
	}

	sleep 5;

	if (DEBUG_LEVEL >= DEBUG_HIGH) {
	    carp "vote_string in $vote_name is '$vote_hash{$email}'";
	}
    } else {
	carp "Database error $error";
    }

    db_close(\$pendingdb, \%pending_hash, \$pending_fh);
    db_close(\$votedb, \%vote_hash, \$vote_fh);
    db_close(\$tallydb, \%tally_hash, \$tally_fh);

    if ($error) {
	print generate_error_page($email, 
				  generate_message_for_error_number($error));
    } else {
	print generate_vote_page($email, $error_message);
    }

    return;    
}

sub do_submit_url {
    my $email = shift;

    my $url_name = 'pending_url.db';
    my $urldb;
    my %url_hash;
    my $url_fh;

    my $approved_name = 'url.db';
    my $approveddb;
    my %approved_hash;
    my $approved_fh;

    my $error = ERROR_OK;
    my $error_message = '';
    my $result_message = '';

    {
	if (DEBUG_LEVEL >= DEBUG_HIGH) {
	    carp 'dealing with url submission from script';
	}
	$error = db_open_hash($url_name, TRUE, \$urldb, 
			      \%url_hash, \$url_fh, TRUE);	

	if ($error) {
	    last;
	}

	$error = db_open_hash($approved_name, TRUE, \$approveddb, 
			      \%approved_hash, \$approved_fh, TRUE);	

	if ($error) {
	    last;
	}
	if (DEBUG_LEVEL >= DEBUG_HIGH) {
	    carp 'after open databases in submit votes';
	}

	my $song;
	my $url;
	$song = uri_unescape(trim($http_transaction->
				  param('select1')));
	if (trim($song) eq '== No song selected ==') {
	    $song = '';
	}
	
	if (! defined $song) {
	    $song = '';
	}

	if ($song eq '') {
	    $result_message = "No song specified, link not added.";
	    last;
	}
	
	$url = trim($http_transaction->param('entry1'));

	if (!defined $url || $url eq '') {
	    $result_message = "No link specified, no changes.";
	    last;
	}

	if (DEBUG_LEVEL >= DEBUG_MEDIUM) {
	    carp 'submit: entered url for '. $song . ' is ' . $url;
	}

	my $approved_urls;
  	
	$approved_urls = $approved_hash{$song};
	if (defined $approved_urls) {
	    if (index ($approved_urls, $url) != -1) {
		$result_message = "This link already suggested and " .
		    'approved for ' . $song . '.';
		last;
	    }
	}

	my $pending_urls;
	$pending_urls = $url_hash{$song};
	if (defined $url_hash{$song}) {
	    if (index ($pending_urls, $url) != -1) {
		$result_message = 'This link already suggested but waiting ' .
		    'approval (for ' . $song . ')';
		last;
	    } else {
		$pending_urls .= ' ' . $url;
		$url_hash{$song} = $pending_urls;
	    }
	} else {
	    $url_hash{$song} = $url;
	}    
	$result_message = 'added ' . $url . ' for ' . $song;
    }   

    if (!$error) {
	
	if (!(defined($approveddb->sync))) {
	    croak "Error flushing to url database file";
	}
	
	if (!(defined($urldb->sync))) {
	    croak "Error flushing to pending url database file";
	}

	sleep 5;

    } else {
	carp "Database error $error";
    }

    db_close(\$urldb, \%url_hash, \$url_fh);
    db_close(\$approveddb, \%approved_hash, \$approved_fh);

    if ($error) {
	print generate_error_page($email, 
				  generate_message_for_error_number($error));
    } else {
	print generate_url_page($email, $result_message);
    }
    return;    
}


sub generate_song_action_dropdown {
    my $songnum = shift;
    my $songname = shift;
    my $dropdown = '';
    $songname = uri_escape($songname);

    $dropdown = '<select name="select' . $songnum . '"> ' .
	'<option selected="true" value="Undecided">Undecided</option>' .
	'<option value="Accept' . $songname .'">Accept</option>' .
	'<option value="Reject' . $songname .'">Reject</option>' .
	'</select>';
    return $dropdown;
}
 
sub generate_admin_homepage {
    my $email = shift;
    my $entry_form_file;
    $current_template = 'admin_homepage.tmpl';
    $current_title = "Welcome Administrator for<BR> ". SITE_NAME;
    
    my %substitutes;
    
    my $pending_name = 'pending.db';
    my $pendingdb;
    my %pending_hash;
    my $pending_fh;

    my $admin_table = '';

    my $error = ERROR_OK;
    my $song;
    my $votes;
    my @pending_rows;
    my $songnum = 1;

    {
	$error = db_open_hash($pending_name, FALSE, \$pendingdb, 
				  \%pending_hash, \$pending_fh, TRUE);
	if ($error) {
	    last;
	}
	    
	if (%pending_hash) {

	    while ( (($song, $votes) = each %pending_hash) && $songnum <= 30) {

		push @pending_rows, 
		$http_transaction->
		    td({class => 'CURRENTADMINELEMENT'},
		       [
			$song, generate_song_action_dropdown($songnum, $song)
			 ]
		       );
		$songnum++;
	    }
	} 

	if (%pending_hash) {
	    $admin_table = 
		$http_transaction->
		div( { class => 'VOTETABLE' },
		     $http_transaction->h2('Songs Pending Approval'),
		     $http_transaction->
		     table({class => "PENDINGVOTETABLE"},
			   $http_transaction->
			   Tr({class => 'VOTEHEAD'}, 
				 $http_transaction->
				 th( { class => 'VOTEHEADELEMENTS' },
				     [ 'Song and Artist/Group', 
				       'Action' ])
				 ),
			   $http_transaction->
			   tbody({class => 'VOTEBODY'},
				 $http_transaction->
				 Tr( { -class => 'CURRENTVOTEROW' },
				       \@pending_rows)
				 )
			   ),
		     );
	} else {
	    $admin_table = 
		$http_transaction->div( { class => 'VOTETABLE' },
		     $http_transaction->p('No songs pending approval')
		     );
	}
    }

    $substitutes{'<!-- script_url -->'} = SCRIPT_BASE_URL . SCRIPT_NAME;
    $substitutes{'<!-- tdtds_heading -->'} = $current_title;
    $substitutes{'<!-- tdtds_vote_table -->'} = $admin_table;

    my $page = generate_page(TRUE, $email, %substitutes);

    db_close(\$pendingdb, \%pending_hash, \$pending_fh);

    if ($error) {
	$page = generate_error_page($email, 
				    generate_message_for_error_number($error));
    }

    return $page;   
}

sub generate_link_approvals {
    my $email = shift;
    my $entry_form_file;
    $current_template = 'link_approvals.tmpl';
    $current_title = "Welcome Administrator for<BR> ". SITE_NAME;
    
    my %substitutes;
    
    my $pending_name = 'pending_url.db';
    my $pendingdb;
    my %pending_hash;
    my $pending_fh;

    my $admin_table = '';

    my $error = ERROR_OK;
    my $song;
    my @urls;
    my $urls;
    my @pending_rows;
    my $songnum = 1;
    my $url;

    {
	$error = db_open_hash($pending_name, FALSE, \$pendingdb, 
				  \%pending_hash, \$pending_fh, TRUE);
	if ($error) {
	    last;
	}
	    
	if (%pending_hash) {

	    while ( (($song, $urls) = each %pending_hash) && $songnum <= 30) {
		@urls = split '\s', $urls;

		foreach $url (@urls) {
		    push @pending_rows, 
		    $http_transaction->
			td({class => 'CURRENTADMINURLELEMENT'},
			   [
			    $song . ":&nbsp;" . $url, 
			    generate_song_action_dropdown($songnum, 
							  $song .
							  '#songurl#' .
							  $url)
			    ]
			   );
		    $songnum++;
		    if ($songnum > 30) {
			last;
		    }
		}
	    }
	} 

	if (%pending_hash) {
	    $admin_table = 
		$http_transaction->
		div( { class => 'LINKTABLE' },
		     $http_transaction->h2('Links Pending Approval'),
		     $http_transaction->
		     table({class => "PENDINGLINKTABLE"},
			   $http_transaction->
			   Tr({class => 'LINKHEAD'}, 
				 $http_transaction->
				 th( { class => 'LINKHEADELEMENTS' },
				     [ 'Song and Artist/Group: link', 
				       'Action' ])
				 ),
			   $http_transaction->
			   tbody({class => 'VOTEBODY'},
				 $http_transaction->
				 Tr( { -class => 'CURRENTLINKROW' },
				       \@pending_rows)
				 )
			   ),
		     );
	} else {
	    $admin_table = 
		$http_transaction->div( { class => 'LINKTABLE' },
		     $http_transaction->p('No links pending approval')
		     );
	}
    }

    $substitutes{'<!-- script_url -->'} = SCRIPT_BASE_URL . SCRIPT_NAME;
    $substitutes{'<!-- tdtds_heading -->'} = $current_title;
    $substitutes{'<!-- tdtds_vote_table -->'} = $admin_table;

    my $page = generate_page(TRUE, $email, %substitutes);

    db_close(\$pendingdb, \%pending_hash, \$pending_fh);

    if ($error) {
	$page = generate_error_page($email, 
				  generate_message_for_error_number($error));
    }

    return $page;   
}

sub generate_song_merge {
    my $email = shift;
    my $success_message = shift;
    my $error_message = shift;
    my $entry_form_file;
    $current_template = 'song_merge.tmpl';
    $current_title = "Welcome Administrator for<BR> ". SITE_NAME;
    
    my %substitutes;
    
    my $pending_name = 'pending.db';
    my $pendingdb;
    my %pending_hash;
    my $pending_fh;

    my $tally_name = 'tally.db';
    my $tallydb;
    my %tally_hash;
    my $tally_fh;

    my $admin_table = '';

    my $error = ERROR_OK;
    my $song;
    my $votes;
    my @merging_rows;
    my $songnum = 1;
    my %combined_hash;

    {
	$error = db_open_hash($pending_name, FALSE, \$pendingdb, 
				  \%pending_hash, \$pending_fh, TRUE);
	if ($error) {
	    last;
	}
	$error = db_open_hash($tally_name, FALSE, \$tallydb, 
				  \%tally_hash, \$tally_fh, TRUE);
	if ($error) {
	    last;
	}

	while (($song, $votes) = each %pending_hash) {
	    $combined_hash{$song} = $votes;
	}

	while (($song, $votes) = each %tally_hash) {
	    $combined_hash{$song} = $votes;
	}
	    
	if (%combined_hash) {

	    while (($song, $votes) = each %combined_hash) {
		if ($songnum >30) {
		    last;
		}
		push @merging_rows, 
		$http_transaction->
		    td({class => 'CURRENTMERGEELEMENT'},
		       [
			$song, 
			$http_transaction->
			div( { class => 'MERGEENTRYBOX' },
			     '<select ' . 
			     'class="MERGEFIELD" tabindex="' . $songnum .
			     '" name="select' . $songnum . '">',
			     generate_option_html($email, $song, TRUE, FALSE),
			     '</select>' .
			     $http_transaction->
			     hidden('hidden' . $songnum,
				    uri_escape($song))
			     )
			 ]
		       );
		$songnum++;
	    }
	} 

	if (%combined_hash) {
	    $admin_table = 
		$http_transaction->
		div( { class => 'MERGETABLEDIV' },
		     $http_transaction->
		     table({class => "MERGETABLE"},
			   $http_transaction->
			   Tr({class => 'MERGEHEAD'}, 
				 $http_transaction->
				 th( { class => 'MERGEHEADELEMENTS' },
				     [ 'Merge Song and Artist/Group', 
				       'With' ])
				 ),
			   $http_transaction->
			   tbody({class => 'MERGEBODY'},
				 $http_transaction->
				 Tr( { -class => 'CURRENTMERGEROW' },
				       \@merging_rows)
				 )
			   ),
		     );
	} else {
	    $admin_table = 
		$http_transaction->div( { class => 'MERGETABLE' },
		     $http_transaction->p('No songs that can be merged.')
		     );
	}
    }

    $substitutes{'<!-- script_url -->'} = SCRIPT_BASE_URL . SCRIPT_NAME;
    if (defined $success_message && ($success_message ne '')) {
	$substitutes{'<!-- merge_success -->'} = $success_message;
    }
    $substitutes{'<!-- tdtds_heading -->'} = $current_title;
    $substitutes{'<!-- tdtds_merge_boxes -->'} = $admin_table;
    if ((defined $error_message) && ($error_message ne '')) {
	$substitutes{'<!-- merge_errors -->'} = $error_message;
    }
    my $page = generate_page(TRUE, $email, %substitutes);

    db_close(\$pendingdb, \%pending_hash, \$pending_fh);
    db_close(\$tallydb, \%tally_hash, \$tally_fh);

    if ($error) {
	print generate_error_page($email, 
				  generate_message_for_error_number($error));
    }

    return $page;   
}

sub generate_remove_action_dropdown {
    my $songnum = shift;
    my $songname = shift;
    my $dropdown = '';
    $songname = uri_escape($songname);

    $dropdown = '<select name="select' . $songnum . '"> ' .
	'<option selected="true" value="Keep">Keep</option>' .
	'<option value="Remove' . $songname .'">Remove</option>' .
	'</select>';
    return $dropdown;
}

sub generate_remove_song_page {
    my $email = shift;
    my $success_message = shift;
    my $error_message = shift;
    my $entry_form_file;
    $current_template = 'song_remove.tmpl';
    $current_title = "Welcome Administrator for<BR> ". SITE_NAME;
    
    my %substitutes;
    
    my $pending_name = 'pending.db';
    my $pendingdb;
    my %pending_hash;
    my $pending_fh;

    my $tally_name = 'tally.db';
    my $tallydb;
    my %tally_hash;
    my $tally_fh;

    my $admin_table = '';

    my $error = ERROR_OK;
    my $song;
    my $votes;
    my @merging_rows;
    my $songnum = 1;
    my %combined_hash;

    {
	$error = db_open_hash($pending_name, FALSE, \$pendingdb, 
				  \%pending_hash, \$pending_fh, TRUE);
	if ($error) {
	    last;
	}
	$error = db_open_hash($tally_name, FALSE, \$tallydb, 
				  \%tally_hash, \$tally_fh, TRUE);
	if ($error) {
	    last;
	}

	while (($song, $votes) = each %pending_hash) {
	    $combined_hash{$song} = $votes;
	}

	while (($song, $votes) = each %tally_hash) {
	    $combined_hash{$song} = $votes;
	}
	    
	if (%combined_hash) {

	    while (($song, $votes) = each %combined_hash) {
		if ($songnum >30) {
		    last;
		}
		push @merging_rows, 
		$http_transaction->
		    td({class => 'CURRENTREMOVEELEMENT'},
		       [
			$song, 
			$http_transaction->
			div( { class => 'REMOVEENTRYBOX' },

			     generate_remove_action_dropdown($songnum,
							     $song)
			     )
			 ]
		       );
		$songnum++;
	    }
	} 

	if (%combined_hash) {
	    $admin_table = 
		$http_transaction->
		div( { class => 'REMOVETABLEDIV' },
		     $http_transaction->
		     table({class => "REMOVETABLE"},
			   $http_transaction->
			   Tr({class => 'REMOVEHEAD'}, 
				 $http_transaction->
				 th( { class => 'REMOVEHEADELEMENTS' },
				     [ 'Remove Song and Artist/Group', 
				       'With' ])
				 ),
			   $http_transaction->
			   tbody({class => 'REMOVEBODY'},
				 $http_transaction->
				 Tr( { -class => 'CURRENTREMOVEROW' },
				       \@merging_rows)
				 )
			   ),
		     );
	} else {
	    $admin_table = 
		$http_transaction->div( { class => 'REMOVEETABLE' },
		     $http_transaction->p('No songs that can be merged.')
		     );
	}
    }

    $substitutes{'<!-- script_url -->'} = SCRIPT_BASE_URL . SCRIPT_NAME;
    if (defined $success_message && ($success_message ne '')) {
	$substitutes{'<!-- remove_success -->'} = $success_message;
    }
    $substitutes{'<!-- tdtds_heading -->'} = $current_title;
    $substitutes{'<!-- tdtds_remove_boxes -->'} = $admin_table;
    if ((defined $error_message) && ($error_message ne '')) {
	$substitutes{'<!-- remove_errors -->'} = $error_message;
    }
    my $page = generate_page(TRUE, $email, %substitutes);

    db_close(\$pendingdb, \%pending_hash, \$pending_fh);
    db_close(\$tallydb, \%tally_hash, \$tally_fh);

    if ($error) {
	print generate_error_page($email, 
				  generate_message_for_error_number($error));
    }

    return $page;   
}


sub do_authhome {
    my $email = shift;
    print generate_homepage($email);
}

sub do_results {
    my $email = shift;
    print generate_results($email);
}

sub do_vote_page {
    my $email = shift;
    print generate_vote_page($email);
}

sub do_url_page {
    my $email = shift;
    print generate_url_page($email);
}

sub do_approve_songs {
    my $email = shift;

    my $pending_name = 'pending.db';
    my $pendingdb;
    my %pending_hash;
    my $pending_fh;

    my $vote_name = 'tally.db';
    my $votedb;
    my %vote_hash;
    my $vote_fh;
    
    my $pending_url_name = 'pending_url.db';
    my $pending_urldb;
    my %pending_url_hash;
    my $pending_url_fh; 
    
    my $error = ERROR_OK;
    my $songnum = 1;
    my %songhash;
    
    {
	if (DEBUG_LEVEL >= DEBUG_HIGH) {
	    carp 'dealing with submission from script';
	}
	$error = db_open_hash($pending_name, TRUE, \$pendingdb, 
			      \%pending_hash, \$pending_fh, TRUE);	

	if ($error) {
	    last;
	}
	
	$error = db_open_hash($vote_name, TRUE, \$votedb,
			      \%vote_hash, \$vote_fh, TRUE);
	
	if ($error) {
	    last;
	}
	
	$error = db_open_hash($pending_url_name, TRUE, \$pending_urldb,
			      \%pending_url_hash, \$pending_url_fh, TRUE);
	if ($error) {
	    last;
	}

	if (DEBUG_LEVEL >= DEBUG_HIGH) {
	    carp 'after open databases in approve songs';
	}

	my $songselect = $http_transaction->param('select' . $songnum);
	my $song;
	my $action;
	
	while ((defined $songselect) && ($songselect ne '') && 
		($songnum <= 30)) {
	    if (DEBUG_LEVEL >= DEBUG_NOISE) {
		carp 'Song number:' . $songnum . ' ' . $songselect;
	    }
	    if ($songselect eq 'Undecided') {
		$songnum++;
		$songselect = $http_transaction->param('select' . $songnum);
		next;
	    }
	    $action = substr($songselect, 0, 6);
	    $song = uri_unescape(substr($songselect, 6));
	    $songhash{$song} = $action;
	    $songnum++;
	    $songselect = $http_transaction->param('select' . $songnum);
	}

	while (($song, $action) = each(%songhash)) {
	    if ($action eq 'Accept') {
		$vote_hash{$song} = $pending_hash{$song};
		delete $pending_hash{$song};
	    } elsif ($action eq 'Reject') {
		# remove urls
		my @url_list = split /\s/, $pending_url_hash{$song};
		delete $pending_url_hash{$song};
		
		# remove song
		delete $pending_hash{$song};	    
	    } else {
		croak 'Should be accept or reject but is "' . $action . 
		    '" for "' . $song . '"';
	    }
	}
	$pendingdb->sync;
	$pending_urldb->sync;
	$votedb->sync;
	sleep 5;
    }
    db_close(\$pendingdb, \%pending_hash, \$pending_fh);
    db_close(\$pending_urldb, \%pending_url_hash, \$pending_url_fh);
    db_close(\$votedb, \%vote_hash, \$vote_fh);
    
    if ($error) {
	print generate_error_page($email, 
				  generate_message_for_error_number($error));
    } else {
	print generate_admin_homepage($email);
    }
}

sub do_remove_songs {
    my $email = shift;

    my $pending_name = 'pending.db';
    my $pendingdb;
    my %pending_hash;
    my $pending_fh;

    my $vote_name = 'tally.db';
    my $votedb;
    my %vote_hash;
    my $vote_fh;
    
    my $pending_url_name = 'pending_url.db';
    my $pending_urldb;
    my %pending_url_hash;
    my $pending_url_fh; 

    my $url_name = 'url.db';
    my $url_db;
    my %url_hash;
    my $url_fh;
    
    my $error = ERROR_OK;
    my $songnum = 1;
    my %songhash;
    
    {
	if (DEBUG_LEVEL >= DEBUG_HIGH) {
	    carp 'dealing with submission from script';
	}
	$error = db_open_hash($pending_name, TRUE, \$pendingdb, 
			      \%pending_hash, \$pending_fh, TRUE);	

	if ($error) {
	    last;
	}
	
	$error = db_open_hash($vote_name, TRUE, \$votedb,
			      \%vote_hash, \$vote_fh, TRUE);
	
	if ($error) {
	    last;
	}
	
	$error = db_open_hash($pending_url_name, TRUE, \$pending_urldb,
			      \%pending_url_hash, \$pending_url_fh, TRUE);
	if ($error) {
	    last;
	}

	$error = db_open_hash($url_name, TRUE, \$url_db, \%url_hash, 
			      \$url_fh, TRUE);

	if ($error) {
	    last;
	}

	if (DEBUG_LEVEL >= DEBUG_HIGH) {
	    carp 'after open databases in approve songs';
	}

	my $songselect = $http_transaction->param('select' . $songnum);
	my $song;
	my $action;
	
	while ((defined $songselect) && ($songselect ne '') && 
		($songnum <= 30)) {
	    if (DEBUG_LEVEL >= DEBUG_NOISE) {
		carp 'Song number:' . $songnum . ' ' . $songselect;
	    }
	    if ($songselect eq 'Keep') {
		$songnum++;
		$songselect = $http_transaction->param('select' . $songnum);
		next;
	    }
	    $action = substr($songselect, 0, 6);
	    $song = uri_unescape(substr($songselect, 6));
	    $songhash{$song} = $action;
	    $songnum++;
	    $songselect = $http_transaction->param('select' . $songnum);
	}

	while (($song, $action) = each(%songhash)) {
	    if ($action eq 'Remove') {
		# remove urls
		my @url_list = split /\s/, $pending_url_hash{$song};
		delete $pending_url_hash{$song};

		@url_list= split /\s/, $url_hash{$song};
		delete $url_hash{$song};
		
		# remove song
		delete $pending_hash{$song};	    
		delete $vote_hash{$song};
	    } else {
		croak 'Should be keep or remove but is "' . $action . 
		    '" for "' . $song . '"';
	    }
	}
	$pendingdb->sync;
	$pending_urldb->sync;
	$votedb->sync;
	sleep 5;
    }
    db_close(\$pendingdb, \%pending_hash, \$pending_fh);
    db_close(\$pending_urldb, \%pending_url_hash, \$pending_url_fh);
    db_close(\$votedb, \%vote_hash, \$vote_fh);
    db_close(\$url_db, \%url_hash, \$url_fh);

    if ($error) {
	print generate_error_page($email, 
				  generate_message_for_error_number($error));
    } else {
	print generate_admin_homepage($email);
    }
}

sub do_merge_songs {
    my $email = shift;

    my $pending_name = 'pending.db';
    my $pendingdb;
    my %pending_hash;
    my $pending_fh;

    my $tally_name = 'tally.db';
    my $tallydb;
    my %tally_hash;
    my $tally_fh;
    
    my $vote_name = 'vote.db';
    my $votedb;
    my %vote_hash;
    my $vote_fh;
    
    my $error = ERROR_OK;
    my $songnum = 1;
    my %songhash;
    my $new_song;
    my $merge_error = '';
    my $merge_success = '';
    
    {
	if (DEBUG_LEVEL >= DEBUG_HIGH) {
	    carp 'dealing with submission from script';
	}
	$error = db_open_hash($pending_name, TRUE, \$pendingdb, 
			      \%pending_hash, \$pending_fh, TRUE);	

	if ($error) {
	    last;
	}
	
	$error = db_open_hash($vote_name, TRUE, \$votedb,
			      \%vote_hash, \$vote_fh, FALSE);
	
	if ($error) {
	    last;
	}
	
	$error = db_open_hash($tally_name, TRUE, \$tallydb,
			      \%tally_hash, \$tally_fh, TRUE);
	
	if ($error) {
	    last;
	}

	if (DEBUG_LEVEL >= DEBUG_HIGH) {
	    carp 'after open databases in approve songs';
	}

	my $songselect = $http_transaction->param('select' . $songnum);
	my $song = $http_transaction->param('hidden' . $songnum);
	
	while ((defined $songselect) && ($songselect ne '') && 
		($songnum <= 30)) {
	    if (DEBUG_LEVEL >= DEBUG_NOISE) {
		carp 'Song number:' . $songnum . ' ' . $songselect;
	    }
	    $songselect = trim(uri_unescape($songselect));
	    if ($songselect eq 'Undecided') {
		$songnum++;
		$songselect = $http_transaction->param('select' . $songnum);
		$song = $http_transaction->param('hidden' . $songnum);
		next;
	    }
	    $song = trim(uri_unescape($song));
	    
	    if ($songselect eq '== No song selected ==') {
		$songselect = '';
	    }    
	    if (defined $songselect && $songselect ne '') {
		if ($songhash{$songselect}) {
		    $merge_error = 'Error: Attempting to merge into a song ' .
			'which is marked for merging into another song.';
		} else {
		    $songhash{$song} .= $songselect;
		}
	    }
	    $songnum++;	    
	    $songselect = $http_transaction->param('select' . $songnum);
	    $song = $http_transaction->param('hidden' . $songnum);
	}

	if ($merge_error ne '') {
	    last;
	}

	while (($song, $new_song) = each(%songhash)) {
	    if (defined $song && defined $new_song && $song ne '' && 
		$new_song ne '') {
		my $target_tally = $tally_hash{$new_song};
	       
		if (defined $target_tally && $target_tally ne '') {
		    if (DEBUG_LEVEL >= DEBUG_HIGH) {
			carp 'old song: ' . $song . 'new song: ' . $new_song;
		    }
		    my $email;
		    my $vote_songs;
		    while (($email, $vote_songs) = each(%vote_hash)) {
			if (DEBUG_LEVEL >= DEBUG_NOISE) {
			    carp 'old vote_string: ' . $vote_songs;
			}
			my $old = '#song#' . $song . '#song#';
			my $replace = '#song#' . $new_song . '#song#';
			$vote_songs =~ s/$old/$replace/g;
			$old = $song . '#song#';
			$replace = $new_song . '#song#';
			$vote_songs =~ s/^$old/$replace/g;
			$old = '#song#' . $song;
			$replace = '#song#' . $new_song;
			$vote_songs =~ s/$old$/$replace/g;
			
			if (DEBUG_LEVEL >= DEBUG_NOISE) {
			    carp 'new vote_string: ' . $vote_songs;
			}
			$vote_hash{$email} = $vote_songs;
		    }
		
		    my $old_pending_emails = $pending_hash{$song};	   
		    my $old_approved_emails = $tally_hash{$song};
		    my $new_approved_emails = $tally_hash{$new_song};
		    my $new_emails = '';
		    my $add_space = FALSE;
		    if (defined $old_pending_emails && 
			$old_pending_emails ne '') {
			$new_emails = $old_pending_emails;
			$add_space = TRUE;
		    }		    
		    if ($old_approved_emails ne '0' && 
			$old_approved_emails ne '') {
			if ($add_space) {
			    $new_emails .= ' ';
			}
			$new_emails .= $old_approved_emails;
			$add_space = TRUE;
		    }
		    if ($new_approved_emails ne '0' &&
			$new_approved_emails ne '') {
			if ($add_space) {
			    $new_emails .= ' ';
			}
			$new_emails .= $new_approved_emails;
		    }
		    $tally_hash{$new_song} = $new_emails;
		    delete $pending_hash{$song};
		    delete $tally_hash{$song};

		    $merge_success .= $http_transaction->
			p('merged ' . $song . ' into ' . $new_song);
		} else {
		    next;
		}
	    } else {
		next;
	    }
	}
    
	$pendingdb->sync;
	$tallydb->sync;
	$votedb->sync;
	sleep 5;
    }
    db_close(\$pendingdb, \%pending_hash, \$pending_fh);
    db_close(\$tallydb, \%tally_hash, \$tally_fh);
    db_close(\$votedb, \%vote_hash, \$vote_fh);

    if ($error) {
	print generate_error_page($email, 
				  generate_message_for_error_number($error));
    } else {
	print generate_song_merge($email, $merge_success, $merge_error);
    }
}


sub do_approve_links {
    my $email = shift;

    my $pending_name = 'pending_url.db';
    my $pendingdb;
    my %pending_hash;
    my $pending_fh;

    my $url_name = 'url.db';
    my $urldb;
    my %url_hash;
    my $url_fh;
    
    my $error = ERROR_OK;
    my $songnum = 1;
    my %songhash;
    
    {
	if (DEBUG_LEVEL >= DEBUG_HIGH) {
	    carp 'dealing with link approvals from script';
	}
	$error = db_open_hash($pending_name, TRUE, \$pendingdb, 
			      \%pending_hash, \$pending_fh, TRUE);	

	if ($error) {
	    last;
	}
	
	$error = db_open_hash($url_name, TRUE, \$urldb,
			      \%url_hash, \$url_fh, TRUE);
	
	if ($error) {
	    last;
	}
	
	if (DEBUG_LEVEL >= DEBUG_HIGH) {
	    carp 'after open databases in approve links';
	}

	my $songselect = $http_transaction->param('select' . $songnum);
	my $song;
	my $songurl;
	my $action;
	
	while ((defined $songselect) && ($songselect ne '') && 
		($songnum <= 30)) {
	    if (DEBUG_LEVEL >= DEBUG_NOISE) {
		carp 'Url number:' . $songnum . ' ' . $songselect;
	    }
	    if ($songselect eq 'Undecided') {
		$songnum++;
		$songselect = $http_transaction->param('select' . $songnum);
		next;
	    }
	    $action = substr($songselect, 0, 6);
	    $songurl = uri_unescape(substr($songselect, 6));
	    $songhash{$songurl} = $action;
	    $songnum++;
	    $songselect = $http_transaction->param('select' . $songnum);
	}

	while (($songurl, $action) = each(%songhash)) {
	    if ($action eq 'Accept') {
		my $url = substr($songurl, index($songurl, '#songurl#') + 9);
		my $song = substr($songurl, 0, index($songurl, '#songurl#'));

		if (defined $url_hash{$song} && $url_hash{$song} ne '') {
		    $url_hash{$song} .= ' ' . $url;
		} else {
		    $url_hash{$song} = $url;
		}
		my $urllist = $pending_hash{$song};
		$urllist =~ s/$url//;
		$urllist =~ s/  / /;
		if (trim($urllist) eq '') {
		    delete $pending_hash{$song};
		} else {
		    $pending_hash{$song} = $urllist;		
		}
	    } elsif ($action eq 'Reject') {
		my $url = substr($songurl, index($songurl, '#songurl#') + 9);
		my $song = substr($songurl, 0, index($songurl, '#songurl#'));

		my $urllist = $pending_hash{$song};
		$urllist =~ s/$url//;
		$urllist =~ s/  / /;
		if (trim($urllist) eq '') {
		    delete $pending_hash{$song};
		} else {
		    $pending_hash{$song} = $urllist;		
		}

	    } else {
		croak 'Should be accept or reject but is "' . $action . 
		    '" for "' . $songurl . '"';
	    }
	}
	$pendingdb->sync;
	$urldb->sync;
	sleep 5;
    }
    db_close(\$pendingdb, \%pending_hash, \$pending_fh);
    db_close(\$urldb, \%url_hash, \$url_fh);

    if ($error) {
	print generate_error_page($email, 
				  generate_message_for_error_number($error));
    } else {
	print generate_link_approvals($email);
    }
}


sub generate_misc_admin_page {
    my $email = shift;
    my $results = shift;
    my %substitutes;
    $current_template = 'admin_misc.tmpl';
    $current_title = "Welcome Administrator for<BR> ". SITE_NAME;
   
    $substitutes{'<!-- script_url -->'} = SCRIPT_BASE_URL . SCRIPT_NAME;
    $substitutes{'<!-- tdtds_misc_admin_results -->'} = $results;
    $substitutes{'<!-- tdtds_heading -->'} = $current_title;
    my $page = generate_page(TRUE, $email, %substitutes);

    return $page;   
}

sub generate_cookie_clean_result {
    my $email = shift;

    my $cookie_name = 'cookie.db';
    my $cookie_db;
    my %cookie_hash;
    my $cookie_fh;

    my $cookie;
    my $cookie_value;
    my $db_email;
    my $expiry;
    my $clean_count = 0;

    my $error = ERROR_OK;

    {
	if (DEBUG_LEVEL >= DEBUG_HIGH) {
	    carp 'cleaning out out expired cookies';
	}
	$error = db_open_hash($cookie_name, TRUE, \$cookie_db, 
			      \%cookie_hash, \$cookie_fh, FALSE);	

	if ($error) {
	    last;
	}

	while (($cookie, $cookie_value) = each (%cookie_hash)) {
	    ($expiry, $db_email) = unpack('l a*', $cookie_value);
	    if (!defined $expiry || !defined $email || $expiry == 0 || 
		$db_email eq '' || time() >= $expiry) {
		delete $cookie_hash{$cookie};
		$clean_count++;
	    }	    
	}
    }

    db_close(\$cookie_db, \%cookie_hash, \$cookie_fh);

    if ($error) {
	return generate_error_page($email, 
				  generate_message_for_error_number($error));
    } else {
	return generate_misc_admin_page($email, 'Cleaned out ' . $clean_count .
					' cookies.');
    }
}

sub generate_end_round_start {
    my $email = shift;
    my $results = shift;
    my %substitutes;
    $current_template = 'end_round_start.tmpl';
    $current_title = "Welcome Administrator for<BR> ". SITE_NAME;
   
    $substitutes{'<!-- script_url -->'} = SCRIPT_BASE_URL . SCRIPT_NAME;
    $substitutes{'<!-- tdtds_end_round_start_results -->'} = $results;
    $substitutes{'<!-- tdtds_heading -->'} = $current_title;
    $substitutes{'<!-- round_number -->'} = get_round();
    my $page = generate_page(TRUE, $email, %substitutes);

    return $page;   
}

sub generate_prune_songs {
    my $email = shift;
    my $round = get_round();
    my $round_num_songs = get_round_num_songs($round);

    my $vote_name = 'tally.db';
    my $vote_db;
    my %vote_hash;
    my $vote_fh;

    my %pruned_hash;
    my @vote_list;
    my $song_num = 0;

    my $error = ERROR_OK;
    {
	$error = db_open_hash($vote_name, FALSE, \$vote_db, \%vote_hash,
			      \$vote_fh, TRUE);

	if ($error) {
	    last;
	}

	@vote_list = sort { 
	    my @a_list = split /\s/, $vote_hash{$b};
	    my @b_list = split /\s/, $vote_hash{$a};
	    my $a_empty = FALSE;
	    my $b_empty = FALSE;
	    if ((!defined $vote_hash{$b}) || ($vote_hash{$b} eq '') ||
		($vote_hash{$b} eq '0')) {
		$b_empty = TRUE;
	    }
	    
	    if ((!defined $vote_hash{$a}) || ($vote_hash{$a} eq '') ||
		($vote_hash{$a} eq '0')) {
		$a_empty = TRUE;
	    }

	    if ($b_empty) {
		if ($a_empty) {
		    return $a cmp $b;
		} else {
		    return -1;
		}
	    } else {
		if ($a_empty) {
		    return 1;
		} else {
		    $#a_list <=> $#b_list or $a cmp $b;
		}
	    }
	} keys %vote_hash;

	my $last_song;
	
	foreach my $song (@vote_list) {
	    if ($song_num < $round_num_songs) {
		$pruned_hash{$song} = $vote_hash{$song};
		$song_num++;
		$last_song = $song;
	    } elsif (!is_hard_limit(get_round())) {
		my @count_list_this = split /\s/, $vote_hash{$song};
		my @count_list_last = split /\s/, $vote_hash{$last_song};
		if ($#count_list_this == $#count_list_last) {
		    $pruned_hash{$song} = $vote_hash{$song};
		    $song_num++;
		    $last_song = $song;		   
		}
	    }
	}
	%vote_hash = %pruned_hash;
	$vote_db->sync;
	sleep 5;
    }
    db_close(\$vote_db, \%vote_hash, \$vote_fh);

    if ($error) {
	print generate_error_page($email, 
				  generate_message_for_error_number($error));
    } else {
	print generate_misc_admin_page($email, 'Pruned list to ' . $song_num . 
				       ' songs. This may be greater than ' .
				       'the max in tdtds.conf if there are ' .
				       'ties for last place and the new ' . 
				       'round is not configured with a hard ' .
				       'limit'				       
				 );
    }

}

sub do_end_round {
    my $email = shift;
    my $result_page;
    my $successful_button = $http_transaction->param('no');
    {
	if ($successful_button eq 'No') {
	    print generate_end_round_start($email, 
					   'You have indicated that the ' . 
					   'round number is incorrect. ' . 
					   'Please edit tdtds.conf in ' . 
					   SCRIPT_FILE_PATH);

	    last;
	}
	$successful_button = $http_transaction->param('yes');
	if ($successful_button eq 'Yes') {
	    print generate_prune_songs($email);
	    last;
	}
	print generate_error_page('Unknown Button', 'Your response does ' .
				   'not match any known values.');
	return;
    }
}

sub generate_misc_admin_result_page {
    my $email = shift;
    my $result_page;
    my $successful_button = $http_transaction->param('end_round');
    {
	if ($successful_button eq 'End Round') {
	    $result_page = generate_end_round_start($email);
	    last;
	}
	$successful_button = $http_transaction->param('cookie_clean');
	if ($successful_button eq 'Clean-out Old Cookies') {
	    $result_page = generate_cookie_clean_result($email);
	    last;
	}
	$successful_button = $http_transaction->param('homepage');
	if ($successful_button eq 'Return to Homepage') {
	    $result_page = generate_homepage($email);
	    last;
	}
	return generate_error_page('Unknown Button', 'Your response does ' .
				   'not match any known values.');
    }
    return $result_page;
}

sub do_admin_tasks {
    my $email = shift;
    my $admin_task = shift;
    if (is_admin($email)) {
	if ($admin_task == ADMIN_HOME) {
	    print generate_admin_homepage($email);
	} elsif ($admin_task == ADMIN_APPROVE_SONGS) {
	    do_approve_songs($email);
	} elsif ($admin_task == ADMIN_APPROVE_LINKS) {
	    do_approve_links($email);
	} elsif ($admin_task == ADMIN_LINK_APPROVE_PAGE) {
	    print generate_link_approvals($email);
	} elsif ($admin_task == ADMIN_MERGE_PAGE) {
	    print generate_song_merge($email);
	} elsif ($admin_task == ADMIN_PERFORM_MERGE) {
	    do_merge_songs($email);
	} elsif ($admin_task == ADMIN_MISC) {
	    print generate_misc_admin_page($email);
	} elsif ($admin_task == ADMIN_PERFORM_MISC) {
	    print generate_misc_admin_result_page($email);
	} elsif ($admin_task == ADMIN_END_ROUND) {
	    do_end_round($email);
	} elsif ($admin_task == ADMIN_REMOVE_SONGS) {
	    print generate_remove_song_page($email);	
	} elsif ($admin_task == ADMIN_PERFORM_REMOVE) {
	    print do_remove_songs($email);
	}
    } else {
	print generate_error_page('Access Denied',
				  'You are trying to perform administrative ' .
				  'functions but you are (' . $email . 
				  ') not an administrator.'
				  );
    }
}

sub do_logout {
    my $error;

    $error = remove_cookie();
    if ($error == AUTH_LOGGED_OUT) {
	$current_template = 'login.tmpl';
	$current_title = "Login to <BR>" . SITE_NAME;
	print generate_preauth_page();
    } elsif ($error == AUTH_DB_ERROR) {
	croak 'There was an error accessing the database while logging out.';
    } else {
	croak 'Unknown return value removing cookie.';
    }	
}

sub page_start {   
    my $auth_cookie;
    my $form_type;
    my $login_url;
    my $first_use = FALSE;
    my $email;
    
    $login_url = shift;
    $auth_cookie = '';

    parse_conf_file();
    
    {
	$form_type = $http_transaction->url_param('action');
	if (!defined $form_type) {
	    if (defined $http_transaction->param()) {
		croak 'Incorrect parameters calling script.';
	    }
	    if (defined $http_transaction->cgi_error()) {
		if ('413 POST too large') { 
		    croak 'You entered more text than the form allows, ' .
			'please try again.';
		} else {
		    croak $http_transaction->cgi_error();
		}
	    } 
	    croak 'Missing action parameter';
	}

	if (defined $http_transaction->url_param('first_use')) {
	    $first_use = TRUE;
	}

	if ($form_type eq 'register') {
	    do_register(FALSE, $first_use);
	} elsif ($form_type eq 'confirm') {
	    if (! defined $http_transaction->param('confirmemail')) {
		do_confirm(TRUE);
	    } else {
		do_confirm($first_use);	    
	    }
	} elsif ($form_type eq 'login') {
	    if (! defined $http_transaction->param('loginemail')) {	    
		do_login(undef, undef, FALSE, TRUE);
	    } else {
		do_login(trim($http_transaction->param('loginemail')), 
			      trim($http_transaction->param('loginpassword')), 
				   FALSE, FALSE);
	    }
	} elsif ($form_type eq 'reset_password') {
	    do_register(TRUE, $first_use);
	} else {
	    $email = is_authenticated();
	    
	    {
		if (!defined $email) {
		    if ($error_number == AUTH_NO_COOKIE) {
			$current_title = "No Session Cookie";
			$current_template = 'no_cookie.tmpl';
			print generate_preauth_page();
			last;
		    } elsif ($error_number == AUTH_DB_ERROR) {
			$current_title = "Server Too Busy";
			$current_template = 'server_busy.tmpl';
			print generate_preauth_page();
			last;
		    } elsif ($error_number == AUTH_NO_DB_COOKIE) {
			$current_title = "No Cookie in Database";
			$current_template = 'no_db_cookie.tmpl';
			print generate_preauth_page();
			last;
		    } elsif ($error_number == AUTH_EXPIRED) {
			$current_title = "Session Expired";
			$current_template = 'session_expired.tmpl';
			print generate_preauth_page();
			last;
		    } elsif ($error_number == AUTH_LOGGED_OUT) {
			page_redirect(NOAUTH_BASE_URL . 'index.html');	    
		    } else {
		        # Otherwise we've got an incorrect action parameter, or
			# we're not authenticated and trying to do something
			# that requires authentication.
			croak 'An incorrect action parameter was passed to ' .
			    'the script.';
		    }
		}

		if ($form_type eq 'cast_vote') {
		    do_vote($email);
		} elsif ($form_type eq 'home') {			
		    do_authhome($email);
		} elsif ($form_type eq 'vote_results') {
		    do_results($email);
		} elsif ($form_type eq 'vote_page') {
		    do_vote_page($email);
		} elsif ($form_type eq 'ballot_box') {
		    do_submit_votes($email);
		} elsif ($form_type eq 'admin') {
		    do_admin_tasks($email, ADMIN_HOME);
		} elsif ($form_type eq 'url_page') {
		    do_url_page($email);
		} elsif ($form_type eq 'admin_apply') {
		    do_admin_tasks($email, ADMIN_APPROVE_SONGS);
		} elsif ($form_type eq 'logout') {
		    do_logout($email);
		} elsif ($form_type eq 'url_submit') {
		    do_submit_url($email);
		} elsif ($form_type eq 'approve_links') {
		    do_admin_tasks($email, ADMIN_LINK_APPROVE_PAGE);
		} elsif ($form_type eq 'submit_link_approvals') {
		    do_admin_tasks($email, ADMIN_APPROVE_LINKS);
		} elsif ($form_type eq 'merge_songs') {
		    do_admin_tasks($email, ADMIN_MERGE_PAGE);
		} elsif ($form_type eq 'merge_submit') {
		    do_admin_tasks($email, ADMIN_PERFORM_MERGE);
		} elsif ($form_type eq 'misc_admin') {
		    do_admin_tasks($email, ADMIN_MISC);		
		} elsif ($form_type eq 'admin_misc_action') {
		    do_admin_tasks($email, ADMIN_PERFORM_MISC);
		} elsif ($form_type eq 'end_round_start') {
		    do_admin_tasks($email, ADMIN_END_ROUND);
		} elsif ($form_type eq 'remove_songs') {
		    do_admin_tasks($email, ADMIN_REMOVE_SONGS);
		} elsif ($form_type eq 'remove_submit') {
		    do_admin_tasks($email, ADMIN_PERFORM_REMOVE);  
		} else {
		    croak 'An incorrect action parameter was passed to the ' .
			'script.';
		}
	    }
	}
    }    
}

