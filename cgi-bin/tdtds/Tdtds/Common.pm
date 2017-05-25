#!/usr/bin/perl -w
#
#     The Dance That Doesn't Suck: Vote on songs for your dance
#     $Id: Common.pm,v 1.33 2006/12/04 16:40:48 mornir Exp $
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

package Tdtds::Common;

use strict;
use warnings;

use CGI;
use CGI::Carp qw(fatalsToBrowser set_message);
use IO::File;

BEGIN {
    use Exporter();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);
            # set the version for version checking
    $VERSION = sprintf "%d.%03d", q$Revision: 1.33 $ =~ /(\d+)/g;

    @ISA         = qw(Exporter);
    @EXPORT      = qw(
		      TEMPLATE_PATH NOAUTH_PAGE_PATH DB_PATH
		      SCRIPT_BASE_URL NOAUTH_BASE_URL CSS_STYLE_PATH
		      ADMIN_EMAIL SMTP_MAILHOST ERROR_DATABASE_TIMEOUT
		      SITE_NAME SITE_SHORT_NAME AUTH_COOKIE_EXPIRY
		      DAY_SECONDS TRUE FALSE ERROR_OK SCRIPT_NAME
		      SCRIPT_PATH DEBUG_NOISE SCRIPT_FILE_PATH
		      DEBUG_LEVEL DEBUG_LOW DEBUG_MEDIUM DEBUG_HIGH
		      DOMAIN_NAME
		      $http_transaction $error_number $auth_cookie
		      $current_title $current_template 
		      
		      &get_round &is_admin &parse_conf_file &is_add_round
		      &get_round_num_songs &get_num_votes
		      &trim &generate_header &generate_footer 
		      &generate_entry_error_page &page_redirect
		      &generate_message_for_error_number &generate_page
		      &generate_sidebar &generate_preauth_page
		      &generate_error_page &is_hard_limit
		      );
    %EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

        # exported package globals go here,
        # as well as any optionally exported functions
    @EXPORT_OK   = qw();

    sub handle_errors {
	my $msg = shift;
	print "<h1>TDTDS: Internal error</h1>";
	print "<p>$msg  Please contact mornir\@liranan.fionavar.dd</p>";
    }
    set_message(\&handle_errors)
}

our @EXPORT_OK;

use constant TEMPLATE_PATH => '/usr/lib/cgi-bin/tdtds/templates/';
use constant NOAUTH_PAGE_PATH => "/var/www/tdtds/";
use constant DB_PATH => "/var/local/tdtds/";
use constant SCRIPT_PATH => '/cgi-bin/tdtds';
use constant SCRIPT_FILE_PATH => '/usr/lib/cgi-bin/tdtds/';
use constant SCRIPT_BASE_URL => "http://liranan" . SCRIPT_PATH . '/';
use constant SCRIPT_NAME => 'tdtds.cgi';
use constant CONF_NAME => 'tdtds.conf';
use constant NOAUTH_BASE_URL => "http://liranan/tdtds/";
use constant CSS_STYLE_PATH => 'http://liranan/tdtds/';
use constant ADMIN_EMAIL => 'mornir@liranan.fionavar.dd';
use constant SMTP_MAILHOST => 'liranan.fionavar.dd';
use constant SITE_NAME => "The Dance That Doesn't Suck";
use constant SITE_SHORT_NAME => "TDTDS";
use constant DAY_SECONDS => 24 * 60 * 60; # number of seconds in a day
use constant AUTH_COOKIE_EXPIRY => 8 * 60 * 60; # 8 hours

use constant DEBUG_LOW => 1;
use constant DEBUG_MEDIUM => 3;
use constant DEBUG_HIGH => 5;
use constant DEBUG_NOISE => 8;
use constant DEBUG_LEVEL => DEBUG_NOISE;

use constant TRUE => 1;
use constant FALSE => 0;

use constant ERROR_OK => 0;

use constant ERROR_DATABASE_TIMEOUT => 1;

# package globals go here
our $http_transaction;
our $error_number;
our $auth_cookie;
our $current_title;
our $current_template;

# initialize package globals

# initialize values for CGI
$CGI::POST_MAX = 10 * 1024; # Max 10k posts (we're just doing song-titles)
$CGI::DISABLE_UPLOADS = 1; # Disable file uploads completely

# continue intializing package globals
$http_transaction = new CGI;
$error_number = ERROR_OK;
$auth_cookie = undef;
$current_title = undef;
$current_template = undef;

# all file-scoped lexicals must be created before
# the functions below that use them.

# file-private lexicals go here
# my $priv_var    = '';
# my %secret_hash = ();

my $round = 0;
my %admin_hash;
my $num_votes_allowed = 0;
my %round_add;
my %round_num_songs;
my %hard_limit;

# here's a file-private function as a closure,
# callable as &$priv_func;  it cannot be prototyped.
# my $priv_func = sub {
        # stuff goes here.
#};

sub trim {
    $_ = $_[0];
    s/^\s+//;
    s/\s+$//;
    return $_;
}

sub page_redirect {
    my $page;
    my $target_url = $_[0];

    print $http_transaction->redirect(-uri=>$target_url,
				   -status=>303) || croak;
}

sub generate_header {
    my $title = shift;
    my $header = '';
    my $browser_title;
    my $header_template;
    my $http_header;
    my $template_path = TEMPLATE_PATH . 'header.tmpl';
    my $css_path = CSS_STYLE_PATH . 'default.css';
    my $html_header = '';

    if (DEBUG_LEVEL >= DEBUG_NOISE) {
	carp 'Generating HTTP header and HTML head';
    }
    
    if (defined $auth_cookie) {
	if (DEBUG_LEVEL >= DEBUG_NOISE) {
	    carp 'using cookie for this page';
	}
	$http_header = $http_transaction->header(-cookie => $auth_cookie);
    } else {
	if (DEBUG_LEVEL >= DEBUG_NOISE) {
	    carp 'not using cookie for this page';
	}
	$http_header = $http_transaction->header();
    }

    $auth_cookie = undef;

    if (DEBUG_LEVEL >= DEBUG_NOISE) {
	carp 'Auth cookie dealt with';
    }

    $_ = $title;
    s/\<BR\>/ /;
    $browser_title = $_;

    if (DEBUG_LEVEL >= DEBUG_HIGH) {
	carp "Browser page title is $browser_title";
    }
    my $framebuster = 'if (self != top) top.location = self.location';

    $html_header = 
	$http_transaction->start_html( { title => $browser_title,
				       style => $css_path,
				       onload => $framebuster }
				      );
    if (DEBUG_LEVEL >= DEBUG_NOISE) {
	carp "html_header = $html_header"
    }

    if ((!(defined $http_header)) || (!(defined $html_header))) {
	$header = undef;
	carp "Unable to generate http or html header";
    } else {
	$header_template = new IO::File $template_path, "r";
	if (defined $header_template) {
	    if (DEBUG_LEVEL >= DEBUG_NOISE) {
		carp 'Generating header from template';
	    }
	    while (<$header_template>) {
		my $script_name = '' . SCRIPT_BASE_URL . SCRIPT_NAME;
		s/'<!-- script_url -->'/$script_name/;
		s/'<!-- tdtds_heading -->'/$title/;
		$html_header .= $_;
	    }
	    $header_template = undef;
	} else {
	    croak "Unable to open header template file.";
	}

	$header = $http_header . $html_header;
	if (DEBUG_LEVEL >= DEBUG_NOISE) {
	    carp "Generated header:\n$header";
	}
    }

    if (!defined $header) {
	carp 'html page header undefined';
    }
    return $header;
}

sub generate_sidebar {
    my $is_authenticated = shift;
    my $email = shift;
    my $sidebar_template_name;
    my $sidebar_template_file;
    my $sidebar_admin_file;
    my $script_name = SCRIPT_BASE_URL . SCRIPT_NAME;
    my $sidebar = '';
    my $script_url_str = '<!-- script_url -->';
    my $sidebar_admin_str = '<!-- sidebar_admin_str -->';
    my $sidebar_admin_options = '';

    $sidebar_admin_file = new IO::File TEMPLATE_PATH . 
	'admin_sidebar.links', "r";
    if (defined $sidebar_admin_file) {
	while (<$sidebar_admin_file>) {
	    s/$script_url_str/$script_name/;
	    $sidebar_admin_options .= $_;
	}
	$sidebar_admin_file = undef;
    } else {
	croak "Unable to open file with admin options for sidebar.";
    }

    if ($is_authenticated) {
	$sidebar_template_name = "auth_sidebar.tmpl";
    } else {
	$sidebar_template_name = "public_sidebar.tmpl";
    }

    if (!is_admin($email)) {
	$sidebar_admin_options = '';
    }

    $sidebar_template_file = new IO::File TEMPLATE_PATH . 
	$sidebar_template_name, "r";
    if (defined $sidebar_template_file) {
	while (<$sidebar_template_file>) {
	    s/$script_url_str/$script_name/;
	    s/$sidebar_admin_str/$sidebar_admin_options/;
	    $sidebar .= $_;
	}
	$sidebar_template_file = undef;
    } else {
	croak "Unable to open template file.";
    }
    return $sidebar;

}

sub generate_footer {
    my $footer = '';
    my $footer_template_file;
    my $script_url_str = '<!-- script_url -->';
    my $script_name = SCRIPT_BASE_URL . SCRIPT_NAME;

    $footer_template_file = new IO::File TEMPLATE_PATH . 'footer.tmpl', "r";
    if (defined $footer_template_file) {
	    while (<$footer_template_file>) {
	    s/$script_url_str/$script_name/;
	    $footer .= $_;
	    }
	    $footer_template_file = undef;
	} else {
	    croak "Unable to open footer template file.";
	}

    $footer .= $http_transaction->end_html();

    if (!defined $footer) {
	carp 'html page footer undefined';
    }
    return $footer;
}

sub generate_error_page {
    my $page_title = shift;
    my $error_message = shift;

    my $page = generate_header($page_title);
    $page .= $http_transaction->h1($page_title);
    $page .= $http_transaction->p($error_message);
    $page .= generate_footer;

    return $page;
}

sub generate_preauth_page {
    my %subs;
    my @subs_list;

    $subs{'<!-- tdtds_heading -->'} = $current_title;
    $subs{'<!-- script_url -->'} = SCRIPT_BASE_URL . SCRIPT_NAME;
    @subs_list= %subs;

    return generate_page(FALSE, '', @subs_list);
}

sub generate_page {
    my $is_authenticated = shift;
    my $email = shift;
    my %substitutes = @_;
    my $entry_form_file;
    if ((!defined $current_title) || ($current_title eq '')) {
	croak 'Error creating page message; no title defined';
    }

    if (DEBUG_LEVEL >= DEBUG_NOISE) {
	carp 'Starting to generate page';
    }
    my $page = generate_header($current_title);

    if (DEBUG_LEVEL >= DEBUG_NOISE) {
	carp 'generated header';
    }
    if ((!defined $current_template) || ($current_template eq '')) {
	croak 'Error creating page; no template defined';
    }	    
    
    $entry_form_file = new IO::File TEMPLATE_PATH . $current_template, "r";

    my $placeholder;
    my $replacement;
    my $line;

    if (DEBUG_LEVEL >= DEBUG_NOISE) {
	carp 'doing replacements for script variables in template';
    }
    if (defined $entry_form_file) {
	while ($line = <$entry_form_file>) {
	    while (($placeholder, $replacement) = each %substitutes) {
		$line =~ s/$placeholder/$replacement/g;
	    }
	    $page .= $line;		

	}
	$page .= generate_sidebar($is_authenticated, $email);
	$page .= generate_footer();
	$entry_form_file = undef;
    } else {
	croak "Unable to open template file.";
    }
    return $page;
}

sub generate_entry_error_page {
    my $entry_error_message = shift;
    my $is_authenticated = shift;
    my $email = shift;
    my $entry_form_file;

    if ($current_title eq '') {
	croak 'Error creating error message; no title defined';
    }
    if ((!defined $entry_error_message) || ($entry_error_message eq '')) {
	croak 'Error creating error message; no message defined';
    }

    if ((!defined $current_template) || ($current_template eq '')) {
	croak 'Error creating error message; no template defined';
    }	    

    my %entry_subst_hash;
    my @entry_subst_list;

    $entry_subst_hash{'<!-- tdtds_heading -->'} = $current_title;
    $entry_subst_hash{'<!-- tdtds_error_in_form -->'} = $entry_error_message;
    $entry_subst_hash{'<!-- tdtds_login_error -->'} = $entry_error_message;
    $entry_subst_hash{'<!-- script_url -->'} = '' . SCRIPT_BASE_URL . SCRIPT_NAME;

    @entry_subst_list = %entry_subst_hash;

    my $entry_page = 
	generate_page($is_authenticated, $email, @entry_subst_list);
		    
    return $entry_page;
}

sub generate_message_for_error_number {
    my $error_number = shift;
    my $entry_error_message;

    if (!defined $error_number) {
	croak 'No error number specified when requesting message for error number';
    }

    if ($error_number == ERROR_DATABASE_TIMEOUT) {
	$entry_error_message = "The site is too busy, so we were unable to save your information.  Please try again in a few minutes.";
    } elsif ($error_number) {
	$entry_error_message = "There was an error, please try again.";
    } else {
	$entry_error_message = undef;
    }
    return $entry_error_message;
}

sub parse_conf_file {
    my $conf_file_fh;
    my $line;
    my $is_cur_round = FALSE;
    my $is_round = FALSE;
    my $is_admin = FALSE;
    my $is_num_vote = FALSE;
    my $round_num = 0;
    my $conf_file_name = SCRIPT_FILE_PATH . 'tdtds.conf';

    $conf_file_fh = new IO::File $conf_file_name , "r";
    if (defined $conf_file_fh) {
	while ($line = <$conf_file_fh>) {
	    chomp($line);
	    if (trim($line) eq '[current_round]') {
		$is_cur_round = TRUE;
	    } elsif (trim($line) eq '[round '. ($round_num + 1). ']') {
		$is_round = TRUE;
		$round_num++;
	    } elsif (trim($line) eq '') {
		$is_admin = FALSE;
		$is_round = FALSE;
		$is_num_vote = FALSE;
		$is_cur_round = FALSE;
	    } elsif ($is_cur_round) {
		$round = trim($line);
	    } elsif ($is_round) {
		$line = trim($line);
		my @parts = split / = /, $line;

		if ($parts[0] eq 'add') {
		    if ($parts[1] eq 'true') {
			$round_add{$round_num} = TRUE;
		    } else {
			$round_add{$round_num} = FALSE;
		    }
		} elsif ($parts[0] eq 'num_songs') {
		    $round_num_songs{$round_num} = $parts[1];
		} elsif ($parts[0] eq 'hard_limit') {
		    if ($parts[1] eq 'true') {
			$hard_limit{$round_num} = TRUE;
		    } else {
			$hard_limit{$round_num} = FALSE;
		    }
		}
	    } elsif (trim($line) eq '[admin_users]') {
		$is_admin = TRUE;
	    } elsif ($is_admin) {
		$admin_hash{trim($line)} = TRUE;
	    } elsif (trim($line) eq '[number_of_votes]') {
		$is_num_vote = TRUE;
	    } elsif ($is_num_vote) {
		$num_votes_allowed = trim($line);
	    }
	    
	}
	undef $conf_file_fh;       # automatically closes the file
	
    } else {
	croak 'Error opening configuration file';
    }
}

sub is_add_round {
    my $cur_round = shift;

    return $round_add{$cur_round};
}

sub is_hard_limit {
    my $cur_round = shift;

    return $hard_limit{$cur_round};
}

sub get_round_num_songs {
    my $cur_round = shift;
    
    return $round_num_songs{$cur_round};
}

sub get_round {
    return $round;
}

sub is_admin {
    my $email = shift;

    if (!defined $email) {
	return FALSE;
    }

    if ($admin_hash{$email} == TRUE) {
	return TRUE;
    } else {
	return FALSE;
    }
}

sub get_num_votes {
    return $num_votes_allowed;
}

END { }

1;
