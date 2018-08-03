
# Copyright 2018 Maximilian Falkenstein <mfalkenstein@sos.ethz.ch>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

=head1 NAME

Mail::SpamAssassin::Plugin::SAGrey - A plugin for greylisting in SpamAssassin

=head1 SYNOPSIS

To use, load the plugin using

 loadplugin Mail::SpamAssassin::Plugin::SAGrey

and add the following line to your local.cf

 header     SAGREY  eval:sagrey()
 describe   SAGREY  Adds 0.1 if the greylisting rule fires
 priority   SAGREY  1010 # run after AWL
 score      SAGREY  0.1 # actual value does not matter much as long as > 0.0

 sagrey_memcd_server 127.0.0.1:11211 # Adjust to your memcached instance

 add_header all Plz-Greylist _SAGREY_
 add_header all Greylist-Reason _SAGREYREASON_


You then need to tempfail all mails with the X-Spam-Plz-Greylist header set to
one, in e.g. Postfix you can do this with the following header_check:

 /^X-Spam-Plz-Greylist: 1/  REJECT 4.2.0 Greylisted, please try again later.

This needs to be done at reinjection time, the exact specifics depend on your
mailserver and on how SpamAssassin is called.

=head1 Description

Greylisting tries to reduce the amount of spam by exploiting a property of SMTP:
Most real mailservers have an interest in actually delivering their mail.
Spambots often only care about sending as many messages as possible in a short
timeframe and do not necessarily implement SMTP correctly.
Greylisting tries to reduce the amount of spam by exploiting a property of SMTP:
When encountering a tempfail (some 4xx error code from the remote mail server)
SMTP requires the sending server to resend the mail after some period of time.
Greylisting works by deliberately tempfailing a mail on the first delivery
attempt, so on the second delivery attempt we can be sure that we are talking to
a real mailserver.

Traditionally, one would use e.g. postgrey to do this before a mail even reaches
SpamAssassin. The disadvantage is that this would always greylist new mails and
is difficult to do when you have multiple servers, since postgrey relies on a
shared relational database in that scenario.
SAGrey tries to solve that problem by doing Greylisting after most SpamAssassin
rules have been evaluated. At that point, we already have an intuition whether
the mail is spam or not. Additionally, we keep track of mailservers we have
already greylisted successfully. In case of multiple mail servers, it is
recommended to use Facebook's MCRouter to replicate memcached writes to all
other mailservers, which will make greylisting work even during a communication
failure between your mailservers with a maximum of n+1 delivery attempts with n
being the number of network partitions.

=head1 TEMPLATE TAGS

 _SAGREY_       1 if we want this mail to be tempfail'd, 0 otherwise
 _SAGREYREASON_ A small text describing how the module determined the action

=head1 Configuration

=over 4

=cut

package Mail::SpamAssassin::Plugin::SAGrey;

our $VERSION = "0.01";

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Plugin::TxRep;
use NetAddr::IP;
use Cache::Memcached;

use strict;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
    my $class = shift;
    my $obj = shift;

    $class = ref($class) || $class;
    my $self = $class->SUPER::new($obj);
    bless ($self, $class);

    $self->{main}          = $obj;
    $self->{conf}          = $obj->{conf};
    $self->set_config($obj->{conf});
    $self->register_eval_rule("sagrey");

    dprint ("new object created");
    return $self;
}

sub set_config {
    my ($self, $config) = @_;
    my @cmds;

=item B<sagrey_memcd_server>
 string     (default: 127.0.0.1:11211)

Where to store greylisting data. In case of multiple servers, this should point
to MCRouter.

=cut
    push (@cmds, {
        setting     => 'sagrey_memcd_server',
        default     => '127.0.0.1:11211',
        type        => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
        code        => sub {
            my ($self, $key, $value, $line) = @_;
            $self->{memcd_server} = $value;
            eval {
                $self->{memcd} = new Cache::Memcached {
                    'servers' => [ $value, ],
                    'compress_threshold' => 10_000,
                };
            };
            if( $@ ) {
                dprint ($@);
                return $Mail::SpamAssassin::Conf::INVALID_VALUE;
            }
        }
    });

=item B<sagrey_whitelist_file>
string      (default: /etc/spamassassin/grey_whitelist)

Where is the static whitelist located? This is the same format as the postgrey
whitelist, so you can/should use that one since it already contains a list of
servers found to be greylisting-intolerant.

=cut
    push (@cmds, {
        setting     => 'sagrey_whitelist_file',
        default     => '/etc/spamassassin/grey_whitelist',
        type        => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
        code        => sub {
            my ($self, $key, $value, $line) = @_;
            $self->{sagrey_whitelist_file} = $value;
            if (not -e $value) {
                return $Mail::SpamAssassin::Conf::INVALID_VALUE;
            }
            $self->read_clients_whitelists();
        }
    });

=item B<sagrey_time>
integer     (default: 300 seconds [5 minutes])

How long do we want to greylist?

=cut
    push (@cmds, {
        setting     => 'sagrey_time',
        default     => 60*5,
        type        => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        code        => sub {
            my ($self, $key, $value, $line) = @_;
            $self->{sagrey_time} = $value;
        }
    });

=item B<sagrey_record_time>
integer     (default: 60*60*24*14 seconds [14 days])

How long do we want to store greylisting information like server reputation
scores? This only effects records that are not accessed for this long and is
the default value of Memcached's lifetime for new objects created.

=cut
    push (@cmds, {
        setting     => 'sagrey_record_time',
        default     => 60*60*24*14,
        type        => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        code        => sub {
            my ($self, $key, $value, $line) = @_;
            $self->{sagrey_record_time} = $value;
        }
    });

    # Register new commands
    $config->{parser}->register_commands(\@cmds);
}
=back
=cut

sub sagrey {
    my ($self, $permsgstatus) = @_;

    # Per documentation, we should check a different variable. The issue
    # is that the documented variable is never set and TxRep *only* sets
    # *any* variable if the message is *new*...
    my $is_new = $permsgstatus->get_tag('TXREP_EMAIL_IP_COUNT');
    my $from = $permsgstatus->get('From:addr');
    my $host = $permsgstatus->get_tag('LASTEXTERNALIP');

    my $ip = NetAddr::IP->new($host);
    my $truncated_ip = $ip;
    if (defined $ip) {
        if ($ip->version() == 6) {
            dprint ("$host is IPv6, truncating to /56");
            $truncated_ip = NetAddr::IP->new6($host, "56");
        }
        else {
            dprint ("$host is IPv4, truncating to /24");
            $truncated_ip = NetAddr::IP->new($host, "24");
        }
        $truncated_ip = $truncated_ip->network();
        dprint ("$host is now $truncated_ip");
    }

    my $host_name = $permsgstatus->get_tag('LASTEXTERNALRDNS');
    my $key = $from . "src" . $host_name;
    #if (defined $truncated_ip) {
    #    $key = $from . "src" . $truncated_ip->cidr();
    #}
    # Score is the SA score so far
    my $score = $permsgstatus->get_hits();
    dprint ("message key\: $key, score: $score");
    # Get server reputation
    my $cnt = $self->{conf}->{memcd}->get("sagrey_$host");
    if (not defined $cnt) {
        $cnt = 0;
    }

    my $value = 0;
    my $reason = "";

    if (defined $is_new) {
        # Let's see if we should greylist this...
        $value = 1;

        # Only greylist if we're not sure about the message
        if ($score < ($permsgstatus->get_required_score()*0.5)) {
            $reason = "message seems not to be spam, skipped";
            $value = 0;
        }

        # Only greylist if we don't know if the server will try again.
        # We do this per single IP on purpose.
        if ($value == 1 and $cnt > 5) {
            $reason = "server is reputable, skipped";
            $value = 0;
            iprint ("$host is reputable ($cnt), skipping greylist");
        }

        # Check if server is in postgrey's domain whitelist
        if ($value == 1) {
            foreach (@{$self->{whitelist_clients}}) {
                if ($host_name =~ $_) {
                    $value = 0;
                    $reason = "$_ triggered";
                    iprint ("$host_name is in whitelist, skipping greylist");
                }
            }
        }

        # Check if server is in postgrey's address whitelist
        if (defined $ip and $value == 1) {
            foreach (@{$self->{whitelist_ips}}) {
                if ($ip->within($_)) {
                    $value = 0;
                    $reason = "$_ triggered";
                    iprint ("$host is in whitelist, skipping greylist");
                }
            }
        }

        # Okay no whitelist reason found, so let's greylist.
        if ($value == 1) {
            iprint ("message was new to TxRep and is not whitelisted, inserting greylist record...");
            my $time = int($self->{conf}->{sagrey_time});
            # The value is not really used, but we need to set *something*
            $self->{conf}->{memcd}->set($key, "Greylisting for $time seconds",
                $time);
        }
    }
    else {
        dprint ("message sender is already known, let's see if we are greylisting.");
        my $res = $self->{conf}->{memcd}->get($key);
        if (defined $res) {
            iprint ("record left, greylisting some more. Contents: $res");
            $reason = "Time has not yet expired.";
            $value = 1;
        }
        else {
            iprint ("record expired, greylist done.");
            $reason = "Greylist time elapsed";

            # Since the greylist was successful, let's increase the server's
            # success count so that we will eventually trust it.
            if (defined $cnt) {
                $cnt = int($cnt);
                if ($cnt < 1000000) {
                    $cnt = $cnt + 1;
                }
            } else {
                $cnt = 1;
            }
            $self->{conf}->{memcd}->set("sagrey_$host", $cnt, $self->{conf}->{sagrey_record_time});

            $value = 0;
        }
    }

    # These values should be converted to headers in the spamassassin local.cf
    $permsgstatus->set_tag('sagreyreason', $reason);
    $permsgstatus->set_tag('sagrey', $value);

    return $value;
}

sub dprint {
    my $str = join('', @_);
    Mail::SpamAssassin::dbg ("SAGrey\: $str");
}

sub iprint {
    my $str = join('', @_);
    Mail::SpamAssassin::info ("SAGrey\: $str");
}

# Taken from the original posgrey source,
# https://github.com/schweikert/postgrey/blob/e017c9a0a1002bcd4acefae5099c68b3f4a20188/postgrey#L30
# Licensed under the GPLv2
#  2004-2007 ETH Zurich
#  2007 Open Systems AG, Switzerland

sub read_clients_whitelists($)
{
    my ($self) = @_;

    my @whitelist_clients = ();
    my @whitelist_ips = ();
    my $f = $self->{conf}->{sagrey_whitelist_file};
    if(open(CLIENTS, $f)) {
        while(<CLIENTS>) {
            s/#.*$//; s/^\s+//; s/\s+$//; next if $_ eq '';
            if(/^\/(\S+)\/$/) {
                # regular expression
                push @whitelist_clients, qr{$1}i;
            }
            elsif(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?$/) {
                # IPv4 address (with or without netmask)
                my $ip = NetAddr::IP->new($_);
                push @whitelist_ips, $ip if defined $ip;
            }
            elsif(/^\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
                # Partial IPv4 address (/24)
                my $ip = NetAddr::IP->new($_, 24);
                push @whitelist_ips, $ip if defined $ip;
            }
            elsif(/^\d{1,3}\.\d{1,3}$/) {
                # Partial IPv4 address (/16)
                my $ip = NetAddr::IP->new($_, 24);
                push @whitelist_ips, $ip if defined $ip;
            }
            elsif(/^.*\:.*\:.*(?:\/\d{1,3})?$/) {
                # IPv6 address (with or without netmask)
                my $ip = NetAddr::IP->new($_);
                push @whitelist_ips, $ip if defined $ip;
            }
            # note: we had ^[^\s\/]+$ but it triggers a bug in
            # perl 5.8.0
            elsif(/^\S+$/) {
                push @whitelist_clients, qr{(?:^|\.)\Q$_\E$}i;
            }
            else {
                warn "$f line $.: doesn't look like a hostname\n";
            }
        }
    }
    else {
        # do not warn about .local file: maybe the user just doesn't
        # have one
        warn "can't open $f: $!\n" unless $f =~ /\.local$/;
    }
    close(CLIENTS);
    $self->{whitelist_clients} = \@whitelist_clients;
    $self->{whitelist_ips}     = \@whitelist_ips;
}

1;
# vim: set ts=4 sw=4 tw=0 et :
