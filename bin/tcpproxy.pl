#!/usr/bin/env perl
# PODNAME: aqhive
# ABSTRACT: The AquariumHive daemon [IN DEVELOPMENT]

use strict;
use warnings;

use Term::ANSIColor qw( colored );
use AnyEvent::Handle;
use AnyEvent::Socket;
use Carp qw( croak );

sub logmsg {
  print colored($_[0],'yellow')."\n";
}

sub in {
  print colored(' IN ','yellow');
  print colored('[','blue');
  data($_[0]);
  print colored(']','blue')."\n";
}

sub out {
  print colored('OUT ','yellow');
  print colored('[','blue');
  data($_[0]);
  print colored(']','blue')."\n";
}

our %ord = (qw(
    1 NUL
    2 SOH
    3 STX
    4 ETX
    5 ENQ
    6 ACK
    7 BEL
    8 BS
    9 TAB
   10 LF
   11 VT
   12 FF
   13 CR
   14 SO
   15 SI 
   16 DLE
   17 DC1
   18 DC2
   19 DC3
   20 DC4
   21 NAK
   22 SYN
   23 ETB
   24 CAN
   25 EM
   26 SUB
   27 ESC
   28 FS
   29 GS
   30 RS
   31 US
  127 DEL
));

sub data {
  my @chars = split(//,$_[0]);
  for my $char (@chars) {
    my $chr = ord($char);
    if (defined $ord{$chr}) {
      print colored('['.$ord{$chr}.']','bright_red');
    } elsif ($char =~ /[ -~]/) {
      print colored($char,'bright_white');
    } else {
      print colored(unpack('H*',$char),'bright_cyan');        
    }
  }
}

sub create_proxy {
  my ( $port, $remote_host, $remote_port ) = @_;

  my %handles;

  my $ip = '127.0.0.1';

  if ($port =~ /:/) {
    ( $ip, $port ) = split(/:/,$port);
  }

  logmsg("starting proxy on $ip:$port");

  return tcp_server $ip, $port, sub {
    my ( $client_fh, $client_host, $client_port ) = @_;

    logmsg("received connection from $client_host:$client_port");

    my $client_h = AnyEvent::Handle->new(
      fh => $client_fh,
    );

    $handles{$client_h} = $client_h;

    tcp_connect $remote_host, $remote_port, sub {
      unless(@_) {
        logmsg("connection failed: $!");
        $client_h->destroy;
        return;
      }
      my ( $host_fh ) = @_;

      my $host_h = AnyEvent::Handle->new(
        fh => $host_fh,
      );

      $handles{$host_h} = $host_h;

      $client_h->on_read(sub {
        my $buffer      = $client_h->rbuf;
        $client_h->rbuf = '';
        out($buffer);
        $host_h->push_write($buffer);
      });

      $client_h->on_error(sub {
        my ( undef, undef, $msg ) = @_;
        logmsg("transmission error: $msg");
        $client_h->destroy;
        $host_h->destroy;
        delete @handles{$client_h, $host_h};
      });

      $client_h->on_eof(sub {
        logmsg("client closed connection");
        $client_h->destroy;
        $host_h->destroy;
        delete @handles{$client_h, $host_h};
      });

      $host_h->on_read(sub {
        my $buffer    = $host_h->rbuf;
        $host_h->rbuf = '';
        in($buffer);
        $client_h->push_write($buffer);
      });

      $host_h->on_error(sub {
        my ( undef, undef, $msg ) = @_;
        logmsg("transmission error: $msg");
        $host_h->destroy;
        $client_h->destroy;
        delete @handles{$client_h, $host_h};
      });

      $host_h->on_eof(sub {
        logmsg("host closed connection");
        $host_h->destroy;
        $client_h->destroy;
        delete @handles{$client_h, $host_h};
      });
    };
  };
}

unless(@ARGV == 3) {
    print <<"END_USAGE";
usage: $0 [<ip:>localport] [remotehost] [remoteport]

END_USAGE
  exit 0
}

my ( $port, $remote_host, $remote_port ) = @ARGV;

my $cond = AnyEvent->condvar;

my $proxy = create_proxy($port, $remote_host, $remote_port);

$cond->recv;

=head1 SYNOPSIS

  $ tcpproxy.pl 2300 localhost 23
  starting proxy on 127.0.0.1:2300
  received connection from 127.0.0.1:37941
   IN [fffd[CAN]fffd fffd#fffd']
  OUT [fffb[CAN]fffb fffb#fffb']
   IN [fffa [NUL]fff0fffa#[NUL]fff0fffa'[NUL]fff0fffa[CAN][NUL]fff0]
  OUT [fffa 0038400,38400fff0fffa#00localhost:16.0fff0fffa'0000DISPLAY[NUL]localhost:16.0fff0fffa[CAN]00xtermfff0]
   IN [fffb[STX]fffd[NUL]fffd[US]fffb[ENQ]fffd!]
  OUT [fffd[STX]fffc[NUL]fffb[US]fffa[US]00c00vfff0fffd[ENQ]fffb!]
   IN [fffb[NUL]]
  OUT [fffd[NUL]]
   IN [Debian GNU/Linux 7[CR][LF]]
   IN [bigbird login: ]
  OUT [a]
   IN [a]
  OUT [t]
   IN [t]
  OUT [c]
   IN [c]
  OUT [[CR]00]
   IN [[CR][LF]]
   IN [Password: ]
  OUT [a]
  OUT [t]
  OUT [c]
  OUT [[CR]00]
   IN [[CR][LF]]
   IN [Last login: Fri Dec  5 01:49:52 CET 2014 from localhost on pts/7[CR][LF]Linux bigbird 3.2.0-4-amd64 #1 SMP Debian 3.2.63-2+deb7u1 x86_64[CR][LF][CR][LF]The programs included with the Debian GNU/Linux system are free software;[CR][LF]the exact distribution terms for each program are described in the[CR][LF]individual files in /usr/share/doc/*/copyright.[CR][LF]]
   IN [[CR][LF]Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent[CR][LF]permitted by applicable law.[CR][LF]]
   IN [[ESC]]0;atc@bigbird: ~[BEL]atc@bigbird:~$ ]
  OUT [[ETX]]
   IN [logout[CR][LF]]

=head1 DESCRIPTION

A simple tcpproxy for analyzing traffic between a tcp client and a tcp server.
Cyan colored data is hex value of the char at this position, while red colored
data are the special control sequences at the beginning of the ASCII table.

=head1 SUPPORT

IRC

  Join #vonbienenstock on irc.freenode.net. Highlight Getty for fast reaction :).

Repository

  http://github.com/Getty/p5-app-tcpproxy
  Pull request and additional contributors are welcome

Issue Tracker

  http://github.com/Getty/p5-app-tcpproxy/issues
