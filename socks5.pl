#!/bin/perl
# Minimal SOCKS5 proxy for Perl 5.6.1
# Features: no-auth, CONNECT command, IPv4 + domain name, select-based relay
# No threads, no non-core modules beyond Socket and IO::Socket::INET.

use strict;           # Perl 5.6.1 supports 'strict'
use vars qw($LISTEN_ADDR $LISTEN_PORT);
use Socket;           # core
use IO::Socket::INET; # core in 5.6.x

$LISTEN_ADDR = $ARGV[0] || '0.0.0.0';
$LISTEN_PORT = $ARGV[1] || 61080;

# Create listening socket
my $server = IO::Socket::INET->new(
    LocalAddr => $LISTEN_ADDR,
    LocalPort => $LISTEN_PORT,
    Proto     => 'tcp',
    Listen    => SOMAXCONN,
    Reuse     => 1
) or die "Failed to listen on $LISTEN_ADDR:$LISTEN_PORT: $!";

print "SOCKS5 proxy listening on $LISTEN_ADDR:$LISTEN_PORT\n";

# Main accept loop (single-process, each client handled sequentially)
# For better concurrency on older systems, you could 'fork' per client.
while (1) {
    my $client = $server->accept();
    next unless $client;
    $client->autoflush(1);

    eval {
        handle_client($client);
    };
    if ($@) {
        # Minimal error handling; ensure we close the client
        eval { close $client; };
    }
}

sub handle_client {
    my ($cli) = @_;

    # SOCKS5 greeting: VER, NMETHODS, METHODS...
    my $buf;
    my $read = sysread($cli, $buf, 2);
    die "Client closed (greeting)" unless defined $read && $read == 2;

    my ($ver, $nmeth) = unpack("C C", $buf);
    die "Not SOCKS5 (VER=$ver)" unless $ver == 5;

    my $methods = '';
    $read = sysread($cli, $methods, $nmeth);
    die "Client closed (methods)" unless defined $read && $read == $nmeth;

    # We only support 'no authentication' (0x00)
    my $NOAUTH = 0x00;
    my $resp = pack("C C", 5, $NOAUTH);
    syswrite_full($cli, $resp) or die "Failed to write method select";

    # Request: VER CMD RSV ATYP DST.ADDR DST.PORT
    $read = sysread($cli, $buf, 4);
    die "Client closed (request header)" unless defined $read && $read == 4;

    my ($r_ver, $cmd, $rsv, $atyp) = unpack("C C C C", $buf);
    die "Bad VER in request" unless $r_ver == 5;

    # Parse address
    my ($dst_addr, $dst_port);
    if ($atyp == 1) {
        # IPv4: 4 bytes + 2 bytes port
        $read = sysread($cli, $buf, 6);
        die "Client closed (IPv4 + port)" unless defined $read && $read == 6;
        my $ip_raw  = substr($buf, 0, 4);
        my $portraw = substr($buf, 4, 2);
        $dst_addr = inet_ntoa($ip_raw);
        $dst_port = unpack("n", $portraw);
    } elsif ($atyp == 3) {
        # Domain: 1 byte len + len bytes + 2 bytes port
        $read = sysread($cli, $buf, 1);
        die "Client closed (domain len)" unless defined $read && $read == 1;
        my $alen = unpack("C", $buf);
        $read = sysread($cli, $buf, $alen + 2);
        die "Client closed (domain + port)" unless defined $read && $read == $alen + 2;
        my $host = substr($buf, 0, $alen);
        my $portraw = substr($buf, $alen, 2);
        $dst_addr = $host;
        $dst_port = unpack("n", $portraw);
    } elsif ($atyp == 4) {
        # IPv6 not implemented
        send_socks_reply($cli, 5, 8, "0.0.0.0", 0); # 0x08: address type not supported
        die "IPv6 not supported";
    } else {
        send_socks_reply($cli, 5, 8, "0.0.0.0", 0);
        die "Unknown ATYP";
    }

    # Only support CONNECT (CMD=0x01)
    if ($cmd != 1) {
        send_socks_reply($cli, 5, 7, "0.0.0.0", 0); # 0x07: Command not supported
        die "CMD not supported: $cmd";
    }

    # Resolve domain if needed
    my $target_host = $dst_addr;
    if ($atyp == 3) {
        # Attempt to resolve using gethostbyname
        my $packed_ip = gethostbyname($dst_addr);
        unless ($packed_ip) {
            send_socks_reply($cli, 5, 4, "0.0.0.0", 0); # 0x04: Host unreachable
            die "DNS resolve failed: $dst_addr";
        }
        $target_host = inet_ntoa($packed_ip);
    }

    # Connect to target
    my $dst = IO::Socket::INET->new(
        PeerAddr => $target_host,
        PeerPort => $dst_port,
        Proto    => 'tcp',
        Timeout  => 10
    );
    unless ($dst) {
        send_socks_reply($cli, 5, 5, "0.0.0.0", 0); # 0x05: Connection refused
        die "Connect failed to $target_host:$dst_port: $!";
    }

    # Send success reply: VER=5, REP=0, RSV=0, ATYP=1, BND.ADDR, BND.PORT
    # BND is local bind address/port. We report 0.0.0.0:0 for simplicity.
    send_socks_reply($cli, 5, 0, "0.0.0.0", 0);

    # Relay data both ways using select
    relay_bidirectional($cli, $dst);

    # Done
    close $dst;
    close $cli;
}

sub send_socks_reply {
    my ($sock, $ver, $rep, $bind_addr, $bind_port) = @_;
    my $ver_byte = pack("C", $ver);
    my $rep_byte = pack("C", $rep);
    my $rsv_byte = pack("C", 0);
    my $atyp = pack("C", 1); # report IPv4
    my $addr = inet_aton($bind_addr);
    my $port = pack("n", $bind_port);

    my $reply = $ver_byte . $rep_byte . $rsv_byte . $atyp . $addr . $port;
    syswrite_full($sock, $reply);
}

sub relay_bidirectional {
    my ($a, $b) = @_;
    my $done = 0;

    # Set to non-blocking? We can keep blocking but use select for readiness.
    while (!$done) {
        my $rin = '';
        vec($rin, fileno($a), 1) = 1;
        vec($rin, fileno($b), 1) = 1;

        my $win = '';
        my $ein = '';

        my $timeout = 300; # seconds; adjust as needed
        my $n = select($rin, $win, $ein, $timeout);
        if (!defined $n) {
            last;
        } elsif ($n == 0) {
            # Timeout; close both
            last;
        }

        # If client readable
        if (vec($rin, fileno($a), 1)) {
            my $buf = '';
            my $r = sysread($a, $buf, 8192);
            if (!defined $r || $r == 0) {
                last;
            }
            my $w = syswrite_full($b, $buf);
            last unless $w;
        }

        # If destination readable
        if (vec($rin, fileno($b), 1)) {
            my $buf = '';
            my $r = sysread($b, $buf, 8192);
            if (!defined $r || $r == 0) {
                last;
            }
            my $w = syswrite_full($a, $buf);
            last unless $w;
        }
    }
}

sub syswrite_full {
    my ($fh, $data) = @_;
    my $len = length($data);
    my $off = 0;
    while ($off < $len) {
        my $w = syswrite($fh, substr($data, $off), $len - $off);
        return 0 unless defined $w && $w > 0;
        $off += $w;
    }
    return 1;
}
