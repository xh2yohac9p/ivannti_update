#!/bin/perl
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Socket;

# ===== Configuration =====
my $LISTEN_HOST = '0.0.0.0';
my $LISTEN_PORT = 61080;
my $BUF_SIZE    = 65536;
my $TIMEOUT_SEC = 60;

# Optional username/password auth (RFC 1929).
# Leave undef for "no auth".
my $AUTH_USER = undef;
my $AUTH_PASS = undef;

# ===== Constants =====
my $VER_SOCKS5 = 0x05;
my $CMD_CONNECT = 0x01;
my $ATYP_IPV4   = 0x01;
my $ATYP_DOMAIN = 0x03;
my $ATYP_IPV6   = 0x04;

my $REP_SUCCEEDED        = 0x00;
my $REP_GENERAL_FAIL     = 0x01;
my $REP_CONN_NOT_ALLOWED = 0x02;
my $REP_NETWORK_UNREACH  = 0x03;
my $REP_HOST_UNREACH     = 0x04;
my $REP_CONN_REFUSED     = 0x05;
my $REP_TTL_EXPIRED      = 0x06;
my $REP_CMD_NOT_SUPP     = 0x07;
my $REP_ATYP_NOT_SUPP    = 0x08;

# ===== Helpers =====
sub read_exact {
    my ($sock, $n) = @_;
    my $buf = '';
    while (length($buf) < $n) {
        my $r = $sock->sysread(my $chunk, $n - length($buf));
        return undef if !defined($r) || $r == 0;
        $buf .= $chunk;
    }
    return $buf;
}

sub read_byte {
    my ($sock) = @_;
    my $d = read_exact($sock, 1) or return undef;
    return ord($d);
}

sub write_all {
    my ($sock, $data) = @_;
    my $len = length($data);
    my $off = 0;
    while ($off < $len) {
        my $w = $sock->syswrite(substr($data, $off), $len - $off);
        return 0 if !defined($w) || $w == 0;
        $off += $w;
    }
    return 1;
}

sub relay_bidirectional {
    my ($c, $d) = @_;
    my $sel = IO::Select->new();
    $sel->add($c, $d);
    $c->timeout($TIMEOUT_SEC);
    $d->timeout($TIMEOUT_SEC);

    while (1) {
        my @ready = $sel->can_read($TIMEOUT_SEC);
        last unless @ready;
        for my $s (@ready) {
            my $other = ($s == $c) ? $d : $c;
            my $r = $s->sysread(my $buf, $BUF_SIZE);
            return if !defined($r) || $r == 0;
            my $w = write_all($other, $buf);
            return if !$w;
        }
    }
}

sub send_reply {
    my ($sock, $rep_code) = @_;
    # bind addr/port set to 0.0.0.0:0 for simplicity
    my $reply = pack("C C C C N n",
        $VER_SOCKS5, $rep_code, 0x00, $ATYP_IPV4, 0, 0);
    write_all($sock, $reply);
}

sub negotiate_auth {
    my ($sock) = @_;
    # Client greeting: VER, NMETHODS, METHODS...
    my $hdr = read_exact($sock, 2) or return 0;
    my ($ver, $nmethods) = unpack("C C", $hdr);
    return 0 unless $ver == $VER_SOCKS5;
    my $methods = read_exact($sock, $nmethods) or return 0;

    my $need_auth = defined($AUTH_USER) && defined($AUTH_PASS);
    my $method_selected = $need_auth ? 0x02 : 0x00; # 0x02=USER/PASS, 0x00=NO AUTH
    write_all($sock, pack("C C", $VER_SOCKS5, $method_selected)) or return 0;

    if ($need_auth) {
        # RFC 1929: VER=1, ULEN, UNAME, PLEN, PASSWD
        my $v = read_byte($sock);
        return 0 unless defined($v) && $v == 0x01;
        my $ulen = read_byte($sock); return 0 unless defined($ulen);
        my $uname = read_exact($sock, $ulen) // return 0;
        my $plen = read_byte($sock); return 0 unless defined($plen);
        my $pass = read_exact($sock, $plen) // return 0;

        my $ok = ($uname eq $AUTH_USER && $pass eq $AUTH_PASS) ? 0x00 : 0x01;
        write_all($sock, pack("C C", 0x01, $ok)) or return 0;
        return 0 if $ok != 0x00;
    }
    return 1;
}

sub handle_client {
    my ($csock) = @_;
    eval {
        $csock->blocking(1);
        $csock->timeout($TIMEOUT_SEC);

        # Auth negotiation
        my $auth_ok = negotiate_auth($csock);
        if (!$auth_ok) { send_reply($csock, $REP_GENERAL_FAIL); return; }

        # Request: VER CMD RSV ATYP ...
        my $req = read_exact($csock, 4) or do { send_reply($csock, $REP_GENERAL_FAIL); return; };
        my ($ver, $cmd, $rsv, $atyp) = unpack("C C C C", $req);
        if ($ver != $VER_SOCKS5 || $cmd != $CMD_CONNECT) {
            send_reply($csock, $REP_CMD_NOT_SUPP);
            return;
        }

        my ($dst_addr, $dst_port);
        if ($atyp == $ATYP_IPV4) {
            my $raw = read_exact($csock, 4) or do { send_reply($csock, $REP_GENERAL_FAIL); return; };
            $dst_addr = inet_ntoa($raw);
        } elsif ($atyp == $ATYP_DOMAIN) {
            my $alen = read_byte($csock); return send_reply($csock, $REP_ATYP_NOT_SUPP) unless defined($alen);
            my $name = read_exact($csock, $alen) or do { send_reply($csock, $REP_GENERAL_FAIL); return; };
            $dst_addr = $name;
        } elsif ($atyp == $ATYP_IPV6) {
            my $raw = read_exact($csock, 16) or do { send_reply($csock, $REP_GENERAL_FAIL); return; };
            $dst_addr = Socket::inet_ntop(AF_INET6, $raw);
        } else {
            send_reply($csock, $REP_ATYP_NOT_SUPP);
            return;
        }

        my $pbytes = read_exact($csock, 2) or do { send_reply($csock, $REP_GENERAL_FAIL); return; };
        $dst_port = unpack("n", $pbytes);

        # Connect to destination
        my $dsock = IO::Socket::INET->new(
            PeerAddr => $dst_addr,
            PeerPort => $dst_port,
            Proto    => 'tcp',
            Timeout  => $TIMEOUT_SEC,
        );

        if (!$dsock) {
            send_reply($csock, $REP_HOST_UNREACH);
            return;
        }

        # Reply success (BND=0.0.0.0:0)
        send_reply($csock, $REP_SUCCEEDED);

        # Relay
        relay_bidirectional($csock, $dsock);

        $dsock->close();
    };
    $csock->close();
}

# ===== Main =====
my $server = IO::Socket::INET->new(
    LocalAddr => $LISTEN_HOST,
    LocalPort => $LISTEN_PORT,
    Proto     => 'tcp',
    Listen    => 128,
    Reuse     => 1,
) or die "Failed to bind $LISTEN_HOST:$LISTEN_PORT: $!";

print "SOCKS5 server listening on $LISTEN_HOST:$LISTEN_PORT\n";

while (1) {
    my $client = $server->accept();
    next unless $client;
    # Prefer fork over threads for isolation
    my $pid = fork();
    if (!defined $pid) {
        $client->close();
        next;
    }
    if ($pid == 0) {
        $server->close();
        handle_client($client);
        exit 0;
    } else {
        $client->close();
    }
}
