package Crypt::Curve25519;
our $AUTHORITY = 'cpan:AJGB';
#ABSTRACT: Generate shared secret using elliptic-curve Diffie-Hellman function
$Crypt::Curve25519::VERSION = '0.06';
use strict;
use warnings;
use Carp qw( croak );

require Exporter;
our @ISA = qw(Exporter);

our %EXPORT_TAGS = ( 'all' => [ qw(
    curve25519
    curve25519_secret_key
    curve25519_public_key
    curve25519_shared_secret
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
    curve25519_secret_key
    curve25519_public_key
    curve25519_shared_secret
);

# Although curve25519_donna is also clamping the secret key this function
# has been provided for completeness and to ensure that secret keys generated
# here can be used in other implementations of the algorithm.
sub curve25519_secret_key {
    my $value = shift;
    croak 'Secret key requires 32 bytes' if length($value) != 32;
    vec($value, 0 , 8) &= 248;
    vec($value, 31, 8) &= 127;
    vec($value, 31, 8) |= 64;
    return $value;
}

require XSLoader;
XSLoader::load('Crypt::Curve25519', $Crypt::Curve25519::{VERSION} ?
    ${ $Crypt::Curve25519::{VERSION} } : ()
);

sub new {
    return bless(\(my $o = 1), ref $_[0] ? ref $_[0] : $_[0] );
}

sub secret_key {
    my ($self, $psk) = (shift, shift);

    my $masked = curve25519_secret_key( pack('H64', $psk) );

    return unpack('H64', $masked);
}

sub public_key {
    my ($self, $sk) = (shift, shift);
    my @args = pack('H64', $sk);
    if ( @_ ) {
        push @args, pack('H64', shift);
    }

    my $pk = unpack('H64', curve25519_public_key( @args ));

    return $pk;
}

sub shared_secret {
    my ($self, $sk, $pk) = @_;

    return unpack('H64', curve25519_shared_secret( pack('H64', $sk), pack('H64', $pk) ));
}

sub generate {
    my ($self, $sk, $bp) = @_;

    return unpack('H64', curve25519( pack('H64', $sk), pack('H64', $bp) ));
}

1;

__END__

=pod

=encoding UTF-8

=head1 NAME

Crypt::Curve25519 - Generate shared secret using elliptic-curve Diffie-Hellman function

=head1 VERSION

version 0.06

=head1 SYNOPSIS

    use Crypt::Curve25519;

    # Alice:
    my $alice_secret_key = curve25519_secret_key(random_32_bytes());
    my $alice_public_key = curve25519_public_key( $alice_secret_key );

    # Bob:
    my $bob_secret_key = curve25519_secret_key(random_32_bytes());
    my $bob_public_key = curve25519_public_key( $bob_secret_key );

    # Alice and Bob exchange their public keys
    my $alice_public_key_hex = unpack('H64', $alice_public_key);
    my $bob_public_key_hex   = unpack('H64', $bob_public_key);

    # Alice calculates shared secret to communicate with Bob
    my $shared_secret_with_bob = curve25519_shared_secret(
        $alice_secret_key,
        pack('H64', $bob_public_key_hex)
    );

    # Bob calculates shared secret to communicate with Alice
    my $shared_secret_with_alice = curve25519_shared_secret(
        $bob_secret_key,
        pack('H64', $alice_public_key_hex)
    );

    # Shared secrets are equal
    die "Something horrible has happend!"
      unless $shared_secret_with_bob eq $shared_secret_with_alice;

This package provides also simplified OO interface:

    use Crypt::Curve25519 ();

    my $c = Crypt::Curve25519->new();

    # Alice:
    my $alice_secret_key_hex = $c->secret_key(random_hexencoded_32_bytes());
    my $alice_public_key_hex = $c->public_key( $alice_secret_key_hex );

    # Bob:
    my $bob_secret_key_hex = $c->secret_key(random_hexencoded_32_bytes());
    my $bob_public_key_hex = $c->public_key( $bob_secret_key_hex );

    # Alice and Bob exchange their public keys

    # Alice calculates shared secret to communicate with Bob
    my $shared_secret_with_bob_hex = $c->shared_secret(
                                    $alice_secret_key_hex,
                                    $bob_public_key_hex);

    # Bob calculates shared secret to communicate with Alice
    my $shared_secret_with_alice_hex = $c->shared_secret(
                                    $bob_secret_key_hex,
                                    $alice_public_key_hex);

    # Shared secrets are equal
    die "Something horrible has happend!"
      unless $shared_secret_with_bob_hex eq $shared_secret_with_alice_hex;

Example functions to generate pseudo-random private secret key:

    sub random_32_bytes {
        return join('', map { chr(int(rand(255))) } 1 .. 32);
    }

    sub random_hexencoded_32_bytes {
       return unpack('H64', random_32_bytes());
    }

=head1 DESCRIPTION

Curve25519 is a state-of-the-art Diffie-Hellman function suitable for a wide
variety of applications.

Given a user's 32-byte secret key, Curve25519 computes the user's 32-byte
public key. Given the user's 32-byte secret key and another user's 32-byte
public key, Curve25519 computes a 32-byte secret shared by the two users. This
secret can then be used to authenticate and encrypt messages between the two
users.

=head1 METHODS

=head2 new

    my $c = Crypt::Curve25519->new();

Create a new object

=head2 secret_key

    my $my_secret_key_hex = $c->secret_key( $my_random_32byte_string_hex );

Using hex encoded 32-byte random string from cryptographically safe source
create masked secret key.

=head2 public_key

    my $public_key_hex = $c->public_key( $my_secret_key_hex );

Using hex encoded masked secret key generate corresponding hex encoded 32-byte
Curve25519 public key.

=head2 shared_secret

    my $shared_secret_hex = $c->shared_secret(
        $my_secret_key_hex, $his_public_key_hex
    );

Using provided hex encoded keys generate 32-byte hex encoded shared secret,
that both parties can use without disclosing their private secret keys.

=head2 generate

Access to primitive method is also provided.

    my $key_hex = $c->generate($my_secret_key_hex, $basepoint_hex);

    # public key
    if ( $basepoint_hex eq unpack("H64", pack("H64", "09")) ) {
        print "\$key_hex is a public key\n";
    }
    elsif ( $basepoint_hex eq $his_public_key_hex ) {
        print "\$key_hex is a shared secret\n";
    }

Using provided hex encoded secret key and depending on the 32-byte hex
encoded basepoint generate 32-byte hex encoded public key or shared secret.

=head1 FUNCTIONS

=head2 curve25519_secret_key

    my $my_secret_key = curve25519_secret_key($my_random_32byte_string);

Using provided 32-byte random string from cryptographically safe source create
masked secret key.

=head2 curve25519_public_key

    my $public_key = curve25519_public_key($my_secret_key);

Using masked secret key generate corresponding 32-byte Curve25519 public key.

=head2 curve25519_shared_secret

    my $shared_secret = curve25519_shared_secret(
        $my_secret_key, $his_public_key
    );

Using provided keys generate 32-byte shared secret, that both parties can use
without disclosing their private secret keys.

=head2 curve25519

Access to primitive function is also provided.

    use Crypt::Curve25519 'curve25519';

    my $key = curve25519($my_secret_key, $basepoint);

    # public key
    if ( $basepoint eq pack('H64', '09') ) {
        print "\$key is a public key\n";
    }
    elsif ( $basepoint eq $his_public_key ) {
        print "\$key is a shared secret\n";
    }

Using provided secret key and depending on the 32-byte basepoint generate
32-byte public key or shared secret.

=head1 SEE ALSO

=over 4

=item * L<http://cr.yp.to/ecdh.html>

=back

=head1 AUTHOR

Alex J. G. Burzyński <ajgb@cpan.org>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2014 by Alex J. G. Burzyński <ajgb@cpan.org>.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
