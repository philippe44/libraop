package CryptX;

use strict;
use warnings ;
our $VERSION = '0.051';

use base qw(Exporter);
our @EXPORT_OK = qw( _decode_json _encode_json);

require XSLoader;
XSLoader::load('CryptX', $VERSION);

use Carp;
my $has_json;

BEGIN {
  if (eval { require Cpanel::JSON::XS }) {
    Cpanel::JSON::XS->import(qw(encode_json decode_json));
    $has_json = 1;
  }
  elsif (eval { require JSON::XS }) {
    JSON::XS->import(qw(encode_json decode_json));
    $has_json = 2;
  }
  elsif (eval { require JSON::PP }) {
    JSON::PP->import(qw(encode_json decode_json));
    $has_json = 3;
  }
  else {
    $has_json = 0;
  }
}

sub _decode_json {
  croak "FATAL: cannot find JSON::PP or JSON::XS or Cpanel::JSON::XS" if !$has_json;
  decode_json(shift);
}

sub _encode_json {
  croak "FATAL: cannot find JSON::PP or JSON::XS or Cpanel::JSON::XS" if !$has_json;
  my $data = shift;
  my $rv = encode_json($data); # non-canonical fallback
  return(eval { Cpanel::JSON::XS->new->canonical->encode($data) } || $rv) if $has_json == 1;
  return(eval { JSON::XS->new->canonical->encode($data)         } || $rv) if $has_json == 2;
  return(eval { JSON::PP->new->canonical->encode($data)         } || $rv) if $has_json == 3;
  return($rv);
}

1;
__END__

=head1 NAME

CryptX - Crypto toolkit (self-contained no external libraries needed)

=head1 DESCRIPTION

Cryptography in CryptX is based on L<https://github.com/libtom/libtomcrypt>

Currently available modules:

=over

=item * Ciphers - see L<Crypt::Cipher> and related modules

L<Crypt::Cipher::AES>, L<Crypt::Cipher::Anubis>, L<Crypt::Cipher::Blowfish>, L<Crypt::Cipher::Camellia>, L<Crypt::Cipher::CAST5>, L<Crypt::Cipher::DES>,
L<Crypt::Cipher::DES_EDE>, L<Crypt::Cipher::KASUMI>, L<Crypt::Cipher::Khazad>, L<Crypt::Cipher::MULTI2>, L<Crypt::Cipher::Noekeon>, L<Crypt::Cipher::RC2>,
L<Crypt::Cipher::RC5>, L<Crypt::Cipher::RC6>, L<Crypt::Cipher::SAFERP>, L<Crypt::Cipher::SAFER_K128>, L<Crypt::Cipher::SAFER_K64>, L<Crypt::Cipher::SAFER_SK128>,
L<Crypt::Cipher::SAFER_SK64>, L<Crypt::Cipher::SEED>, L<Crypt::Cipher::Skipjack>, L<Crypt::Cipher::Twofish>, L<Crypt::Cipher::XTEA>

=item * Block cipher modes

L<Crypt::Mode::CBC>, L<Crypt::Mode::CFB>, L<Crypt::Mode::CTR>, L<Crypt::Mode::ECB>, L<Crypt::Mode::OFB>

=item * Stream ciphers

L<Crypt::Stream::RC4>, L<Crypt::Stream::ChaCha>, L<Crypt::Stream::Sober128>

=item * Authenticated encryption modes

L<Crypt::AuthEnc::CCM>, L<Crypt::AuthEnc::EAX>, L<Crypt::AuthEnc::GCM>, L<Crypt::AuthEnc::OCB>, L<Crypt::AuthEnc::ChaCha20Poly1305>

=item * Hash Functions - see L<Crypt::Digest> and related modules

L<Crypt::Digest::BLAKE2b_160>, L<Crypt::Digest::BLAKE2b_256>, L<Crypt::Digest::BLAKE2b_384>, L<Crypt::Digest::BLAKE2b_512>,
L<Crypt::Digest::BLAKE2s_128>, L<Crypt::Digest::BLAKE2s_160>, L<Crypt::Digest::BLAKE2s_224>, L<Crypt::Digest::BLAKE2s_256>,
L<Crypt::Digest::CHAES>, L<Crypt::Digest::MD2>, L<Crypt::Digest::MD4>, L<Crypt::Digest::MD5>, L<Crypt::Digest::RIPEMD128>, L<Crypt::Digest::RIPEMD160>,
L<Crypt::Digest::RIPEMD256>, L<Crypt::Digest::RIPEMD320>, L<Crypt::Digest::SHA1>, L<Crypt::Digest::SHA224>, L<Crypt::Digest::SHA256>, L<Crypt::Digest::SHA384>,
L<Crypt::Digest::SHA512>, L<Crypt::Digest::SHA512_224>, L<Crypt::Digest::SHA512_256>, L<Crypt::Digest::Tiger192>, L<Crypt::Digest::Whirlpool>,
L<Crypt::Digest::SHA3_224>, L<Crypt::Digest::SHA3_256>, L<Crypt::Digest::SHA3_384>, L<Crypt::Digest::SHA3_512>, L<Crypt::Digest::SHAKE>

=item * Message Authentication Codes

L<Crypt::Mac::F9>, L<Crypt::Mac::HMAC>, L<Crypt::Mac::OMAC>, L<Crypt::Mac::Pelican>, L<Crypt::Mac::PMAC>, L<Crypt::Mac::XCBC>, L<Crypt::Mac::Poly1305>

=item * Public key cryptography

L<Crypt::PK::RSA>, L<Crypt::PK::DSA>, L<Crypt::PK::ECC>, L<Crypt::PK::DH>

=item * Cryptographically secure random number generators

L<Crypt::PRNG>, L<Crypt::PRNG::Fortuna>, L<Crypt::PRNG::Yarrow>, L<Crypt::PRNG::RC4>, L<Crypt::PRNG::Sober128>, L<Crypt::PRNG::ChaCha20>

=item * Key derivation functions - PBKDF1, PBKFD2 and HKDF

L<Crypt::KeyDerivation>

=item * Other handy functions related to cryptography

L<Crypt::Misc>

=back

=head1 LICENSE

This program is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=head1 COPYRIGHT

Copyright (c) 2013+ DCIT, a.s. L<http://www.dcit.cz> / Karel Miko