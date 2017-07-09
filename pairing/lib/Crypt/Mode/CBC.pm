package Crypt::Mode::CBC;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;
our $VERSION = '0.048';

use Crypt::Cipher;
use base 'Crypt::Mode';

sub new { my $class = shift; _new(Crypt::Cipher::_trans_cipher_name(shift), @_) }

1;

=pod

=head1 NAME

Crypt::Mode::CBC - Block cipher mode CBC [Cipher-block chaining]

=head1 SYNOPSIS

   use Crypt::Mode::CBC;
   my $m = Crypt::Mode::CBC->new('AES');

   #(en|de)crypt at once
   my $ciphertext = $m->encrypt($plaintext, $key, $iv);
   my $plaintext = $m->decrypt($ciphertext, $key, $iv);

   #encrypt more chunks
   $m->start_encrypt($key, $iv);
   my $ciphertext = $m->add('some data');
   $ciphertext .= $m->add('more data');
   $ciphertext .= $m->finish;

   #decrypt more chunks
   $m->start_decrypt($key, $iv);
   my $plaintext = $m->add($some_ciphertext);
   $plaintext .= $m->add($more_ciphertext);
   $plaintext .= $m->finish;

=head1 DESCRIPTION

This module implements CBC cipher mode. B<NOTE:> it works only with ciphers from L<CryptX> (Crypt::Cipher::NNNN).

=head1 METHODS

=head2 new

 my $m = Crypt::Mode::CBC->new('AES');
 #or
 my $m = Crypt::Mode::CBC->new('AES', $padding);
 #or
 my $m = Crypt::Mode::CBC->new('AES', $padding, $cipher_rounds);

 # $padding .... 0 no padding (plaintext size has to be myltiple of block length)
 #               1 PKCS5 padding, Crypt::CBC's "standard" - DEFAULT
 #               2 Crypt::CBC's "oneandzeroes"
 # $cipher_rounds ... optional num of rounds for given cipher

=head2 encrypt

   my $ciphertext = $m->encrypt($plaintext, $key, $iv);

=head2 decrypt

   my $plaintext = $m->decrypt($ciphertext, $key, $iv);

=head2 start_encrypt

See example below L</finish>.

=head2 start_decrypt

See example below L</finish>.

=head2 add

See example below L</finish>.

=head2 finish

   #encrypt more chunks
   $m->start_encrypt($key, $iv);
   my $ciphertext = '';
   $ciphertext .= $m->add('some data');
   $ciphertext .= $m->add('more data');
   $ciphertext .= $m->finish;

   #decrypt more chunks
   $m->start_decrypt($key, $iv);
   my $plaintext = '';
   $plaintext .= $m->add($some_ciphertext);
   $plaintext .= $m->add($more_ciphertext);
   $plaintext .= $m->finish;

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::Cipher|Crypt::Cipher>

=item * L<Crypt::Cipher::AES|Crypt::Cipher::AES>, L<Crypt::Cipher::Blowfish|Crypt::Cipher::Blowfish>, ...

=item * L<https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher-block_chaining_.28CBC.29|https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher-block_chaining_.28CBC.29>

=back
