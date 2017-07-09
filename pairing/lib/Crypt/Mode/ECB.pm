package Crypt::Mode::ECB;

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

Crypt::Mode::ECB - Block cipher mode ECB [Electronic codebook]

=head1 SYNOPSIS

   use Crypt::Mode::ECB;
   my $m = Crypt::Mode::ECB->new('AES');

   #(en|de)crypt at once
   my $ciphertext = $m->encrypt($plaintext, $key);
   my $plaintext = $m->decrypt($ciphertext, $key);

   #encrypt more chunks
   $m->start_encrypt($key);
   my $ciphertext = $m->add('some data');
   $ciphertext .= $m->add('more data');
   $ciphertext .= $m->finish;

   #decrypt more chunks
   $m->start_decrypt($key);
   my $plaintext = $m->add($some_ciphertext);
   $plaintext .= $m->add($more_ciphertext);
   $plaintext .= $m->finish;

=head1 DESCRIPTION

This module implements ECB cipher mode. B<NOTE:> it works only with ciphers from L<CryptX> (Crypt::Cipher::NNNN).
B<BEWARE: ECB is inherently insecure>, if you are not sure go for L<Crypt::Mode::CBC>!

=head1 METHODS

=head2 new

 my $m = Crypt::Mode::ECB->new('AES');
 #or
 my $m = Crypt::Mode::ECB->new('AES', $padding);
 #or
 my $m = Crypt::Mode::ECB->new('AES', $padding, $cipher_rounds);

 # $padding .... 0 no padding (plaintext size has to be myltiple of block length)
 #               1 PKCS5 padding, Crypt::CBC's "standard" - DEFAULT
 #               2 Crypt::CBC's "oneandzeroes"
 # $cipher_rounds ... optional num of rounds for given cipher

=head2 encrypt

   my $ciphertext = $m->encrypt($plaintext, $key);

=head2 decrypt

   my $plaintext = $m->decrypt($ciphertext, $key);

=head2 start_encrypt

See example below L</finish>.

=head2 start_decrypt

See example below L</finish>.

=head2 add

See example below L</finish>.

=head2 finish

   #encrypt more chunks
   $m->start_encrypt($key);
   my $ciphertext = '';
   $ciphertext .= $m->add('some data');
   $ciphertext .= $m->add('more data');
   $ciphertext .= $m->finish;

   #decrypt more chunks
   $m->start_decrypt($key);
   my $plaintext = '';
   $plaintext .= $m->add($some_ciphertext);
   $plaintext .= $m->add($more_ciphertext);
   $plaintext .= $m->finish;

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::Cipher|Crypt::Cipher>

=item * L<Crypt::Cipher::AES|Crypt::Cipher::AES>, L<Crypt::Cipher::Blowfish|Crypt::Cipher::Blowfish>, ...

=item * L<https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_.28ECB.29|https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_.28ECB.29>

=back
