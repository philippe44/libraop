package Crypt::AuthEnc::CCM;

use strict;
use warnings;
our $VERSION = '0.048';

use base qw(Crypt::AuthEnc Exporter);
our %EXPORT_TAGS = ( all => [qw( ccm_encrypt_authenticate ccm_decrypt_verify )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use CryptX;
use Crypt::Cipher;

### the following functions are implemented in XS:
# - _memory_encrypt
# - _memory_decrypt

sub ccm_encrypt_authenticate {
  my $cipher_name = shift;
  my $key = shift;
  my $nonce = shift;
  my $adata = shift;
  my $tag_len = shift;
  my $plaintext = shift;
  return _memory_encrypt(Crypt::Cipher::_trans_cipher_name($cipher_name), $key, $nonce, $adata, $tag_len, $plaintext);
}

sub ccm_decrypt_verify {
  my $cipher_name = shift;
  my $key = shift;
  my $nonce = shift;
  my $adata = shift;
  my $ciphertext = shift;
  my $tag = shift;
  return _memory_decrypt(Crypt::Cipher::_trans_cipher_name($cipher_name), $key, $nonce, $adata, $ciphertext, $tag);
}

1;

=pod

=head1 NAME

Crypt::AuthEnc::CCM - Authenticated encryption in CCM mode

=head1 SYNOPSIS

 ### functional interface
 use Crypt::AuthEnc::CCM qw(ccm_encrypt_authenticate ccm_decrypt_verify);

 my ($ciphertext, $tag) = ccm_encrypt_authenticate('AES', $key, $nonce, $adata, $tag_len, $plaintext);
 my $plaintext = ccm_decrypt_verify('AES', $key, $nonce, $adata, $ciphertext, $tag);

=head1 DESCRIPTION

CCM is a encrypt+authenticate mode that is centered around using AES (or any 16-byte cipher) as aprimitive.
Unlike EAX and OCB mode, it is only meant for packet mode where the length of the input is known in advance.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::AuthEnc::CCM qw(ccm_encrypt_authenticate ccm_decrypt_verify);

=head1 FUNCTIONS

=head2 ccm_encrypt_authenticate

 my ($ciphertext, $tag) = ccm_encrypt_authenticate($cipher, $key, $nonce, $adata, $tag_len, $plaintext);

 # $cipher .. 'AES' or name of any other cipher with 16-byte block len
 # $key ..... key of proper length (e.g. 128/192/256bits for AES)
 # $nonce ... unique nonce/salt (no need to keep it secret)
 # $adata ... additional authenticated data
 # $tag_len . required length of output tag

CCM parameters should follow L<http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf>

 # tag length:   4, 6, 8, 10, 12, 14, 16 (reasonable minimum is 8)
 # nonce length: 7, 8, 9, 10, 11, 12, 13 (if you are not sure, use 11)
 # BEWARE nonce length determines max. enc/dec data size: max_data_size = 2^(8*(15-nonce_len))

=head2 ccm_decrypt_verify

  my $plaintext = ccm_decrypt_verify($cipher, $key, $nonce, $adata, $ciphertext, $tag);

  # on error returns undef

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::AuthEnc::EAX|Crypt::AuthEnc::EAX>, L<Crypt::AuthEnc::GCM|Crypt::AuthEnc::GCM>, L<Crypt::AuthEnc::OCB|Crypt::AuthEnc::OCB>

=item * L<https://en.wikipedia.org/wiki/CCM_mode|https://en.wikipedia.org/wiki/CCM_mode>

=back
