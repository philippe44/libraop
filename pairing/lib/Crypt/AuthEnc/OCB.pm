package Crypt::AuthEnc::OCB;

use strict;
use warnings;
our $VERSION = '0.048';

use base qw(Crypt::AuthEnc Exporter);
our %EXPORT_TAGS = ( all => [qw( ocb_encrypt_authenticate ocb_decrypt_verify )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use CryptX;
use Crypt::Cipher;

sub new { my $class = shift; _new(Crypt::Cipher::_trans_cipher_name(shift), @_) }

sub ocb_encrypt_authenticate {
  my $cipher_name = shift;
  my $key = shift;
  my $nonce = shift;
  my $adata = shift;
  my $plaintext = shift;

  my $m = Crypt::AuthEnc::OCB->new($cipher_name, $key, $nonce);
  $m->aad_add($adata) if defined $adata;
  my $ct = $m->encrypt_last($plaintext);
  my $tag = $m->encrypt_done;
  return ($ct, $tag);
}

sub ocb_decrypt_verify {
  my $cipher_name = shift;
  my $key = shift;
  my $nonce = shift;
  my $adata = shift;
  my $ciphertext = shift;
  my $tag = shift;

  my $m = Crypt::AuthEnc::OCB->new($cipher_name, $key, $nonce);
  $m->aad_add($adata) if defined $adata;
  my $ct = $m->decrypt_last($ciphertext);
  return $m->decrypt_done($tag) ? $ct : undef;
}

sub adata_add {
  # obsolete, only for backwards compatibility
  shift->aad_add(@_);
}

1;

=pod

=head1 NAME

Crypt::AuthEnc::OCB - Authenticated encryption in OCBv3 mode

=head1 SYNOPSIS

 ### OO interface
 use Crypt::AuthEnc::OCB;

 # encrypt and authenticate
 my $ae = Crypt::AuthEnc::OCB->new("AES", $key, $nonce);
 $ae->aad_add('additional_authenticated_data1');
 $ae->aad_add('additional_authenticated_data2');
 $ct = $ae->encrypt_add('data1');
 $ct = $ae->encrypt_add('data2');
 $ct = $ae->encrypt_add('data3');
 $ct = $ae->encrypt_last('rest of data');
 ($ct,$tag) = $ae->encrypt_done();

 # decrypt and verify
 my $ae = Crypt::AuthEnc::OCB->new("AES", $key, $nonce);
 $ae->aad_add('additional_authenticated_data1');
 $ae->aad_add('additional_authenticated_data2');
 $pt = $ae->decrypt_add('ciphertext1');
 $pt = $ae->decrypt_add('ciphertext2');
 $pt = $ae->decrypt_add('ciphertext3');
 $pt = $ae->decrypt_last('rest of data');
 ($pt,$tag) = $ae->decrypt_done();

 ### functional interface
 use Crypt::AuthEnc::OCB qw(ocb_encrypt_authenticate ocb_decrypt_verify);

 my ($ciphertext, $tag) = ocb_encrypt_authenticate('AES', $key, $nonce, $adata, $plaintext);
 my $plaintext = ocb_decrypt_verify('AES', $key, $nonce, $adata, $ciphertext, $tag);

=head1 DESCRIPTION

This module implements OCB version 3 according http://datatracker.ietf.org/doc/draft-irtf-cfrg-ocb/

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::AuthEnc::OCB qw(ocb_encrypt_authenticate ocb_decrypt_verify);

=head1 FUNCTIONS

=head2 ocb_encrypt_authenticate

 my ($ciphertext, $tag) = ocb_encrypt_authenticate($cipher, $key, $nonce, $adata, $plaintext);

 # $cipher .. 'AES' or name of any other cipher with 16-byte block len
 # $key ..... AES key of proper length (128/192/256bits)
 # $nonce ... unique nonce/salt (no need to keep it secret)
 # $adata ... additional authenticated data

=head2 ocb_decrypt_verify

  my $plaintext = ocb_decrypt_verify($cipher, $key, $nonce, $adata, $ciphertext, $tag);

  # on error returns undef

=head1 METHODS

=head2 new

 my $ae = Crypt::AuthEnc::OCB->new($cipher, $key, $nonce);

 # $cipher .. 'AES' or name of any other cipher with 16-byte block len
 # $key ..... AES key of proper length (128/192/256bits)
 # $nonce ... unique nonce/salt (no need to keep it secret)

=head2 aad_add

 $ae->aad_add($adata);                          #can be called multiple times

=head2 encrypt_add

 $ciphertext = $ae->encrypt_add($data);         #can be called multiple times

 #BEWARE: size of $data has to be multiple of blocklen (16 for AES)

=head2 encrypt_last

 $ciphertext = $ae->encrypt_last($data);

=head2 encrypt_done

 $tag = $ae->encrypt_done();

=head2 decrypt_add

 $plaintext = $ae->decrypt_add($ciphertext);    #can be called multiple times

 #BEWARE: size of $ciphertext has to be multiple of blocklen (16 for AES)

=head2 encrypt_last

 $plaintext = $ae->decrypt_last($data);

=head2 decrypt_done

 my $result = $ae->decrypt_done($tag);  # returns 1 (success) or 0 (failure)
 #or
 my $tag = $ae->decrypt_done;           # returns $tag value

=head2 clone

 my $ae_new = $ae->clone;

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::AuthEnc::CCM|Crypt::AuthEnc::CCM>, L<Crypt::AuthEnc::GCM|Crypt::AuthEnc::GCM>, L<Crypt::AuthEnc::EAX|Crypt::AuthEnc::EAX>

=item * L<https://en.wikipedia.org/wiki/OCB_mode|https://en.wikipedia.org/wiki/OCB_mode>

=back