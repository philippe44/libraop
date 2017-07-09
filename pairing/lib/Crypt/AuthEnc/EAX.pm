package Crypt::AuthEnc::EAX;

use strict;
use warnings;
our $VERSION = '0.048';

use base qw(Crypt::AuthEnc Exporter);
our %EXPORT_TAGS = ( all => [qw( eax_encrypt_authenticate eax_decrypt_verify )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use CryptX;
use Crypt::Cipher;

### the following methods/functions are implemented in XS:
# - _new
# - DESTROY
# - clone
# - encrypt_add
# - encrypt_done
# - decrypt_add
# - decrypt_done
# - aad_add

sub new { my $class = shift; _new(Crypt::Cipher::_trans_cipher_name(shift), @_) }

sub eax_encrypt_authenticate {
  my $cipher_name = shift;
  my $key = shift;
  my $iv = shift;
  my $adata = shift;
  my $plaintext = shift;

  my $m = Crypt::AuthEnc::EAX->new($cipher_name, $key, $iv);
  $m->aad_add($adata) if defined $adata;
  my $ct = $m->encrypt_add($plaintext);
  my $tag = $m->encrypt_done;
  return ($ct, $tag);
}

sub eax_decrypt_verify {
  my $cipher_name = shift;
  my $key = shift;
  my $iv = shift;
  my $adata = shift;
  my $ciphertext = shift;
  my $tag = shift;

  my $m = Crypt::AuthEnc::EAX->new($cipher_name, $key, $iv);
  $m->aad_add($adata) if defined $adata;
  my $ct = $m->decrypt_add($ciphertext);
  return $m->decrypt_done($tag) ? $ct : undef;
}

sub header_add {
  # obsolete, only for backwards compatibility
  shift->aad_add(@_);
}

1;

=pod

=head1 NAME

Crypt::AuthEnc::EAX - Authenticated encryption in EAX mode

=head1 SYNOPSIS

 ### OO interface
 use Crypt::AuthEnc::EAX;

 # encrypt and authenticate
 my $ae = Crypt::AuthEnc::EAX->new("AES", $key, $iv);
 $ae->aad_add('additional_authenticated_data1');
 $ae->aad_add('additional_authenticated_data2');
 $ct = $ae->encrypt_add('data1');
 $ct = $ae->encrypt_add('data2');
 $ct = $ae->encrypt_add('data3');
 $tag = $ae->encrypt_done();

 # decrypt and verify
 my $ae = Crypt::AuthEnc::EAX->new("AES", $key, $iv);
 $ae->aad_add('additional_authenticated_data1');
 $ae->aad_add('additional_authenticated_data2');
 $pt = $ae->decrypt_add('ciphertext1');
 $pt = $ae->decrypt_add('ciphertext2');
 $pt = $ae->decrypt_add('ciphertext3');
 $tag = $ae->decrypt_done();
 die "decrypt failed" unless $tag eq $expected_tag;

 #or
 my $result = $ae->decrypt_done($expected_tag) die "decrypt failed";

 ### functional interface
 use Crypt::AuthEnc::EAX qw(eax_encrypt_authenticate eax_decrypt_verify);

 my ($ciphertext, $tag) = eax_encrypt_authenticate('AES', $key, $iv, $adata, $plaintext);
 my $plaintext = eax_decrypt_verify('AES', $key, $iv, $adata, $ciphertext, $tag);

=head1 DESCRIPTION

EAX is a mode that requires a cipher, CTR and OMAC support and provides encryption and authentication.
It is initialized with a random IV that can be shared publicly, additional authenticated data which can 
be fixed and public, and a random secret symmetric key.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::AuthEnc::EAX qw(eax_encrypt_authenticate eax_decrypt_verify);

=head1 FUNCTIONS

=head2 eax_encrypt_authenticate

 my ($ciphertext, $tag) = eax_encrypt_authenticate($cipher, $key, $iv, $adata, $plaintext);

 # $cipher .. 'AES' or name of any other cipher with 16-byte block len
 # $key ..... AES key of proper length (128/192/256bits)
 # $iv ...... unique initialization vector (no need to keep it secret)
 # $adata ... additional authenticated data

=head2 eax_decrypt_verify

  my $plaintext = eax_decrypt_verify($cipher, $key, $iv, $adata, $ciphertext, $tag);

  # on error returns undef

=head1 METHODS

=head2 new

 my $ae = Crypt::AuthEnc::EAX->new($cipher, $key, $iv);
 #or
 my $ae = Crypt::AuthEnc::EAX->new($cipher, $key, $iv, $adata);

 # $cipher .. 'AES' or name of any other cipher with 16-byte block len
 # $key ..... AES key of proper length (128/192/256bits)
 # $iv ...... unique initialization vector (no need to keep it secret)
 # $adata ... additional authenticated data (optional)

=head2 aad_add

 $ae->aad_add($adata);                          #can be called multiple times

=head2 encrypt_add

 $ciphertext = $ae->encrypt_add($data);         #can be called multiple times

=head2 encrypt_done

 $tag = $ae->encrypt_done();

=head2 decrypt_add

 $plaintext = $ae->decrypt_add($ciphertext);    #can be called multiple times

=head2 decrypt_done

 my $result = $ae->decrypt_done($tag);  # returns 1 (success) or 0 (failure)
 #or
 my $tag = $ae->decrypt_done;           # returns $tag value

=head2 clone

 my $ae_new = $ae->clone;

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::AuthEnc::CCM|Crypt::AuthEnc::CCM>, L<Crypt::AuthEnc::GCM|Crypt::AuthEnc::GCM>, L<Crypt::AuthEnc::OCB|Crypt::AuthEnc::OCB>

=item * L<https://en.wikipedia.org/wiki/EAX_mode|https://en.wikipedia.org/wiki/EAX_mode>

=back
