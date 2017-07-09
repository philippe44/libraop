package Crypt::AuthEnc::ChaCha20Poly1305;

use strict;
use warnings;
our $VERSION = '0.048';

use base qw(Crypt::AuthEnc Exporter);
our %EXPORT_TAGS = ( all => [qw( chacha20poly1305_encrypt_authenticate chacha20poly1305_decrypt_verify )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use CryptX;

sub new { my $class = shift; _new(@_) }

sub chacha20poly1305_encrypt_authenticate {
  my $key = shift;
  my $iv = shift;
  my $adata = shift;
  my $plaintext = shift;

  my $m = Crypt::AuthEnc::ChaCha20Poly1305->new($key, $iv);
  $m->adata_add(defined $adata ? $adata : ''); #XXX-TODO if no aad we have to pass empty string
  my $ct = $m->encrypt_add($plaintext);
  my $tag = $m->encrypt_done;
  return ($ct, $tag);
}

sub chacha20poly1305_decrypt_verify {
  my $key = shift;
  my $iv = shift;
  my $adata = shift;
  my $ciphertext = shift;
  my $tag = shift;

  my $m = Crypt::AuthEnc::ChaCha20Poly1305->new($key, $iv);
  $m->adata_add(defined $adata ? $adata : ''); #XXX-TODO if no aad we have to pass empty string
  my $ct = $m->decrypt_add($ciphertext);
  return $m->decrypt_done($tag) ? $ct : undef;
}

1;

=pod

=head1 NAME

Crypt::AuthEnc::ChaCha20Poly1305 - Authenticated encryption in ChaCha20Poly1305 mode

=head1 SYNOPSIS

 ### OO interface
 use Crypt::AuthEnc::ChaCha20Poly1305;

 # encrypt and authenticate
 my $ae = Crypt::AuthEnc::ChaCha20Poly1305->new($key, $iv);
 $ae->aad_add('additional_authenticated_data1');
 $ae->aad_add('additional_authenticated_data2');
 $ct = $ae->encrypt_add('data1');
 $ct = $ae->encrypt_add('data2');
 $ct = $ae->encrypt_add('data3');
 $tag = $ae->encrypt_done();

 # decrypt and verify
 my $ae = Crypt::AuthEnc::ChaCha20Poly1305->new($key, $iv);
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
 use Crypt::AuthEnc::ChaCha20Poly1305 qw(chacha20poly1305_encrypt_authenticate chacha20poly1305_decrypt_verify);

 my ($ciphertext, $tag) = chacha20poly1305_encrypt_authenticate($key, $iv, $adata, $plaintext);
 my $plaintext = chacha20poly1305_decrypt_verify($key, $iv, $adata, $ciphertext, $tag);

=head1 DESCRIPTION

Provides encryption and authentication based on ChaCha20 + Poly1305 as defined in RFC 7539 - L<https://tools.ietf.org/html/rfc7539>

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::AuthEnc::ChaCha20Poly1305 qw(chacha20poly1305_encrypt_authenticate chacha20poly1305_decrypt_verify);

=head1 FUNCTIONS

=head2 chacha20poly1305_encrypt_authenticate

 my ($ciphertext, $tag) = chacha20poly1305_encrypt_authenticate($key, $iv, $adata, $plaintext);

 # $key ..... key of proper length (128 or 256 bits / 16 or 32 bytes)
 # $iv ...... initialization vector (64 or 96 bits / 8 or 12 bytes)
 # $adata ... additional authenticated data (optional)

=head2 chacha20poly1305_decrypt_verify

 my $plaintext = chacha20poly1305_decrypt_verify($key, $iv, $adata, $ciphertext, $tag);

 # on error returns undef

=head1 METHODS

=head2 new

 my $ae = Crypt::AuthEnc::ChaCha20Poly1305->new($key, $iv);

 # $key ..... encryption key of proper length (128 or 256 bits / 16 or 32 bytes)
 # $iv ...... initialization vector (64 or 96 bits / 8 or 12 bytes)

=head2 aad_add

Can be called before the first C<encrypt_add> or C<decrypt_add>;

 $ae->aad_add($aad_data);                       #can be called multiple times

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

=head2 set_iv

 $ae->set_iv($iv);

=head2 set_iv_rfc7905

 $ae->set_iv_rfc7905($iv, $seqnum);

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::AuthEnc::GCM|Crypt::AuthEnc::GCM>, L<Crypt::AuthEnc::CCM|Crypt::AuthEnc::CCM>, L<Crypt::AuthEnc::EAX|Crypt::AuthEnc::EAX>, L<Crypt::AuthEnc::OCB|Crypt::AuthEnc::OCB>

=item * L<https://tools.ietf.org/html/rfc7539>

=back
