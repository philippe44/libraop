package Crypt::Mac::HMAC;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;
our $VERSION = '0.048';

use base qw(Crypt::Mac Exporter);
our %EXPORT_TAGS = ( all => [qw( hmac hmac_hex hmac_b64 hmac_b64u )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use CryptX;
use Crypt::Digest;

sub new { my $class = shift; _new(Crypt::Digest::_trans_digest_name(shift), @_) }
sub hmac { Crypt::Mac::HMAC->new(shift, shift)->add(@_)->mac }
sub hmac_hex  { Crypt::Mac::HMAC->new(shift, shift)->add(@_)->hexmac }
sub hmac_b64  { Crypt::Mac::HMAC->new(shift, shift)->add(@_)->b64mac }
sub hmac_b64u { Crypt::Mac::HMAC->new(shift, shift)->add(@_)->b64umac }

1;

=pod

=head1 NAME

Crypt::Mac::HMAC - Message authentication code HMAC

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Mac::HMAC qw( hmac hmac_hex );

   # calculate MAC from string/buffer
   $hmac_raw  = hmac('SHA256', $key, 'data buffer');
   $hmac_hex  = hmac_hex('SHA256', $key, 'data buffer');
   $hmac_b64  = hmac_b64('SHA256', $key, 'data buffer');
   $hmac_b64u = hmac_b64u('SHA256', $key, 'data buffer');

   ### OO interface:
   use Crypt::Mac::HMAC;

   $d = Crypt::Mac::HMAC->new('SHA256', $key);
   $d->add('any data');
   $d->addfile('filename.dat');
   $d->addfile(*FILEHANDLE);
   $result_raw  = $d->mac;     # raw bytes
   $result_hex  = $d->hexmac;  # hexadecimal form
   $result_b64  = $d->b64mac;  # Base64 form
   $result_b64u = $d->b64umac; # Base64 URL Safe form

=head1 DESCRIPTION

Provides an interface to the HMAC message authentication code (MAC) algorithm.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Mac::HMAC qw(hmac hmac_hex );

Or all of them at once:

  use Crypt::Mac::HMAC ':all';

=head1 FUNCTIONS

=head2 hmac

Logically joins all arguments into a single string, and returns its HMAC message authentication code encoded as a binary string.

 $hmac_raw = hmac($hash_name, $key, 'data buffer');
 #or
 $hmac_raw = hmac($hash_name, $key, 'any data', 'more data', 'even more data');

=head2 hmac_hex

Logically joins all arguments into a single string, and returns its HMAC message authentication code encoded as a hexadecimal string.

 $hmac_hex = hmac_hex($hash_name, $key, 'data buffer');
 #or
 $hmac_hex = hmac_hex($hash_name, $key, 'any data', 'more data', 'even more data');

=head2 hmac_b64

Logically joins all arguments into a single string, and returns its HMAC message authentication code encoded as a Base64 string.

 $hmac_b64 = hmac_b64($hash_name, $key, 'data buffer');
 #or
 $hmac_b64 = hmac_b64($hash_name, $key, 'any data', 'more data', 'even more data');

=head2 hmac_b64u

Logically joins all arguments into a single string, and returns its HMAC message authentication code encoded as a Base64 URL Safe string (see RFC 4648 section 5).

 $hmac_b64url = hmac_b64u($hash_name, $key, 'data buffer');
 #or
 $hmac_b64url = hmac_b64u($hash_name, $key, 'any data', 'more data', 'even more data');

=head1 METHODS

=head2 new

 $d = Crypt::Mac::HMAC->new($hash_name, $key);

=head2 clone

 $d->clone();

=head2 reset

 $d->reset();

=head2 add

 $d->add('any data');
 #or
 $d->add('any data', 'more data', 'even more data');

=head2 addfile

 $d->addfile('filename.dat');
 #or
 $d->addfile(*FILEHANDLE);

=head2 mac

 $result_raw = $d->mac();

=head2 hexmac

 $result_hex = $d->hexmac();

=head2 b64mac

 $result_b64 = $d->b64mac();

=head2 b64umac

 $result_b64url = $d->b64umac();

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>

=item * L<https://en.wikipedia.org/wiki/Hmac|https://en.wikipedia.org/wiki/Hmac>

=item * L<https://tools.ietf.org/html/rfc2104|https://tools.ietf.org/html/rfc2104>

=back

=cut

__END__