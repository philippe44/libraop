package Crypt::Checksum::CRC32;

use strict;
use warnings;
our $VERSION = '0.048';
use Carp;
use CryptX;

sub addfile {
  my ($self, $file) = @_;

  my $handle;
  if (ref(\$file) eq 'SCALAR') {        #filename
    open($handle, "<", $file) || croak "FATAL: cannot open '$file': $!";
    binmode($handle);
  }
  else {                                #handle
    $handle = $file
  }
  croak "FATAL: invalid handle" unless defined $handle;

  my $n;
  my $buf = "";
  while (($n = read($handle, $buf, 32*1024))) {
    $self->add($buf)
  }
  croak "FATAL: read failed: $!" unless defined $n;

  return $self;
}

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::Checksum::CRC32 - Compute CRC32 checksum

=head1 SYNOPSIS

   use Crypt::Checksum::CRC32;

   $d = Crypt::Checksum::CRC32->new;
   $d->add('any data');
   $d->addfile('filename.dat');
   $d->addfile(*FILEHANDLE);
   $checksum_raw = $d->digest;     # raw bytes
   $checksum_hex = $d->hexdigest;  # hexadecimal form

=head1 DESCRIPTION

Calculating CRC32 checksums (OO interface);

I<Since: CryptX-0.032>

=head1 METHODS

=head2 new

Constructor, returns a reference to the checksum object.

 $d = Crypt::Checksum::CRC32->new;

=head2 clone

Creates a copy of the checksum object state and returns a reference to the copy.

 $d->clone();

=head2 reset

Reinitialize the checksum object state and returns a reference to the checksum object.

 $d->reset();

=head2 add

All arguments are appended to the message we calculate checksum for.
The return value is the checksum object itself.

 $d->add('any data');
 #or
 $d->add('any data', 'more data', 'even more data');

=head2 addfile

The content of the file (or filehandle) is appended to the message we calculate checksum for.
The return value is the checksum object itself.

 $d->addfile('filename.dat');
 #or
 $d->addfile(*FILEHANDLE);

B<BEWARE:> You have to make sure that the filehandle is in binary mode before you pass it as argument to the addfile() method.

=head2 digest

Returns the binary checksum (raw bytes).

 $result_raw = $d->digest();

=head2 hexdigest

Returns the checksum encoded as a hexadecimal string.

 $result_hex = $d->hexdigest();

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::Checksum>

=item * L<https://en.wikipedia.org/wiki/Cyclic_redundancy_check>

=back

=cut