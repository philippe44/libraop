package Crypt::Checksum;

use strict;
use warnings;
our $VERSION = '0.048';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw/
                                  adler32_data adler32_data_hex adler32_data_int adler32_file adler32_file_hex adler32_file_int
                                  crc32_data crc32_data_hex crc32_data_int crc32_file crc32_file_hex crc32_file_int
                               /] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
use Crypt::Checksum::Adler32;
use Crypt::Checksum::CRC32;

sub adler32_data        { Crypt::Checksum::Adler32->new->add(@_)->digest                  }
sub adler32_data_hex    { Crypt::Checksum::Adler32->new->add(@_)->hexdigest               }
sub adler32_data_int    { unpack("N", Crypt::Checksum::Adler32->new->add(@_)->digest)     }
sub adler32_file        { Crypt::Checksum::Adler32->new->addfile(@_)->digest              }
sub adler32_file_hex    { Crypt::Checksum::Adler32->new->addfile(@_)->hexdigest           }
sub adler32_file_int    { unpack("N", Crypt::Checksum::Adler32->new->addfile(@_)->digest) }
sub crc32_data          { Crypt::Checksum::CRC32->new->add(@_)->digest                    }
sub crc32_data_hex      { Crypt::Checksum::CRC32->new->add(@_)->hexdigest                 }
sub crc32_data_int      { unpack("N", Crypt::Checksum::CRC32->new->add(@_)->digest)       }
sub crc32_file          { Crypt::Checksum::CRC32->new->addfile(@_)->digest                }
sub crc32_file_hex      { Crypt::Checksum::CRC32->new->addfile(@_)->hexdigest             }
sub crc32_file_int      { unpack("N", Crypt::Checksum::CRC32->new->addfile(@_)->digest)   }

1;

=pod

=head1 NAME

Crypt::Checksum - functional interface to CRC32 and Adler32 checksums

=head1 SYNOPSIS

   use Crypt::Checksum ':all';
   
   # calculate Adler32 checksum from string/buffer
   $checksum_raw  = adler32_data($data);
   $checksum_hex  = adler32_data_hex($data);

   # calculate Adler32 checksum from file
   $checksum_raw  = adler32_file('filename.dat');
   $checksum_hex  = adler32_file_hex('filename.dat');

   # calculate Adler32 checksum from filehandle
   $checksum_raw  = adler32_file(*FILEHANDLE);
   $checksum_hex  = adler32_file_hex(*FILEHANDLE);

   # calculate CRC32 checksum from string/buffer
   $checksum_raw  = crc32_data($data);
   $checksum_hex  = crc32_data_hex($data);

   # calculate CRC32 checksum from file
   $checksum_raw  = crc32_file('filename.dat');
   $checksum_hex  = crc32_file_hex('filename.dat');

   # calculate CRC32 checksum from filehandle
   $checksum_raw  = crc32_file(*FILEHANDLE);
   $checksum_hex  = crc32_file_hex(*FILEHANDLE);
   
=head1 DESCRIPTION

Calculating CRC32 and Adler32 checksums (functional interface);

I<Since: CryptX-0.032>

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Checksum qw( adler32_data adler32_data_hex adler32_file adler32_file_hex
                          crc32_data crc32_data_hex crc32_file crc32_file_hex );

Or all of them at once:

  use Crypt::Checksum ':all';

=head1 FUNCTIONS

=head2 adler32_data

Returns checksum as raw octects.

 $checksum_raw = adler32_data('data string');
 #or
 $checksum_raw = adler32_data('any data', 'more data', 'even more data');

=head2 adler32_data_hex

Returns checksum as a hexadecimal string.

 $checksum_hex = adler32_data_hex('data string');
 #or
 $checksum_hex = adler32_data_hex('any data', 'more data', 'even more data');

=head2 adler32_data_int

Returns checksum as unsingned 32bit integer.

 $checksum_hex = adler32_data_int('data string');
 #or
 $checksum_hex = adler32_data_int('any data', 'more data', 'even more data');

=head2 adler32_file

Returns checksum as raw octects.

 $checksum_raw = adler32_file('filename.dat');
 #or
 $checksum_raw = adler32_file(*FILEHANDLE);

=head2 adler32_file_hex

Returns checksum as a hexadecimal string.

 $checksum_hex = adler32_file_hex('filename.dat');
 #or
 $checksum_hex = adler32_file_hex(*FILEHANDLE);

=head2 adler32_file_int

Returns checksum as unsingned 32bit integer.

 $checksum_hex = adler32_file_int('data string');
 #or
 $checksum_hex = adler32_file_int('any data', 'more data', 'even more data');

=head2 crc32_data

Returns checksum as raw octects.

 $checksum_raw = crc32_data('data string');
 #or
 $checksum_raw = crc32_data('any data', 'more data', 'even more data');

=head2 crc32_data_hex

Returns checksum as a hexadecimal string.

 $checksum_hex = crc32_data_hex('data string');
 #or
 $checksum_hex = crc32_data_hex('any data', 'more data', 'even more data');

=head2 crc32_data_int

Returns checksum as unsingned 32bit integer.

 $checksum_hex = crc32_data_int('data string');
 #or
 $checksum_hex = crc32_data_int('any data', 'more data', 'even more data');

=head2 crc32_file

Returns checksum as raw octects.

 $checksum_raw = crc32_file('filename.dat');
 #or
 $checksum_raw = crc32_file(*FILEHANDLE);

=head2 crc32_file_hex

Returns checksum as a hexadecimal string.

 $checksum_hex = crc32_file_hex('filename.dat');
 #or
 $checksum_hex = crc32_file_hex(*FILEHANDLE);

=head2 crc32_file_int

Returns checksum as unsingned 32bit integer.

 $checksum_hex = crc32_file_int('data string');
 #or
 $checksum_hex = crc32_file_int('any data', 'more data', 'even more data');

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::Checksum::Adler32>, L<Crypt::Checksum::CRC32>

=item * L<https://en.wikipedia.org/wiki/Adler-32>

=item * L<https://en.wikipedia.org/wiki/Cyclic_redundancy_check>

=back

=cut