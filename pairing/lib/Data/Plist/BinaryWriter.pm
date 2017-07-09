=head1 NAME

Data::Plist::BinaryWriter - write binary property lists
from Perl data structures

=head1 SYNOPSIS

 # Create new
 my $write = Data::Plist::BinaryWriter->new();

 # Writing to a string ($ret is binary output)
 my $ret = $write->write($data);

 # Writing to a file C<$filename>
 $write->write($filename, $data);

=head1 DESCRIPTION

C<Data::Plist::BinaryWriter> takes perl data structures,
serializes them (see L<Data::Plist/SERIALIZED DATA>) and
recursively writes to a given filehandle in Apple's binary
property list format.

=cut

package Data::Plist::BinaryWriter;

use strict;
use warnings;
use Storable;
use Math::BigInt;
use Digest::MD5;

use base qw/Data::Plist::Writer/;

=head1 METHODS

=head2 write_fh $fh, $data

Takes a perl data structure C<$data>, serializes it (see
L<Data::Plist/SERIALIZED DATA>) and writes it to the given
filehandle C<$fh> in Apple's binary property list format.

The format starts with "bplist00" and contains a 32-byte
trailer. The 32-byte trailer consists of the size of the
offset objects in the offset table, the size of the indices
of the offset table, the number of objects in the binary
file, the index of top object in the binary file and the
offset table offset.

=cut

sub write_fh {
    my $self = shift;
    $self = $self->new() unless ref $self;

    my ( $fh, $object ) = @_;
    $object = $self->serialize($object) if ( $self->{serialize} );
	binmode $fh;
    $self->{fh}       = $fh;
    $self->{index}    = [];
    $self->{size}     = $self->count($object);
    $self->{objcache} = {};
    if ( $self->{size} >= 2**8 ) {
        $self->{refsize} = 2;
    } else {
        $self->{refsize} = 1;
    }
    print $fh "bplist00";
    my $top_index    = $self->dispatch($object);
    my $offset_size  = $self->bytes( $self->{index}->[-1] );
    my $table_offset = tell $fh;
    for ( @{ $self->{index} } ) {
        my $value = pack $self->pack_in( $offset_size - 1 ), $_;
        if ( $offset_size == 3 ) {
            $value = substr $value, -3;
        }
        print $fh $value;
    }
    print $fh ( pack "x6CC", ($offset_size), $self->{refsize} );
    print $fh ( pack "x4N", scalar keys %{ $self->{objcache} } );
    print $fh ( pack "x4N", $top_index );
    print $fh ( pack "x4N", $table_offset );
    close $fh;
    return 1;
}

=head2 dispatch $data

Takes serialized data structure C<$data> (see
L<Data::Plist/SERIALIZED DATA>) and checks its type. Checks
the object against previously written objects. If no match
is found, calls the appropriate write_ method. Returns the
index into the offset table of the offset object that
points to the data's position in the binary file.

=cut

sub dispatch {
    my $self       = shift;
    my ($arrayref) = @_;
    my $type       = $arrayref->[0];
    my $method     = "write_" . $type;
    local $Storable::canonical = 1;
    my $digest = eval { Digest::MD5::md5_hex( Storable::freeze($arrayref) ) };
    die "Can't $method" unless $self->can($method);
    $self->{objcache}{$digest} = $self->$method( $arrayref->[1] )
        unless ( exists $self->{objcache}{$digest} );
    return $self->{objcache}{$digest};
}

=head2 make_type $type, $length

Takes a string representing the object's type C<$type> and an
integer indicating its size C<$length>. Returns their binary
representation.

Each object in the binary file is preceded by a byte - the
higher nybble denoting its type and the lower its size. For
objects whose size is equal to or great than 15, the lower
byte contains an f and an integer object is added right
after the first byte containing the object's actual size.

=cut

sub make_type {
    my $self = shift;
    my ( $type, $len ) = @_;
    my $ans = "";

    my $optint = "";
    if ( $len < 15 ) {
        $type .= sprintf( "%x", $len );
    } else {
        $type .= "f";
        my $optlen = $self->power($len);
        $optint = pack( "C" . $self->pack_in($optlen), hex( "1" . $optlen ),
            $len );
    }
    $ans = pack( "H*", $type ) . $optint;

    return $ans;
}

=head2 write_integer $int, $type

Takes an integer C<$int> and an optional type C<$type>
(used for writing UIDs, since they're essentially the
same). Returns the index into the offset table of the
offset object that points to the integer's location in the
binary file.

=cut

sub write_integer {
    my $self = shift;
    my ( $int, $type ) = @_;
    my $fmt;
    my $obj;

    unless ( defined $type ) {
        $type = "1";
    }
    my $len = $self->power($int);

    if ( $len == 3 ) {
        if ( $int < 0 ) {
            $int += Math::BigInt->new(2)->bpow(64);
        }
        my $hw = Math::BigInt->new($int);
        $hw->brsft(32);
        my $lw = Math::BigInt->new($int);
        $lw->band( Math::BigInt->new("4294967295") );

        $obj
            = $self->make_type( $type, $len )
            . pack( "N", $hw )
            . pack( "N", $lw );
    } else {
        $fmt = $self->pack_in($len);
        $obj = pack( "C" . $fmt, hex( $type . $len ), $int );
    }
    return $self->binary_write($obj);
}

=head2 write_string $string

Takes a string C<$string> and returns the index into the offset table
of the offset object that points to its location in the binary file.
It is encoded in the file using UTF-8.

=cut

sub write_string {
    my $self     = shift;
    my ($string) = @_;
    my $type     = $self->make_type( "5", length($string) );
    my $obj      = $type . $string;
	return $self->binary_write($obj);
}

=head2 write_ustring $ustring

Takes a string C<$ustring> and returns the index into the offset table
of the offset object that points to its location in the binary file.

While C<ustrings> are technically supposed to be stored in UTF-16,
there is no known reason for them to not be written as UTF-8 encoded
C<string>s instead; thus, for simplicity, all C<ustring>s are written
as C<string>s.

=cut

sub write_ustring {
    my $self = shift;
    return $self->write_string(@_);
}

=head2 write_dict $dict

Takes a hash reference C<$dict> and recursively processes
each of its keys and values. Stores indices into the offset
table of the offset objects pointing to its keys and values
in the binary file. Returns the index into the offset table
of the offset object that points to its location in the
binary file.

=cut

sub write_dict {
    my $self   = shift;
    my $fh     = $self->{fh};
    my ($hash) = @_;
    my @keys;
    my @values;
    for my $key ( keys %$hash ) {
        push @keys, $self->dispatch( [ "string", $key ] );
        push @values, $self->dispatch( $hash->{$key} );
    }
    my $current = tell $self->{fh};
    print $fh $self->make_type( "d", scalar keys(%$hash) );
    my $packvar = $self->pack_in( $self->{refsize} - 1 );
    print $fh pack $packvar, $_ for @keys, @values;
    push @{ $self->{index} }, $current;
    return ( @{ $self->{index} } - 1 );
}

=head2 write_array $array

Take an array reference C<$array> and recursively processes
its contents. Stores the indices into the offset table of
the offset objects pointing to its value. Returns the index
into the offset table of the offset object that points to
its location in the binary file.

=cut

sub write_array {
    my $self    = shift;
    my $fh      = $self->{fh};
    my ($array) = @_;
    my $size    = @$array;
    my @values;
    for (@$array) {
        push @values, $self->dispatch($_);
    }
    my $current = tell $self->{fh};
    print $fh $self->make_type( "a", $size );
    my $packvar = $self->pack_in( $self->{refsize} - 1 );
    print $fh pack $packvar, $_ for @values;
    push @{ $self->{index} }, $current;
    return ( @{ $self->{index} } - 1 );
}

=head2 write_UID $id

Takes a UID C<$id> and returns the index into the offset
table of the offset object that points to its location in
the binary file. Passes the UID off to L</write_integer> for
actual writing, since they're processed in the same manner,
simply with different types.

=cut

sub write_UID {
    my $self = shift;
    my ($id) = @_;
    return $self->write_integer( $id, "8" );
}

=head2 write_real $real, $type

Takes a float C<$real> and an optional type C<$type>
(used for writing dates, since they're essentially the
same), and returns the index into the
offset table of the offset object that points to its
location in the binary file. The bytes of the float are
packed in reverse.

=cut

sub write_real {
    my $self    = shift;
    my ($float, $type) = @_;
    unless ( defined $type ) {
        $type = "2";
    }
    my $obj     = $self->make_type( $type, 3 ) . reverse( pack( "d", $float ) );
    return $self->binary_write($obj);
}

=head2 write_null $null

Takes a null C<$null> and passes it to L</write_misc>, along
with an integer indicating what type of misc it is. The
null belongs to the misc category (see L</write_misc>).

=cut

sub write_null {
    my $self = shift;
    return $self->write_misc( 0 );
}

=head2 write_false $false

Takes a false C<$false> and passes it to L</write_misc>, along with an
integer indicating what type of misc it is. The false
belongs to the misc category (see L</write_misc>).

=cut

sub write_false {
    my $self = shift;
    return $self->write_misc( 8 );
}

=head2 write_true $true

Takes a true C<$true> and passes it to L</write_misc>, along with an
integer indicating what type of misc it is. The true
belongs to the misc category (see L</write_misc>).

=cut

sub write_true {
    my $self = shift;
    return $self->write_misc( 9 );
}

=head2 write_fill $fill

Takes a fill C<$fill> and passes it to L</write_misc>, along with an
integer indicating what type of misc it is. The fill
belongs to the misc category (see L</write_misc>).

=cut

sub write_fill {
    my $self = shift;
    return $self->write_misc( 15 );
}

=head2 write_misc $type

Takes an integer indicating an object belonging to the misc
category C<$type> (false, null, true or fill) and returns
the index into the offset table of the offset object that
points to its location in the file.

Miscs are a group of data types not easily represented in Perl, and
they are written with the only header byte containing a 0 to indicate
that they are a misc and their misc type.

=cut

sub write_misc {
    my $self = shift;
    my ( $type ) = @_;
    my $obj = $self->make_type( "0", $type );
    return $self->binary_write($obj);
}

=head2 write_data $data

Takes some binary data C<$data> and returns the index into the
offset table of the offset object that points to its
location in the file. Doesn't attempt to process the data
at all.

=cut

sub write_data {
    my $self = shift;
    my ($data) = @_;
    use bytes;
    my $len = length $data;
    my $obj = $self->make_type( 4, $len ) . $data;
	return $self->binary_write($obj);
}

=head2 count $data

Recursively counts the number of objects in a serialized
data structure C<$data>. Does not take into account
duplicates, so this number might be slightly higher than
the number of objects that is indicated in the 32-byte
trailer.

=cut

sub count {

    # this might be slightly over, since it doesn't take into account duplicates
    my $self       = shift;
    my ($arrayref) = @_;
    my $type       = $arrayref->[0];
    my $value;
    if ( $type eq "dict" ) {
        my @keys = ( keys %{ $arrayref->[1] } );
        $value = 1 + @keys;
        $value += $_ for map { $self->count( $arrayref->[1]->{$_} ) } @keys;
        return $value;
    } elsif ( $type eq "array" ) {
        $value = 1;
        $value += $_ for map { $self->count($_) } @{ $arrayref->[1] };
        return $value;
    } else {
        return 1;
    }
}

=head2 binary_write $obj

Does the actual writing to the binary file. Takes some
binary data C<$obj> and writes it to the filehandle. Also
adds the location of the binary data to the offset table
and returns the index into the offset table of the current
object.

=cut

sub binary_write {
    my $self    = shift;
    my $fh      = $self->{fh};
    my ($obj)   = @_;
    my $current = tell $self->{fh};
    print $fh $obj;
    push @{ $self->{index} }, $current;
    return ( @{ $self->{index} } - 1 );
}

=head2 power $int

Calculates the number of bytes necessary to encode an
integer C<$int>. Returns a power of 2 indicating the number
of bytes.

=cut

sub power {
    my $self = shift;
    my ($int) = @_;
    if ( $int > 4294967295 ) {
        return 3;

        # actually refers to 2^3 bytes
    } elsif ( $int > 65535 ) {
        return 2;

        # actually refers to 2^2 bytes
    } elsif ( $int > 255 ) {
        return 1;

        # I'm sure you see the trend
    } elsif ( $int < 0 ) {
        return 3;
    } else {
        return 0;
    }
}

=head2 bytes $int

Calculates the number of bytes necessary to encode an
integer C<$int>. Returns the actual number of bytes.

=cut

sub bytes {
    my $self = shift;
    my ($int) = @_;
    if ( $int >= 2**24 ) {
        return 4;

        # actually refers to 4 bytes
    } elsif ( $int >= 2**16 ) {
        return 3;

        # actually refers to 3 bytes
    } elsif ( $int >= 256 ) {
        return 2;

        # I'm sure you see the trend
    } else {
        return 1;
    }
}

=head2 pack_in $int

Takes either a power of 2 or a number of bytes C<$int> and
returns the format pack() needs for encoding.

=cut

sub pack_in {

    # can be used with powers or bytes
    my $self  = shift;
    my ($int) = @_;
    my $fmt   = [ "C", "n", "N", "N" ]->[$int];
    return $fmt;
}

1;
