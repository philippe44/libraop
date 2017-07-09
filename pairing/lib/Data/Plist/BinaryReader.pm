=head1 NAME

Data::Plist::BinaryReader - Creates Data::Plists from binary files

=head1 SYNOPSIS

 # Create new
 my $read = Data::Plist::BinaryReader->new;

 # Read from a string
 my $plist = $read->open_string($binarystring);

 # Read from a binary file
 $plist = $read->open_fh($filename);

=head1 DESCRIPTION

C<Data::Plist::BinaryReader> takes data formatted as one of
Apple's binary property lists, either from a string or a
filehandle and returns it as a C<Data::Plist>.

=cut

package Data::Plist::BinaryReader;

use strict;
use warnings;

use base qw/Data::Plist::Reader/;
use Data::Plist;

use Encode qw(decode);
use Fcntl qw(:seek);
use Math::BigInt;

=head1 METHODS

=head2 read_misc $type

Takes an integer C<$type> indicating which misc is being
read. Returns an array containing the type of misc and its
associated integer.

=cut

sub read_misc {
    my $self = shift;

    my ($type) = @_;
    if ( $type == 0 ) {
        return [ "null", 0 ];
    } elsif ( $type == 8 ) {
        return [ "false", 0 ];
    } elsif ( $type == 9 ) {
        return [ "true", 1 ];
    } elsif ( $type == 15 ) {
        return [ "fill", 15 ];
    } else {
        return [ "???", $type ];
    }
}

=head2 read_integer $size

Takes an integer C<$size> indicating number of bytes needed
to encode the integer (2**C<$size> = number of
bytes). Reads that number of bytes from the filehandle and
unpacks it. Returns an array containing the string
"integer" and the value of the integer read from the
filehandle.

=cut

sub read_integer {
    my $self = shift;
    my ($size) = @_;

    my ( $buf, $val );
    read( $self->{fh}, $buf, 1 << $size );
    if ( $size == 0 ) {    # 8 bit
        $val = unpack( "C", $buf );
    } elsif ( $size == 1 ) {    # 16 bit
        $val = unpack( "n", $buf );
    } elsif ( $size == 2 ) {    # 32 bit
        $val = unpack( "N", $buf );
    } elsif ( $size == 3 ) {    # 64 bit

        my ( $hw, $lw ) = unpack( "NN", $buf );
        $val = Math::BigInt->new($hw)->blsft(32)->bior($lw);
        if ( $val->bcmp( Math::BigInt->new(2)->bpow(63) ) > 0 ) {
            $val -= Math::BigInt->new(2)->bpow(64);
        }
    } else {
        die "Invalid size for integer ($size)";
    }

    return [ "integer", $val ];
}

=head2 read_real $size

Takes an integer C<$size> indicating the number of bytes
needed to encode the float (see L</read_integer>). Reads
that number of bytes from the filehandle and unpacks
it. The number of bytes is limited to 4 and 8. Returns an
array containing the string "array" and the float read from
the filehandle.

=cut

sub read_real {
    my $self = shift;
    my ($size) = @_;

    my ( $buf, $val );
    read( $self->{fh}, $buf, 1 << $size );
    if ( $size == 2 ) {    # 32 bit
        $val = unpack( "f", reverse $buf );
    } elsif ( $size == 3 ) {    # 64 bit
        $val = unpack( "d", reverse $buf );
    } else {
        die "Invalid size for real ($size)";
    }

    return [ "real", $val ];
}


=head2 read_data $size

Takes an integer C<$size>, indicating the number of bytes
of binary data stored and reads them from the
filehandle. Checks if the bytes are actually another binary
plist and unpacks it if so. Returns an array containing the
string "data" and the binary data read from the filehandle.

=cut

sub read_data {
    my $self = shift;
    my ($size) = @_;

    my $buf;
    read( $self->{fh}, $buf, $size );

    # Binary data is often a binary plist!  Unpack it.
    if ( $buf =~ /^bplist00/ ) {
        $buf = eval { ( ref $self )->open_string($buf) } || $buf;
    }
	
	return [ "data", $buf ];
}

=head2 read_string $size

Takes an integer C<$size> indicating the number of bytes
used to encode the UTF-8 string stored and reads them from
the filehandle. Marks them as Unicode and returns an array
containing the string "string" and the string read from the
filehandle.

=cut

sub read_string {
    my $self = shift;
    my ($size) = @_;

    my $buf;
    read( $self->{fh}, $buf, $size );

    $buf = pack "U0C*", unpack "C*", $buf;    # mark as Unicode
	
	return [ "string", $buf ];
}

=head2 read_ustring

Takes an integer C<$size> indicating the number of bytes
used to encode the UTF-16 string stored and reads them from
the filehandle. Returns an array containing the string
"ustring" and the string read from the filehandle.

=cut

sub read_ustring {
    my $self = shift;
    my ($size) = @_;

    my $buf;
    read( $self->{fh}, $buf, 2 * $size );

    return [ "ustring", decode( "UTF-16BE", $buf ) ];
}

=head2 read_refs $count

Takes an integer C<$count> indicating the number of
references in either a dict or an array. Returns the
references pointing to the locations fo the contents of the
dict or array.

=cut

sub read_refs {
    my $self = shift;
    my ($count) = @_;
    my $buf;
    read( $self->{fh}, $buf, $count * $self->{refsize} );
    return unpack( ( $self->{refsize} == 1 ? "C*" : "n*" ), $buf );
}

=head2 read_array $size

Takes an integer C<$size> indicating the number of objects
that are contained in the array. Returns an array
containing the string "array" and the references pointing
to the location of the contents of the array in the file.

=cut

sub read_array {
    my $self = shift;
    my ($size) = @_;

    return [
        "array", [ map { $self->binary_read($_) } $self->read_refs($size) ]
    ];
}

=head2 read_dict $size

Takes an integer C<$size> indicating the number of
key-value pairs contained in the dict. Returns an array
containing the string "dict" and the references pointing to
the location of the key-value pairs of the dict in the
file.

=cut

sub read_dict {
    my $self = shift;
    my ($size) = @_;
    my %dict;

    # read keys
    my @keys = $self->read_refs($size);
    my @objs = $self->read_refs($size);

    for my $j ( 0 .. $#keys ) {
        my $key = $self->binary_read( $keys[$j] );
        die "Key of hash isn't a string!" unless $key->[0] eq "string";
        $key = $key->[1];
        my $obj = $self->binary_read( $objs[$j] );
        $dict{$key} = $obj;
    }

    return [ "dict", \%dict ];
}

=head2 read_uid $size

Takes an integer C<$size> indicating number of bytes needed
to encode the uid (2**C<$size> = number of bytes) and then
passes it to L</read_integer> to be dealt with, since uids
are stored identically to integers. Returns an array
containing the string "uid" and the uid read from the
filehandle.

=cut

sub read_uid {
    my $self = shift;
    my ($size) = @_;

    # UIDs are stored internally identically to ints
    my $v = $self->read_integer($size)->[1];
    return [ UID => $v ];
}

=head2 binary_read $objNum

Takes an integer indicating the offset number of the
current object C<$objNum> and checks to make sure it's
valid. Reads the object's type and size and then matches
the type to its read method. Passes the size to the correct
method and returns what that method returns.

=cut

sub binary_read {
    my $self = shift;
    my ($objNum) = @_;

    if ( defined $objNum ) {
        die "Bad offset: $objNum"
            unless $objNum < @{ $self->{offsets} };
        seek( $self->{fh}, $self->{offsets}[$objNum], SEEK_SET );
    }

    # get object type/size
    my $buf;
    read( $self->{fh}, $buf, 1 )
        or die "Can't read type byte: $!\byte:";

    my $size    = unpack( "C*", $buf ) & 0x0F;    # Low nybble is size
    my $objType = unpack( "C*", $buf ) >> 4;      # High nybble is type
    $size = $self->binary_read->[1]
        if $objType != 0 and $size == 15;

    my %types = (
        0  => "misc",
        1  => "integer",
        2  => "real",
        3  => "data",	# was date
        4  => "data",
        5  => "string",
        6  => "ustring",
        8  => "uid",
        10 => "array",
        13 => "dict",
    );

    die "Unknown type $objType" unless $types{$objType};
    my $method = "read_" . $types{$objType};
    die "Can't $method" unless $self->can($method);
    return $self->$method($size);
}

=head2 open_string $string

Takes a string of binary information in Apple's binary
property list format C<$string>. Checks to ensure that it's
of the correct format and then passes its superclass's
L</open_string>. The error proofing is done because
seeking in in-memory filehandles can cause perl 5.8.8 to
explode with "Out of memory" or "panic: memory wrap".

=cut

sub open_string {
    my $self = shift;
    my ($str) = @_;

    die "Not a binary plist file\n"
        unless length $str >= 8 and substr( $str, 0, 8 ) eq "bplist00";
    die "Read of plist trailer failed\n"
        unless length $str >= 40;
    die "Invalid top object identifier\n"
        unless length $str > 40;

    return $self->SUPER::open_string($str);
}

=head2 open_fh $filehandle

Used for reading binary data from a filehandle
C<$filehandle> rather than a string. Opens the filehandle
and sanity checks the header, trailer and offset
table. Returns a C<Data::Plist> containing the top object
of the filehandle after it's been passed to
L</binary_read>.

=cut

sub open_fh {
    my $self = shift;
    $self = $self->new() unless ref $self;

    my ($fh) = @_;

    my $buf;
    $self->{fh} = $fh;
    seek( $self->{fh}, 0, SEEK_SET );
    read( $self->{fh}, $buf, 8 );
    unless ( $buf eq "bplist00" ) {
        die "Not a binary plist file\n";
    }

    # get trailer
    eval { seek( $self->{fh}, -32, SEEK_END ) }
        or die "Read of plist trailer failed\n";
    my $end = tell( $self->{fh} );

    die "Read of plist trailer failed\n"
        unless $end >= 8;

    unless ( read( $self->{fh}, $buf, 32 ) == 32 ) {
        die "Read of plist trailer failed\n";
    }
    local $self->{refsize};
    my ( $OffsetSize, $NumObjects, $TopObject, $OffsetTableOffset );
    (   $OffsetSize, $self->{refsize}, $NumObjects, $TopObject,
        $OffsetTableOffset
    ) = unpack "x6CC(x4N)3", $buf;

    # Sanity check the trailer
    if ( $OffsetSize < 1 or $OffsetSize > 4 ) {
        die "Invalid offset size\n";
    } elsif ( $self->{refsize} < 1 or $self->{refsize} > 2 ) {
        die "Invalid reference size\n";
    } elsif ( 2**( 8 * $self->{refsize} ) < $NumObjects ) {
        die
            "Reference size (@{[$self->{refsize}]}) is too small for purported number of objects ($NumObjects)\n";
    } elsif ( $TopObject >= $NumObjects ) {
        die "Invalid top object identifier\n";
    } elsif ( $OffsetTableOffset < 8
        or $OffsetTableOffset > $end
        or $OffsetTableOffset + $NumObjects * $OffsetSize > $end )
    {
        die "Invalid offset table address (overlap with header or footer).";
    }

    # get the offset table
    seek( $fh, $OffsetTableOffset, SEEK_SET );

    my $offsetTable;
    my $readSize
        = read( $self->{fh}, $offsetTable, $NumObjects * $OffsetSize );
    if ( $readSize != $NumObjects * $OffsetSize ) {
        die "Offset table read $readSize bytes, expected ",
            $NumObjects * $OffsetSize;
    }

    my @Offsets = unpack( [ "", "C*", "n*", "(H6)*", "N*" ]->[$OffsetSize],
        $offsetTable );
    if ( $OffsetSize == 3 ) {
        @Offsets = map { hex($_) } @Offsets;
    }

    # Catch invalid offset addresses in the offset table
    if (grep {
                   $_ < 8
                or $_ >= $end
                or ($_ >= $OffsetTableOffset
                and $_ < $OffsetTableOffset + $NumObjects * $OffsetSize )
        } @Offsets
        )
    {
        die "Invalid address in offset table\n";
    }

    local $self->{offsets} = \@Offsets;

    my $top = $self->binary_read($TopObject);
    close($fh);

    return Data::Plist->new( data => $top );
}

1;
