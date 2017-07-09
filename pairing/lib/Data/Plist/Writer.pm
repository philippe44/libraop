=head1 NAME

Data::Plist::Writer - Object serializer and abstact
superclass for BinaryWriter and XMLWriter

=head1 SYNOPSIS

 # Create new
 my $write = Data::Plist::BinaryWriter->new;

 # Writing to a string ($ret is binary output)
 my $ret = $write->write($data);

 # Writing to a file C<$filename>
 $ret = $write->write($filename, $data);

=head1 DESCRIPTION

C<Data::Plist::Writer> is the abstract superclass of
L<Data::Plist::BinaryWriter> and L<Data::Plist::XMLWriter>. It takes
perl data structures, serializes them (see L<Data::Plist/SERIALIZED
DATA>), and recursively writes to a given filehandle in the desired
format.

=cut

package Data::Plist::Writer;

use strict;
use warnings;
use Storable;
use Digest::MD5;
use Scalar::Util qw(blessed);

=head1 METHODS

=cut

=head2 new

Creates a new writer. 'serialize' is set to 1 since it's
assumed that data being passed in will be perl data
structures that need to be serialized. Users may set it to
0 when creating a writer if they wish to use preserialized
data.

=cut

sub new {
    my $class = shift;
    my %args = ( serialize => 1, @_ );
    return bless \%args => $class;
}

=head2 write $filehandle, $data

=head2 write $filename, $data

=head2 write $data

Takes a perl data structure C<$data> and writes to the given
filehandle C<$filehandle>, or filename C<$filename>.  If only the
C<$data> is provided, returns the data to be written, as a string.

=cut

sub write {
    my $self   = shift;
    my $object = pop;
    my $to     = shift;

	if ( not $to ) {
        my $content = '';
        my $fh;
        open( $fh, ">", \$content );
        $self->write_fh( $fh, $object ) or return;
        return $content;
    } elsif ( ref $to ) {
        $self->write_fh( $to, $object );
    } else {
        my $fh;
        open( $fh, ">", $to ) or die "Can't open $to for writing: $!";
        $self->write_fh( $fh, $object ) or return;
    }
    return;
}

=head2 fold_uids $data

Takes a serialized object C<$data> (see
L<Data::Plist/SERIALIZED DATA>) and rewrites it as a keyed
archive (see L<Data::Plist/KEYED ARCHIVES>) by folding on
UIDs.

=cut

sub fold_uids {
    my $self = shift;
    my $data = shift;

    if ( $data->[0] eq "UID" ) {
        local $Storable::canonical = 1;
        my $digest = Digest::MD5::md5_hex( Storable::freeze( $data->[1] ) );
        if ( exists $self->{objcache}{$digest} ) {
            return [ UID => $self->{objcache}{$digest} ];
        }
        push @{ $self->{objects} }, $self->fold_uids( $data->[1] );
        $self->{objcache}{$digest} = @{ $self->{objects} } - 1;
        return [ UID => @{ $self->{objects} } - 1 ];
    } elsif ( $data->[0] eq "array" ) {
        return [ "array", [ map { $self->fold_uids($_) } @{ $data->[1] } ] ];
    } elsif ( $data->[0] eq "dict" ) {
        my %dict = %{ $data->[1] };
        $dict{$_} = $self->fold_uids( $dict{$_} ) for keys %dict;
        return [ "dict", \%dict ];
    } else {
        return $data;
    }
}

=head2 serialize_value $data

Takes a perl data structure C<$data> and turns it into a
series of nested arrays of the format [datatype => data]
(see L<Data::Plist/SERIALIZED DATA>) in preparation for
writing. This is an internal data structure that should be
immediately handed off to a writer.

=cut

sub serialize_value {
    my $self = shift;
    my ($value) = @_;
	
    if ( not defined $value ) {
        return [ string => '$null' ];
    } elsif ( ref $value ) {
        if ( ref $value eq "ARRAY" ) {
            return [
                array => [ map { $self->serialize_value($_) } @{$value} ] ];
        } elsif ( ref $value and ref $value eq "HASH" ) {
            my %hash = %{$value};
            $hash{$_} = $self->serialize_value( $hash{$_} ) for keys %hash;
            return [ dict => \%hash ];
        } elsif ( $value->isa("Data::Plist::Foundation::NSObject") ) {
            return $value->serialize;
        } else {
            die "Can't serialize unknown ref @{[ref $value]}\n";
        }
    } elsif ( $value =~ /^-?\d+$/ ) {
        return [ integer => $value ];
    } elsif ( Scalar::Util::looks_like_number($value) ) {
        return [ real => $value ];
    } elsif ( $value =~ /\p{XPosixCntrl}/ ) {
        return [ data => $value ];
    } else {
        return [ string => $value ];
    }
}

=head2 serialize $data

Takes a data structure C<$data> and determines what sort of
serialization it should go through.

Objects wishing to provide their own serializations should
have a 'serialize' method, which should return something in
the internal structure mentioned above (see also
L<Data::Plist/SERIALIZED DATA>).

=cut

sub serialize {
    my $self   = shift;
    my $object = shift;

	return $self->serialize_value($object)
        if not ref($object)
        or ref($object) =~ /ARRAY|HASH/
        or not $object->can("serialize");

	$object = $object->serialize;

    local $self->{objects}  = [];
    local $self->{objcache} = {};
    my $top = $self->fold_uids( [ dict => { root => [ UID => $object ] } ] );

    return [
        dict => {
            '$archiver' => [ string  => "NSKeyedArchiver" ],
            '$version'  => [ integer => 100_000 ],
            '$top'      => $top,
            '$objects'  => [ array   => $self->{objects} ],
        },
    ];
}

1;
