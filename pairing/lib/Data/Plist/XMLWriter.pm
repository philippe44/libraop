=head1 NAME

Data::Plist::XMLWriter - writes XML property lists from
perl data structures.

=head1 SYNOPSIS

 # Create new
 my $write = Data::Plist::XMLWriter->new;

 # Writing to a string
 my $str = $write->write($data);

 # Writing to a file C<$filename>
 $write->write($filename, $data);

=head1 DESCRIPTION

C<Data::Plist::XMLWriter> takes perl data structures,
serializes them (see L<Data::Plist/SERIALIZED DATA>) and
recursively writes to a given filehandle in Apple's XML
property list format.

=cut

package Data::Plist::XMLWriter;

use strict;
use warnings;

use base qw/Data::Plist::Writer/;
use XML::Writer;
use MIME::Base64 qw//;

=head2 write_fh $fh, $data

Takes a perl data structure C<$data>, serializes it (see
L<Data::Plist/SERIALIZED DATA>) and passes it to
L</xml_write> to be written to the filehandle C<$fh>. Also
writes the headers and footers for the XML document. Returns
1 to indicate success.

=cut

sub write_fh {
    my $self = shift;
    $self = $self->new() unless ref $self;

    my ( $fh, $object ) = @_;
    local $self->{x}
        = XML::Writer->new( OUTPUT => $fh, DATA_MODE => 1, DATA_INDENT => 8 );
    $self->{x}->xmlDecl("UTF-8");
    $self->{x}->doctype(
        "plist",
        "-//Apple//DTD PLIST 1.0//EN",
        "http://www.apple.com/DTDs/PropertyList-1.0.dtd"
    );
    $self->{x}->startTag( plist => version => "1.0" );
    $object = $self->serialize($object) if ( $self->{serialize} );
    $self->xml_write($object);
    $self->{x}->endTag("plist");
    $self->{x}->end();

    return 1;
}

=head2 xml_write

Takes serialized perl structures (see
L<Data::Plist/SERIALIZED DATA>) and recursively checks tags
and writes the data to the filehandle.

=cut

sub xml_write {
    my $self = shift;
    my $data = shift;

    if ( $data->[0] =~ /^(true|false|fill|null)$/ ) {
        $self->{x}->emptyTag( $data->[0] );
    } elsif ( $data->[0] =~ /^(integer|real|date|string|ustring)$/ ) {
        $self->{x}->dataElement( $data->[0], $data->[1] );
    } elsif ( $data->[0] eq "UID" ) {

        # UIDs are only hackishly supported in the XML version.
        # Apple's plutil converts them as follows:
        $self->{x}->startTag("dict");
        $self->{x}->dataElement( "key",     'CF$UID' );
        $self->{x}->dataElement( "integer", $data->[1] );
        $self->{x}->endTag("dict");
    } elsif ( $data->[0] eq "data" ) {
        $self->{x}->dataElement( "data",
            MIME::Base64::encode_base64( $data->[1] ) );
    } elsif ( $data->[0] eq "dict" ) {
        $self->{x}->startTag("dict");
        for my $k ( sort keys %{ $data->[1] } ) {
            $self->{x}->dataElement( "key", $k );
            $self->xml_write( $data->[1]{$k} );
        }
        $self->{x}->endTag("dict");
    } elsif ( $data->[0] eq "array" ) {
        $self->{x}->startTag("array");
        $self->xml_write($_) for @{ $data->[1] };
        $self->{x}->endTag("array");
    } else {
        $self->{x}->comment( $data->[0] );
    }
}

1;
