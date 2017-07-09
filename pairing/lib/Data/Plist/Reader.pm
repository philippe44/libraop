=head1 NAME

Data::Plist::Reader - Abstract superclass for BinaryReader

=head1 SYNOPSIS

 # Create new
 $read = Data::Plist::BinaryReader->new;

 # Reading from a string C<$str>
 my $plist = $read->open_string($str);

 # Writing from file C<$filename>
 $plist = $read->read($filename);

=head1 DESCRIPTION

C<Data::Plist::Reader> is an abstract superclass of
BinaryReader. Takes either a string or a filehandle containing data
formatted as an Apple property list and returns it as a
C<Data::Plist>.

=cut

package Data::Plist::Reader;

use strict;
use warnings;

=head1 METHODS

=head2 new

Create a new reader.

=cut

sub new {
    my $class = shift;
    return bless {} => $class;
}

=head2 open_string $content

Takes binary data C<$content> and reads it into a
filehandle. Then passes that filehandle to L</open_fh>.

=cut

sub open_string {
    my $self = shift;
    my ($content) = @_;

    my $fh;
    open( $fh, "<", \$content );
	
    return $self->open_fh($fh);
}

=head2 open_file $filename

Takes a filename C<$filename> and reads its data into a
filehandle. Then passes the filehandle to L</open_fh>.

=cut

sub open_file {
    my $self = shift;
    my ($filename) = @_;

    my $fh;
    open( $fh, "<", $filename ) or die "can't open $filename for conversion";
    binmode($fh);
    return $self->open_fh($fh);
}

=head2 open_fh

Place-holder method for Reader's subclass. Currently
unimplemented.

=cut

sub open_fh {
    my $self = shift;

    die "Unimplemented!";
}

1;
