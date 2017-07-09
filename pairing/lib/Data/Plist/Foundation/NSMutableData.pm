package Data::Plist::Foundation::NSMutableData;

use strict;
use warnings;

use base qw/Data::Plist::Foundation::NSData/;
use Data::Plist::BinaryWriter;

sub data {
    my $self = shift;
    return $self->{"NS.data"};
}

sub serialize_equiv {
    my $self = shift;
    return $self->SUPER::serialize_equiv unless ref $self->data;
    return { "NS.data" => Data::Plist::BinaryWriter->write( $self->data ) };
}

1;

