package Data::Plist::Foundation::NSURL;

use strict;
use warnings;

use base qw/Data::Plist::Foundation::NSObject URI::http/;

sub replacement {
    my $self = shift;
    my $uri = URI->new( $self->{"NS.relative"}, "http" );
    bless $uri, ( ref $self );
    return $uri;
}

sub serialize_equiv {
    my $self = shift;
    return { "NS.relative" => $self->as_string, "NS.base" => undef };
}

1;
