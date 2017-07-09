package Data::Plist::Foundation::NSMutableString;

use strict;
use warnings;

use base qw/Data::Plist::Foundation::NSString/;

sub replacement {
    my $self = shift;
    return $self->{"NS.string"};
}

1;
