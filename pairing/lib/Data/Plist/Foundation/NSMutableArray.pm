package Data::Plist::Foundation::NSMutableArray;

use strict;
use warnings;

use base qw/Data::Plist::Foundation::NSArray/;

sub serialize {
    my $self = shift;
    my $ret  = $self->SUPER::serialize;
    $ret->[1]{'NS.objects'}
        = [
        array => [ map { [ UID => $_ ] } @{ $ret->[1]{'NS.objects'}[1][1] } ]
        ];
    return $ret;
}

1;

