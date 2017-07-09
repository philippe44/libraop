package Data::Plist::Foundation::ToDoAlarm;

use strict;
use warnings;

use base qw/Data::Plist::Foundation::NSObject/;

sub serialize {
    my $self = shift;
    my $ret  = $self->SUPER::serialize;
    $ret->[1]{"ToDo Alarm Enabled"}
        = $ret->[1]{"ToDo Alarm Enabled"}[1] ? [ true => 1 ] : [ false => 0 ];
    return $ret;
}

1;
